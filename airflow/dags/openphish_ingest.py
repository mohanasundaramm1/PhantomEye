# airflow/dags/openphish_ingest.py
from __future__ import annotations
import os, re, time, shutil, tempfile, logging
from urllib.parse import urlparse
from datetime import datetime

import pandas as pd
import requests
import great_expectations as ge

from airflow import DAG
from alerts import notify_failure
from airflow.operators.python import PythonOperator, get_current_context
from airflow.exceptions import AirflowSkipException, AirflowFailException
from feed_fetch import PermanentFeedError, TransientFeedError, fetch_feed, host_from_url

log = logging.getLogger(__name__)

BRONZE_BASE = "/opt/airflow/bronze/openphish"
MIN_ROWS = 50  # guardrail threshold

def _effective_ds_ts(ds: str, ts: str, **context):
    """Honor dag_run.conf overrides for ds/ts if provided."""
    dr = context.get("dag_run")
    if dr and getattr(dr, "conf", None):
        ds2 = dr.conf.get("ds") or ds
        ts2 = dr.conf.get("ts") or ts
        if ds2 != ds or ts2 != ts:
            log.info("Overriding ds/ts from dag_run.conf: %s,%s -> %s,%s", ds, ts, ds2, ts2)
        return ds2, ts2
    return ds, ts

def _resolve_ds_ts_flexible(ds: str | None, ts: str | None, **maybe_ctx):
    """
    Works whether ds/ts/context were provided explicitly or not.
    Falls back to Airflow runtime context; final fallback = 'now' in UTC.
    """
    try:
        ctx = maybe_ctx if ("dag_run" in maybe_ctx) else get_current_context()
        ds0 = ds or ctx["ds"]
        ts0 = ts or ctx["ts"]
        return _effective_ds_ts(ds0, ts0, **ctx)
    except Exception:
        # Absolute fallback for tests/non-Airflow execution
        now = pd.Timestamp.utcnow()
        return (now.date().isoformat(), now.strftime("%Y-%m-%d %H:%M:%S"))

def _to_utc_timestamp(ts_str: str):
    """Safely convert Airflow ts (aware or naive) to UTC-aware pandas Timestamp."""
    t = pd.Timestamp(ts_str)
    return t.tz_localize("UTC") if t.tzinfo is None else t.tz_convert("UTC")

# Any URL scheme (feeds list ftp:// URLs too); see feed_fetch.host_from_url.
_host = host_from_url

def fetch_and_write_openphish(ds: str | None = None, ts: str | None = None, **context):
    # Align with orchestrator’s logical date/time (robust to invocation style)
    ds, ts = _resolve_ds_ts_flexible(ds, ts, **context)

    ds_date = pd.to_datetime(ds).date()
    today_date = pd.Timestamp.utcnow().date()
    outdir = f"{BRONZE_BASE}/ingest_date={ds}"

    # OpenPhish public feed is a *current* snapshot → never synthesize history
    if ds_date != today_date:
        if os.path.exists(outdir):
            raise AirflowSkipException(
                f"[openphish_ingest] Historical partition exists for {ds}; skipping rewrite."
            )
        raise AirflowSkipException("[openphish_ingest] OpenPhish has no historical feed; skipping backfill.")

    # Resilient fetch: a permanent HTTP error fails at once (no retries); transient ones are retried.
    url = "https://openphish.com/feed.txt"
    try:
        r = fetch_feed(requests.Session(), url, min_len=200, timeout=(5, 30),
                       headers={"User-Agent": "threat-intel-lab/0.1"})
    except PermanentFeedError as e:
        raise AirflowFailException(f"[openphish_ingest] {e}") from None
    except TransientFeedError as e:
        raise RuntimeError(f"[openphish_ingest] {e}") from None

    # Normalize: one URL per line (ignore comments/blank lines)
    lines = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")]
    df = pd.DataFrame({"url": lines})
    df["domain"] = df["url"].map(_host)
    df["first_seen"] = _to_utc_timestamp(ts)  # tz-safe UTC
    df = df.dropna(subset=["domain"]).drop_duplicates(subset=["url"])
    df = df[["url", "domain", "first_seen"]]

    # Guardrails
    n = len(df)
    if n < MIN_ROWS:
        if os.path.exists(outdir):
            # Keep existing same-day partition if it already exists
            raise AirflowSkipException(
                f"[openphish_ingest] rows={n} < {MIN_ROWS}; keeping existing partition for {ds}"
            )
        # First attempt today and tiny -> fail loudly for visibility
        raise ValueError(f"[openphish_ingest] returned {n} rows (<{MIN_ROWS})")

    # Light GE checks
    gdf = ge.from_pandas(df)
    assert gdf.expect_column_to_exist("domain").success
    assert gdf.expect_column_values_to_not_be_null("domain").success
    assert gdf.expect_column_values_to_match_regex("url", r"^(https?|ftp)://").success

    # Idempotent + atomic write
    if os.path.exists(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir, exist_ok=True)
    final_path = f"{outdir}/openphish.parquet"
    fd, tmp = tempfile.mkstemp(suffix=".parquet", dir=outdir); os.close(fd)
    df.to_parquet(tmp, index=False)
    os.replace(tmp, final_path)
    log.info("[openphish_ingest] %s: wrote %d rows -> %s", ds, n, final_path)

default_args = {
    "on_failure_callback": notify_failure,"owner": "you", "retries": 2}

with DAG(
    dag_id="openphish_ingest",
    start_date=datetime(2025, 11, 3),
    schedule_interval=None,     # <— let the ORCHESTRATOR trigger this; prevents duplicate runs
    catchup=False,
    max_active_runs=1,
    default_args=default_args,
    tags=["ingest", "bronze"],
) as dag:
    PythonOperator(
        task_id="openphish_fetch_normalize_bronze",
        python_callable=fetch_and_write_openphish,
    )
