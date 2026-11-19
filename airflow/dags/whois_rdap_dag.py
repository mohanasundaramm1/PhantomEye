# airflow/dags/whois_rdap_dag.py
from __future__ import annotations

import os
import tempfile
import logging
from datetime import datetime, timedelta

import pandas as pd
import tldextract

from airflow import DAG
from alerts import notify_failure
from airflow.operators.python import PythonOperator, get_current_context
from airflow.exceptions import AirflowSkipException

log = logging.getLogger(__name__)

# --------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------

LABELS_UNION_BASE = "/opt/airflow/silver/labels_union"
LOOKUPS_BASE = "/opt/airflow/lookups"

WHOIS_CACHE_PATH = f"{LOOKUPS_BASE}/whois_cache.parquet"   # rolling cache
WHOIS_DAILY_DIR = f"{LOOKUPS_BASE}/whois"                  # partitioned snapshots

# TTL knobs (override via env if needed)
TTL_DAYS = int(os.getenv("WHOIS_TTL_DAYS", "30"))                  # refresh good rows after N days
ERROR_REFRESH_DAYS = int(os.getenv("WHOIS_ERROR_REFRESH_DAYS", "7"))  # retry errored rows after N days

# --------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------


def _effective_ds_ts(ds: str, ts: str, **context):
    """
    If orchestrator passed ds/ts via dag_run.conf, prefer those.
    Otherwise keep the scheduler's ds/ts.
    """
    dr = context.get("dag_run")
    if dr and getattr(dr, "conf", None):
        ds2 = dr.conf.get("ds") or ds
        ts2 = dr.conf.get("ts") or ts
        if ds2 != ds or ts2 != ts:
            log.info(
                "Overriding ds/ts from dag_run.conf: %s,%s -> %s,%s",
                ds, ts, ds2, ts2
            )
        return ds2, ts2
    return ds, ts


def _resolve_ds_ts_flexible(ds: str | None, ts: str | None, **maybe_ctx):
    """
    Works whether ds/ts/context are passed explicitly or not.
    Fallbacks:
      - Airflow runtime context (get_current_context)
      - Now in UTC if no context is available (e.g. ad-hoc local test)
    """
    try:
        ctx = maybe_ctx if ("dag_run" in maybe_ctx or "ds" in maybe_ctx) else get_current_context()
        ds0 = ds or ctx["ds"]
        ts0 = ts or ctx["ts"]
        return _effective_ds_ts(ds0, ts0, **ctx)
    except Exception:
        now = pd.Timestamp.now(tz="UTC")
        return now.date().isoformat(), now.strftime("%Y-%m-%d %H:%M:%S")


def _atomic_to_parquet(df: pd.DataFrame, final_path: str):
    """
    Atomic write: write to a temp file then move into place.
    Prevents half-written files if the process dies.
    """
    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        suffix=".parquet",
        dir=os.path.dirname(final_path) or ".",
    )
    os.close(fd)
    try:
        df.to_parquet(tmp, index=False)
        os.replace(tmp, final_path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


def _load_labels_for_day(ds: str) -> pd.DataFrame:
    """
    Load labels_union for a given ds, or skip if missing/empty.
    """
    p = f"{LABELS_UNION_BASE}/ingest_date={ds}/labels_union.parquet"
    if not os.path.exists(p):
        raise AirflowSkipException(
            f"[whois_rdap] labels_union parquet not found for ds={ds}: {p}"
        )
    df = pd.read_parquet(p).dropna(subset=["domain"])
    if df.empty:
        raise AirflowSkipException(
            f"[whois_rdap] labels_union empty for ds={ds}, nothing to enrich."
        )
    return df


def _effective_domain(d: str) -> str:
    """
    Normalize to registered domain (example.com from foo.bar.example.com).
    Handles both registered_domain and top_domain_under_public_suffix so
    we’re safe across tldextract versions.
    """
    ext = tldextract.extract(d or "")
    reg = (
        getattr(ext, "registered_domain", None)
        or getattr(ext, "top_domain_under_public_suffix", None)
        or ""
    )
    return reg.lower().strip()


# --------------------------------------------------------------------
# Main task
# --------------------------------------------------------------------


def whois_rdap_task(ds: str | None = None, ts: str | None = None, **context):
    # Resolve ds/ts, preferring dag_run.conf when triggered by orchestrator
    ds, ts = _resolve_ds_ts_flexible(ds, ts, **context)

    os.makedirs(LOOKUPS_BASE, exist_ok=True)
    os.makedirs(WHOIS_DAILY_DIR, exist_ok=True)

    # Two kinds of runs share this task:
    #   - orchestrator/manual trigger: enqueue this ds's labeled domains, then
    #     drain a bounded chunk and write the daily whois subset (original job).
    #   - the DAG's own 2-hourly SCHEDULED runs: DRAIN-ONLY. Their purpose is to
    #     keep eating the shared queue backlog between orchestrator runs. They
    #     must not re-enqueue the day's labels 12x/day, and must not skip just
    #     because the (mid-day) logical ds has no labels file yet.
    dag_run = context.get("dag_run")
    drain_only = dag_run is not None and getattr(dag_run, "run_type", "") == "scheduled"

    domains: list = []
    if not drain_only:
        labels = _load_labels_for_day(ds)
        labels["registered_domain"] = labels["domain"].map(_effective_domain)
        domains = sorted(
            d
            for d in labels["registered_domain"]
            .dropna()
            .astype(str)
            .str.lower()
            .unique()
            .tolist()
            if d
        )
        if not domains:
            raise AirflowSkipException(f"[whois_rdap] no valid domains for ds={ds}")

    # -------- queue-decoupled path --------
    # Enqueue domains into the durable enrichment queue and drain it via the
    # shared worker (token-bucket rate limits, per-call timeouts, circuit
    # breaker, TTL'd parquet caches). Knobs live in config/enrichment.json.
    from ct.enrich.config import load_config
    from ct.enrich.enrich_worker import build_caches, enqueue_domains, run_worker

    cfg = load_config()
    cfg["paths"]["lookups_dir"] = LOOKUPS_BASE
    if domains:
        # labeled malicious domains: no triage_score -> treated as high priority (Tier 2)
        enqueue_domains(domains, cfg)
    # BOUNDED drain (fix for the run-forever failure): the shared queue is
    # continuously refilled by enrich_hot every 2h, so an unbounded
    # drain-until-empty here can mathematically never finish -- it just runs
    # until execution_timeout (4h) kills it and the run is recorded FAILED,
    # every time. Instead each run drains for at most drain_budget_seconds,
    # exits SUCCESS, and the next scheduled run continues where it left off
    # (unprocessed items stay queued, no attempts burned). Override per-trigger:
    #   airflow dags trigger whois_rdap_ingest -c '{"drain_budget_seconds": 120}'
    conf = (dag_run.conf if dag_run is not None and dag_run.conf else {}) or {}
    budget = float(conf.get("drain_budget_seconds")
                   or os.getenv("CT_WHOIS_DRAIN_BUDGET_SECONDS", "3000"))
    stats = run_worker(cfg, max_seconds=budget)
    log.info("[whois_rdap] bounded drain done (budget=%.0fs, drain_only=%s): %s",
             budget, drain_only, stats)

    if drain_only:
        return  # scheduled drain runs don't own a ds; no daily subset to write

    # Daily subset for this ds, taken from the refreshed rolling cache
    cache = build_caches(cfg)["whois"]._df
    daily = cache[cache["domain"].astype(str).isin(domains)].copy()
    outdir = f"{WHOIS_DAILY_DIR}/ingest_date={ds}"
    outpath = f"{outdir}/whois.parquet"
    _atomic_to_parquet(daily, outpath)

    log.info(
        "[whois_rdap] ds=%s daily_rows=%d cache_size=%d -> %s",
        ds, len(daily), len(cache), outpath,
    )
    return


default_args = {
    "on_failure_callback": notify_failure,
    "owner": "you",
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
}

with DAG(
    dag_id="whois_rdap_ingest",
    start_date=datetime(2025, 11, 1),
    # Every 2h (offset :30 to stagger against ct_enrich_and_score_dag's :00
    # cadence), PLUS the daily orchestrator trigger. Each run drains a bounded
    # chunk of the shared enrichment queue (see drain_budget_seconds in the
    # task); trigger-only + unbounded drain could never keep up with the
    # queue's continuous 2-hourly refill from enrich_hot.
    schedule_interval="30 */2 * * *",
    catchup=False,
    max_active_runs=1,
    default_args=default_args,
    tags=["enrich", "whois", "lookup"],
) as dag:
    PythonOperator(
        task_id="whois_rdap_fetch",
        python_callable=whois_rdap_task,
        # generous headroom over the 50-min default drain budget; the budget,
        # not this timeout, is what ends a normal run now
        execution_timeout=timedelta(hours=4),
    )
