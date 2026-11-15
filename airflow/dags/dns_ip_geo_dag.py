# airflow/dags/dns_ip_geo_dag.py
from __future__ import annotations
import os, tempfile, logging
from datetime import datetime, timedelta

import pandas as pd
import tldextract

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.exceptions import AirflowSkipException

log = logging.getLogger(__name__)

LABELS_UNION_BASE = "/opt/airflow/silver/labels_union"
LOOKUPS_BASE      = "/opt/airflow/lookups"

DNS_GEO_CACHE_PATH = f"{LOOKUPS_BASE}/dns_geo_cache.parquet"   # rolling cache
DNS_GEO_DAILY_DIR  = f"{LOOKUPS_BASE}/dns_geo"                 # partitioned snapshots


# ---------------- helpers ----------------

def _effective_ds_ts(ds: str, ts: str, **context):
    """
    Use ds/ts from dag_run.conf when triggered by the orchestrator; fall back to Airflow context.
    """
    dr = context.get("dag_run")
    if dr and getattr(dr, "conf", None):
        return dr.conf.get("ds", ds), dr.conf.get("ts", ts)
    return ds, ts

def _atomic_to_parquet(df: pd.DataFrame, final_path: str):
    """Atomic write to avoid partial files if the process dies."""
    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(final_path), delete=False, suffix=".parquet") as tmp:
        tmp_path = tmp.name
    try:
        df.to_parquet(tmp_path, index=False)
        os.replace(tmp_path, final_path)  # atomic on POSIX
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

def _load_labels_for_day(ds: str) -> pd.DataFrame:
    p = f"{LABELS_UNION_BASE}/ingest_date={ds}/labels_union.parquet"
    if not os.path.exists(p):
        raise AirflowSkipException(f"[dns_ip_geo] labels_union parquet not found for ds={ds}: {p}")
    df = pd.read_parquet(p).dropna(subset=["domain"])
    if df.empty:
        raise AirflowSkipException(f"[dns_ip_geo] labels_union empty for ds={ds}")
    return df

def _regdom(d: str) -> str:
    ext = tldextract.extract((d or "").strip())
    return (ext.registered_domain or "").lower()

def _to_punycode(d: str) -> str:
    try:
        return d.encode("idna").decode("ascii")
    except Exception:
        return d  # best effort; leave as-is

# ---------------- main task ----------------

def dns_ip_geo_task(ds: str, ts: str, **context):
    ds, ts = _effective_ds_ts(ds, ts, **context)

    os.makedirs(LOOKUPS_BASE, exist_ok=True)
    os.makedirs(DNS_GEO_DAILY_DIR, exist_ok=True)
    outdir = f"{DNS_GEO_DAILY_DIR}/ingest_date={ds}"

    labels = _load_labels_for_day(ds)

    # normalize to registered domain + punycode
    labels["reg_domain"] = labels["domain"].map(_regdom)
    labels = labels[labels["reg_domain"] != ""].copy()
    if labels.empty:
        raise AirflowSkipException(f"[dns_ip_geo] no valid registered domains for ds={ds}")

    labels["puny_domain"] = labels["reg_domain"].map(_to_punycode)
    domains = sorted(labels["puny_domain"].dropna().unique().tolist())

    # -------- queue-decoupled path --------
    # Enqueue domains into the durable enrichment queue and drain via the shared
    # worker (rate limits, timeouts, circuit breaker, TTL'd caches). Knobs in
    # config/enrichment.json. DNS/GeoIP is Tier 0/1; WHOIS is gated by triage_score.
    from ct.enrich.config import load_config
    from ct.enrich.enrich_worker import build_caches, enqueue_domains, run_worker

    cfg = load_config()
    cfg["paths"]["lookups_dir"] = LOOKUPS_BASE
    # keep this DAG cheap: DNS/geo only, skip Tier 2 WHOIS for these items
    items = [{"registered_domain": d, "domain": d, "triage_score": 0.0} for d in domains]
    enqueue_domains(items, cfg)
    # BOUNDED drain: this drains the SHARED enrichment queue, which also holds
    # WHOIS-heavy items enqueued by other DAGs and is continuously refilled by
    # enrich_hot -- an unbounded drain-until-empty here ran for 4h+ until it was
    # killed and the run recorded FAILED. Each run now drains a bounded chunk
    # and exits SUCCESS; the remainder stays queued for the next run.
    # Override per-trigger: -c '{"drain_budget_seconds": 120}'
    _dag_run = context.get("dag_run")
    _conf = (_dag_run.conf if _dag_run is not None and _dag_run.conf else {}) or {}
    _budget = float(_conf.get("drain_budget_seconds")
                    or os.getenv("CT_DNS_DRAIN_BUDGET_SECONDS", "1800"))
    _stats = run_worker(cfg, max_seconds=_budget)
    log.info("[dns_ip_geo] bounded drain done (budget=%.0fs): %s", _budget, _stats)

    # daily subset from refreshed caches: dns pairs joined with ip geo
    caches = build_caches(cfg)
    dns_df = caches["dns"]._df
    geo_df = caches["geo"]._df
    daily = dns_df[dns_df["puny_domain"].astype(str).isin(domains)].copy()
    if not geo_df.empty and "ip" in daily.columns:
        daily = daily.merge(
            geo_df.drop(columns=["fetched_at"], errors="ignore"),
            on="ip", how="left", suffixes=("", "_geo"),
        )
    _atomic_to_parquet(daily, f"{outdir}/dns_geo.parquet")
    log.info("[dns_ip_geo] ds=%s domains=%d daily_rows=%d -> %s",
             ds, len(domains), len(daily), outdir)
    return


default_args = {
    "owner": "you",
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
}

with DAG(
    dag_id="dns_ip_geo_ingest",
    start_date=datetime(2025, 11, 1),
    schedule_interval=None,          # <-- trigger-only (orchestrator handles ds/ts)
    catchup=False,
    max_active_runs=1,
    default_args=default_args,
    tags=["enrich","dns","geo","lookup"],
) as dag:
    PythonOperator(
        task_id="dns_ip_geo_fetch",
        python_callable=dns_ip_geo_task,
        # hard stop well above the 30-min default drain budget; previously this
        # task had NO timeout and ran unbounded for 4h+ before being killed
        execution_timeout=timedelta(hours=1),
    )
