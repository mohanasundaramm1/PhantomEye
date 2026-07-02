# ct/enrich/enrich_worker.py
"""Queue-decoupled enrichment worker.

Runs standalone:
    python -m ct.enrich.enrich_worker --enqueue-from-bronze --drain
    python -m ct.enrich.enrich_worker --drain               # drain existing queue
    python -m ct.enrich.enrich_worker --enqueue-domains a.com b.com

or from Airflow (PythonOperator/BashOperator) via `run_worker(...)` /
`enqueue_domains(...)`. Consumes batches from the durable file queue,
enriches tier-by-tier under token-bucket rate limits, time-boxed calls,
and per-service circuit breakers; failures are requeued with an attempt
counter (max attempts -> failed ledger). Emits queue depth / enrichment
lag and per-cache hit rates each cycle.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone

import pandas as pd

from ct.enrich.cache import ParquetTTLCache, atomic_to_parquet
from ct.enrich.circuit import CircuitBreaker
from ct.enrich.config import abspath, load_config
from ct.enrich.queue import FileQueue
from ct.enrich.ratelimit import TokenBucket
from ct.enrich.tiers import CircuitOpen, EnrichFailure, enrich_item

log = logging.getLogger(__name__)


# ---------------- construction helpers ----------------

def build_queue(cfg: dict) -> FileQueue:
    q = cfg["queue"]
    return FileQueue(abspath(cfg, q["dir"]), batch_size=q["batch_size"],
                     max_attempts=q["max_attempts"])


def build_caches(cfg: dict) -> dict:
    lookups = abspath(cfg, cfg["paths"]["lookups_dir"])
    ttls = cfg["cache_ttls"]
    return {
        "whois": ParquetTTLCache("whois", os.path.join(lookups, "whois_cache.parquet"),
                                 key_col="domain",
                                 ttl_seconds=ttls["whois_days"] * 86400),
        "dns": ParquetTTLCache("dns_geo", os.path.join(lookups, "dns_geo_cache.parquet"),
                               key_col="puny_domain",
                               ttl_seconds=ttls["dns_hours"] * 3600),
        "geo": ParquetTTLCache("ip_geo", os.path.join(lookups, "ip_geo_cache.parquet"),
                               key_col="ip",
                               ttl_seconds=ttls["geo_hours"] * 3600),
    }


def build_rate_limiters(cfg: dict) -> dict:
    rl = cfg["rate_limits"]
    return {"whois": TokenBucket(rl["whois_rps"]), "dns": TokenBucket(rl["dns_rps"])}


def build_breakers(cfg: dict) -> dict:
    cb = cfg["circuit_breaker"]
    return {
        name: CircuitBreaker(name, failure_threshold=cb["failure_threshold"],
                             cooldown_seconds=cb["cooldown_seconds"])
        for name in ("whois", "dns")
    }


# ---------------- enqueue paths ----------------

def enqueue_domains(domains_or_records, cfg: dict | None = None) -> int:
    """Enqueue registered domains (strings) or record dicts (may carry triage_score)."""
    cfg = cfg or load_config()
    queue = build_queue(cfg)
    items = []
    for r in domains_or_records:
        if isinstance(r, str):
            items.append({"registered_domain": r, "domain": r, "triage_score": None})
        else:
            item = dict(r)
            item.setdefault("registered_domain", item.get("domain"))
            item.setdefault("triage_score", None)
            items.append(item)
    for i in range(0, len(items), queue.batch_size):
        queue.enqueue(items[i:i + queue.batch_size])
    log.info("[worker] enqueued %d items", len(items))
    queue.log_metrics()
    return len(items)


def enqueue_from_bronze(cfg: dict | None = None) -> int:
    """Read new bronze CT rows (bookmark-incremental, same as the old inline path)
    and enqueue them for the worker. Records with a triage_score field keep it."""
    from ct.enrich import enrich_ct  # reuse existing bronze reader + bookmark

    cfg = cfg or load_config()
    df = enrich_ct.read_bronze()
    if df.empty:
        log.info("[worker] no new bronze rows to enqueue")
        return 0
    df = df.head(enrich_ct.MAX_DOMAINS)
    records = []
    for _, r in df.iterrows():
        records.append({
            "registered_domain": r.get("registered_domain"),
            "domain": r.get("domain"),
            "event_ts": str(r.get("event_ts")) if r.get("event_ts") is not None else None,
            "source": r.get("source"),
            "triage_score": (float(r["triage_score"])
                             if "triage_score" in df.columns and pd.notna(r.get("triage_score"))
                             else None),
        })
    n = enqueue_domains(records, cfg)
    # advance bookmark now that rows are durably queued
    if "ingest_ts" in df.columns and not df["ingest_ts"].empty:
        enrich_ct._write_bookmark({"last_ingest_ts": str(df["ingest_ts"].max())})
    return n


# ---------------- drain loop ----------------

def run_worker(cfg: dict | None = None, max_batches: int | None = None,
               dns_fetch=None, whois_fetch=None) -> dict:
    """Drain the pending queue. Returns summary stats. Fetchers injectable for tests."""
    cfg = cfg or load_config()
    queue = build_queue(cfg)
    caches = build_caches(cfg)
    limiters = build_rate_limiters(cfg)
    breakers = build_breakers(cfg)

    queue.recover_stale()

    from ct.enrich import tiers as _tiers
    dns_fetch = dns_fetch or _tiers.default_dns_fetch
    whois_fetch = whois_fetch or _tiers.default_whois_fetch

    enriched_rows: list[dict] = []
    stats = {"processed": 0, "requeued": 0, "batches": 0}

    while max_batches is None or stats["batches"] < max_batches:
        queue.log_metrics()
        claimed = queue.claim_batch()
        if claimed is None:
            break
        claim_path, items = claimed
        stats["batches"] += 1
        for item in items:
            try:
                row = enrich_item(
                    item,
                    whois_cache=caches["whois"], dns_cache=caches["dns"],
                    geo_cache=caches["geo"], rate_limiters=limiters,
                    breakers=breakers, cfg=cfg,
                    dns_fetch=dns_fetch, whois_fetch=whois_fetch,
                )
            except CircuitOpen as e:
                # circuit open: requeue WITHOUT burning an attempt beyond normal path
                queue.requeue(item, reason=str(e))
                stats["requeued"] += 1
                continue
            except EnrichFailure as e:
                queue.requeue(item, reason=str(e))
                stats["requeued"] += 1
                continue
            row["enrichment_completed_at"] = datetime.now(timezone.utc).isoformat()
            enriched_rows.append(row)
            queue.record_processed({**item, "enrichment_level": row["enrichment_level"]})
            stats["processed"] += 1
        queue.complete_batch(claim_path)

    # persist caches (atomic temp-swap) + hit-rate stats
    for c in caches.values():
        c.flush()
        c.log_stats()

    # write enriched output + latest pointer (same contract as old inline path)
    if enriched_rows:
        out_df = pd.DataFrame(enriched_rows)
        enriched_dir = abspath(cfg, cfg["paths"]["enriched_dir"])
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = os.path.join(enriched_dir, f"ct_enriched_{ts}.parquet")
        atomic_to_parquet(out_df, out_path)
        ptr = os.path.join(enriched_dir, "_latest_enriched.json")
        tmp = ptr + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"path": out_path, "rows": len(out_df), "created_utc": ts}, f)
        os.replace(tmp, ptr)
        log.info("[worker] wrote %d enriched rows -> %s", len(out_df), out_path)
        stats["output_path"] = out_path

    queue.log_metrics()
    log.info("[worker] done: %s", stats)
    return stats


# ---------------- CLI ----------------

def main(argv=None):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    ap = argparse.ArgumentParser(description="CT enrichment queue worker")
    ap.add_argument("--config", default=None, help="path to enrichment config json")
    ap.add_argument("--enqueue-from-bronze", action="store_true",
                    help="read new bronze CT rows and enqueue them")
    ap.add_argument("--enqueue-domains", nargs="*", default=None,
                    help="enqueue explicit registered domains")
    ap.add_argument("--drain", action="store_true", help="drain the pending queue")
    ap.add_argument("--max-batches", type=int, default=None)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    did = False
    if args.enqueue_from_bronze:
        enqueue_from_bronze(cfg)
        did = True
    if args.enqueue_domains:
        enqueue_domains(args.enqueue_domains, cfg)
        did = True
    if args.drain or not did:
        run_worker(cfg, max_batches=args.max_batches)


if __name__ == "__main__":
    main()
