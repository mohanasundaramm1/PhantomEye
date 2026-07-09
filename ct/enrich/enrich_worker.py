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
import time
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
    # whois_rps was 2.0 until a live backfill run showed rdap.org actively
    # rate-limiting this system with HTTP 429 "Too Many Requests" at that
    # rate (found live, config/enrichment.json's whois_rps -- see also
    # ct.enrich.tiers.default_whois_fetch's docstring for the related
    # timeout-budget incident found in the same investigation). Lowered to
    # 1.0 to stay under whatever threshold rdap.org enforces.
    rl = cfg["rate_limits"]
    return {"whois": TokenBucket(rl["whois_rps"]), "dns": TokenBucket(rl["dns_rps"])}


def build_breakers(cfg: dict) -> dict:
    cb = cfg["circuit_breaker"]
    # "whois_other" (non-reliable_tlds domains) gets its OWN breaker, not
    # shared with "whois" -- see ct.enrich.tiers._tld_bucket()'s docstring
    # for why a shared breaker let a run of flaky-registry failures block
    # perfectly healthy .com/.net/.org lookups too.
    cb_other = cfg.get("circuit_breaker_other", cb)
    return {
        "whois": CircuitBreaker("whois", failure_threshold=cb["failure_threshold"],
                                cooldown_seconds=cb["cooldown_seconds"]),
        "whois_other": CircuitBreaker("whois_other", failure_threshold=cb_other["failure_threshold"],
                                      cooldown_seconds=cb_other["cooldown_seconds"]),
        "dns": CircuitBreaker("dns", failure_threshold=cb["failure_threshold"],
                              cooldown_seconds=cb["cooldown_seconds"]),
    }


# ---------------- enqueue paths ----------------

def enqueue_domains(domains_or_records, cfg: dict | None = None) -> int:
    """Enqueue registered domains (strings) or record dicts (may carry triage_score).

    Skips domains already sitting in pending/processing (in-flight dedup): an
    Airflow retry or a TriggerDagRunOperator reset_dag_run re-run calls this
    again from scratch with the same day's domain list, and without this guard
    would silently re-enqueue a duplicate copy on every retry -- real wasted
    rate-limited WHOIS/DNS work against the shared queue, not just a cosmetic
    depth bump. See FileQueue.in_flight_domains()."""
    cfg = cfg or load_config()
    queue = build_queue(cfg)
    in_flight = queue.in_flight_domains()
    items = []
    skipped = 0
    for r in domains_or_records:
        if isinstance(r, str):
            item = {"registered_domain": r, "domain": r, "triage_score": None}
        else:
            item = dict(r)
            item.setdefault("registered_domain", item.get("domain"))
            item.setdefault("triage_score", None)
        dom = item.get("registered_domain")
        if dom and dom in in_flight:
            skipped += 1
            continue
        items.append(item)
    for i in range(0, len(items), queue.batch_size):
        queue.enqueue(items[i:i + queue.batch_size])
    log.info("[worker] enqueued %d items (%d skipped, already in-flight)", len(items), skipped)
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


# ---------------- enriched output ----------------

def _write_enriched_output(enriched_rows: list[dict], cfg: dict,
                           update_pointer: bool = True) -> str | None:
    """Persist enriched rows to a timestamped parquet. When update_pointer is
    True, atomically advance _latest_enriched.json so the scorer picks it up.
    Backfill passes set it False so they warm caches without hijacking the
    pointer away from the freshest hot-path output."""
    if not enriched_rows:
        return None
    out_df = pd.DataFrame(enriched_rows)
    enriched_dir = abspath(cfg, cfg["paths"]["enriched_dir"])
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = os.path.join(enriched_dir, f"ct_enriched_{ts}.parquet")
    atomic_to_parquet(out_df, out_path)
    if update_pointer:
        ptr = os.path.join(enriched_dir, "_latest_enriched.json")
        tmp = ptr + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"path": out_path, "rows": len(out_df), "created_utc": ts}, f)
        os.replace(tmp, ptr)
    log.info("[worker] wrote %d enriched rows -> %s (pointer=%s)",
             len(out_df), out_path, update_pointer)
    return out_path


# ---------------- drain loop ----------------

def run_worker(cfg: dict | None = None, max_batches: int | None = None,
               dns_fetch=None, whois_fetch=None, update_pointer: bool = True,
               max_seconds: float | None = None) -> dict:
    """Drain the pending queue. Returns summary stats. Fetchers injectable for tests.

    update_pointer=False (cold/backfill mode) warms caches and records enriched
    output without moving _latest_enriched.json, so it never overwrites the
    fresher hot-path pointer the scorer reads.

    max_seconds bounds the WORK PER RUN, not the queue: when the time budget is
    exhausted the worker stops cleanly (unprocessed items stay/return to
    pending, nothing is lost or attempt-penalized) and reports success. This
    exists because the shared queue is continuously refilled (enrich_hot every
    2h), so an unbounded drain-until-empty run can mathematically never finish
    -- it just runs until Airflow's execution_timeout/dagrun_timeout kills it
    and the DAG records a failure. Bounded runs turn that into: each run drains
    a chunk, succeeds, and the next scheduled run continues. The budget is
    checked per-ITEM, not just per-batch, because one 200-item batch of dead
    registrars at whois_seconds each can alone outlast a whole budget."""
    cfg = cfg or load_config()
    queue = build_queue(cfg)
    caches = build_caches(cfg)
    limiters = build_rate_limiters(cfg)
    breakers = build_breakers(cfg)

    queue.recover_stale()

    from ct.enrich import tiers as _tiers
    dns_fetch = dns_fetch or _tiers.default_dns_fetch
    whois_fetch = whois_fetch or _tiers.default_whois_fetch

    deadline = (time.monotonic() + max_seconds) if max_seconds else None

    enriched_rows: list[dict] = []
    stats = {"processed": 0, "requeued": 0, "batches": 0, "budget_deferred": 0}

    while max_batches is None or stats["batches"] < max_batches:
        if deadline is not None and time.monotonic() >= deadline:
            log.info("[worker] time budget (%.0fs) exhausted between batches -- stopping cleanly", max_seconds)
            break
        queue.log_metrics()
        claimed = queue.claim_batch()
        if claimed is None:
            break
        claim_path, items = claimed
        stats["batches"] += 1
        out_of_budget = False
        for idx, item in enumerate(items):
            if deadline is not None and time.monotonic() >= deadline:
                # Hand the unprocessed remainder straight back to pending via
                # enqueue() (NOT requeue(): running out of time is not a
                # failure, so no attempt counter is burned) and finish the
                # claim so nothing is left in processing/.
                remainder = items[idx:]
                queue.enqueue(remainder)
                stats["budget_deferred"] += len(remainder)
                log.info("[worker] time budget (%.0fs) exhausted mid-batch -- "
                         "deferred %d unprocessed item(s) back to pending",
                         max_seconds, len(remainder))
                out_of_budget = True
                break
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
        if out_of_budget:
            break

    # persist caches (atomic temp-swap) + hit-rate stats
    for c in caches.values():
        c.flush()
        c.log_stats()

    # write enriched output (+ pointer unless this is a backfill pass)
    out_path = _write_enriched_output(enriched_rows, cfg, update_pointer=update_pointer)
    if out_path:
        stats["output_path"] = out_path

    queue.log_metrics()
    log.info("[worker] done: %s", stats)
    return stats


# ---------------- hot path (fresh, bounded, non-blocking) ----------------

def run_hot_cycle(cfg: dict | None = None, max_domains: int | None = None,
                  dns_fetch=None, whois_fetch=None) -> dict:
    """Fast path that closes the freshness loop: score the newest, highest-triage
    CT domains with no blocking on rate-limited WHOIS.

    Reads the newest bronze window (bookmark-incremental), keeps the top
    `max_domains` by triage_score, enriches each WHOIS-cache-only (DNS is the
    only network call, fast at dns_rps), writes the enriched output and advances
    _latest_enriched.json so the scorer immediately sees fresh data. High-triage
    domains that missed the WHOIS cache are handed to the durable queue for the
    background (cold) worker to backfill at its safe rate. Lower-triage rows in
    the window are deliberately dropped -- triage-hard: spend the budget only on
    the candidates that matter."""
    from ct.enrich import enrich_ct
    from ct.enrich import tiers as _tiers

    cfg = cfg or load_config()
    hp = cfg.get("hot_path", {})
    max_domains = max_domains or hp.get("max_domains", 600)
    min_triage = hp.get("min_triage_score", 0.0)

    df = enrich_ct.read_bronze()
    if df.empty:
        log.info("[hot] no new bronze rows")
        return {"processed": 0, "backfill_enqueued": 0, "output_path": None}

    if "triage_score" in df.columns:
        df = df.copy()
        # missing triage treated as high priority (backward compat with old bronze)
        df["_ts"] = pd.to_numeric(df["triage_score"], errors="coerce").fillna(1.0)
        df = df[df["_ts"] >= min_triage].sort_values("_ts", ascending=False)
    window = df.head(max_domains)

    caches = build_caches(cfg)
    limiters = build_rate_limiters(cfg)
    breakers = build_breakers(cfg)
    dns_fetch = dns_fetch or _tiers.default_dns_fetch
    whois_fetch = whois_fetch or _tiers.default_whois_fetch

    enriched_rows: list[dict] = []
    backfill: list[dict] = []
    for _, r in window.iterrows():
        dom = r.get("registered_domain") or r.get("domain")
        item = {
            "registered_domain": dom,
            "domain": r.get("domain"),
            "event_ts": str(r.get("event_ts")) if r.get("event_ts") is not None else None,
            "source": r.get("source"),
            "triage_score": (float(r["triage_score"])
                             if "triage_score" in window.columns and pd.notna(r.get("triage_score"))
                             else None),
        }
        try:
            row = _tiers.enrich_item(
                item, whois_cache=caches["whois"], dns_cache=caches["dns"],
                geo_cache=caches["geo"], rate_limiters=limiters, breakers=breakers,
                cfg=cfg, dns_fetch=dns_fetch, whois_fetch=whois_fetch,
                whois_mode="cache_only",
            )
        except (CircuitOpen, EnrichFailure) as e:
            # hot path never blocks/requeues -- score on lexical features alone
            row = {
                "registered_domain": dom, "domain_sample": item["domain"],
                "triage_score": item["triage_score"], "event_ts": item["event_ts"],
                "source": item["source"], "enrichment_level": "tier0",
                "whois_backfill_needed": False, "enrich_note": f"hot_skip:{e}",
            }
        if row.pop("whois_backfill_needed", False):
            backfill.append({"registered_domain": dom, "domain": item["domain"],
                             "triage_score": item["triage_score"]})
        enriched_rows.append(row)

    for c in caches.values():
        c.flush()
        c.log_stats()

    out_path = _write_enriched_output(enriched_rows, cfg, update_pointer=True)

    # advance bookmark past the whole window (dropped low-triage rows included)
    if "ingest_ts" in df.columns and not df["ingest_ts"].empty:
        enrich_ct._write_bookmark({"last_ingest_ts": str(df["ingest_ts"].max())})

    n_bf = enqueue_domains(backfill, cfg) if backfill else 0
    stats = {"processed": len(enriched_rows), "backfill_enqueued": n_bf,
             "output_path": out_path}
    log.info("[hot] done: %s", stats)
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
    ap.add_argument("--hot", action="store_true",
                    help="run the fast fresh-scoring cycle (bounded, WHOIS cache-only)")
    ap.add_argument("--no-pointer", action="store_true",
                    help="drain without advancing _latest_enriched.json (backfill / cache-warming)")
    ap.add_argument("--max-batches", type=int, default=None)
    ap.add_argument("--max-seconds", type=float, default=None,
                    help="time budget for this drain run; unprocessed items stay queued")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    did = False
    if args.hot:
        run_hot_cycle(cfg)
        did = True
    if args.enqueue_from_bronze:
        enqueue_from_bronze(cfg)
        did = True
    if args.enqueue_domains:
        enqueue_domains(args.enqueue_domains, cfg)
        did = True
    if args.drain:
        run_worker(cfg, max_batches=args.max_batches, update_pointer=not args.no_pointer,
                   max_seconds=args.max_seconds)
    elif not did:
        run_worker(cfg, max_batches=args.max_batches, update_pointer=not args.no_pointer,
                   max_seconds=args.max_seconds)


if __name__ == "__main__":
    main()
