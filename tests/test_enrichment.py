"""Tests for the queue-decoupled enrichment layer (ct/enrich).

All network calls are mocked; nothing here touches the internet.
"""
import json
import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ct.enrich.cache import ParquetTTLCache
from ct.enrich.circuit import CLOSED, OPEN, CircuitBreaker
from ct.enrich.config import load_config
from ct.enrich.queue import FileQueue
from ct.enrich.ratelimit import TokenBucket
from ct.enrich.tiers import EnrichFailure, enrich_item, needs_tier2


# ---------------- helpers ----------------

class FakeClock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, dt):
        self.t += dt


def make_cfg(tmp_path, **overrides):
    cfg = load_config(path="/nonexistent")  # pure defaults
    cfg["paths"]["lookups_dir"] = str(tmp_path / "lookups")
    cfg["paths"]["enriched_dir"] = str(tmp_path / "enriched")
    cfg["queue"]["dir"] = str(tmp_path / "queue")
    for k, v in overrides.items():
        cfg[k].update(v)
    return cfg


def make_caches(tmp_path, whois_ttl=7 * 86400, dns_ttl=86400, geo_ttl=86400, now=None):
    kw = {"now": now} if now else {}
    base = str(tmp_path / "lookups")
    return {
        "whois": ParquetTTLCache("whois", f"{base}/whois_cache.parquet", "domain", whois_ttl, **kw),
        "dns": ParquetTTLCache("dns", f"{base}/dns_geo_cache.parquet", "puny_domain", dns_ttl, **kw),
        "geo": ParquetTTLCache("geo", f"{base}/ip_geo_cache.parquet", "ip", geo_ttl, **kw),
    }


def fast_limiters():
    return {"whois": TokenBucket(1000), "dns": TokenBucket(1000)}


def breakers():
    return {"whois": CircuitBreaker("whois"), "dns": CircuitBreaker("dns")}


# ---------------- token bucket ----------------

def test_token_bucket_allows_burst_then_limits():
    clk = FakeClock()
    tb = TokenBucket(rate=1.0, capacity=2, clock=clk, sleep=clk.sleep)
    assert tb.try_acquire()
    assert tb.try_acquire()
    assert not tb.try_acquire()  # bucket drained
    clk.t += 1.0                 # 1 token refilled after 1s at 1 rps
    assert tb.try_acquire()
    assert not tb.try_acquire()


def test_token_bucket_blocking_acquire_waits_for_refill():
    clk = FakeClock()
    tb = TokenBucket(rate=2.0, capacity=1, clock=clk, sleep=clk.sleep)
    tb.acquire()
    t0 = clk.t
    tb.acquire()  # must "sleep" via fake clock until a token exists
    assert clk.t - t0 >= 0.5 - 1e-6  # 1 token at 2 rps => 0.5s


def test_token_bucket_never_exceeds_capacity():
    clk = FakeClock()
    tb = TokenBucket(rate=100.0, capacity=1, clock=clk, sleep=clk.sleep)
    clk.t += 100  # long idle: still only 1 token
    assert tb.try_acquire()
    assert not tb.try_acquire()


# ---------------- cache TTL ----------------

def test_cache_fresh_hit_and_expired_miss(tmp_path):
    now = [pd.Timestamp("2026-07-01", tz="UTC")]
    c = ParquetTTLCache("t", str(tmp_path / "c.parquet"), "domain",
                        ttl_seconds=3600, now=lambda: now[0])
    c.upsert([{"domain": "a.com", "registrar": "R"}])
    assert c.get("a.com") is not None          # fresh -> hit
    assert c.get("missing.com") is None        # absent -> miss
    now[0] += pd.Timedelta(hours=2)
    assert c.get("a.com") is None              # expired -> miss
    assert c.hits == 1 and c.misses == 2 and c.expired == 1
    assert c.hit_rate == pytest.approx(1 / 3)


def test_cache_upsert_refreshes_and_persists(tmp_path):
    path = str(tmp_path / "c.parquet")
    now = [pd.Timestamp("2026-07-01", tz="UTC")]
    c = ParquetTTLCache("t", path, "domain", 3600, now=lambda: now[0])
    c.upsert([{"domain": "a.com", "registrar": "old"}])
    now[0] += pd.Timedelta(hours=2)
    c.upsert([{"domain": "a.com", "registrar": "new"}])  # re-fetch after expiry
    rows = c.get("a.com")
    assert rows is not None and rows.iloc[0]["registrar"] == "new"
    c.flush()
    # reload from disk: fetched_at column persisted
    c2 = ParquetTTLCache("t", path, "domain", 3600, now=lambda: now[0])
    assert c2.get("a.com") is not None


# ---------------- circuit breaker ----------------

def test_circuit_opens_after_threshold_and_recloses():
    clk = FakeClock()
    cb = CircuitBreaker("svc", failure_threshold=3, cooldown_seconds=60, clock=clk)
    for _ in range(2):
        cb.record_failure()
    assert cb.state == CLOSED and cb.allow()
    cb.record_failure()
    assert cb.state == OPEN and not cb.allow()   # open: calls blocked
    clk.t += 61
    assert cb.allow()                             # half-open probe allowed
    cb.record_success()
    assert cb.state == CLOSED and cb.allow()


def test_circuit_half_open_failure_reopens():
    clk = FakeClock()
    cb = CircuitBreaker("svc", failure_threshold=2, cooldown_seconds=60, clock=clk)
    cb.record_failure(); cb.record_failure()
    clk.t += 61
    assert cb.allow()          # probe
    cb.record_failure()        # probe failed
    assert cb.state == OPEN and not cb.allow()


def test_circuit_success_resets_consecutive_count():
    cb = CircuitBreaker("svc", failure_threshold=2, cooldown_seconds=60)
    cb.record_failure()
    cb.record_success()
    cb.record_failure()
    assert cb.state == CLOSED


# ---------------- queue: requeue on timeout / failed ledger ----------------

def test_requeue_on_timeout_then_failed_ledger(tmp_path):
    q = FileQueue(str(tmp_path / "q"), batch_size=10, max_attempts=3)
    q.enqueue([{"registered_domain": "a.com", "domain": "a.com"}])

    # attempts 1 and 2: item comes back to pending with the counter incremented
    for expected_attempts in (1, 2):
        path, items = q.claim_batch()
        q.requeue(items[0], reason="whois: timeout>10s")
        q.complete_batch(path)
        m = q.metrics()
        assert m["queue_depth"] == 1
        # peek without consuming semantics: claim to inspect, then requeue path below
        path, items = q.claim_batch()
        assert items[0]["attempts"] == expected_attempts
        # put it back untouched for the next loop iteration / final step
        q.enqueue([items[0]])
        q.complete_batch(path)

    # third failure exhausts max_attempts -> failed ledger, queue empty
    path, items = q.claim_batch()
    q.requeue(items[0], reason="whois: timeout>10s")   # attempts -> 3 == max
    q.complete_batch(path)
    assert q.claim_batch() is None
    with open(q.failed_ledger) as f:
        failed = [json.loads(l) for l in f]
    assert failed[0]["registered_domain"] == "a.com" and failed[0]["attempts"] == 3
    assert "timeout" in failed[0]["last_error"]


def test_queue_metrics_depth_and_lag(tmp_path):
    q = FileQueue(str(tmp_path / "q"))
    q.enqueue([{"registered_domain": "a.com",
                "enqueued_at": "2026-07-01T00:00:00+00:00"},
               {"registered_domain": "b.com"}])
    m = q.metrics()
    assert m["queue_depth"] == 2
    assert m["enrichment_lag_seconds"] is not None and m["enrichment_lag_seconds"] > 0


def test_worker_requeues_item_when_fetch_times_out(tmp_path):
    from ct.enrich.enrich_worker import build_queue, run_worker
    cfg = make_cfg(tmp_path)
    q = build_queue(cfg)
    q.enqueue([{"registered_domain": "slow.com", "domain": "slow.com",
                "triage_score": 0.9}])

    def dns_ok(domain):
        return ["1.2.3.4"]

    def whois_timeout(domain, timeout=10.0):
        raise EnrichFailure("whois", "timeout>10s")

    stats = run_worker(cfg, max_batches=1, dns_fetch=dns_ok, whois_fetch=whois_timeout)
    assert stats["requeued"] == 1 and stats["processed"] == 0
    # item is back in pending with attempts=1 (NOT retried inline)
    _, items = build_queue(cfg).claim_batch()
    assert items[0]["attempts"] == 1 and "timeout" in items[0]["last_error"]


# ---------------- tier selection ----------------

def test_needs_tier2_threshold_and_missing_score():
    assert needs_tier2({"triage_score": 0.9}, 0.5)
    assert not needs_tier2({"triage_score": 0.2}, 0.5)
    assert needs_tier2({}, 0.5)                                  # missing -> high
    assert not needs_tier2({}, 0.5, missing_is_high=False)
    assert needs_tier2({"triage_score": "bogus"}, 0.5)           # unparsable -> high


def test_low_triage_skips_whois_and_marks_level(tmp_path):
    cfg = make_cfg(tmp_path)
    caches = make_caches(tmp_path)
    calls = {"whois": 0}

    def whois_fetch(domain, timeout=10.0):
        calls["whois"] += 1
        return {"domain": domain, "registrar": "R"}

    row = enrich_item(
        {"registered_domain": "low.com", "domain": "low.com", "triage_score": 0.1},
        whois_cache=caches["whois"], dns_cache=caches["dns"], geo_cache=caches["geo"],
        rate_limiters=fast_limiters(), breakers=breakers(), cfg=cfg,
        dns_fetch=lambda d: ["1.2.3.4"], whois_fetch=whois_fetch,
    )
    assert calls["whois"] == 0
    assert row["enrichment_level"] == "tier1"
    assert row["registrar"] is None


def test_high_triage_gets_whois_tier2(tmp_path):
    cfg = make_cfg(tmp_path)
    caches = make_caches(tmp_path)
    calls = {"whois": 0}

    def whois_fetch(domain, timeout=10.0):
        calls["whois"] += 1
        return {"domain": domain, "registrar": "GoDaddy"}

    row = enrich_item(
        {"registered_domain": "bad.com", "domain": "bad.com", "triage_score": 0.95},
        whois_cache=caches["whois"], dns_cache=caches["dns"], geo_cache=caches["geo"],
        rate_limiters=fast_limiters(), breakers=breakers(), cfg=cfg,
        dns_fetch=lambda d: ["1.2.3.4", "::1"], whois_fetch=whois_fetch,
    )
    assert calls["whois"] == 1
    assert row["enrichment_level"] == "tier2"
    assert row["registrar"] == "GoDaddy"
    assert row["has_ipv6"] == 1


def test_cache_satisfied_item_is_tier0_no_network(tmp_path):
    cfg = make_cfg(tmp_path)
    caches = make_caches(tmp_path)
    caches["dns"].upsert([{"puny_domain": "cached.com", "ip": "9.9.9.9"}])
    caches["whois"].upsert([{"domain": "cached.com", "registrar": "CacheReg",
                             "status": "ok", "created": None, "expires": None}])
    caches["geo"].upsert([{"ip": "9.9.9.9", "country": "CH", "asn": "AS19281"}])

    def boom(*a, **k):
        raise AssertionError("network should not be called")

    row = enrich_item(
        {"registered_domain": "cached.com", "domain": "cached.com", "triage_score": 0.99},
        whois_cache=caches["whois"], dns_cache=caches["dns"], geo_cache=caches["geo"],
        rate_limiters=fast_limiters(), breakers=breakers(), cfg=cfg,
        dns_fetch=boom, whois_fetch=boom,
    )
    assert row["enrichment_level"] == "tier0"
    assert row["registrar"] == "CacheReg"
    assert row["sample_country"] == "CH"


def test_circuit_open_requeues_without_calling(tmp_path):
    from ct.enrich.tiers import CircuitOpen
    cfg = make_cfg(tmp_path)
    caches = make_caches(tmp_path)
    brk = breakers()
    for _ in range(5):
        brk["whois"].record_failure()
    assert brk["whois"].state == OPEN

    def boom(*a, **k):
        raise AssertionError("whois must not be called while circuit is open")

    with pytest.raises(CircuitOpen):
        enrich_item(
            {"registered_domain": "x.com", "domain": "x.com", "triage_score": 0.9},
            whois_cache=caches["whois"], dns_cache=caches["dns"], geo_cache=caches["geo"],
            rate_limiters=fast_limiters(), breakers=brk, cfg=cfg,
            dns_fetch=lambda d: [], whois_fetch=boom,
        )


# ---------------- end-to-end worker (mocked network) ----------------

def test_worker_end_to_end_writes_output_and_ledgers(tmp_path):
    from ct.enrich.enrich_worker import build_queue, run_worker
    cfg = make_cfg(tmp_path)
    build_queue(cfg).enqueue([
        {"registered_domain": "hi.com", "domain": "hi.com", "triage_score": 0.9},
        {"registered_domain": "lo.com", "domain": "lo.com", "triage_score": 0.1},
    ])
    stats = run_worker(
        cfg, max_batches=5,
        dns_fetch=lambda d: ["1.1.1.1"],
        whois_fetch=lambda d, timeout=10.0: {"domain": d, "registrar": "R"},
    )
    assert stats["processed"] == 2 and stats["requeued"] == 0
    out = pd.read_parquet(stats["output_path"])
    levels = dict(zip(out["registered_domain"], out["enrichment_level"]))
    assert levels == {"hi.com": "tier2", "lo.com": "tier1"}
    q = build_queue(cfg)
    assert q.metrics()["queue_depth"] == 0
    assert os.path.exists(q.processed_ledger)
    # caches persisted with fetched_at
    whois = pd.read_parquet(str(tmp_path / "lookups" / "whois_cache.parquet"))
    assert "fetched_at" in whois.columns and (whois["domain"] == "hi.com").any()
