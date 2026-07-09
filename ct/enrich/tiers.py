# ct/enrich/tiers.py
"""Tiered enrichment of a single queue item.

Tier 0: local parquet caches only (lookups/*.parquet, TTL-checked).
Tier 1: cheap network — DNS resolution; GeoIP strictly from the local
        ip_geo cache (no external geo call on this path).
Tier 2: expensive rate-limited WHOIS/RDAP — only for items whose
        triage_score exceeds the configured threshold. Missing
        triage_score is treated as high priority (backward compat).

Every external call is time-boxed; timeouts/errors raise EnrichFailure so
the worker requeues the item instead of retrying inline.
"""
from __future__ import annotations

import concurrent.futures as _fut
import functools
import json
import logging
import socket

import pandas as pd

log = logging.getLogger(__name__)

_EXECUTOR = _fut.ThreadPoolExecutor(max_workers=8, thread_name_prefix="enrich-io")


class EnrichFailure(Exception):
    """External call failed/timed out; item should be requeued (not retried inline)."""

    def __init__(self, service: str, reason: str):
        super().__init__(f"{service}: {reason}")
        self.service = service
        self.reason = reason


class CircuitOpen(EnrichFailure):
    """Circuit is open for this service; requeue without attempting the call."""

    def __init__(self, service: str):
        super().__init__(service, "circuit_open")


def call_with_timeout(fn, timeout: float, service: str, *args, **kwargs):
    """Run fn in a worker thread with a hard timeout."""
    future = _EXECUTOR.submit(fn, *args, **kwargs)
    try:
        return future.result(timeout=timeout)
    except _fut.TimeoutError:
        future.cancel()
        raise EnrichFailure(service, f"timeout>{timeout}s")
    except EnrichFailure:
        raise
    except Exception as e:
        raise EnrichFailure(service, f"{type(e).__name__}: {e}")


# ---------------- default fetchers (mockable in tests / worker) ----------------

def default_dns_fetch(domain: str) -> list[str]:
    """Resolve A/AAAA via the system resolver."""
    infos = socket.getaddrinfo(domain, None)
    return sorted({ai[4][0] for ai in infos if ai and ai[4]})


def default_whois_fetch(domain: str, timeout: float = 10.0) -> dict:
    """RDAP lookup via rdap.org, normalized to the whois_cache row shape.

    `timeout` is the TOTAL wall-clock budget for this call, split into a
    fixed 3s connect allowance and the remainder for the read -- so
    connect(3) + read(timeout-3) never exceeds `timeout`. This must line up
    with the outer call_with_timeout() supervisor in enrich_item() (which
    used to enforce cfg["timeouts"]["whois_seconds"]=6.0 while this
    function's OWN default stayed at 10.0, unreachable because the caller
    never passed timeout= through at all -- found live: every WHOIS call
    that legitimately took 6-10s, well within what this function was always
    willing to wait for, got killed by the outer wrapper first, showing up
    as "reason=whois: timeout>6.0s" on the majority of backfill items).
    """
    import requests  # lazy: not needed for cache-only paths / tests

    read_timeout = max(1.0, timeout - 3.0)
    r = requests.get(
        f"https://rdap.org/domain/{domain}",
        timeout=(3, read_timeout),
        headers={"User-Agent": "threat-intel-lab/rdap/0.2",
                 "Accept": "application/rdap+json, application/json;q=0.8"},
    )
    if r.status_code == 404:
        return {"domain": domain, "registrar": None, "status": "not_found",
                "created": pd.NaT, "expires": pd.NaT, "raw": None, "error": None}
    r.raise_for_status()
    data = r.json()

    registrar = None
    if isinstance(data.get("registrar"), dict):
        registrar = data["registrar"].get("name")
    if not registrar:
        for ent in (data.get("entities") or []):
            if "registrar" in (ent.get("roles") or []):
                vcard = ent.get("vcardArray") or []
                if isinstance(vcard, list) and len(vcard) == 2:
                    for item in vcard[1]:
                        if item and item[0] == "fn":
                            registrar = item[3]

    created = expires = None
    for ev in (data.get("events") or []):
        if ev.get("eventAction") == "registration":
            created = ev.get("eventDate")
        if ev.get("eventAction") in ("expiration", "expire"):
            expires = ev.get("eventDate")

    return {
        "domain": domain,
        "registrar": registrar,
        "status": ",".join(data.get("status") or []) or None,
        "created": pd.to_datetime(created, utc=True, errors="coerce"),
        "expires": pd.to_datetime(expires, utc=True, errors="coerce"),
        "raw": json.dumps(data)[:200_000],
        "error": None,
    }


# ---------------- tier selection ----------------

def needs_tier2(item: dict, threshold: float, missing_is_high: bool = True) -> bool:
    """Should this item get expensive WHOIS/RDAP enrichment?"""
    score = item.get("triage_score")
    if score is None:
        return bool(missing_is_high)
    try:
        return float(score) > float(threshold)
    except (TypeError, ValueError):
        return bool(missing_is_high)


def _tld_bucket(domain: str, reliable_tlds) -> str:
    """"reliable" (Verisign .com/.net, PIR .org by default -- config-driven
    via reliable_tlds) or "other" (everything else, federated per-TLD to a
    registry of much more variable RDAP reliability/latency).

    Found live: a single shared WHOIS circuit breaker meant a run of
    failures on a handful of flaky-registry domains (they cluster together
    in a batch -- a CT burst tends to share a TLD) tripped the breaker and
    then blocked WHOIS for every domain, including .com/.net/.org lookups
    that work fine on their own. Bucketing by TLD reliability gives each
    group its own breaker (see enrich_worker.py::build_breakers) so a bad
    "other" streak can never block a "reliable" domain, and its own longer
    timeout budget (timeouts.whois_seconds_other_tld) so a registry that's
    merely slower doesn't get miscounted as a failure at all.

    Plain last-dot-segment extraction (not full public-suffix parsing) --
    consistent with how this codebase already buckets TLDs elsewhere (e.g.
    config/triage.json's suspicious_tlds), and correct for the purpose here:
    a domain actually registered under a second-level suffix like .co.uk
    still gets RDAP-federated via its last segment's registry ("uk"), which
    is exactly the reliability signal this bucket needs.
    """
    if not domain or "." not in domain:
        return "other"
    tld = domain.rsplit(".", 1)[-1].lower()
    return "reliable" if tld in reliable_tlds else "other"


# ---------------- per-item enrichment ----------------

def enrich_item(item: dict, *, whois_cache, dns_cache, geo_cache,
                rate_limiters: dict, breakers: dict, cfg: dict,
                dns_fetch=default_dns_fetch, whois_fetch=default_whois_fetch,
                whois_mode: str = "network") -> dict:
    """Enrich one item tier-by-tier. Raises EnrichFailure/CircuitOpen for requeue.

    whois_mode:
      "network"    - Tier 2 does a rate-limited RDAP call on cache miss (cold path).
                     Routed through one of TWO breakers by _tld_bucket() --
                     breakers["whois"] for reliable_tlds, breakers["whois_other"]
                     for everything else -- so `breakers` must carry both keys
                     whenever whois_mode="network" enrichment is possible.
      "cache_only" - Tier 2 uses the WHOIS cache only; on a miss it does NOT make
                     the (slow, rate-limited) network call, leaves WHOIS fields
                     empty, and sets row["whois_backfill_needed"]=True so the hot
                     path can hand the domain to the background backfill worker.
    """
    domain = item.get("registered_domain") or item.get("domain")
    row: dict = {
        "registered_domain": domain,
        "domain_sample": item.get("domain"),
        "triage_score": item.get("triage_score"),
        "enqueued_at": item.get("enqueued_at"),
        "source": item.get("source"),
        "event_ts": item.get("event_ts"),
    }
    level = 0

    # ---- Tier 0/1: DNS ----
    dns_rows = dns_cache.get(domain)
    if dns_rows is not None:
        ips = [ip for ip in dns_rows["ip"].dropna().astype(str) if ip and ip != "None"]
    else:
        breaker = breakers["dns"]
        if not breaker.allow():
            raise CircuitOpen("dns")
        rate_limiters["dns"].acquire()
        try:
            ips = call_with_timeout(
                dns_fetch, cfg["timeouts"]["dns_seconds"], "dns", domain)
        except EnrichFailure:
            breaker.record_failure()
            raise
        breaker.record_success()
        dns_cache.upsert([{"puny_domain": domain, "ip": ip} for ip in ips]
                         or [{"puny_domain": domain, "ip": None}])
        level = max(level, 1)

    # ---- Tier 1: GeoIP from local cache only ----
    countries, asns = set(), set()
    sample = {}
    for ip in ips:
        geo = geo_cache.get(ip)
        if geo is not None and not geo.empty:
            g = geo.iloc[0].to_dict()
            if g.get("country"):
                countries.add(g["country"])
            if g.get("asn"):
                asns.add(g["asn"])
            if not sample:
                sample = g

    row.update({
        "num_unique_ips": len(set(ips)),
        "has_ipv6": int(any(":" in ip for ip in ips)),
        "num_countries": len(countries),
        "num_asns": len(asns),
        "sample_country": sample.get("country"),
        "sample_asn": sample.get("asn"),
        "sample_isp": sample.get("asn_name") or sample.get("isp"),
    })

    # ---- Tier 2: WHOIS/RDAP (expensive, priority-gated) ----
    tiers_cfg = cfg["tiers"]
    row["whois_backfill_needed"] = False
    if needs_tier2(item, tiers_cfg["triage_threshold"],
                   tiers_cfg.get("missing_triage_is_high_priority", True)):
        whois_rows = whois_cache.get(domain)
        if whois_rows is not None:
            w = whois_rows.iloc[0].to_dict()
        elif whois_mode == "cache_only":
            # hot path: skip the rate-limited network call, flag for backfill
            w = None
            row["whois_backfill_needed"] = True
        else:
            bucket = _tld_bucket(domain, cfg.get("reliable_tlds", ("com", "net", "org")))
            breaker_key = "whois" if bucket == "reliable" else "whois_other"
            breaker = breakers[breaker_key]
            if not breaker.allow():
                raise CircuitOpen(breaker_key)
            rate_limiters["whois"].acquire()
            try:
                whois_budget = (cfg["timeouts"]["whois_seconds"] if bucket == "reliable"
                                else cfg["timeouts"].get("whois_seconds_other_tld",
                                                          cfg["timeouts"]["whois_seconds"]))
                # Pass the SAME budget to both the outer hard-timeout (below)
                # and the function's own internal request timeout -- these
                # used to be two independently-configured numbers (6.0
                # outer vs. this function's unreachable 10.0 default) that
                # could silently drift out of alignment; see
                # default_whois_fetch()'s docstring for the incident this
                # caused. functools.partial (not a plain kwarg on
                # call_with_timeout itself) because call_with_timeout's own
                # `timeout` parameter -- the OUTER budget -- already owns
                # that name.
                bound_whois_fetch = functools.partial(whois_fetch, timeout=whois_budget)
                # service=breaker_key (not a bare "whois") so a genuine
                # failure's EnrichFailure -- and the failed_ledger.jsonl
                # entry it becomes -- says which bucket it came from, same
                # as CircuitOpen(breaker_key) above.
                w = call_with_timeout(bound_whois_fetch, whois_budget, breaker_key, domain)
            except EnrichFailure:
                breaker.record_failure()
                raise
            breaker.record_success()
            whois_cache.upsert([w])
            level = 2
        if w is not None:
            row.update({
                "registrar": w.get("registrar"),
                "whois_status": w.get("status"),
                "whois_created": w.get("created"),
                "whois_expires": w.get("expires"),
            })
        else:
            row.update({"registrar": None, "whois_status": None,
                        "whois_created": None, "whois_expires": None})
    else:
        row.update({"registrar": None, "whois_status": None,
                    "whois_created": None, "whois_expires": None})

    row["enrichment_level"] = f"tier{level}"
    return row
