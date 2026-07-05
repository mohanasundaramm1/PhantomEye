# product/content_probe.py
"""Content/lifecycle probe for top-ranked campaigns (Track C).

DISABLED BY DEFAULT. This is the one job in the campaign-radar system that
makes outbound requests to suspected-malicious infrastructure directly from
this machine -- that has real opsec/exposure consequences distinct from every
other job here (reveals reconnaissance activity to whoever controls the
target, and some of that "infrastructure" may be actively hostile). It ships
fully built and tested, but config/content_probe.json's `enabled` must be
explicitly set to true before a single network call is made (user decision,
recorded when this track was planned).

When enabled, for each cluster above min_confidence, probes up to
max_targets_per_cluster member domains (highest risk_score first) and
extracts: http_status, final URL (after redirects), page title, a
password-form hint, and MX presence. Results land on ct_observations
(http_status/content_fingerprint/mx_present) and evidence_events
(event_type="content_probe_result"), then call site 4/4 of the stage engine
(product/stage_engine.py) -- live HTTP/MX evidence can push a cluster to
"active".

Follows ct/enrich/tiers.py's established shape for any external fetch:
circuit breaker -> rate limiter -> call_with_timeout, with injectable
fetchers (http_fetch/mx_fetch) for tests, mirroring dns_fetch/whois_fetch
there. HTTP client matches the house style already used in
airflow/dags/whois_rdap_dag.py (Retry+HTTPAdapter, timeout tuple, a
"threat-intel-lab/{service}/{version}" User-Agent).

Deliberately ONE request per target for the page fetch (no separate favicon
fetch): a second network call per target would need its own rate-limit/
circuit-breaker accounting for arguably little signal beyond what the page
body + title already give via content_fingerprint. Documented scope cut, not
a silent omission -- can be added later behind the same safety rails if it
proves valuable.

Run:
    python -m product.content_probe   # no-ops loudly if disabled
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone

from sqlalchemy import select

from ct.enrich.circuit import CircuitBreaker
from ct.enrich.ratelimit import TokenBucket
from ct.enrich.tiers import EnrichFailure, call_with_timeout
from product.db import SessionLocal
from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent
from product.stage_engine import apply_stage_transition

log = logging.getLogger(__name__)

CONFIG_PATH = os.getenv("CONTENT_PROBE_CONFIG", "config/content_probe.json")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_PASSWORD_FIELD_RE = re.compile(r'type\s*=\s*["\']password["\']', re.IGNORECASE)


def load_probe_config(path: str = CONFIG_PATH) -> dict:
    with open(path) as f:
        return json.load(f)


# ---------------- default fetchers (mockable in tests) ----------------

def default_http_fetch(url: str, timeout: float, user_agent: str) -> dict:
    """One GET, redirects followed. Returns {"status_code", "final_url", "text"}."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    sess = requests.Session()
    retry = Retry(total=2, connect=1, read=1, backoff_factor=0.5,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods={"GET"}, raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry, pool_connections=5, pool_maxsize=5)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers.update({"User-Agent": user_agent})
    resp = sess.get(url, timeout=(3, timeout), allow_redirects=True)
    return {"status_code": resp.status_code, "final_url": resp.url, "text": resp.text[:200_000]}


def default_mx_fetch(domain: str) -> bool:
    """True if the domain has any MX record."""
    import dns.resolver
    resolver = dns.resolver.Resolver(configure=True)
    answers = resolver.resolve(domain, "MX", lifetime=3)
    return len(list(answers)) > 0


# ---------------- extraction ----------------

def extract_title(html: str) -> str | None:
    m = _TITLE_RE.search(html or "")
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:256] or None


def has_password_form(html: str) -> bool:
    return bool(_PASSWORD_FIELD_RE.search(html or ""))


def content_fingerprint(status_code: int | None, title: str | None, has_pw_form: bool) -> str:
    return hashlib.sha256(f"{status_code}|{title}|{has_pw_form}".encode()).hexdigest()[:64]


# ---------------- probe one target ----------------

def probe_target(
    host: str,
    cfg: dict,
    breaker: CircuitBreaker,
    limiter: TokenBucket,
    http_fetch=None,
    mx_fetch=None,
) -> dict:
    """Probe one host. Never raises -- returns {"error": ...} on failure so
    the caller can continue with other targets. Tries https then http."""
    http_fetch = http_fetch or default_http_fetch
    mx_fetch = mx_fetch or default_mx_fetch
    timeout = float(cfg.get("timeout_seconds", 8))
    ua = cfg.get("user_agent", "threat-intel-lab/content-probe/0.1")

    if not breaker.allow():
        return {"error": "circuit open"}
    limiter.acquire()

    result = None
    last_error = None
    for scheme in ("https", "http"):
        try:
            result = call_with_timeout(http_fetch, timeout, "content_probe",
                                       f"{scheme}://{host}/", timeout, ua)
            break
        except EnrichFailure as e:
            last_error = str(e)
            continue

    if result is None:
        breaker.record_failure()
        return {"error": last_error or "fetch failed"}
    breaker.record_success()

    title = extract_title(result.get("text", ""))
    pw_form = has_password_form(result.get("text", ""))
    mx_present = False
    try:
        mx_present = bool(call_with_timeout(mx_fetch, timeout, "content_probe", host))
    except EnrichFailure:
        pass  # MX lookup failure doesn't invalidate the HTTP result

    return {
        "http_status": result.get("status_code"),
        "final_url": result.get("final_url"),
        "title": title,
        "has_password_form": pw_form,
        "mx_present": mx_present,
        "content_fingerprint": content_fingerprint(result.get("status_code"), title, pw_form),
    }


# ---------------- main run ----------------

def run_probe(cfg: dict | None = None, http_fetch=None, mx_fetch=None,
             cluster_ids: list[int] | None = None) -> dict:
    """cluster_ids restricts the run to exactly those clusters, ignoring
    min_confidence entirely -- an explicit ID list is a deliberate override
    (an operator re-probing specific campaigns, or a test isolating itself
    from real data). Without it, every cluster above min_confidence is in
    scope, same as always.

    This parameter exists because of a real incident: a live test called
    run_probe() with only a confidence filter, which -- with injected FAKE
    fetchers -- matched real production clusters above that confidence
    alongside the test's own synthetic one, overwriting 43 real observations'
    http_status/content_fingerprint/mx_present with fabricated "Fake Login"
    content and incorrectly advancing 35 real clusters to stage=active on
    evidence that was never actually fetched. Confidence-based filtering
    alone can NEVER safely isolate a test from shared production data --
    only an explicit ID allowlist can. Caught during Day 12 end-to-end
    verification, repaired via a one-off data-correction pass; see git log."""
    cfg = cfg or load_probe_config()
    if not cfg.get("enabled", False):
        log.info("[content_probe] disabled (config/content_probe.json enabled=false) -- no network calls made")
        return {"ok": True, "enabled": False, "probed": 0}

    breaker = CircuitBreaker("content_probe", **cfg.get("circuit_breaker", {}))
    limiter = TokenBucket(rate=float(cfg.get("rate_limit_rps", 0.5)))
    max_per_cluster = int(cfg.get("max_targets_per_cluster", 2))

    probed = 0
    active_transitions = 0
    with SessionLocal() as s:
        if cluster_ids is not None:
            clusters = s.execute(
                select(CampaignCluster).where(CampaignCluster.id.in_(cluster_ids))
            ).scalars().all()
        else:
            min_confidence = float(cfg.get("min_confidence", 0.5))
            clusters = s.execute(
                select(CampaignCluster).where(CampaignCluster.confidence_score >= min_confidence)
            ).scalars().all()

        for cluster in clusters:
            members = s.execute(
                select(CtObservation)
                .join(ClusterMember, ClusterMember.observation_id == CtObservation.id)
                .where(ClusterMember.cluster_id == cluster.id)
                .order_by(CtObservation.risk_score.desc())
                .limit(max_per_cluster)
            ).scalars().all()

            cluster_evidence = []
            for member in members:
                host = member.raw_host
                if not host:
                    continue
                result = probe_target(host, cfg, breaker, limiter, http_fetch, mx_fetch)
                probed += 1
                if "error" in result:
                    log.info("[content_probe] %s: %s", host, result["error"])
                    continue

                member.http_status = result["http_status"]
                member.content_fingerprint = result["content_fingerprint"]
                member.mx_present = result["mx_present"]
                detail = {"raw_host": host, "http_status": result["http_status"],
                          "final_url": result["final_url"], "title": result["title"],
                          "has_password_form": result["has_password_form"],
                          "mx_present": result["mx_present"]}
                # Persist the raw probe result as its OWN evidence_events row --
                # apply_stage_transition()'s `evidence` kwarg is a TRANSIENT input
                # to evaluate_stage()'s decision (it does not write per-item rows
                # itself, only ever writes its own "stage_transition" summary row
                # when the stage actually changes), so without this explicit write
                # the raw content-probe result would never land in the audit trail.
                s.add(EvidenceEvent(cluster_id=cluster.id, event_type="content_probe_result",
                                    observed_at=datetime.now(timezone.utc), detail=detail))
                cluster_evidence.append({"event_type": "content_probe_result", "detail": detail})
            s.commit()  # persist member column updates + evidence rows before the stage transition reads them

            if cluster_evidence:
                # Call site 4/4 of the stage engine: live HTTP/MX evidence can
                # push this cluster to "active" (see evaluate_stage()).
                transition = apply_stage_transition(s, cluster.id, evidence=cluster_evidence)
                if transition["changed"]:
                    active_transitions += 1

    return {"ok": True, "enabled": True, "probed": probed, "clusters_transitioned": active_transitions}


def main(argv=None) -> int:
    result = run_probe()
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
