# api/agent/internal_agent.py
"""Internal query agent for POST /threats/ask -- replaces the Perplexity
Sonar integration (formerly api/agent/perplexity_client.py, now removed).

Design: a fixed, small, reviewable set of intent-matched query functions,
not general LLM tool-calling. The risk this avoids isn't classic SQL
injection (every query here is parameterized via SQLAlchemy .where(), same
as the rest of api/main.py) -- it's *semantic* manipulation: a chat message
containing forwarded/pasted untrusted content (a suspicious email, a scraped
report) could otherwise be crafted to steer an LLM's tool-invocation choices
toward attacker-chosen filters/parameters in a tool an analyst trusts. A
fixed regex-matched set of functions makes the entire space of possible
queries auditable at code-review time instead of emergent at runtime.

There's deliberately no LLM call anywhere in this module, not even to
"phrase" results: no LLM API key is configured anywhere in this project
(confirmed -- .env.example only ever had a Perplexity key, blank by
default), and a phrasing-only LLM step would still be a prompt-injection
surface for no real benefit over a plain, honest template. The whole point
of replacing Perplexity was to stop returning a broken "ERROR: ... not
configured" string dressed up as an agent's own words -- a template that
always works beats a probabilistic one that's usually broken.
"""
from __future__ import annotations

import re

from sqlalchemy import select

# Hard cap before any regex sees the input -- bounds worst-case matching
# cost against a very long adversarial paste regardless of pattern shape.
MAX_QUERY_LEN = 500

_INTENT_PATTERNS: list[tuple[re.Pattern, callable]] = []


def _intent(pattern: str):
    compiled = re.compile(pattern, re.I)

    def register(fn):
        _INTENT_PATTERNS.append((compiled, fn))
        return fn

    return register


@_intent(r"\b(?:show|list|find)\b.*\bcampaigns?\b.*\b(?:brand|for|of|about)\s+([a-z0-9][a-z0-9._-]{0,63})")
def _campaigns_by_brand(session, match: re.Match) -> dict:
    from product.models import CampaignCluster

    brand = match.group(1).lower()
    rows = session.execute(
        select(CampaignCluster)
        .where(CampaignCluster.target_brand == brand)
        .order_by(CampaignCluster.confidence_score.desc())
        .limit(10)
    ).scalars().all()
    if not rows:
        return {
            "intent": "campaigns_by_brand", "brand": brand, "count": 0,
            "text": f"No campaigns on record for brand '{brand}'.",
        }
    lines = [
        f"- campaign #{c.id}: {round(c.confidence_score or 0, 2)} confidence, "
        f"{c.observation_count} domain(s), stage={c.stage}"
        for c in rows
    ]
    return {
        "intent": "campaigns_by_brand", "brand": brand, "count": len(rows),
        "text": f"{len(rows)} campaign(s) for '{brand}':\n" + "\n".join(lines),
    }


@_intent(r"\bstatus of\s+([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b")
def _observation_by_domain(session, match: re.Match) -> dict:
    from product.models import CtObservation

    domain = match.group(1).lower()
    row = session.execute(
        select(CtObservation)
        .where(CtObservation.registered_domain == domain)
        .order_by(CtObservation.event_ts.desc())
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        return {
            "intent": "observation_by_domain", "domain": domain, "found": False,
            "text": f"No observation on record for '{domain}'.",
        }
    return {
        "intent": "observation_by_domain", "domain": domain, "found": True,
        "text": (
            f"{domain}: risk={round(row.risk_score, 3) if row.risk_score is not None else 'n/a'}, "
            f"decision={row.decision_reason or 'n/a'}, registrar={row.registrar or 'unknown'}, "
            f"enrichment={row.enrichment_level or 'tier0'}, "
            f"last seen {row.event_ts.isoformat() if row.event_ts else 'unknown'}"
        ),
    }


@_intent(r"\btop\b.*\brisk\b")
def _top_risk_domains(session, match: re.Match) -> dict:
    from product.models import CtObservation

    # ct_observations is one row per host+event_ts, so the same domain can
    # legitimately appear many times (re-scored, multiple subdomains) --
    # over-fetch and dedupe by domain in Python rather than showing the same
    # domain 3x in a "top 5", which is what a flat LIMIT 5 would do.
    rows = session.execute(
        select(CtObservation)
        .where(CtObservation.risk_score.isnot(None))
        .order_by(CtObservation.risk_score.desc())
        .limit(50)
    ).scalars().all()
    if not rows:
        return {"intent": "top_risk_domains", "count": 0, "text": "No scored observations on record yet."}
    seen: dict[str, float] = {}
    for r in rows:
        if r.registered_domain and r.registered_domain not in seen:
            seen[r.registered_domain] = r.risk_score
        if len(seen) >= 5:
            break
    lines = [f"- {domain}: {round(score, 3)}" for domain, score in seen.items()]
    return {
        "intent": "top_risk_domains", "count": len(lines),
        "text": "Top risk domains:\n" + "\n".join(lines),
    }


_SUPPORTED_INTENTS_HELP = (
    "I can answer a fixed set of queries against the live database:\n"
    "- \"show campaigns for <brand>\"\n"
    "- \"status of <domain>\"\n"
    "- \"top risk domains\"\n"
    "Try one of those phrasings."
)


def route_query(session, query: str) -> dict:
    """Match `query` against the fixed intent set and dispatch to a
    parameterized, already-scoped lookup. An unmatched query -- including
    one crafted to look like a control instruction -- gets the same graceful
    fallback as any unrelated one; caller-supplied text is never used to
    pick a query shape, only (for matched intents) as a single bind
    parameter within an already-fixed, already-reviewed query."""
    q = (query or "").strip()[:MAX_QUERY_LEN]
    for pattern, fn in _INTENT_PATTERNS:
        m = pattern.search(q)
        if m:
            try:
                return fn(session, m)
            except Exception as e:  # noqa: BLE001
                return {
                    "intent": None, "error": str(e),
                    "text": "That matched a known query type but the lookup failed. Try again or rephrase.",
                }
    return {"intent": None, "text": _SUPPORTED_INTENTS_HELP}
