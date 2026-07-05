# product/suppression.py
"""Suppression rule matching, shared by assemble_campaigns.py and api/main.py.

rule_type semantics:
    domain    - match_value is a registrable-domain-or-suffix; matches an
                observation whose raw_host equals or is a subdomain of it
                (reuses ct/ingest/triage.py's _domain_under -- the same
                end-anchored matching rule already used for the Day-1
                provider-allowlist, so a.paypal.com.evil.tk under match_value
                "paypal.com" correctly does NOT match: that host ends in
                .evil.tk, not .paypal.com).
    registrar - match_value is a substring checked against observation.registrar
                (case-insensitive).
    asn       - match_value is checked for exact match (case-insensitive)
                against observation.sample_asn.

A rule is live if active=True AND (expires_at is None OR expires_at is in the
future) -- checked at read time, so an expired rule goes inert on its own
without a cleanup job.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ct.ingest.triage import _domain_under
from product.models import CtObservation, SuppressionRule


def is_rule_live(rule: SuppressionRule, now: datetime | None = None) -> bool:
    if not rule.active:
        return False
    if rule.expires_at is not None:
        now = now or datetime.now(timezone.utc)
        if rule.expires_at <= now:
            return False
    return True


def load_live_rules(session, now: datetime | None = None) -> list[SuppressionRule]:
    """All active, unexpired rules. Loaded once per assemble() run (mirrors
    load_brands' pattern) -- cheap since rule counts are small."""
    from sqlalchemy import select
    rules = session.execute(select(SuppressionRule)).scalars().all()
    return [r for r in rules if is_rule_live(r, now)]


def matching_rule(observation: CtObservation, rules: list[SuppressionRule]) -> SuppressionRule | None:
    """The first live rule that matches this observation, or None."""
    host = (observation.raw_host or "").lower()
    reg_domain = (observation.registered_domain or "").lower()
    registrar = (observation.registrar or "").lower()
    asn = (observation.sample_asn or "").upper()

    for r in rules:
        mv = (r.match_value or "").strip()
        if not mv:
            continue
        if r.rule_type == "domain":
            if _domain_under(host, [mv.lower()]) or reg_domain == mv.lower():
                return r
        elif r.rule_type == "registrar":
            if registrar and mv.lower() in registrar:
                return r
        elif r.rule_type == "asn":
            if asn and asn == mv.upper():
                return r
    return None
