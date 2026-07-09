"""Suppression rule matching: pure logic runs without a DB; load_live_rules
(a real query) is checked against the live app-db and skips cleanly when
unreachable."""
import datetime as dt

import pytest

from product.db import ping
from product.models import CtObservation, SuppressionRule
from product.suppression import is_rule_live, matching_rule


def _rule(rule_type, match_value, active=True, expires_at=None):
    return SuppressionRule(rule_type=rule_type, match_value=match_value, created_by="test",
                            active=active, expires_at=expires_at)


def _obs(raw_host, registered_domain=None, registrar=None, sample_asn=None):
    return CtObservation(raw_host=raw_host, registered_domain=registered_domain or raw_host,
                          registrar=registrar, sample_asn=sample_asn,
                          event_ts=dt.datetime(2026, 7, 4, tzinfo=dt.timezone.utc), risk_score=0.9)


# ---------- is_rule_live ----------

def test_inactive_rule_is_not_live():
    assert is_rule_live(_rule("domain", "x.com", active=False)) is False


def test_expired_rule_is_not_live():
    past = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    assert is_rule_live(_rule("domain", "x.com", expires_at=past)) is False


def test_future_expiry_is_live():
    future = dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc)
    assert is_rule_live(_rule("domain", "x.com", expires_at=future)) is True


def test_no_expiry_is_live():
    assert is_rule_live(_rule("domain", "x.com")) is True


# ---------- matching_rule ----------

def test_domain_rule_matches_subdomain_not_lookalike():
    rules = [_rule("domain", "paypal.com")]
    assert matching_rule(_obs("secure.paypal.com"), rules) is not None
    assert matching_rule(_obs("paypal.com"), rules) is not None
    # the classic lookalike trick must NOT match -- this host ends in
    # .evil.tk, not .paypal.com (same anchoring as the Day-1 self_domains fix)
    assert matching_rule(_obs("paypal.com.evil.tk"), rules) is None


def test_domain_rule_matches_via_registered_domain_too():
    rules = [_rule("domain", "sketchy-tld.tk")]
    # raw_host differs from registered_domain (e.g. a deep subdomain), but
    # registered_domain itself matches
    assert matching_rule(_obs("a.b.c.sketchy-tld.tk", registered_domain="sketchy-tld.tk"), rules) is not None


def test_registrar_rule_is_substring_case_insensitive():
    rules = [_rule("registrar", "namecheap")]
    assert matching_rule(_obs("x.com", registrar="NameCheap, Inc."), rules) is not None
    assert matching_rule(_obs("x.com", registrar="GoDaddy.com, LLC"), rules) is None


def test_asn_rule_is_exact_case_insensitive():
    rules = [_rule("asn", "AS12345")]
    assert matching_rule(_obs("x.com", sample_asn="as12345"), rules) is not None
    assert matching_rule(_obs("x.com", sample_asn="AS99999"), rules) is None


def test_no_rules_never_matches():
    assert matching_rule(_obs("anything.com"), []) is None


def test_inactive_rule_in_list_is_ignored_by_matching_rule_caller():
    # matching_rule itself doesn't filter liveness -- that's load_live_rules'
    # job (mirrors load_brands: caller passes already-filtered rules).
    # Confirm the division of labor explicitly so a future refactor can't
    # silently merge these responsibilities and double-filter or skip it.
    rules = [_rule("domain", "x.com", active=False)]
    assert matching_rule(_obs("x.com"), rules) is not None  # matching_rule doesn't check .active


# ---------- load_live_rules (live) ----------

@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_load_live_rules_excludes_inactive_and_expired():
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.suppression import load_live_rules

    with SessionLocal() as s:
        try:
            s.add_all([
                SuppressionRule(rule_type="domain", match_value="zz-live.tk", created_by="t", active=True),
                SuppressionRule(rule_type="domain", match_value="zz-inactive.tk", created_by="t", active=False),
                SuppressionRule(rule_type="domain", match_value="zz-expired.tk", created_by="t", active=True,
                                expires_at=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)),
            ])
            s.commit()
            live = load_live_rules(s)
            live_values = {r.match_value for r in live}
            assert "zz-live.tk" in live_values
            assert "zz-inactive.tk" not in live_values
            assert "zz-expired.tk" not in live_values
        finally:
            s.execute(delete(SuppressionRule).where(SuppressionRule.match_value.like("zz-%")))
            s.commit()
