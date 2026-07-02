"""Tests for ct/score/measure_lead_time.py.

All data is synthetic; nothing here reads the real gold/bronze directories.
"""
import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ct.score.measure_lead_time import (
    compute_lead_time,
    load_blocklist_first_seen,
    load_ct_high_risk,
    reg_domain,
    summarize,
)


def test_reg_domain_normalizes_subdomains():
    assert reg_domain("login.paypal-secure.tk") == "paypal-secure.tk"
    assert reg_domain("EXAMPLE.COM") == "example.com"
    assert reg_domain("") == ""
    assert reg_domain(None) == ""


def test_reg_domain_preserves_identity_on_shared_hosting_platforms():
    """The exact bug caught by inspecting real output: plain tldextract
    collapses "evil-phish.herokuapp.com" to "herokuapp.com", which would make
    every phishing site on a shared PaaS/dynamic-DNS platform falsely match
    every other site on the same platform. Must stay distinct."""
    assert reg_domain("evil-phish.herokuapp.com") == "evil-phish.herokuapp.com"
    assert reg_domain("legit-app.herokuapp.com") == "legit-app.herokuapp.com"
    assert reg_domain("evil-phish.herokuapp.com") != reg_domain("legit-app.herokuapp.com")
    assert reg_domain("a1b2c3.dpdns.org") == "a1b2c3.dpdns.org"
    assert reg_domain("malicious.plesk.page") == "malicious.plesk.page"


def test_load_ct_high_risk_filters_threshold_and_dedupes_by_earliest(tmp_path):
    gold = tmp_path / "gold"
    gold.mkdir()
    # two "runs" scoring overlapping domains at different times -- should
    # collapse to one row per raw_host with the EARLIEST event_ts
    pd.DataFrame({
        "registered_domain": ["bad.com", "low.com", "later.com"],
        "domain_sample": ["www.bad.com", "low.com", "later.com"],
        "event_ts": pd.to_datetime(["2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"]),
        "risk_score": [0.95, 0.10, 0.92],
    }).to_parquet(gold / "run1.parquet")
    pd.DataFrame({
        # bad.com re-scored LATER under a new filename -- min() must still win
        "registered_domain": ["bad.com"],
        "domain_sample": ["www.bad.com"],
        "event_ts": pd.to_datetime(["2026-01-05T00:00:00Z"]),
        "risk_score": [0.96],
    }).to_parquet(gold / "run2.parquet")

    out = load_ct_high_risk(str(gold), risk_threshold=0.90)
    assert set(out["raw_host"]) == {"www.bad.com", "later.com"}  # low.com filtered out
    bad_row = out[out["raw_host"] == "www.bad.com"].iloc[0]
    assert bad_row["registered_domain"] == "bad.com"
    assert bad_row["ct_first_seen"] == pd.Timestamp("2026-01-01T00:00:00Z")  # earliest, not latest
    assert bad_row["risk_score"] == 0.96  # max score kept


def test_load_ct_high_risk_empty_dir_returns_empty_frame(tmp_path):
    out = load_ct_high_risk(str(tmp_path / "nonexistent"), risk_threshold=0.9)
    assert out.empty
    assert set(["raw_host", "registered_domain", "ct_first_seen", "risk_score"]).issubset(out.columns)


def test_load_ct_high_risk_skips_files_missing_risk_score_explicitly(tmp_path, capsys):
    """Regression test for a real bug found by auditing this module's own
    output: an older gold file used week5_score/risk_bucket instead of
    risk_score. The original loader padded the missing column with None,
    and `None >= threshold` silently filtered out every row in that file --
    2892 real domains vanished with zero indication. Must now be an
    explicit, visible skip instead."""
    gold = tmp_path / "gold"
    gold.mkdir()
    # old-schema file: no risk_score at all
    pd.DataFrame({
        "registered_domain": ["old-schema-domain.com"],
        "domain_sample": ["old-schema-domain.com"],
        "event_ts": pd.to_datetime(["2025-11-30T00:00:00Z"]),
        "week5_score": [0.99],
        "risk_bucket": ["high"],
    }).to_parquet(gold / "old_schema.parquet")
    # current-schema file: has risk_score
    pd.DataFrame({
        "registered_domain": ["new-schema-domain.com"],
        "domain_sample": ["new-schema-domain.com"],
        "event_ts": pd.to_datetime(["2026-01-01T00:00:00Z"]),
        "risk_score": [0.95],
    }).to_parquet(gold / "new_schema.parquet")

    out = load_ct_high_risk(str(gold), risk_threshold=0.90, verbose=True)
    assert list(out["raw_host"]) == ["new-schema-domain.com"]  # old-schema row absent, not silently None-filtered
    captured = capsys.readouterr()
    assert "skipped 1 file" in captured.out  # the skip is reported, not silent


def test_load_blocklist_first_seen_dedupes_across_sources_and_partitions(tmp_path):
    op_dir = tmp_path / "openphish" / "ingest_date=2026-01-01"
    op_dir.mkdir(parents=True)
    pd.DataFrame({
        "url": ["http://sub.evil.com/x"],
        "domain": ["sub.evil.com"],
        "first_seen": pd.to_datetime(["2026-01-03T00:00:00Z"]),
    }).to_parquet(op_dir / "openphish.parquet")

    uh_dir = tmp_path / "urlhaus" / "ingest_date=2026-01-02"
    uh_dir.mkdir(parents=True)
    pd.DataFrame({
        "url": ["http://sub.evil.com/y"],
        "domain": ["sub.evil.com"],
        "first_seen": pd.to_datetime(["2026-01-01T00:00:00Z"]),  # earlier than openphish's
    }).to_parquet(uh_dir / "urlhaus.parquet")

    out = load_blocklist_first_seen(str(tmp_path / "openphish"), str(tmp_path / "urlhaus"))
    row = out[out["raw_host"] == "sub.evil.com"].iloc[0]
    assert row["registered_domain"] == "evil.com"
    assert row["blocklist_first_seen"] == pd.Timestamp("2026-01-01T00:00:00Z")  # earliest across sources
    assert set(row["sources"].split(",")) == {"openphish", "urlhaus"}


def test_compute_lead_time_exact_hostname_tier_positive_means_ct_first():
    """Same fully-qualified hostname on both sides -> exact_hostname tier."""
    ct_df = pd.DataFrame({
        "raw_host": ["early.com", "late.com"],
        "registered_domain": ["early.com", "late.com"],
        "ct_first_seen": pd.to_datetime(["2026-01-01T00:00:00Z", "2026-01-10T00:00:00Z"]),
        "risk_score": [0.95, 0.95],
    })
    blocklist_df = pd.DataFrame({
        "raw_host": ["early.com", "late.com"],
        "registered_domain": ["early.com", "late.com"],
        "blocklist_first_seen": pd.to_datetime(["2026-01-02T00:00:00Z", "2026-01-05T00:00:00Z"]),
        "sources": ["openphish", "urlhaus"],
    })
    joined = compute_lead_time(ct_df, blocklist_df)
    assert (joined["match_tier"] == "exact_hostname").all()
    early = joined[joined["raw_host"] == "early.com"].iloc[0]
    late = joined[joined["raw_host"] == "late.com"].iloc[0]
    assert early["lead_time_hours"] == pytest.approx(24.0)   # CT saw it 1 day before blocklist
    assert late["lead_time_hours"] == pytest.approx(-5 * 24.0)  # blocklist had it 5 days first


def test_compute_lead_time_falls_back_to_registered_domain_tier():
    """Different subdomains, same apex, on a platform not covered by the PSL:
    no exact_hostname match, but a registered_domain (apex) match still fires
    -- and must be tagged as the lower-confidence tier."""
    ct_df = pd.DataFrame({
        "raw_host": ["t4w.5c2.myftpupload.com"],
        "registered_domain": ["myftpupload.com"],
        "ct_first_seen": pd.to_datetime(["2026-01-01T00:00:00Z"]),
        "risk_score": [0.95],
    })
    blocklist_df = pd.DataFrame({
        "raw_host": ["different-subdomain.myftpupload.com"],
        "registered_domain": ["myftpupload.com"],
        "blocklist_first_seen": pd.to_datetime(["2026-01-02T00:00:00Z"]),
        "sources": ["openphish"],
    })
    joined = compute_lead_time(ct_df, blocklist_df)
    assert len(joined) == 1
    assert joined.iloc[0]["match_tier"] == "registered_domain"
    assert joined.iloc[0]["lead_time_hours"] == pytest.approx(24.0)


def test_compute_lead_time_exact_match_excluded_from_apex_tier_no_double_count():
    """A domain that already matched at the exact-hostname level must not
    ALSO be counted again via the apex tier."""
    ct_df = pd.DataFrame({
        "raw_host": ["site.example.com"],
        "registered_domain": ["example.com"],
        "ct_first_seen": pd.to_datetime(["2026-01-01T00:00:00Z"]),
        "risk_score": [0.95],
    })
    blocklist_df = pd.DataFrame({
        "raw_host": ["site.example.com"],
        "registered_domain": ["example.com"],
        "blocklist_first_seen": pd.to_datetime(["2026-01-02T00:00:00Z"]),
        "sources": ["openphish"],
    })
    joined = compute_lead_time(ct_df, blocklist_df)
    assert len(joined) == 1  # not 2
    assert joined.iloc[0]["match_tier"] == "exact_hostname"


def test_compute_lead_time_empty_inputs_returns_empty_frame():
    empty = pd.DataFrame(columns=["raw_host", "registered_domain"])
    out = compute_lead_time(empty, empty)
    assert out.empty
    assert "lead_time_hours" in out.columns
    assert "match_tier" in out.columns


def test_summarize_reports_coverage_and_tiers():
    ct_df = pd.DataFrame({"registered_domain": [f"d{i}.com" for i in range(10)],
                          "raw_host": [f"d{i}.com" for i in range(10)]})
    joined = pd.DataFrame({
        "registered_domain": ["d0.com", "d1.com", "d2.com"],
        "lead_time_hours": [10.0, -5.0, 20.0],
        "match_tier": ["exact_hostname", "exact_hostname", "registered_domain"],
    })
    s = summarize(ct_df, joined, risk_threshold=0.9)
    assert s["n_ct_high_risk_domains"] == 10
    assert s["n_matched_total"] == 3
    assert s["n_matched_exact_hostname"] == 2
    assert s["n_matched_registered_domain_only"] == 1
    assert s["coverage_pct"] == pytest.approx(30.0)
    assert s["n_ct_ahead_of_blocklist"] == 2       # 10.0 and 20.0 are > 0
    assert s["n_ct_ahead_exact_hostname_only"] == 1  # only d0.com (10.0) is exact AND ahead
    assert s["n_blocklist_first_or_same_time"] == 1  # -5.0
    assert s["median_lead_time_hours_when_ahead"] == pytest.approx(15.0)  # median of [10,20]
    assert "LOW confidence" in s["confidence_note"]  # n_exact=2 < 30


def test_summarize_apex_only_matches_are_flagged_low_confidence_even_if_present():
    """If every match is apex-tier (no exact-hostname matches at all), the
    confidence note must say so explicitly rather than implying a real signal."""
    ct_df = pd.DataFrame({"registered_domain": ["a.com", "b.com"], "raw_host": ["a.com", "b.com"]})
    joined = pd.DataFrame({
        "registered_domain": ["a.com", "b.com"],
        "lead_time_hours": [10.0, -5.0],
        "match_tier": ["registered_domain", "registered_domain"],
    })
    s = summarize(ct_df, joined, risk_threshold=0.9)
    assert s["n_matched_exact_hostname"] == 0
    assert "NO exact-hostname matches" in s["confidence_note"]


def test_summarize_coverage_pct_never_exceeds_100_with_shared_apex(tmp_path):
    """Regression test for a real bug found by auditing this module's own
    output: counting n_ct at registered_domain granularity while
    exact_hostname matches are counted at raw_host granularity let
    coverage_pct exceed 100% whenever multiple raw_hosts sharing one apex
    (e.g. several phishing subdomains of the same actor-owned domain) all
    matched. Must stay mathematically bounded."""
    gold = tmp_path / "gold"
    gold.mkdir()
    pd.DataFrame({
        "registered_domain": ["evil.com", "evil.com"],
        "domain_sample": ["phish1.evil.com", "phish2.evil.com"],
        "event_ts": pd.to_datetime(["2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"]),
        "risk_score": [0.95, 0.95],
    }).to_parquet(gold / "run1.parquet")
    ct_df = load_ct_high_risk(str(gold), risk_threshold=0.90, verbose=False)
    assert len(ct_df) == 2  # two distinct raw_hosts under one apex

    blocklist_df = pd.DataFrame({
        "raw_host": ["phish1.evil.com", "phish2.evil.com"],
        "registered_domain": ["evil.com", "evil.com"],
        "blocklist_first_seen": pd.to_datetime(["2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z"]),
        "sources": ["openphish", "openphish"],
    })
    joined = compute_lead_time(ct_df, blocklist_df)
    assert len(joined) == 2  # both raw_hosts matched at exact_hostname tier

    s = summarize(ct_df, joined, risk_threshold=0.9)
    assert s["n_ct_high_risk_domains"] == 2       # raw_host-based, not apex-based (would be 1)
    assert s["n_matched_total"] == 2
    assert s["coverage_pct"] == pytest.approx(100.0)  # not 200%
    assert s["coverage_pct"] <= 100.0


def test_load_ct_high_risk_recomputes_registered_domain_psl_aware(tmp_path):
    """Regression test: the gold file's own registered_domain column is
    written by an OLDER, non-PSL-aware convention elsewhere in the repo
    (ct/score/score_ct_with_latest.py). If load_ct_high_risk trusted that
    column instead of recomputing it, the apex-tier join in
    compute_lead_time would silently fail to match anything on a
    PSL-private platform, because the blocklist side uses the PSL-aware
    convention. Both sides must agree."""
    gold = tmp_path / "gold"
    gold.mkdir()
    pd.DataFrame({
        # gold's OWN registered_domain column uses the old convention:
        # "evil.herokuapp.com" was (wrongly) collapsed to "herokuapp.com"
        # by the pipeline that originally wrote this file.
        "registered_domain": ["herokuapp.com"],
        "domain_sample": ["evil.herokuapp.com"],
        "event_ts": pd.to_datetime(["2026-01-01T00:00:00Z"]),
        "risk_score": [0.95],
    }).to_parquet(gold / "run1.parquet")

    out = load_ct_high_risk(str(gold), risk_threshold=0.90, verbose=False)
    row = out[out["raw_host"] == "evil.herokuapp.com"].iloc[0]
    # PSL-aware recomputation must win, not the gold file's stale value
    assert row["registered_domain"] == "evil.herokuapp.com"
    assert row["registered_domain"] != "herokuapp.com"


def test_summarize_no_matches_is_explicit_not_silent():
    ct_df = pd.DataFrame({"registered_domain": ["a.com"], "raw_host": ["a.com"]})
    empty_joined = pd.DataFrame(columns=["registered_domain", "lead_time_hours", "match_tier"])
    s = summarize(ct_df, empty_joined, risk_threshold=0.9)
    assert s["n_matched_total"] == 0
    assert s["median_lead_time_hours_when_ahead"] is None
    assert "NO MATCHES" in s["confidence_note"]
