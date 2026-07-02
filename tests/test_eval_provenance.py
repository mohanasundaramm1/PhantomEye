"""Tests for ml/core/eval_provenance.py.

All data is small and synthetic; nothing here reads the real silver/lookups
directories or trains against the real ~56K-row dataset (that's exercised
manually, not in the fast test suite).
"""
import os
import sys

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.core.eval_provenance import (
    build_full_features,
    build_infra_only_features,
    infra_only_shortcut_check,
    leave_one_source_out,
    reg_domain,
)


def _synthetic_dataset(n_per_group=40, seed=0):
    """Benign domains: real-word-like, low entropy, established registrars.
    urlhaus/openphish domains: higher entropy random strings, sketchy TLDs --
    genuinely distinguishable by lexical features, not just infra, so a
    healthy model should generalize across sources here."""
    rng = np.random.RandomState(seed)
    rows = []
    real_words = ["shop", "bank", "mail", "news", "blog", "store", "docs", "media"]
    for i in range(n_per_group):
        rows.append({
            "registered_domain": f"{rng.choice(real_words)}{i}.com",
            "label": 0, "source": "benign_seed",
            "sample_asn": "AS1234", "sample_isp": "BigCloud", "sample_country": "US",
            "registrar": "GoDaddy", "status": "ok",
            "num_unique_ips": 1, "has_ipv6": 0, "num_countries": 1, "num_asns": 1,
            "age_days": 2000, "days_to_expiry": 300, "created_isnull": 0, "expires_isnull": 0, "has_error": 0,
        })
    for i in range(n_per_group):
        junk = "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789"), size=14))
        rows.append({
            "registered_domain": f"{junk}.xyz",
            "label": 1, "source": "urlhaus",
            "sample_asn": "AS9999", "sample_isp": "BulletproofHost", "sample_country": "RU",
            "registrar": "NameCheap", "status": "clientHold",
            "num_unique_ips": 3, "has_ipv6": 0, "num_countries": 2, "num_asns": 2,
            "age_days": 2, "days_to_expiry": 360, "created_isnull": 0, "expires_isnull": 0, "has_error": 0,
        })
    for i in range(n_per_group):
        junk = "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789"), size=16))
        rows.append({
            "registered_domain": f"{junk}.top",
            "label": 1, "source": "openphish",
            "sample_asn": "AS8888", "sample_isp": "CheapVPS", "sample_country": "CN",
            "registrar": "Alibaba", "status": "clientHold",
            "num_unique_ips": 2, "has_ipv6": 0, "num_countries": 1, "num_asns": 1,
            "age_days": 1, "days_to_expiry": 360, "created_isnull": 0, "expires_isnull": 0, "has_error": 0,
        })
    return pd.DataFrame(rows)


def test_reg_domain_basic():
    assert reg_domain("sub.example.com") == "example.com"
    assert reg_domain(None) == ""
    assert reg_domain("") == ""


def test_build_full_features_shape_matches_expected_width():
    Xdf = _synthetic_dataset(n_per_group=5)
    X = build_full_features(Xdf.copy())
    # 4096 char + 10 lexical + 4 dns + 256 cat + 5 whois
    assert X.shape == (15, 4096 + 10 + 4 + 256 + 5)


def test_build_infra_only_features_excludes_lexical_width():
    Xdf = _synthetic_dataset(n_per_group=5)
    X = build_infra_only_features(Xdf.copy())
    # 4 dns + 256 cat + 5 whois -- no char/lexical columns at all
    assert X.shape == (15, 4 + 256 + 5)


def test_leave_one_source_out_holds_out_source_entirely():
    Xdf = _synthetic_dataset(n_per_group=30)
    results = leave_one_source_out(Xdf, malicious_sources=["urlhaus", "openphish"], random_state=1)
    assert set(results.keys()) == {"urlhaus", "openphish"}
    for source, r in results.items():
        assert "error" not in r, r
        assert r["held_out_source"] == source
        assert source not in r["train_sources"]  # never trained on the held-out source
        assert r["n_test_pos"] > 0 and r["n_test_neg"] > 0
        assert 0.0 <= r["roc_auc"] <= 1.0


def test_leave_one_source_out_generalizes_on_lexically_separable_synthetic_data():
    """On this synthetic dataset the classes ARE genuinely lexically
    separable (junk strings vs real words), independent of source. A model
    that only memorized source-specific quirks would fail to generalize to
    the held-out source; a model that learned real lexical signal should
    still score well. This is a sanity check that the LOSO harness itself
    produces a meaningful, non-degenerate number, not that the real
    production model generalizes (that's measured separately, against real
    data, not asserted in a fast unit test)."""
    Xdf = _synthetic_dataset(n_per_group=40, seed=7)
    results = leave_one_source_out(Xdf, malicious_sources=["urlhaus", "openphish"], random_state=1)
    for source, r in results.items():
        assert r["roc_auc"] > 0.7, f"expected clear generalization signal for held-out {source}, got {r}"


def test_leave_one_source_out_reports_error_for_missing_source():
    Xdf = _synthetic_dataset(n_per_group=10)
    results = leave_one_source_out(Xdf, malicious_sources=["urlhaus", "nonexistent_source"], random_state=1)
    assert "error" in results["nonexistent_source"]


def test_infra_only_shortcut_check_returns_both_variants_and_gap():
    Xdf = _synthetic_dataset(n_per_group=30)
    result = infra_only_shortcut_check(Xdf, random_state=1)
    assert "error" not in result
    assert "roc_auc" in result["full_features"]
    assert "roc_auc" in result["infra_only_features"]
    assert result["full_minus_infra_auc_gap"] is not None
    assert isinstance(result["interpretation"], str) and len(result["interpretation"]) > 0


def test_infra_only_shortcut_check_gap_can_be_small_when_infra_is_also_separable():
    """On this synthetic dataset, infra features (ASN/ISP/country/registrar)
    ALSO perfectly separate the classes by construction (benign uses
    AS1234/GoDaddy/US; malicious uses AS9999 or AS8888 with sketchy
    registrars) -- so a small full-minus-infra gap here is the CORRECT,
    expected result, not a bug. This proves the diagnostic actually detects
    the shortcut-baseline scenario it's designed to catch."""
    Xdf = _synthetic_dataset(n_per_group=40, seed=3)
    result = infra_only_shortcut_check(Xdf, random_state=1)
    assert result["full_minus_infra_auc_gap"] < 0.15  # infra alone should be a strong baseline here


def test_leave_one_source_out_errors_gracefully_on_too_few_benign_rows():
    Xdf = pd.DataFrame({
        "registered_domain": ["a.com", "b.xyz"], "label": [0, 1], "source": ["benign_seed", "urlhaus"],
    })
    result = leave_one_source_out(Xdf, malicious_sources=["urlhaus"])
    assert "error" in result
