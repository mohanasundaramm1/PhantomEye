"""Tests for the canonical feature-building module (ml/core/features.py).

Checks output shape/width and that the single-domain builder matches the
DataFrame/batch builder used by ct/score/score_ct_with_latest.py, since the
two must stay bit-for-bit compatible with what the models were trained on.
"""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.core.features import (
    DNS_NUM_COLS,
    N_CAT_FEATURES,
    N_CHAR_FEATURES,
    STRING_FEATS,
    TOTAL_FEATURES,
    WHOIS_NUM_COLS,
    build_features,
    build_features_from_df,
)


def test_total_features_matches_schema_components():
    assert TOTAL_FEATURES == N_CHAR_FEATURES + len(STRING_FEATS) + len(DNS_NUM_COLS) + N_CAT_FEATURES + len(WHOIS_NUM_COLS)


def test_build_features_shape_no_enrichment():
    X = build_features("example.com")
    assert X.shape == (1, TOTAL_FEATURES)


def test_build_features_shape_with_enrichment():
    enr = {
        "num_unique_ips": 2, "has_ipv6": 1, "num_countries": 1, "num_asns": 1,
        "sample_asn": "AS1234", "sample_isp": "SomeHost", "sample_country": "US",
        "registrar": "SomeRegistrar", "whois_status": "ok",
        "age_days": 100, "days_to_expiry": 200,
        "created_isnull": 0, "expires_isnull": 0, "has_error": 0,
    }
    X = build_features("example.com", enr)
    assert X.shape == (1, TOTAL_FEATURES)


def test_build_features_matches_batch_builder():
    """Single-domain and DataFrame builders must produce identical vectors
    for the same inputs -- this is the guarantee the API relies on."""
    enr = {
        "num_unique_ips": 3, "has_ipv6": 0, "num_countries": 2, "num_asns": 2,
        "sample_asn": "AS12345", "sample_isp": "BulletproofHost", "sample_country": "RU",
        "registrar": "NiceRegistrar", "whois_status": "clientTransferProhibited",
        "age_days": 3, "days_to_expiry": 360,
        "created_isnull": 0, "expires_isnull": 0, "has_error": 0,
    }
    domain = "paypal-secure-login.tk"
    X_single = build_features(domain, enr)

    df = pd.DataFrame([{
        "registered_domain": domain,
        "num_unique_ips": 3, "has_ipv6": 0, "num_countries": 2, "num_asns": 2,
        "sample_asn": "AS12345", "sample_isp": "BulletproofHost", "sample_country": "RU",
        "registrar": "NiceRegistrar", "status": "clientTransferProhibited",
        "age_days": 3, "days_to_expiry": 360,
        "created_isnull": 0, "expires_isnull": 0, "has_error": 0,
    }])
    X_batch = build_features_from_df(df)

    assert X_single.shape == X_batch.shape
    assert (X_single != X_batch).nnz == 0


def test_build_features_missing_enrichment_zero_fills_numeric_blocks():
    """No enrichment dict -> DNS/WHOIS numeric blocks are all zero, but the
    lexical block is still populated (never silently dropped)."""
    X = build_features("totally-random-domain-xyz.com")
    lex_width = N_CHAR_FEATURES + len(STRING_FEATS)
    dns_block = X[:, lex_width:lex_width + len(DNS_NUM_COLS)]
    whois_block = X[:, -len(WHOIS_NUM_COLS):]
    assert dns_block.nnz == 0
    assert whois_block.nnz == 0
    # lexical block (char n-grams) should have nonzero entries for a real domain
    assert X[:, :lex_width].nnz > 0


def test_build_features_empty_domain_does_not_crash():
    X = build_features("")
    assert X.shape == (1, TOTAL_FEATURES)
