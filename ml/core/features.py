# ml/core/features.py
#
# Canonical feature-building module shared by the training pipeline
# (ml/core/train_model.py), the batch scorer (ct/score/score_ct_with_latest.py),
# and the live API (api/main.py).
#
# The feature schema here MUST stay in lockstep with what those two callers
# build inline: char n-gram hashing (4096) + 10 lexical stats + 4 DNS numeric
# columns + 256 hashed categoricals + 5 WHOIS numeric columns, concatenated
# in exactly this order:
#
#   X_full = hstack([X_char, X_string, X_dns_num, X_cat, X_whois_num])
#
# Changing column order/count here silently breaks every trained model, so
# any change to this schema must be made in train_model.py and
# score_ct_with_latest.py at the same time (out of scope for this module).

from __future__ import annotations

import math
from collections import Counter

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import FeatureHasher, HashingVectorizer

# ---------------- schema constants ----------------

STRING_FEATS = [
    "len", "digits", "hyphens", "dots",
    "digit_ratio", "hyphen_ratio",
    "entropy", "xn_punycode", "labels", "tld_len",
]

DNS_NUM_COLS = ["num_unique_ips", "has_ipv6", "num_countries", "num_asns"]

WHOIS_NUM_COLS = ["age_days", "days_to_expiry", "created_isnull", "expires_isnull", "has_error"]

N_CHAR_FEATURES = 4096
N_CAT_FEATURES = 256

# total width = 4096 (char) + 10 (lexical) + 4 (dns) + 256 (cat) + 5 (whois)
TOTAL_FEATURES = N_CHAR_FEATURES + len(STRING_FEATS) + len(DNS_NUM_COLS) + N_CAT_FEATURES + len(WHOIS_NUM_COLS)


def _char_vectorizer() -> HashingVectorizer:
    return HashingVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        n_features=N_CHAR_FEATURES,
        lowercase=True,
        alternate_sign=False,
    )


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def basic_string_feats(dom: str) -> dict:
    d = dom or ""
    feats = {}
    feats["len"] = len(d)
    feats["digits"] = sum(ch.isdigit() for ch in d)
    feats["hyphens"] = d.count("-")
    feats["dots"] = d.count(".")
    feats["digit_ratio"] = feats["digits"] / (feats["len"] + 1e-6)
    feats["hyphen_ratio"] = feats["hyphens"] / (feats["len"] + 1e-6)
    feats["entropy"] = shannon_entropy(d)
    feats["xn_punycode"] = int("xn--" in d)
    parts = d.split(".")
    feats["labels"] = len([p for p in parts if p])
    feats["tld_len"] = len(parts[-1]) if parts else 0
    return feats


def cat_row(r: dict) -> dict:
    """Hashed-categorical source dict for one row (ASN/ISP/country/registrar/status)."""
    d = {}
    asn = r.get("sample_asn")
    isp = r.get("sample_isp")
    cc = r.get("sample_country")
    reg = r.get("registrar")
    st = r.get("status")

    def _push(key, val):
        if val is None:
            return
        if isinstance(val, float) and math.isnan(val):
            return
        s = str(val).strip()
        if s and s.lower() != "nan":
            d[key + s] = 1

    _push("asn=", asn)
    _push("isp=", isp)
    _push("cc=", cc)
    _push("reg=", reg)
    _push("status=", st)
    return d


# ---------------- DataFrame-level builder (batch, matches score_ct_with_latest.py) ----------------

def build_features_from_df(df: pd.DataFrame):
    """Build the full feature matrix for a DataFrame of enriched rows.

    Reproduces ct/score/score_ct_with_latest.py's build_features()
    (and ml/core/train_model.py's inline equivalent) exactly, column-for-column.
    `df` is mutated in place to fill missing DNS/WHOIS numeric columns with 0,
    same as the reference implementations.
    """
    domains = df["registered_domain"].fillna("")

    char_vect = _char_vectorizer()
    X_char = char_vect.transform(domains.tolist())

    S = np.vstack([
        [basic_string_feats(d).get(k, 0) for k in STRING_FEATS]
        for d in domains.tolist()
    ])
    X_string = csr_matrix(S)

    for c in DNS_NUM_COLS:
        if c not in df.columns:
            df[c] = 0
    df[DNS_NUM_COLS] = df[DNS_NUM_COLS].fillna(0)
    X_dns_num = csr_matrix(df[DNS_NUM_COLS].to_numpy(dtype=float))

    cats = [cat_row(r) for r in df.to_dict(orient="records")]
    hasher = FeatureHasher(n_features=N_CAT_FEATURES, input_type="dict", alternate_sign=False)
    X_cat = hasher.transform(cats)

    for c in WHOIS_NUM_COLS:
        if c not in df.columns:
            df[c] = 0
    df[WHOIS_NUM_COLS] = df[WHOIS_NUM_COLS].fillna(0)
    X_whois_num = csr_matrix(df[WHOIS_NUM_COLS].to_numpy(dtype=float))

    X_full = hstack([X_char, X_string, X_dns_num, X_cat, X_whois_num]).tocsr()
    return X_full


# ---------------- single-domain builder (live scoring) ----------------

def build_features(domain: str, enrichment: dict | None = None):
    """Build the full feature vector (1 x TOTAL_FEATURES) for a single domain.

    `enrichment` is an optional dict carrying whatever DNS/geo/WHOIS/categorical
    fields are available for this domain, using the same field names as the
    gold schema / ct.enrich.tiers.enrich_item() output:
        num_unique_ips, has_ipv6, num_countries, num_asns,
        sample_asn, sample_isp, sample_country, registrar, status (or whois_status),
        age_days, days_to_expiry, created_isnull, expires_isnull, has_error.

    Any field that is missing/unavailable is zero-filled (numeric) or omitted
    (categorical) — the caller is responsible for tracking/reporting whether
    the enrichment was complete (see api/main.py's enrichment_status).
    """
    e = dict(enrichment or {})
    d = (domain or "").lower().strip()

    char_vect = _char_vectorizer()
    X_char = char_vect.transform([d])

    S = np.array([[basic_string_feats(d).get(k, 0) for k in STRING_FEATS]])
    X_string = csr_matrix(S)

    dns_vals = [[float(e.get(c, 0) or 0) for c in DNS_NUM_COLS]]
    X_dns_num = csr_matrix(np.array(dns_vals, dtype=float))

    # cat_row() reads "status"; enrich_item() writes "whois_status" — accept either.
    cat_source = dict(e)
    if "status" not in cat_source and "whois_status" in cat_source:
        cat_source["status"] = cat_source["whois_status"]
    cats = [cat_row(cat_source)]
    hasher = FeatureHasher(n_features=N_CAT_FEATURES, input_type="dict", alternate_sign=False)
    X_cat = hasher.transform(cats)

    whois_vals = [[float(e.get(c, 0) or 0) for c in WHOIS_NUM_COLS]]
    X_whois_num = csr_matrix(np.array(whois_vals, dtype=float))

    X_full = hstack([X_char, X_string, X_dns_num, X_cat, X_whois_num]).tocsr()
    return X_full
