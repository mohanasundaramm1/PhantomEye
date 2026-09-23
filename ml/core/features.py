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


# ---------------- WHOIS numeric derivation (serving side of train_model.py) ----------------
#
# train_model.py derives the five WHOIS_NUM_COLS from the raw WHOIS record
# (created / expires / error). ct.enrich.tiers.enrich_item() only emits the
# RAW fields (whois_created / whois_expires / whois_error / whois_status), and
# until this helper existed nothing on the serving side derived them: every
# caller zero-filled all five. age_days=0 with created_isnull=0 reads to the
# model as "registered today, date known" -- the most phishing-like WHOIS
# profile possible -- so google.com scored ~0.49 and amazon.com ~0.76 live,
# and every batch-scored row carried the same garbage.
#
# Semantics mirror train_model.py exactly, including its left-merge:
#   * WHOIS record present -> age/expiry from dates (NaN -> 0 when a date is
#     missing), created_isnull/expires_isnull = 1 for a missing date,
#     has_error = 1 if the lookup recorded an error.
#   * No WHOIS record at all (never looked up / cache miss) -> all five 0,
#     because training's left-merge leaves them NaN and then fillna(0)s them.

_WHOIS_PRESENCE_KEYS = ("registrar", "whois_status", "status", "whois_created",
                        "created", "whois_expires", "expires", "whois_error", "error")


def _is_missing(v) -> bool:
    if v is None:
        return True
    try:
        return bool(pd.isna(v))
    except (TypeError, ValueError):
        return False


def _to_utc(v):
    if _is_missing(v):
        return None
    ts = pd.to_datetime(v, utc=True, errors="coerce")
    return None if pd.isna(ts) else ts


def derive_whois_numeric(rec: dict, now=None) -> dict:
    """Return the five WHOIS_NUM_COLS for one enriched record, derived the
    way train_model.py derives them.

    Raw WHOIS fields are the source of truth: if any are present, derive
    from them even when WHOIS_NUM_COLS already exist on the record -- several
    upstream steps zero-fill those columns, and trusting a pre-existing 0
    would silently preserve the exact bug this fixes. Pre-computed values
    are used only when no raw WHOIS field is present at all."""
    has_record = any(not _is_missing(rec.get(k)) for k in _WHOIS_PRESENCE_KEYS)
    if not has_record:
        if all(not _is_missing(rec.get(c)) for c in WHOIS_NUM_COLS):
            return {c: float(rec[c]) for c in WHOIS_NUM_COLS}
        return {c: 0.0 for c in WHOIS_NUM_COLS}

    def _first(*keys):
        # enrich_item() always writes whois_* keys (often as None), so a
        # plain .get(a, .get(b)) would never reach the fallback key.
        for k in keys:
            if not _is_missing(rec.get(k)):
                return rec.get(k)
        return None

    now = now or pd.Timestamp.now(tz="UTC")
    created = _to_utc(_first("whois_created", "created"))
    expires = _to_utc(_first("whois_expires", "expires"))
    err = _first("whois_error", "error")
    return {
        "age_days": (now - created).total_seconds() / 86400.0 if created is not None else 0.0,
        "days_to_expiry": (expires - now).total_seconds() / 86400.0 if expires is not None else 0.0,
        "created_isnull": 0.0 if created is not None else 1.0,
        "expires_isnull": 0.0 if expires is not None else 1.0,
        "has_error": 0.0 if _is_missing(err) else 1.0,
    }


def prepare_whois_columns(df: pd.DataFrame, now=None) -> pd.DataFrame:
    """In-place: fill WHOIS_NUM_COLS from raw WHOIS fields (see
    derive_whois_numeric) and alias whois_status -> status for cat_row(),
    which reads "status" -- the batch path lost that categorical because
    enrich_item() writes it as whois_status. Returns df for chaining."""
    if df.empty:
        return df
    now = now or pd.Timestamp.now(tz="UTC")
    derived = pd.DataFrame(
        [derive_whois_numeric(r, now) for r in df.to_dict(orient="records")],
        index=df.index,
    )
    for c in WHOIS_NUM_COLS:
        df[c] = derived[c]
    if "whois_status" in df.columns:
        if "status" not in df.columns:
            df["status"] = df["whois_status"]
        else:
            df["status"] = df["status"].where(df["status"].notna(), df["whois_status"])
    return df


# ---------------- DataFrame-level builder (batch, matches score_ct_with_latest.py) ----------------

def build_features_from_df(df: pd.DataFrame):
    """Build the full feature matrix for a DataFrame of enriched rows.

    Reproduces ct/score/score_ct_with_latest.py's build_features()
    (and ml/core/train_model.py's inline equivalent) exactly, column-for-column.
    `df` is mutated in place to fill missing DNS/WHOIS numeric columns with 0,
    same as the reference implementations.
    """
    # Derive WHOIS numerics + status alias BEFORE cats/whois blocks read them.
    prepare_whois_columns(df)
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
    e.update(derive_whois_numeric(e))
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
