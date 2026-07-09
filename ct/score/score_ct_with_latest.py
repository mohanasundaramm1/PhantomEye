#!/usr/bin/env python
# ct/score/score_ct_with_latest.py
#
# Score recent CT enriched domains with the latest ML model,
# and fuse with external threat intel from MISP (silver/misp_osint).

import os, glob, json
from datetime import datetime, timezone, timedelta

import numpy as np
import pandas as pd
import tldextract
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import HashingVectorizer, FeatureHasher

# Optional model deps
try:
    import joblib
except ImportError:
    joblib = None
try:
    import lightgbm as lgb
except ImportError:
    lgb = None

# ---------- paths ----------

THIS_DIR  = os.path.dirname(__file__)
CT_DIR    = os.path.abspath(os.path.join(THIS_DIR, ".."))
REPO_ROOT = os.path.abspath(os.path.join(CT_DIR, ".."))

DATA_DIR         = os.path.join(CT_DIR, "data")
ENRICHED_DEFAULT = os.path.join(DATA_DIR, "enriched")
SCORED_DEFAULT   = os.path.join(REPO_ROOT, "gold", "threat_scores")
os.makedirs(SCORED_DEFAULT, exist_ok=True)

MODEL_REG_DIR = os.path.join(REPO_ROOT, "ml", "models", "registry")
META_LATEST   = os.path.join(MODEL_REG_DIR, "ct_risk_meta_latest.json")
LOGREG_LATEST = os.path.join(MODEL_REG_DIR, "ct_risk_logreg_full_latest.joblib")
LGBM_LATEST   = os.path.join(MODEL_REG_DIR, "ct_risk_lgbm_full_latest.txt")
LATEST_PTR    = os.path.join(ENRICHED_DEFAULT, "_latest_enriched.json")

CT_ENRICHED_DIR = os.getenv("CT_ENRICHED_DIR", ENRICHED_DEFAULT)
CT_SCORED_DIR   = os.getenv("CT_SCORED_DIR", SCORED_DEFAULT)

# MISP is in SILVER, not bronze:
# host default: <repo>/silver/misp_osint
MISP_SILVER_ROOT_DEFAULT = os.path.join(REPO_ROOT, "silver", "misp_osint")
MISP_SILVER_ROOT = os.getenv("MISP_SILVER_ROOT", MISP_SILVER_ROOT_DEFAULT)

# ---------- helpers ----------

def reg_domain(d: str) -> str:
    if not isinstance(d, str) or not d:
        return ""
    ext = tldextract.extract(d)
    reg = getattr(ext, "top_domain_under_public_suffix", None) or getattr(
        ext, "registered_domain", None
    ) or ""
    return reg.lower().strip()


# --- load enriched file path ---

def resolve_enriched_path() -> str:
    env_override = os.getenv("CT_ENRICHED_FILE")
    if env_override and os.path.exists(env_override):
        print("[info] using enriched file via CT_ENRICHED_FILE:", env_override)
        return env_override

    if os.path.exists(LATEST_PTR):
        try:
            with open(LATEST_PTR, "r") as f:
                j = json.load(f)
            if j.get("path") and os.path.exists(j["path"]):
                print("[info] loading enriched CT from pointer:", j["path"])
                return j["path"]
        except Exception:
            pass

    pattern = os.path.join(CT_ENRICHED_DIR, "ct_enriched_*.parquet")
    paths = sorted(glob.glob(pattern))
    if not paths:
        raise SystemExit(f"[error] no enriched CT files under {CT_ENRICHED_DIR}")
    latest = paths[-1]
    print(f"[info] loading enriched CT from: {latest}")
    return latest


# --- feature builders (MUST match training) ---

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * np.log2(v / n) for v in c.values())


def basic_string_feats(dom: str) -> dict:
    d = dom or ""
    feats = {}
    feats["len"]          = len(d)
    feats["digits"]       = sum(ch.isdigit() for ch in d)
    feats["hyphens"]      = d.count("-")
    feats["dots"]         = d.count(".")
    feats["digit_ratio"]  = feats["digits"] / (feats["len"] + 1e-6)
    feats["hyphen_ratio"] = feats["hyphens"] / (feats["len"] + 1e-6)
    feats["entropy"]      = shannon_entropy(d)
    feats["xn_punycode"]  = int("xn--" in d)
    parts                 = d.split(".")
    feats["labels"]       = len([p for p in parts if p])
    feats["tld_len"]      = len(parts[-1]) if parts else 0
    return feats


DNS_NUM_COLS   = ["num_unique_ips", "has_ipv6", "num_countries", "num_asns"]
WHOIS_NUM_COLS = ["age_days", "days_to_expiry", "created_isnull", "expires_isnull", "has_error"]


def cat_row(r):
    d = {}
    asn = r.get("sample_asn")
    isp = r.get("sample_isp")
    cc  = r.get("sample_country")
    reg = r.get("registrar")
    st  = r.get("status")

    def _push(key, val):
        if val is None:
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


def build_features(df: pd.DataFrame):
    domains = df["registered_domain"].fillna("")

    # char-level n-gram hashing
    char_vect = HashingVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        n_features=4096,
        lowercase=True,
        alternate_sign=False,
    )
    X_char = char_vect.transform(domains.tolist())

    # simple lexical stats
    string_feats = [
        "len", "digits", "hyphens", "dots",
        "digit_ratio", "hyphen_ratio",
        "entropy", "xn_punycode", "labels", "tld_len",
    ]
    S = np.vstack([
        [basic_string_feats(d).get(k, 0) for k in string_feats]
        for d in domains.tolist()
    ])
    X_string = csr_matrix(S)

    # DNS numeric enrichment
    for c in DNS_NUM_COLS:
        if c not in df.columns:
            df[c] = 0
    df[DNS_NUM_COLS] = df[DNS_NUM_COLS].fillna(0)
    X_dns_num = csr_matrix(df[DNS_NUM_COLS].to_numpy(dtype=float))

    # categorical features (ASN, registrar, status...)
    cats = [cat_row(r) for r in df.to_dict(orient="records")]
    hasher = FeatureHasher(
        n_features=256,
        input_type="dict",
        alternate_sign=False,
    )
    X_cat = hasher.transform(cats)

    # WHOIS numeric enrichment
    for c in WHOIS_NUM_COLS:
        if c not in df.columns:
            df[c] = 0
    df[WHOIS_NUM_COLS] = df[WHOIS_NUM_COLS].fillna(0)
    X_whois_num = csr_matrix(df[WHOIS_NUM_COLS].to_numpy(dtype=float))

    X_full = hstack([X_char, X_string, X_dns_num, X_cat, X_whois_num]).tocsr()
    return X_full


# --- model loading ---

def load_models():
    meta = None
    if os.path.exists(META_LATEST):
        try:
            with open(META_LATEST, "r") as f:
                meta = json.load(f)
            print("[info] loaded model meta:", META_LATEST)
            print(
                "[info] meta summary: created_utc=",
                meta.get("created_utc"),
                "| feature_shapes=",
                meta.get("feature_shapes"),
            )
        except Exception as e:
            print("[warn] failed to parse meta:", e)

    if not (joblib and os.path.exists(LOGREG_LATEST)):
        raise SystemExit(f"[error] missing LogisticRegression model at {LOGREG_LATEST}")
    logreg = joblib.load(LOGREG_LATEST)
    print("[info] loaded LogisticRegression full model from:", LOGREG_LATEST)

    booster = None
    if lgb and os.path.exists(LGBM_LATEST):
        booster = lgb.Booster(model_file=LGBM_LATEST)
        print("[info] loaded LightGBM booster from:", LGBM_LATEST)

    return logreg, booster, meta


def model_version_tag(primary_name: str, meta: dict | None) -> str:
    """e.g. "lgbm_full@20260708T035042Z" -- created_utc from meta.json,
    ISO-8601-basic timestamp suffix. Fits CtObservation.model_used's
    String(32) column (27 chars for the longest primary_name, "logreg_full").
    Falls back to the bare primary_name (the old behavior) if meta.json is
    missing/malformed, so every CtObservation row can be told apart by
    which specific training run scored it -- before this, model_used was
    just the literal string "lgbm_full" for every row ever scored,
    indistinguishable across retrains."""
    if meta and meta.get("created_utc"):
        try:
            ts = datetime.fromisoformat(meta["created_utc"].replace("Z", "+00:00"))
            return f"{primary_name}@{ts.strftime('%Y%m%dT%H%M%SZ')}"
        except (ValueError, TypeError):
            pass
    return primary_name


def choose_threshold(meta, primary_name=None):
    """
    Pick the risk-classification cutoff dynamically from measured model
    performance in the training metadata, falling back to a conservative
    hardcoded default when it isn't available (e.g. older meta.json files
    written before per-model thresholds were recorded, or a degenerate
    ROC curve with no metrics at all).

    Looks up meta["metrics"][primary_name]["threshold_at_1pct_fpr"] first
    (the current, correctly-nested location matching how train_model.py's
    evaluate_model() saves it). Falls back to legacy/top-level key names
    for forward compatibility, then to 0.90 if nothing is found.
    """
    if meta:
        metrics = meta.get("metrics")
        if isinstance(metrics, dict) and primary_name:
            model_metrics = metrics.get(primary_name)
            if isinstance(model_metrics, dict):
                for k in ("threshold_at_1pct_fpr", "fpr_1pct_threshold"):
                    v = model_metrics.get(k)
                    if v is not None:
                        try:
                            return float(v)
                        except Exception:
                            pass
        # legacy fallback: some older/alternate meta formats may have
        # stored the threshold at the top level instead of nested under
        # metrics[<model_name>].
        for k in ("threshold_at_1pct_fpr", "fpr_1pct_threshold"):
            v = meta.get(k)
            if v is not None:
                try:
                    return float(v)
                except Exception:
                    pass
    # conservative default
    return 0.90


# --- MISP silver loader ---

def load_recent_misp_domains(days_back: int = 30) -> set:
    """
    Load registered domains from MISP silver (misp_osint) for the last N days.
    Returns a set of normalized registered_domain strings.
    """
    root = MISP_SILVER_ROOT
    if not os.path.exists(root):
        print(f"[warn] MISP silver root not found at {root}")
        return set()

    cutoff_date = (datetime.utcnow() - timedelta(days=days_back)).date()
    # expect: <root>/ingest_date=YYYY-MM-DD/*.parquet
    pattern = os.path.join(root, "ingest_date=*/*.parquet")
    paths = sorted(glob.glob(pattern))
    if not paths:
        print(f"[warn] no MISP silver parquet files under {root}")
        return set()

    regs = []
    for p in paths:
        try:
            parent = os.path.basename(os.path.dirname(p))
            ds_str = parent.split("=", 1)[-1]
            ds = datetime.strptime(ds_str, "%Y-%m-%d").date()
        except Exception:
            continue

        if ds < cutoff_date:
            continue

        try:
            df_misp = pd.read_parquet(p)
        except Exception as e:
            print(f"[warn] failed to read MISP silver {p}: {e}")
            continue

        # Try multiple possible domain columns
        col = None
        for cand in ("registered_domain", "domain", "host", "value"):
            if cand in df_misp.columns:
                col = cand
                break
        if not col:
            continue

        doms = (
            df_misp[col]
            .astype(str)
            .str.lower()
            .str.strip()
            .str.rstrip(".")
        )
        regs.extend([reg_domain(d) for d in doms if d])

    misp_set = {r for r in regs if r}
    print(
        f"[info] loaded {len(misp_set)} unique registered domains from "
        f"MISP silver (last {days_back} days) from {root}"
    )
    return misp_set


# ---------- main ----------

def main():
    # 1) Load CT enriched
    enriched_path = resolve_enriched_path()
    df = pd.read_parquet(enriched_path)

    # ensure registered_domain present
    if (
        "registered_domain" not in df.columns
        or not df["registered_domain"].astype(str).str.strip().any()
    ):
        src = "domain_sample" if "domain_sample" in df.columns else "domain"
        df["registered_domain"] = df[src].map(reg_domain)

    # 2) Build feature matrix
    X_full = build_features(df)
    print("[info] CT feature matrix shapes: X_full=", X_full.shape)

    # 3) Load models
    logreg, booster, meta = load_models()

    # 4) Score with LR + optional LGBM
    print("[info] scoring with Logistic Regression (full feature set)")
    p_lr = logreg.predict_proba(X_full)[:, 1]

    p_lgb = None
    if booster is not None:
        print("[info] scoring with LightGBM boosted model")
        p_lgb = booster.predict(X_full)
        p_lgb = np.asarray(p_lgb, dtype=float)

    primary_name = "lgbm_full" if p_lgb is not None else "logreg_full"
    probs = p_lgb if p_lgb is not None else p_lr

    out = df.copy()
    out["risk_score_logreg"] = p_lr
    if p_lgb is not None:
        out["risk_score_lgbm"] = p_lgb
    out["risk_score"] = probs

    thr = choose_threshold(meta, primary_name=primary_name)
    print(f"[info] using threshold={thr:.3f} for risk_label (model={primary_name})")
    out["risk_label"] = (out["risk_score"] >= thr).astype(int)
    out["model_used"] = model_version_tag(primary_name, meta)

    # 5) Fuse with MISP silver
    misp_set = load_recent_misp_domains(days_back=30)
    if misp_set:
        out["ti_misp_hit"] = out["registered_domain"].isin(misp_set).astype(int)
        n_hits = int(out["ti_misp_hit"].sum())
        print(
            f"[info] MISP overlap: {n_hits} / {len(out)} domains "
            f"({n_hits / len(out):.3%}) present in MISP OSINT"
        )
    else:
        out["ti_misp_hit"] = 0
        print(
            f"[info] MISP overlap: 0 / {len(out)} domains "
            f"(no CT domains matched recent MISP OSINT; realistic but not guaranteed)"
        )

    # Final decision = ML OR MISP
    out["risk_label_final"] = (
        (out["risk_label"] == 1) | (out["ti_misp_hit"] == 1)
    ).astype(int)

    def _reason(row):
        if row["ti_misp_hit"]:
            if row["risk_label"]:
                return "MISP_AND_ML"
            return "MISP_IOC"
        if row["risk_label"]:
            return "ML_SCORE"
        return "BENIGN_BASELINE"

    out["decision_reason"] = out.apply(_reason, axis=1)

    # 6) Persist scored CT
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = os.path.join(CT_SCORED_DIR, f"ct_scored_{ts}.parquet")
    out.to_parquet(out_path, index=False)
    print(f"[info] wrote scored CT data: {len(out)} rows → {out_path}")

    # 7) Debug snippet
    cols = [
        c
        for c in [
            "registered_domain",
            "domain_sample",
            "event_ts",
            "source",
            "num_unique_ips",
            "num_countries",
            "sample_country",
            "sample_asn",
            "risk_score_logreg",
            "risk_score_lgbm",
            "risk_score",
            "risk_label",
            "risk_label_final",
            "ti_misp_hit",
            "decision_reason",
        ]
        if c in out.columns
    ]

    print("\n[info] top 15 high-risk domains (by primary risk_score):")
    print(
        out.sort_values("risk_score", ascending=False)
        .head(15)[cols]
        .to_string(index=False)
    )


if __name__ == "__main__":
    main()
