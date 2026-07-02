#!/usr/bin/env python
# ml/core/eval_provenance.py
#
# Tests the model's headline AUC for source-provenance leakage: the training
# labels are constructed as label=0 iff source=="benign_seed" else label=1
# (see ml/core/train_model.py). That's a standard, practical way to build a
# security-ML dataset, but it also means "malicious" and "which feed reported
# it" are perfectly confounded by construction. A model can score well by
# genuinely learning malicious-domain characteristics, OR by partially
# learning to distinguish "urlhaus-style" / "openphish-style" / "benign_seed
# collection artifacts" from each other -- and a single blended AUC cannot
# tell you which. This script runs two concrete, honest checks instead of
# assuming either answer:
#
#   1. LEAVE-ONE-SOURCE-OUT (LOSO) GENERALIZATION: for each malicious source,
#      train with that source held out entirely (never seen during training)
#      and test ONLY on it. If AUC holds up on a malicious-domain style the
#      model never trained on, that's real evidence of generalization, not
#      memorized feed quirks. If it craters, that's the honest finding to
#      report -- not something to hide behind a single blended number.
#
#   2. INFRA-ONLY SHORTCUT BASELINE: train using ONLY the hashed categorical
#      infrastructure features (ASN/ISP/country/registrar/status) -- no
#      lexical/char-ngram features at all. If this alone scores suspiciously
#      close to the full model, a meaningful share of the full model's signal
#      is coming from infrastructure/collection artifacts rather than the
#      domain's own textual/behavioral characteristics.
#
# Uses LogisticRegression only (not LightGBM) to keep wall-clock time
# reasonable across multiple folds -- this is a diagnostic tool, not a
# replacement for ml/core/train_model.py's production training run.
#
# Output: ml/reports/provenance_eval_<ts>.json + a human-readable report on
# stdout. Does not touch or overwrite anything train_model.py produces.

import argparse
import glob
import json
import math
import os
from collections import Counter
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import tldextract
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import FeatureHasher, HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, average_precision_score
from sklearn.model_selection import train_test_split

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.abspath(os.path.join(THIS_DIR, ".."))
REPO_ROOT = os.path.abspath(os.path.join(ML_DIR, ".."))

SILVER_LABELS_DIR = os.path.join(REPO_ROOT, "silver", "labels_union")
DNS_GEO_DIR = os.path.join(REPO_ROOT, "lookups", "dns_geo")
WHOIS_DIR = os.path.join(REPO_ROOT, "lookups", "whois")
REPORTS_DIR = os.path.join(ML_DIR, "reports")

N_CHAR_FEATURES = 4096
N_CAT_FEATURES = 256
STRING_FEATS = ["len", "digits", "hyphens", "dots", "digit_ratio", "hyphen_ratio",
                "entropy", "xn_punycode", "labels", "tld_len"]
DNS_NUM_COLS = ["num_unique_ips", "has_ipv6", "num_countries", "num_asns"]
WHOIS_NUM_COLS = ["age_days", "days_to_expiry", "created_isnull", "expires_isnull", "has_error"]


# ---------- loading (mirrors ml/core/train_model.py's loading logic;
# duplicated rather than imported because train_model.py is a flat script
# that runs its full training pipeline as a side effect of import, not a
# library -- importing it here would trigger an entire unwanted training run) ----------

def reg_domain(domain) -> str:
    if not isinstance(domain, str) or not domain:
        return ""
    ext = tldextract.extract(domain)
    reg = getattr(ext, "registered_domain", None) or getattr(
        ext, "top_domain_under_public_suffix", None) or ""
    return reg.lower().strip()


def _df_from_parquets(pattern):
    files = sorted(glob.glob(pattern))
    dfs = []
    for f in files:
        try:
            dfs.append(pd.read_parquet(f))
        except Exception as e:
            print(f"[warn] failed {f}: {e}")
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


def load_labeled_dataset():
    """Returns Xdf: one row per registered_domain with label + source +
    merged DNS/WHOIS features -- the same population train_model.py trains
    on (labels + DNS-geo + WHOIS, merged on registered_domain)."""
    labels = _df_from_parquets(os.path.join(SILVER_LABELS_DIR, "ingest_date=*/labels_union.parquet"))
    if labels.empty:
        return pd.DataFrame()
    labels["registered_domain"] = labels["domain"].map(reg_domain)
    labels = labels[labels["registered_domain"].astype(bool)].copy()
    labels["label"] = np.where(labels["source"] == "benign_seed", 0, 1)
    labels = labels[labels["label"].isin([0, 1])].copy()
    labels["label"] = labels["label"].astype(int)
    # keep source for the LOSO split; dedupe keeping first source seen per domain
    labels = labels.drop_duplicates("registered_domain")[["registered_domain", "label", "source"]]

    dns = _df_from_parquets(os.path.join(DNS_GEO_DIR, "ingest_date=*/dns_geo.parquet"))
    if not dns.empty:
        dns = dns.rename(columns={"puny_domain": "registered_domain"})
        dns["registered_domain"] = dns["registered_domain"].astype(str).str.lower().str.strip()
        agg = dns.groupby("registered_domain").agg(
            num_unique_ips=("ip", "nunique"),
            has_ipv6=("family", lambda x: int((pd.Series(x) == 6).any())),
            num_countries=("country", "nunique"),
            num_asns=("asn", "nunique"),
            sample_asn=("asn", "first"),
            sample_isp=("isp", "first"),
            sample_country=("country", "first"),
        ).reset_index()
    else:
        agg = pd.DataFrame(columns=["registered_domain"])

    whois = _df_from_parquets(os.path.join(WHOIS_DIR, "ingest_date=*/whois.parquet"))
    if not whois.empty:
        whois = whois.copy()
        whois["registered_domain"] = whois["domain"].astype(str).str.lower().str.strip()
        whois = whois[["registered_domain", "registrar", "status", "created", "expires", "error"]].copy()
        now = datetime.now(timezone.utc)
        whois["created"] = pd.to_datetime(whois["created"], utc=True, errors="coerce")
        whois["expires"] = pd.to_datetime(whois["expires"], utc=True, errors="coerce")
        whois["age_days"] = (now - whois["created"]).dt.total_seconds() / 86400.0
        whois["days_to_expiry"] = (whois["expires"] - now).dt.total_seconds() / 86400.0
        whois["created_isnull"] = whois["created"].isna().astype(int)
        whois["expires_isnull"] = whois["expires"].isna().astype(int)
        whois["has_error"] = whois["error"].notna().astype(int)
        whois = whois.drop(columns=["created", "expires", "error"])
    else:
        whois = pd.DataFrame(columns=["registered_domain"])

    Xdf = labels.merge(agg, on="registered_domain", how="left").merge(whois, on="registered_domain", how="left")
    return Xdf


# ---------- feature building (two variants: full, infra-only) ----------

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _basic_string_feats(d: str) -> dict:
    d = d or ""
    feats = {"len": len(d), "digits": sum(ch.isdigit() for ch in d), "hyphens": d.count("-"),
            "dots": d.count("."), "entropy": _shannon_entropy(d), "xn_punycode": int("xn--" in d)}
    feats["digit_ratio"] = feats["digits"] / (feats["len"] + 1e-6)
    feats["hyphen_ratio"] = feats["hyphens"] / (feats["len"] + 1e-6)
    parts = d.split(".")
    feats["labels"] = len([p for p in parts if p])
    feats["tld_len"] = len(parts[-1]) if parts else 0
    return feats


def _cat_row(r: dict) -> dict:
    d = {}
    for prefix, key in (("asn=", "sample_asn"), ("isp=", "sample_isp"), ("cc=", "sample_country"),
                       ("reg=", "registrar"), ("status=", "status")):
        v = r.get(key)
        if v is None or (isinstance(v, float) and math.isnan(v)):
            continue
        s = str(v).strip()
        if s and s.lower() != "nan":
            d[prefix + s] = 1
    return d


def build_full_features(Xdf: pd.DataFrame):
    """Full feature set: char n-grams + lexical + DNS numeric + hashed
    categoricals (infra) + WHOIS numeric -- same schema as train_model.py."""
    domains = Xdf["registered_domain"].fillna("")
    char_vect = HashingVectorizer(analyzer="char", ngram_range=(3, 5),
                                  n_features=N_CHAR_FEATURES, lowercase=True, alternate_sign=False)
    X_char = char_vect.transform(domains.tolist())
    S = np.vstack([[_basic_string_feats(d).get(k, 0) for k in STRING_FEATS] for d in domains.tolist()])
    X_string = csr_matrix(S)
    for c in DNS_NUM_COLS:
        if c not in Xdf.columns:
            Xdf[c] = 0
    X_dns = csr_matrix(Xdf[DNS_NUM_COLS].fillna(0).to_numpy(dtype=float))
    cats = [_cat_row(r) for r in Xdf.to_dict(orient="records")]
    X_cat = FeatureHasher(n_features=N_CAT_FEATURES, input_type="dict", alternate_sign=False).transform(cats)
    for c in WHOIS_NUM_COLS:
        if c not in Xdf.columns:
            Xdf[c] = 0
    X_whois = csr_matrix(Xdf[WHOIS_NUM_COLS].fillna(0).to_numpy(dtype=float))
    return hstack([X_char, X_string, X_dns, X_cat, X_whois]).tocsr()


def build_infra_only_features(Xdf: pd.DataFrame):
    """Infra-only feature set: hashed categoricals (ASN/ISP/country/registrar/
    status) + DNS/WHOIS numeric -- deliberately EXCLUDES char n-grams and
    lexical string features, so the model has no access to the domain's own
    textual characteristics. Tests how much signal is available purely from
    infrastructure/collection-artifact features."""
    for c in DNS_NUM_COLS:
        if c not in Xdf.columns:
            Xdf[c] = 0
    X_dns = csr_matrix(Xdf[DNS_NUM_COLS].fillna(0).to_numpy(dtype=float))
    cats = [_cat_row(r) for r in Xdf.to_dict(orient="records")]
    X_cat = FeatureHasher(n_features=N_CAT_FEATURES, input_type="dict", alternate_sign=False).transform(cats)
    for c in WHOIS_NUM_COLS:
        if c not in Xdf.columns:
            Xdf[c] = 0
    X_whois = csr_matrix(Xdf[WHOIS_NUM_COLS].fillna(0).to_numpy(dtype=float))
    return hstack([X_dns, X_cat, X_whois]).tocsr()


# ---------- evaluation ----------

def _fit_eval(Xtr, ytr, Xte, yte) -> dict:
    if len(np.unique(ytr)) < 2 or len(np.unique(yte)) < 2:
        return {"error": "degenerate split -- fewer than 2 classes present", "n_train": int(len(ytr)), "n_test": int(len(yte))}
    clf = LogisticRegression(solver="liblinear", class_weight="balanced", max_iter=200)
    clf.fit(Xtr, ytr)
    p = clf.predict_proba(Xte)[:, 1]
    return {
        "n_train": int(len(ytr)), "n_test": int(len(yte)),
        "n_test_pos": int((yte == 1).sum()), "n_test_neg": int((yte == 0).sum()),
        "roc_auc": round(float(roc_auc_score(yte, p)), 4),
        "pr_auc": round(float(average_precision_score(yte, p)), 4),
    }


def leave_one_source_out(Xdf: pd.DataFrame, malicious_sources: list, random_state: int = 42) -> dict:
    """For each malicious source, train with it held out entirely (train on
    benign_seed + the OTHER malicious source(s)), test ONLY on a held-out
    split of (that source + a matching benign_seed sample). random_state
    fixed for reproducibility across runs."""
    results = {}
    benign = Xdf[Xdf["label"] == 0]
    if len(benign) < 4:
        return {"error": f"too few benign_seed rows ({len(benign)}) to split for LOSO"}
    benign_train, benign_test = train_test_split(benign, test_size=0.5, random_state=random_state)

    for held_out_source in malicious_sources:
        train_mal = Xdf[(Xdf["label"] == 1) & (Xdf["source"] != held_out_source)]
        test_mal = Xdf[(Xdf["label"] == 1) & (Xdf["source"] == held_out_source)]
        if train_mal.empty or test_mal.empty:
            results[held_out_source] = {"error": f"no rows for source={held_out_source!r} on one side of the split"}
            continue

        train_df = pd.concat([benign_train, train_mal], ignore_index=True)
        test_df = pd.concat([benign_test, test_mal], ignore_index=True)
        combined = pd.concat([train_df, test_df], ignore_index=True)
        X_full = build_full_features(combined)
        n_train = len(train_df)
        Xtr, Xte = X_full[:n_train], X_full[n_train:]
        ytr, yte = train_df["label"].to_numpy(), test_df["label"].to_numpy()

        r = _fit_eval(Xtr, ytr, Xte, yte)
        r["held_out_source"] = held_out_source
        r["train_sources"] = sorted(set(train_mal["source"]))
        results[held_out_source] = r
    return results


def infra_only_shortcut_check(Xdf: pd.DataFrame, random_state: int = 42) -> dict:
    """Full-feature vs infra-only-feature AUC on the same random split, to
    gauge how much of the full model's signal could come from infrastructure/
    collection artifacts rather than the domain's own text."""
    y = Xdf["label"].to_numpy()
    if len(np.unique(y)) < 2:
        return {"error": "fewer than 2 classes present in the dataset"}

    idx_train, idx_test = train_test_split(
        np.arange(len(Xdf)), test_size=0.25, stratify=y, random_state=random_state)

    X_full = build_full_features(Xdf.copy())
    full_result = _fit_eval(X_full[idx_train], y[idx_train], X_full[idx_test], y[idx_test])

    X_infra = build_infra_only_features(Xdf.copy())
    infra_result = _fit_eval(X_infra[idx_train], y[idx_train], X_infra[idx_test], y[idx_test])

    gap = None
    if "roc_auc" in full_result and "roc_auc" in infra_result:
        gap = round(full_result["roc_auc"] - infra_result["roc_auc"], 4)

    return {
        "full_features": full_result,
        "infra_only_features": infra_result,
        "full_minus_infra_auc_gap": gap,
        "interpretation": (
            "gap is None -- one of the fits failed, see errors above" if gap is None else
            "SMALL gap: infra-only features alone nearly match the full model -- a meaningful "
            "share of the signal may be infrastructure/collection artifacts, not the domain's "
            "own textual/behavioral characteristics. Investigate before trusting the headline AUC."
            if gap < 0.05 else
            "MODERATE gap: infra-only features carry real signal but the full model is meaningfully "
            "better -- lexical/behavioral features are contributing, though infra-driven separability "
            "still exists and is worth keeping an eye on."
            if gap < 0.15 else
            "LARGE gap: infra-only features are a weak baseline compared to the full model -- the "
            "full model's signal is not primarily explained by infrastructure shortcuts."
        ),
    }


def _print_report(loso: dict, shortcut: dict):
    print("=" * 72)
    print("MODEL PROVENANCE / LEAKAGE DIAGNOSTIC")
    print("=" * 72)
    print("\n--- Leave-one-source-out generalization ---")
    for source, r in loso.items():
        if "error" in r:
            print(f"  [{source}] SKIPPED: {r['error']}")
            continue
        print(f"  Held out '{source}' entirely from training (trained only on {r['train_sources']} + benign_seed):")
        print(f"    test set: {r['n_test']} rows ({r['n_test_pos']} pos / {r['n_test_neg']} neg, all pos from '{source}')")
        print(f"    ROC-AUC={r['roc_auc']}  PR-AUC={r['pr_auc']}")
    print("\n--- Infra-only shortcut baseline ---")
    if "error" in shortcut:
        print(f"  SKIPPED: {shortcut['error']}")
    else:
        f, i = shortcut["full_features"], shortcut["infra_only_features"]
        print(f"  Full features:       ROC-AUC={f.get('roc_auc')}  PR-AUC={f.get('pr_auc')}  (n_test={f.get('n_test')})")
        print(f"  Infra-only features: ROC-AUC={i.get('roc_auc')}  PR-AUC={i.get('pr_auc')}  (n_test={i.get('n_test')})")
        print(f"  Gap (full - infra):  {shortcut['full_minus_infra_auc_gap']}")
        print(f"  Interpretation: {shortcut['interpretation']}")
    print("=" * 72)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args(argv)

    print("[info] loading labeled dataset (labels + DNS + WHOIS)...")
    Xdf = load_labeled_dataset()
    print(f"[info] {len(Xdf)} rows, sources: {dict(Xdf['source'].value_counts())}" if not Xdf.empty else "[warn] no data")
    if Xdf.empty:
        print("[error] no labeled data available; cannot run provenance diagnostics.")
        return None

    malicious_sources = sorted(Xdf[Xdf["label"] == 1]["source"].unique())
    print(f"[info] malicious sources found: {malicious_sources}")

    print("\n[info] running leave-one-source-out generalization test...")
    loso = leave_one_source_out(Xdf, malicious_sources)

    print("[info] running infra-only shortcut baseline...")
    shortcut = infra_only_shortcut_check(Xdf)

    _print_report(loso, shortcut)

    result = {
        "computed_utc": datetime.now(timezone.utc).isoformat(),
        "n_rows": int(len(Xdf)),
        "source_counts": {k: int(v) for k, v in Xdf["source"].value_counts().items()},
        "leave_one_source_out": loso,
        "infra_only_shortcut_check": shortcut,
    }

    if not args.no_write:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = os.path.join(REPORTS_DIR, f"provenance_eval_{ts}.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        latest_path = os.path.join(REPORTS_DIR, "provenance_eval_latest.json")
        with open(latest_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n[info] wrote {out_path}")
        print(f"[info] wrote {latest_path}")

    return result


if __name__ == "__main__":
    main()
