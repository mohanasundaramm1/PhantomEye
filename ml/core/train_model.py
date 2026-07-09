# ml/core/train_model.py
#
# Dynamic phishing vs benign baseline, using all available labels / lookups.
# Run from repo root:
#   export PYTHONPATH=$PYTHONPATH:.
#   python ml/core/train_model.py
#
# Outputs:
#   - ml/models/registry/ct_risk_logreg_full_<TS>.joblib
#   - ml/models/registry/ct_risk_lgbm_full_<TS>.txt   (if LightGBM available)
#   - ml/models/registry/ct_risk_meta_<TS>.json
#   - "latest" copies:
#       ct_risk_logreg_full_latest.joblib
#       ct_risk_lgbm_full_latest.txt (if exists)
#       ct_risk_meta_latest.json
#

import os, glob, math, json, shutil
from datetime import datetime, timezone
from collections import Counter

import numpy as np
import pandas as pd
import tldextract

from sklearn.feature_extraction.text import HashingVectorizer, FeatureHasher
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from scipy.sparse import csr_matrix, hstack

# Optional: save models
try:
    import joblib
except ImportError:
    joblib = None

try:
    import lightgbm as lgb
except ImportError:
    lgb = None

NOW_UTC = datetime.now(timezone.utc)

# ---------------- paths ----------------

THIS_DIR = os.path.dirname(__file__)                    # .../ml/core
ML_DIR = os.path.abspath(os.path.join(THIS_DIR, ".."))  # .../ml
REPO_ROOT = os.path.abspath(os.path.join(ML_DIR, "..")) # .../threat-intel

SILVER_LABELS_DIR = os.path.join(REPO_ROOT, "silver", "labels_union")
DNS_GEO_DIR       = os.path.join(REPO_ROOT, "lookups", "dns_geo")
WHOIS_DIR         = os.path.join(REPO_ROOT, "lookups", "whois")

MODEL_DIR = os.path.join(ML_DIR, "models", "registry")
TMP_DIR   = os.path.join(ML_DIR, "tmp")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)

# ---------------- helpers ----------------

def reg_domain(domain: str) -> str:
    """Normalize to registered domain."""
    if not isinstance(domain, str) or not domain:
        return ""
    ext = tldextract.extract(domain)
    # keep the old behaviour for consistency with week5
    reg = getattr(ext, "registered_domain", None) or getattr(
        ext, "top_domain_under_public_suffix", None
    ) or ""
    return reg.lower().strip()


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


def df_from_parquets(patterns):
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
    dfs = []
    for f in sorted(files):
        try:
            dfs.append(pd.read_parquet(f))
        except Exception as e:
            print(f"[warn] failed {f}: {e}")
    if not dfs:
        return pd.DataFrame()
    return pd.concat(dfs, ignore_index=True)


# ---------------- load labels (dynamic) ----------------

# ---------------- load labels (dynamic + feedback) ----------------

def load_all_labels():
    # 1) Main labels
    pattern_main = os.path.join(SILVER_LABELS_DIR, "ingest_date=*/labels_union.parquet")
    print("[info] loading labels from pattern:", pattern_main)
    labels = df_from_parquets([pattern_main])

    if not labels.empty:
        # Label: benign=0 if source==benign_seed else 1 (same convention as week5)
        # The label column may exist but contain string values (e.g., "malware_download")
        # We need to convert to binary: benign=0, phishing/malware=1. This
        # derivation is only valid for THIS source (silver/labels_union has
        # exactly two source families: benign_seed and openphish/urlhaus) --
        # it must run before concatenating with feedback below, not after.
        labels["label"] = np.where(labels["source"] == "benign_seed", 0, 1)

    # 2) Active Learning feedback
    FEEDBACK_DIR = os.path.join(REPO_ROOT, "ml", "data", "feedback")
    pattern_fb = os.path.join(FEEDBACK_DIR, "feedback_labels_*.parquet")
    print("[info] loading feedback from pattern:", pattern_fb)
    fb = df_from_parquets([pattern_fb])

    if not fb.empty:
        print(f"[info] found {len(fb)} active learning feedback rows")
        # Feedback files carry their own trustworthy binary label (0/1) --
        # e.g. ml/core/seed_benign_feedback.py's benign_tranco (label=0) or
        # product/export_analyst_labels.py's analyst_disposition (label=0
        # or 1 per verdict). Found live: applying the source=="benign_seed"
        # heuristic to the CONCATENATED frame (the previous ordering) forced
        # every non-benign_seed feedback row to label=1 regardless of its
        # real label -- silently flipping ~16k confirmed-benign Tranco
        # domains (and every analyst-suppressed false positive) into
        # "malicious" training signal, which is what a broken retrain
        # (ROC-AUC 0.43, benign-holdout FPR 1.0) surfaced. Feedback's label
        # is trusted as-is; only dtype is normalized here.
        fb["label"] = fb["label"].astype(int)
        labels = pd.concat([labels, fb], ignore_index=True)

    if labels.empty:
        # Fallback for initial run if no data exists yet
        print("[warn] No labels found. Returning empty DataFrame.")
        return pd.DataFrame(columns=["domain", "registered_domain", "label", "source", "ingest_date"])

    print("[info] total labels rows:", len(labels))

    # Normalise
    labels["registered_domain"] = labels["domain"].map(reg_domain)
    labels = labels[labels["registered_domain"].astype(bool)].copy()

    # only benign + phishing
    labels = labels[labels["label"].isin([0, 1])].copy()
    labels["label"] = labels["label"].astype(int)

    # ensure ingest_date is string for grouping / temporal split.
    #
    # silver/labels_union's own parquet files carry NO ingest_date column at
    # all (it only lives in the Hive-style partition folder name, which
    # df_from_parquets doesn't parse out) -- so before any feedback existed,
    # "ingest_date" not in labels.columns was always True and this uniformly
    # backfilled every row to NOW_UTC. Once ml/data/feedback/*.parquet files
    # exist (they DO carry a real ingest_date), pd.concat gives the merged
    # frame an ingest_date column sourced from feedback rows only -- the
    # column now "exists" so the branch below is skipped, and the base
    # labels' real gaps become NaN, then get stringified to the literal text
    # "nan" by .astype(str). "nan" sorts lexicographically AFTER every real
    # "YYYY-MM-DD" string, so the temporal-split cutoff (sorted(...)[-1])
    # locks onto exactly the base-vs-feedback boundary instead of a genuine
    # recent-vs-old date boundary -- silently splitting almost the entire
    # base label set into "test" and almost only feedback rows into "train"
    # (found live: train ended up with 1 positive example total). Filling
    # missing values (whether or not the column pre-existed) restores the
    # original, intended fallback for every row that lacks a real date.
    if "ingest_date" not in labels.columns:
        labels["ingest_date"] = NOW_UTC.strftime("%Y-%m-%d")
    else:
        labels["ingest_date"] = labels["ingest_date"].fillna(NOW_UTC.strftime("%Y-%m-%d"))
    labels["ingest_date"] = labels["ingest_date"].astype(str)

    print(
        "[info] labels after filtering:",
        len(labels),
        "positives=",
        int((labels["label"] == 1).sum()),
        "negatives=",
        int((labels["label"] == 0).sum()),
    )
    return labels


labels = load_all_labels()

# pick latest ingest_date per registered_domain (for temporal split later)
if not labels.empty:
    last_seen = (
        labels.groupby("registered_domain")["ingest_date"]
        .max()
        .reset_index()
        .rename(columns={"ingest_date": "last_ingest_date"})
    )
else:
    last_seen = pd.DataFrame(columns=["registered_domain", "last_ingest_date"])

# ---------------- load DNS (all days) ----------------

def load_all_dns():
    pattern = os.path.join(DNS_GEO_DIR, "ingest_date=*/dns_geo.parquet")
    print("[info] loading DNS-Geo from pattern:", pattern)
    dns = df_from_parquets([pattern])
    if dns.empty:
        print("[warn] no DNS-Geo data loaded.")
        return dns
    dns = dns.rename(columns={"puny_domain": "registered_domain"})
    dns["registered_domain"] = (
        dns["registered_domain"].astype(str).str.lower().str.strip()
    )
    return dns


dns = load_all_dns()

# reduce DNS to per-domain aggregates
if not dns.empty:
    agg = (
        dns.groupby("registered_domain")
        .agg(
            num_unique_ips=("ip", "nunique"),
            has_ipv6=("family", lambda x: int((pd.Series(x) == 6).any())),
            num_countries=("country", "nunique"),
            num_asns=("asn", "nunique"),
            sample_asn=("asn", "first"),
            sample_isp=("isp", "first"),
            sample_country=("country", "first"),
        )
        .reset_index()
    )
else:
    agg = pd.DataFrame(columns=["registered_domain"])
print("[info] DNS agg rows:", len(agg))

# ---------------- load WHOIS (all days) ----------------

def load_all_whois():
    pattern = os.path.join(WHOIS_DIR, "ingest_date=*/whois.parquet")
    print("[info] loading WHOIS from pattern:", pattern)
    w = df_from_parquets([pattern])
    if w.empty:
        print("[warn] no WHOIS data loaded.")
        return w
    w = w.copy()
    w["registered_domain"] = w["domain"].astype(str).str.lower().str.strip()
    return w


whois = load_all_whois()

if not whois.empty:
    wcols = ["registered_domain", "registrar", "status", "created", "expires", "error"]
    whois = whois[wcols].copy()
    whois["created"] = pd.to_datetime(
        whois["created"], utc=True, errors="coerce"
    )
    whois["expires"] = pd.to_datetime(
        whois["expires"], utc=True, errors="coerce"
    )
    whois["age_days"] = (
        NOW_UTC - whois["created"]
    ).dt.total_seconds() / 86400.0
    whois["days_to_expiry"] = (
        whois["expires"] - NOW_UTC
    ).dt.total_seconds() / 86400.0
    whois["created_isnull"] = whois["created"].isna().astype(int)
    whois["expires_isnull"] = whois["expires"].isna().astype(int)
    whois["has_error"] = whois["error"].notna().astype(int)
    whois = whois.drop(columns=["created", "expires", "error"])
else:
    whois = pd.DataFrame(columns=["registered_domain"])
print("[info] WHOIS rows after featurization:", len(whois))

# ---------------- merge to one row per registered_domain ----------------

base = (
    labels[["registered_domain", "label"]]
    .drop_duplicates("registered_domain")
    .merge(last_seen, on="registered_domain", how="left")
)

Xdf = (
    base
    .merge(agg, on="registered_domain", how="left")
    .merge(whois, on="registered_domain", how="left")
)

print(
    "[info] merged Xdf rows:",
    len(Xdf),
    "positives=",
    int((Xdf["label"] == 1).sum()),
    "negatives=",
    int((Xdf["label"] == 0).sum()),
)

print("\n[info] sample feature rows (Xdf.head()):")
cols_to_show = [
    "registered_domain",
    "label",
    "last_ingest_date",
    "num_unique_ips",
    "num_countries",
    "sample_country",
    "sample_asn",
    "age_days",
    "days_to_expiry",
]
print(Xdf[cols_to_show].head(10))

# Save frozen Xdf for debugging / reuse
stamp = NOW_UTC.strftime("%Y%m%dT%H%M%SZ")
xdf_path = os.path.join(TMP_DIR, f"latest_Xdf_{stamp}.parquet")
Xdf.to_parquet(xdf_path, index=False)
print(f"[info] wrote Xdf to {xdf_path}")

# ---------------- build feature matrices ----------------

domains = Xdf["registered_domain"].fillna("")

# 1) string hashed (char n-grams)
char_vect = HashingVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    n_features=4096,
    lowercase=True,
    alternate_sign=False,
)
X_char = char_vect.transform(domains.tolist())

# 2) basic numeric string features
string_feats = [
    "len",
    "digits",
    "hyphens",
    "dots",
    "digit_ratio",
    "hyphen_ratio",
    "entropy",
    "xn_punycode",
    "labels",
    "tld_len",
]
S = np.vstack(
    [
        [basic_string_feats(d).get(k, 0) for k in string_feats]
        for d in domains.tolist()
    ]
)
X_string = csr_matrix(S)

# 3) DNS small numeric
dns_num_cols = ["num_unique_ips", "has_ipv6", "num_countries", "num_asns"]
for c in dns_num_cols:
    if c not in Xdf.columns:
        Xdf[c] = 0
Xdf[dns_num_cols] = Xdf[dns_num_cols].fillna(0)
X_dns_num = csr_matrix(Xdf[dns_num_cols].to_numpy(dtype=float))

# 4) hashed categoricals (ASN / ISP / country / registrar / status)
def cat_row(r):
    d = {}

    asn = r.get("sample_asn")
    if asn is not None and not (isinstance(asn, float) and math.isnan(asn)):
        asn_str = str(asn).strip()
        if asn_str and asn_str.lower() != "nan":
            d["asn=" + asn_str] = 1

    isp = r.get("sample_isp")
    if isp is not None and not (isinstance(isp, float) and math.isnan(isp)):
        d["isp=" + str(isp)] = 1

    cc = r.get("sample_country")
    if cc is not None and not (isinstance(cc, float) and math.isnan(cc)):
        d["cc=" + str(cc)] = 1

    reg = r.get("registrar")
    if reg is not None and not (isinstance(reg, float) and math.isnan(reg)):
        d["reg=" + str(reg)] = 1

    st = r.get("status")
    if st is not None and not (isinstance(st, float) and math.isnan(st)):
        d["status=" + str(st)] = 1

    return d

cats = [cat_row(r) for r in Xdf.to_dict(orient="records")]
hasher = FeatureHasher(
    n_features=256, input_type="dict", alternate_sign=False
)
X_cat = hasher.transform(cats)

# 5) WHOIS numeric
whois_num_cols = [
    "age_days",
    "days_to_expiry",
    "created_isnull",
    "expires_isnull",
    "has_error",
]
for c in whois_num_cols:
    if c not in Xdf.columns:
        Xdf[c] = 0
Xdf[whois_num_cols] = Xdf[whois_num_cols].fillna(0)
X_whois_num = csr_matrix(Xdf[whois_num_cols].to_numpy(dtype=float))

# Final feature matrices
X_lex  = hstack([X_char, X_string]).tocsr()
X_full = hstack([X_char, X_string, X_dns_num, X_cat, X_whois_num]).tocsr()
y = Xdf["label"].astype(int).to_numpy()

print(
    f"Feature matrix (lex only): {X_lex.shape} | (full): {X_full.shape} | "
    f"positives= {int(y.sum())} negatives= {int((y == 0).sum())}"
)

# ---------------- temporal / random split ----------------

def has_two_classes(arr, min_count: int = 30):
    """Not just "both labels present" -- both labels must appear at least
    min_count times. A bare >=2-unique-values check still passes on a
    1-example minority class, which is statistically meaningless and, found
    live, let a temporal cutoff that landed on a data-source boundary
    (nearly all undated openphish/urlhaus rows default-filled to "today",
    coinciding with a same-day feedback batch) silently produce a "valid"
    split with exactly 1 positive in the entire training set. min_count=30
    is a rough floor for "enough to say anything," not a tuned threshold."""
    vals, counts = np.unique(arr, return_counts=True)
    return len(vals) >= 2 and counts.min() >= min_count

Xtr_lex = Xte_lex = Xtr_full = Xte_full = None
y_train = y_test = None
used_temporal = False
temporal_cutoff = None

if "last_ingest_date" in Xdf.columns and Xdf["last_ingest_date"].notna().any():
    # Use last couple of days as "test" if possible
    cutoff = sorted(Xdf["last_ingest_date"].dropna().unique())[-1]
    print("[info] temporal split cutoff last_ingest_date >=", cutoff)
    temporal_cutoff = str(cutoff)
    test_mask = (Xdf["last_ingest_date"] >= cutoff).to_numpy(bool)
    n_test = int(test_mask.sum())
    n_total = len(test_mask)

    y_train_temp = y[~test_mask]
    y_test_temp = y[test_mask]

    temporal_ok = (
        0 < n_test < n_total
        and has_two_classes(y_train_temp)
        and has_two_classes(y_test_temp)
    )

    if temporal_ok:
        Xtr_lex, Xte_lex = X_lex[~test_mask], X_lex[test_mask]
        Xtr_full, Xte_full = X_full[~test_mask], X_full[test_mask]
        y_train, y_test = y_train_temp, y_test_temp
        used_temporal = True
        print(
            "[info] temporal split OK:",
            "train=",
            Xtr_lex.shape[0],
            "test=",
            Xte_lex.shape[0],
        )
    else:
        print("[warn] temporal split degenerate; falling back to random split")
        temporal_cutoff = None  # attempted but not actually used -- don't report a cutoff that wasn't applied

if not used_temporal:
    Xtr_lex, Xte_lex, y_train, y_test = train_test_split(
        X_lex,
        y,
        test_size=0.25,
        stratify=y,
        random_state=42,
    )
    Xtr_full, Xte_full, _, _ = train_test_split(
        X_full,
        y,
        test_size=0.25,
        stratify=y,
        random_state=42,
    )
    print(
        "[info] random stratified split:",
        "train=",
        Xtr_lex.shape[0],
        "test=",
        Xte_lex.shape[0],
    )

print(
    "[info] y_train: positives=",
    int((y_train == 1).sum()),
    "negatives=",
    int((y_train == 0).sum()),
)
print(
    "[info] y_test:  positives=",
    int((y_test == 1).sum()),
    "negatives=",
    int((y_test == 0).sum()),
)

# ---------------- models ----------------

def evaluate_model(name, clf, Xtr, ytr, Xte, yte):
    clf.fit(Xtr, ytr)
    p_te = clf.predict_proba(Xte)[:, 1]
    roc = roc_auc_score(yte, p_te)
    pr = average_precision_score(yte, p_te)
    fpr, tpr, thr = roc_curve(yte, p_te)
    if (fpr >= 0.01).any():
        idx = np.searchsorted(fpr, 0.01, side="right") - 1
        idx = max(idx, 0)
        r_at_1pct = float(tpr[idx])
        thr_at_1pct = float(thr[idx])
    else:
        r_at_1pct = float(tpr[-1])
        thr_at_1pct = float(thr[-1])
    print(
        f"[{name}] ROC-AUC={roc:.4f}  PR-AUC={pr:.4f}  "
        f"Recall@FPR=1%={r_at_1pct:.3f}"
    )
    return clf, {
        "roc_auc": roc,
        "pr_auc": pr,
        "recall_at_1pct": r_at_1pct,
        "threshold_at_1pct_fpr": thr_at_1pct,
    }


# 1) Logistic Regression baselines
logreg_lex = LogisticRegression(
    solver="liblinear", class_weight="balanced", max_iter=200, n_jobs=None
)
logreg_full = LogisticRegression(
    solver="liblinear", class_weight="balanced", max_iter=200, n_jobs=None
)

logreg_lex,  metrics_logreg_lex  = evaluate_model(
    "LogReg[lex_only]", logreg_lex,  Xtr_lex,  y_train, Xte_lex,  y_test
)
logreg_full, metrics_logreg_full = evaluate_model(
    "LogReg[full]",     logreg_full, Xtr_full, y_train, Xte_full, y_test
)

# 2) LightGBM (optional)
metrics_lgbm_lex = metrics_lgbm_full = None
if lgb is not None:
    try:
        lgbm_lex = lgb.LGBMClassifier(
            n_estimators=600,
            learning_rate=0.05,
            num_leaves=63,
            subsample=0.9,
            colsample_bytree=0.9,
            reg_alpha=0.1,
            reg_lambda=0.1,
            objective="binary",
            class_weight="balanced",
            n_jobs=-1,
        )
        lgbm_full = lgb.LGBMClassifier(
            n_estimators=600,
            learning_rate=0.05,
            num_leaves=63,
            subsample=0.9,
            colsample_bytree=0.9,
            reg_alpha=0.1,
            reg_lambda=0.1,
            objective="binary",
            class_weight="balanced",
            n_jobs=-1,
        )

        lgbm_lex,  metrics_lgbm_lex  = evaluate_model(
            "LightGBM[lex_only]", lgbm_lex,  Xtr_lex,  y_train, Xte_lex,  y_test
        )
        lgbm_full, metrics_lgbm_full = evaluate_model(
            "LightGBM[full]",     lgbm_full, Xtr_full, y_train, Xte_full, y_test
        )
    except Exception as e:
        print("[warn] LightGBM training failed:", e)
        lgbm_lex = lgbm_full = None
else:
    print("[info] LightGBM not installed; skipping")

# ---------------- benign false-positive rate (held-out, never trained on) ----------------
#
# ROC-AUC/PR-AUC above are computed on the same kind of distribution as
# training (openphish/urlhaus positives vs whatever negatives got sampled
# into this run) -- they don't answer "how often does this model cry wolf
# on a domain we KNOW is legitimate". ml/data/eval/benign_holdout.parquet
# (see ml/core/seed_benign_feedback.py) is deliberately held OUT of
# training and skewed toward the long/complex domains that were the actual
# false-positive failure mode found live (nzapplesandpears.com,
# bergstromvolkswagenappleton.com, ... scoring 0.94-0.99+).
#
# Uses the fitted LGBMClassifier's .booster_, not the sklearn wrapper
# itself -- wrapper.predict(X) returns class labels, not probabilities;
# api/main.py's production scoring path loads a raw lgb.Booster from disk,
# so eval_benign_fpr.py's "lgbm_full" branch expects that same interface.
from ml.core.eval_benign_fpr import compute_benign_fpr, HOLDOUT_PATH_DEFAULT

benign_holdout_fpr = None
if os.path.exists(HOLDOUT_PATH_DEFAULT):
    try:
        holdout_df = pd.read_parquet(HOLDOUT_PATH_DEFAULT)
        if lgb is not None and "lgbm_full" in locals() and lgbm_full is not None:
            benign_holdout_fpr = compute_benign_fpr(lgbm_full.booster_, "lgbm_full", holdout_df)
        else:
            benign_holdout_fpr = compute_benign_fpr(logreg_full, "logreg_full", holdout_df)
        print(f"[info] benign holdout FPR ({benign_holdout_fpr['n_holdout']} domains): "
              f"{benign_holdout_fpr['fpr']}")
    except Exception as e:
        print("[warn] benign FPR evaluation failed:", e)
else:
    print(f"[info] no benign holdout file at {HOLDOUT_PATH_DEFAULT}; skipping FPR eval "
          f"(run `python -m ml.core.seed_benign_feedback` to generate one)")

# ---------------- save models + metadata ----------------

ts_stamp = NOW_UTC.strftime("%Y%m%dT%H%M%SZ")

meta = {
    "created_utc": NOW_UTC.isoformat(),
    "n_rows": int(len(Xdf)),
    "n_pos": int((y == 1).sum()),
    "n_neg": int((y == 0).sum()),
    # Split methodology, made explicit rather than silently ambiguous: a
    # reported AUC from a random split is not evidence of forward-looking
    # predictive performance the way a genuine temporal split is. Consumers
    # of this file (e.g. ct/score/score_ct_with_latest.py, dashboards) should
    # treat used_temporal=False metrics with reduced confidence.
    "used_temporal_split": used_temporal,
    "temporal_cutoff_date": temporal_cutoff,
    "n_train": int(len(y_train)),
    "n_test": int(len(y_test)),
    "metrics": {
        "logreg_lex": metrics_logreg_lex,
        "logreg_full": metrics_logreg_full,
        "lgbm_lex": metrics_lgbm_lex,
        "lgbm_full": metrics_lgbm_full,
    },
    "feature_shapes": {
        "X_lex":  X_lex.shape,
        "X_full": X_full.shape,
    },
    "benign_holdout_fpr": benign_holdout_fpr,
}

meta_path = os.path.join(MODEL_DIR, f"ct_risk_meta_{ts_stamp}.json")
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)
print(f"[info] wrote meta to {meta_path}")

# Logistic Regression models
logreg_lex_path = os.path.join(MODEL_DIR, f"ct_risk_logreg_lex_{ts_stamp}.joblib")
logreg_full_path = os.path.join(MODEL_DIR, f"ct_risk_logreg_full_{ts_stamp}.joblib")

if joblib is not None:
    joblib.dump(logreg_lex, logreg_lex_path)
    joblib.dump(logreg_full, logreg_full_path)
    print("[info] saved LogisticRegression models via joblib")
else:
    print("[warn] joblib missing; LogReg models not saved to disk")

# LightGBM boosters (if available)
if lgb is not None and "lgbm_full" in locals() and lgbm_full is not None:
    try:
        lgb_full_path = os.path.join(MODEL_DIR, f"ct_risk_lgbm_full_{ts_stamp}.txt")
        lgbm_full.booster_.save_model(lgb_full_path)
        print("[info] saved LightGBM full booster to", lgb_full_path)
    except Exception as e:
        print("[warn] failed to save LightGBM full booster:", e)
        lgb_full_path = None
else:
    lgb_full_path = None

# ---------------- update "latest" symlinks/copies (gated) ----------------
#
# _copy_latest() used to run unconditionally on every training run -- a bad
# run (data issue, degenerate split, unlucky hyperparameters) could silently
# replace a good production model (the one api/main.py and
# ct/score/score_ct_with_latest.py actually read from) with a worse one, with
# no check and no record. ml/core/promotion_gate.py decides whether this
# run's model ("challenger") is allowed to replace the current production
# model ("champion") before any copy happens.

from ml.core.promotion_gate import append_promotion_log, decide_promotion, load_champion_meta

def _copy_latest(src, latest_name):
    if src is None or not os.path.exists(src):
        return
    latest_path = os.path.join(MODEL_DIR, latest_name)
    try:
        # copy2 to preserve mtime, works on all platforms
        shutil.copy2(src, latest_path)
        print(f"[info] updated latest model: {latest_path}")
    except Exception as e:
        print(f"[warn] failed to update latest copy {latest_path}: {e}")

champion_meta = load_champion_meta(MODEL_DIR)
decision = decide_promotion(champion_meta, meta)
for w in decision["warnings"]:
    print("[warn] promotion:", w)

# Make the timestamped meta.json self-documenting: it records its own
# promotion outcome, not just its metrics.
meta["promotion_decision"] = decision
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)

append_promotion_log(decision, os.path.join(MODEL_DIR, "promotion_log.jsonl"))

if decision["promote"]:
    print("[info] promotion GATE PASSED:", decision["reason"])
    _copy_latest(meta_path, "ct_risk_meta_latest.json")
    _copy_latest(logreg_full_path, "ct_risk_logreg_full_latest.joblib")
    if lgb_full_path is not None:
        _copy_latest(lgb_full_path, "ct_risk_lgbm_full_latest.txt")
else:
    print("[warn] promotion GATE REJECTED:", decision["reason"])
    print(f"[warn] keeping existing production model; this run's artifacts are preserved "
          f"at {meta_path} (and sibling model files) for inspection, just not promoted.")

print("[info] training run complete.")
