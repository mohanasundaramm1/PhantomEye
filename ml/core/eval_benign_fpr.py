# ml/core/eval_benign_fpr.py
"""False-positive rate on a held-out set of known-legitimate domains.

Neither existing evaluation script measures this: eval_provenance.py checks
source-leakage and infrastructure shortcuts, eval_precision_at_k.py checks
precision against MISP hits. Nothing measures "how often does the model cry
wolf on a domain we KNOW is benign" -- which is exactly the failure mode
found live (a VW dealership, a produce association, scoring 0.94-0.99+).

compute_benign_fpr() is the shared, pure core: it's called two ways --
  1. From ml/core/train_model.py, right after training, scoring the JUST-
     TRAINED challenger model against ml/data/eval/benign_holdout.parquet
     (see ml/core/seed_benign_feedback.py) so the result lands in that run's
     meta.json for the promotion gate to compare against the champion.
  2. From this module's own CLI, for ad-hoc spot-checks of whichever model
     is CURRENTLY promoted -- independent of a training run, same pattern as
     eval_precision_at_k.py's standalone CLI.

Uses ml/core/features.py's build_features_from_df() -- the same canonical
feature builder train_model.py and the live API both use. The holdout set
has no DNS/WHOIS enrichment (it's a static domain list, never resolved or
looked up); those columns default to 0, which correctly represents "no
enrichment yet" -- the real state of a CT hot-path observation before
cold-path enrichment lands, not a data quality gap.

Run:
    python -m ml.core.eval_benign_fpr   # scores the currently-promoted model
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from ml.core.features import build_features_from_df

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))

HOLDOUT_PATH_DEFAULT = os.path.join(REPO_ROOT, "ml", "data", "eval", "benign_holdout.parquet")
LOGREG_MODEL_PATH_DEFAULT = os.path.join(REPO_ROOT, "ml", "models", "registry", "ct_risk_logreg_full_latest.joblib")
LGBM_MODEL_PATH_DEFAULT = os.path.join(REPO_ROOT, "ml", "models", "registry", "ct_risk_lgbm_full_latest.txt")
OUTPUT_PATH_DEFAULT = os.path.join(REPO_ROOT, "ml", "reports", "benign_fpr_latest.json")
DEFAULT_THRESHOLD = 0.5  # matches the campaign-radar candidate gate (product/ingest_observations.py)


def predict_batch(model, model_kind: str, X) -> np.ndarray:
    """Score a full feature matrix regardless of model backend -- batch
    counterpart to api/main.py's predict_risk() (same two backends, same
    precedence: LightGBM Booster.predict() vs sklearn predict_proba())."""
    if model_kind == "lgbm_full":
        return np.asarray(model.predict(X), dtype=float)
    return np.asarray(model.predict_proba(X)[:, 1], dtype=float)


def compute_benign_fpr(model, model_kind: str, holdout_df: pd.DataFrame,
                       threshold: float = DEFAULT_THRESHOLD) -> dict:
    """holdout_df must have a `registered_domain` column (see
    ml/core/seed_benign_feedback.py's holdout output). Every row is
    known-benign by construction (sourced from Tranco, excluded against
    current malicious labels) -- so "predicted >= threshold" IS a false
    positive, not a judgment call."""
    if len(holdout_df) == 0:
        return {"n_holdout": 0, "n_false_positive": 0, "fpr": None, "threshold": threshold}
    X = build_features_from_df(holdout_df.copy())
    scores = predict_batch(model, model_kind, X)
    n_fp = int((scores >= threshold).sum())
    return {
        "n_holdout": len(holdout_df),
        "n_false_positive": n_fp,
        "fpr": round(n_fp / len(holdout_df), 4),
        "threshold": threshold,
        "score_percentiles": {
            "p50": round(float(np.percentile(scores, 50)), 4),
            "p90": round(float(np.percentile(scores, 90)), 4),
            "p99": round(float(np.percentile(scores, 99)), 4),
            "max": round(float(np.max(scores)), 4),
        },
    }


def load_promoted_model(logreg_path: str = LOGREG_MODEL_PATH_DEFAULT,
                        lgbm_path: str = LGBM_MODEL_PATH_DEFAULT):
    """Load the currently-promoted production model. Same precedence as
    api/main.py's load_model(): LightGBM Booster preferred, LogisticRegression
    joblib fallback. Returns (model, kind) or (None, None)."""
    try:
        import lightgbm as lgb
    except ImportError:
        lgb = None

    if lgb is not None and os.path.exists(lgbm_path):
        try:
            return lgb.Booster(model_file=lgbm_path), "lgbm_full"
        except Exception:
            pass

    if os.path.exists(logreg_path):
        try:
            import joblib
            return joblib.load(logreg_path), "logreg_full"
        except Exception:
            pass

    return None, None


def _atomic_write_json(obj: dict, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, default=str)
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--holdout-path", default=HOLDOUT_PATH_DEFAULT)
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--output", default=OUTPUT_PATH_DEFAULT)
    args = ap.parse_args(argv)

    if not os.path.exists(args.holdout_path):
        print(f"[error] no holdout file at {args.holdout_path}; "
              f"run `python -m ml.core.seed_benign_feedback` first")
        return 2

    model, kind = load_promoted_model()
    if model is None:
        print("[error] no promoted model found in ml/models/registry/")
        return 2

    holdout_df = pd.read_parquet(args.holdout_path)
    result = compute_benign_fpr(model, kind, holdout_df, threshold=args.threshold)
    result["model_kind"] = kind
    result["computed_utc"] = datetime.now(timezone.utc).isoformat()

    _atomic_write_json(result, args.output)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
