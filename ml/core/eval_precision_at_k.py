# ml/core/eval_precision_at_k.py
"""Precision@K against an INDEPENDENT ground truth (Track D, decision #4).

Ground truth is ti_misp_hit ALONE, not the fused risk_label_final. Using the
model's own fused decision to evaluate the model would be circular -- MISP
hits are an external confirmation the model had no part in producing, so
precision measured against them means something. This is a real limitation to
be upfront about: it only measures precision on the subset of malicious
activity that happens to already be in MISP, not on domains the model alone
would need to have caught first (that's what ct/score/measure_lead_time.py's
job is, from a different angle).

Uses the SINGLE NEWEST scored parquet (matching api/main.py's
get_latest_parquet() pattern), not an accumulation across files like
measure_lead_time.py's load_ct_high_risk() -- precision@K should reflect the
CURRENT model's ranking quality on one batch, not conflate risk_score values
that may span different model versions/calibrations over time.

Run:
    python -m ml.core.eval_precision_at_k [--gold-dir gold/threat_scores] [--k 10 25 50]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from datetime import datetime, timezone

import pandas as pd

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
GOLD_DIR_DEFAULT = os.path.join(REPO_ROOT, "gold", "threat_scores")
OUTPUT_PATH_DEFAULT = os.path.join(REPO_ROOT, "ml", "models", "registry", "precision_at_k_latest.json")
DEFAULT_KS = (10, 25, 50)


def get_latest_scored_parquet(gold_dir: str) -> str | None:
    files = glob.glob(os.path.join(gold_dir, "*.parquet"))
    return max(files, key=os.path.getmtime) if files else None


def precision_at_k(df: pd.DataFrame, k: int, score_col: str = "risk_score",
                    label_col: str = "ti_misp_hit") -> dict:
    """Of the top-K rows ranked by score_col, what fraction have label_col
    truthy. Missing/NaN label values count as "not a hit", not dropped --
    ti_misp_hit is populated for every scored row by the MISP-fusion step, so
    treating a gap as a miss (rather than excluding the row) doesn't bias the
    denominator toward only-checked rows."""
    if len(df) == 0 or score_col not in df.columns:
        return {"k": k, "precision": None, "n_evaluated": 0, "n_hits": 0}
    ranked = df.sort_values(score_col, ascending=False)
    top_k = ranked.head(k)
    if len(top_k) == 0:
        return {"k": k, "precision": None, "n_evaluated": 0, "n_hits": 0}
    labels = top_k[label_col] if label_col in top_k.columns else pd.Series(0, index=top_k.index)
    hits = int((labels.fillna(0).astype(float) > 0).sum())
    return {"k": k, "precision": round(hits / len(top_k), 4), "n_evaluated": len(top_k), "n_hits": hits}


def evaluate(gold_dir: str = GOLD_DIR_DEFAULT, ks: tuple = DEFAULT_KS) -> dict:
    path = get_latest_scored_parquet(gold_dir)
    if not path:
        return {"available": False, "reason": f"no scored parquet found under {gold_dir}"}
    df = pd.read_parquet(path)
    n_misp_hits_total = int((df["ti_misp_hit"].fillna(0).astype(float) > 0).sum()) if "ti_misp_hit" in df.columns else 0

    if n_misp_hits_total == 0:
        confidence_note = (
            f"NOT MEANINGFUL: 0 MISP hits in this batch of {len(df)} rows, so precision@K is "
            "trivially 0 for every K regardless of ranking quality -- there is no positive ground "
            "truth to find, not a model failure. Re-run once a batch with MISP overlap lands."
        )
    elif n_misp_hits_total < 10:
        confidence_note = f"LOW CONFIDENCE: only {n_misp_hits_total} MISP hits in this batch -- precision@K estimates are noisy at this sample size."
    else:
        confidence_note = f"{n_misp_hits_total} MISP hits in this batch -- precision@K estimates below are on that sample."

    return {
        "available": True,
        "computed_utc": datetime.now(timezone.utc).isoformat(),
        "scored_file": os.path.basename(path),
        "n_rows": len(df),
        "n_misp_hits_total": n_misp_hits_total,
        "ground_truth": "ti_misp_hit (independent external confirmation, not the model's own fused decision)",
        "confidence_note": confidence_note,
        "precision_at_k": [precision_at_k(df, k) for k in ks],
    }


def _atomic_write_json(obj: dict, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, default=str)
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gold-dir", default=os.getenv("CT_SCORED_DIR", GOLD_DIR_DEFAULT))
    ap.add_argument("--k", type=int, nargs="+", default=list(DEFAULT_KS))
    ap.add_argument("--output", default=OUTPUT_PATH_DEFAULT)
    args = ap.parse_args(argv)

    result = evaluate(args.gold_dir, tuple(args.k))
    print(json.dumps(result, indent=2, default=str))
    if result.get("available"):
        _atomic_write_json(result, args.output)
        print(f"\nWritten to {args.output}")
    return 0 if result.get("available") else 2


if __name__ == "__main__":
    raise SystemExit(main())
