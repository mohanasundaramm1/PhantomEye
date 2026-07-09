# ml/core/seed_benign_feedback.py
"""Generate benign (label=0) training/eval signal from the unused Tranco-style
list at airflow/benign/top-1m.csv, to fix a real gap: the model's ONLY
negative training examples (source=="benign_seed" in silver/labels_union/)
are a static snapshot of 2,688 domains frozen since 2025-10-28..31, mean
length 13.3 chars, max 37. Found live: legitimate long/multi-word business
domains (a produce association, a VW dealership, a plumbing company -- 20-32
chars) score 0.94-0.99+ because the model has never seen a real negative
example of that shape. It learned "long/complex = suspicious" as a proxy,
because that's the only pattern its stale negative set could teach it.

Deliberately over-samples LONGER domains (see LENGTH_BUCKETS) rather than
sampling uniformly across the 1M-row file -- a uniform/rank-weighted sample
would be dominated by short, famous, easy domains (google.com, ...) and do
almost nothing to close the actual gap. This is NOT a claim that the sample
is representative of the general internet; it's deliberately shaped to
target the model's specific known weakness.

Produces two DISJOINT outputs from one stratified draw:
  - a feedback-schema parquet, picked up automatically by
    ml/core/train_model.py's existing feedback-ingestion hook (zero changes
    needed there -- see that file's load_all_labels(), lines ~129-137).
  - a held-out eval parquet that NEVER enters training, used only by
    ml/core/eval_benign_fpr.py to measure false-positive rate honestly. A
    holdout sampled from the SAME easy/uniform distribustion as training
    would hide the real number; this one is drawn from the identical
    length-skewed distribution, so it's testing the actual hard cases.

Run:
    python -m ml.core.seed_benign_feedback
"""
from __future__ import annotations

import argparse
import glob
import os
from datetime import datetime, timezone

import numpy as np
import pandas as pd

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))

TRANCO_PATH_DEFAULT = os.path.join(REPO_ROOT, "airflow", "benign", "top-1m.csv")
FEEDBACK_OUTPUT_DEFAULT = os.path.join(REPO_ROOT, "ml", "data", "feedback", "feedback_labels_tranco_seed.parquet")
HOLDOUT_OUTPUT_DEFAULT = os.path.join(REPO_ROOT, "ml", "data", "eval", "benign_holdout.parquet")
SILVER_LABELS_DIR_DEFAULT = os.path.join(REPO_ROOT, "silver", "labels_union")

N_SAMPLE_DEFAULT = 20_000
HOLDOUT_FRACTION_DEFAULT = 0.2
RANDOM_SEED = 42

# (min_len, max_len_exclusive, target_share). Shares sum to 1.0. Skewed toward
# long/complex domains on purpose -- see module docstring.
LENGTH_BUCKETS = [
    (0, 12, 0.10),
    (12, 20, 0.20),
    (20, 30, 0.35),
    (30, 10_000, 0.35),
]


def load_malicious_domains(silver_labels_dir: str = SILVER_LABELS_DIR_DEFAULT) -> set:
    """Every domain currently in openphish/urlhaus labels (any historical
    date-partition) -- a Tranco-derived "benign" sample must never coincide
    with a domain that's actually labeled malicious elsewhere."""
    files = glob.glob(os.path.join(silver_labels_dir, "ingest_date=*", "labels_union.parquet"))
    if not files:
        return set()
    frames = []
    for f in files:
        try:
            frames.append(pd.read_parquet(f, columns=["domain", "source"]))
        except Exception:
            continue
    if not frames:
        return set()
    df = pd.concat(frames, ignore_index=True)
    malicious = df.loc[df["source"] != "benign_seed", "domain"]
    return set(malicious.astype(str).str.lower())


def stratified_sample(tranco_df: pd.DataFrame, n: int, buckets=LENGTH_BUCKETS,
                      seed: int = RANDOM_SEED) -> pd.DataFrame:
    """Sample n domains from tranco_df, stratified by length bucket per the
    target shares above. If a bucket has fewer rows than its target share
    needs, takes everything available in that bucket (a real, reported
    shortfall -- not a silent under-sample)."""
    rng = np.random.RandomState(seed)
    lengths = tranco_df["domain"].str.len()
    parts = []
    for lo, hi, share in buckets:
        bucket_df = tranco_df[(lengths >= lo) & (lengths < hi)]
        want = int(round(n * share))
        take = min(want, len(bucket_df))
        if take < want:
            print(f"[warn] length bucket [{lo},{hi}) wanted {want}, only {len(bucket_df)} available")
        if take > 0:
            parts.append(bucket_df.sample(n=take, random_state=rng))
    if not parts:
        return tranco_df.iloc[0:0]
    return pd.concat(parts, ignore_index=True)


def build_benign_sets(
    tranco_path: str = TRANCO_PATH_DEFAULT,
    n_sample: int = N_SAMPLE_DEFAULT,
    holdout_fraction: float = HOLDOUT_FRACTION_DEFAULT,
    seed: int = RANDOM_SEED,
    malicious_domains: set | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Returns (feedback_df, holdout_df), disjoint, both with a `domain`
    column, both drawn from the same length-skewed stratification."""
    tranco = pd.read_csv(tranco_path, header=None, names=["rank", "domain"])
    tranco["domain"] = tranco["domain"].astype(str).str.lower().str.strip()
    tranco = tranco[tranco["domain"].astype(bool)].drop_duplicates("domain")

    malicious_domains = malicious_domains if malicious_domains is not None else load_malicious_domains()
    if malicious_domains:
        before = len(tranco)
        tranco = tranco[~tranco["domain"].isin(malicious_domains)]
        excluded = before - len(tranco)
        if excluded:
            print(f"[info] excluded {excluded} tranco domains overlapping current malicious labels")

    sampled = stratified_sample(tranco, n_sample, seed=seed)
    sampled = sampled.sample(frac=1.0, random_state=seed).reset_index(drop=True)  # shuffle before splitting

    n_holdout = int(round(len(sampled) * holdout_fraction))
    holdout = sampled.iloc[:n_holdout].copy()
    feedback = sampled.iloc[n_holdout:].copy()
    return feedback, holdout


def _atomic_write_parquet(df: pd.DataFrame, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    df.to_parquet(tmp, index=False)
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tranco-path", default=TRANCO_PATH_DEFAULT)
    ap.add_argument("--n-sample", type=int, default=N_SAMPLE_DEFAULT)
    ap.add_argument("--holdout-fraction", type=float, default=HOLDOUT_FRACTION_DEFAULT)
    ap.add_argument("--feedback-output", default=FEEDBACK_OUTPUT_DEFAULT)
    ap.add_argument("--holdout-output", default=HOLDOUT_OUTPUT_DEFAULT)
    args = ap.parse_args(argv)

    feedback_df, holdout_df = build_benign_sets(
        tranco_path=args.tranco_path, n_sample=args.n_sample, holdout_fraction=args.holdout_fraction,
    )
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    feedback_out = pd.DataFrame({
        "domain": feedback_df["domain"].values,
        "label": 0,
        "source": "benign_tranco",
        "ingest_date": today,
    })
    holdout_out = pd.DataFrame({
        "registered_domain": holdout_df["domain"].values,
        "label": 0,
    })

    _atomic_write_parquet(feedback_out, args.feedback_output)
    _atomic_write_parquet(holdout_out, args.holdout_output)

    result = {
        "feedback_rows": len(feedback_out),
        "holdout_rows": len(holdout_out),
        "feedback_path": args.feedback_output,
        "holdout_path": args.holdout_output,
        "feedback_length_stats": {k: round(v, 2) for k, v in
                                  feedback_df["domain"].str.len().describe().to_dict().items()},
    }
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
