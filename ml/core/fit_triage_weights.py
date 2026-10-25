# ml/core/fit_triage_weights.py
"""Fit the triage rule weights in config/triage.json from data, instead of
hand-setting them.

What triage actually decides
----------------------------
Triage doesn't just gate Kafka. The enrichment hot path takes only the top
`hot_path.max_domains` (600) domains BY TRIAGE SCORE per 2-hour cycle -- about
7,200 a day out of ~500,000 forwarded. So the triage score's RANKING decides
which domains ever reach the model. The quantity this script optimizes and
reports is therefore **budget recall**: of known-malicious domains, what share
would land inside that daily scoring budget, ranked against a real day of CT
traffic.

Method
------
- Positives: OpenPhish/URLHaus hostnames from silver/labels_union.
- Background: one real day of CT, rebuilt from what the forwarder kept --
  forwarded rows (ct/data/raw) plus the low-priority spool -- each weighted by
  the inverse of the probability the *collection-time* config sampled it, so
  the background estimates the full, unsampled stream. CT is overwhelmingly
  benign, so it's the population malicious domains must out-rank. (Tranco is
  not: it's popular sites, and it made long/hyphenated names look malicious,
  when in CT they're mostly cloud and CDN hostnames.)
- Features: the exact live rule detector, ct.ingest.triage.rule_hits(), so a
  fitted weight can't drift from the rule it weights.
- Model: logistic regression. Negative coefficients are clipped to 0 (the rule
  still fires and still appears in `reasons`; it just carries no weight), and
  weights are normalized to sum to 1, so the score stays in [0, 1] and the
  cap in triage_score() never binds.
- Load is held constant: the new pass_threshold is chosen so the forwarder
  sends the same daily volume to Kafka as the collection-time config did, and
  the WHOIS tier threshold (config/enrichment.json tiers.triage_threshold) so
  the same share of forwarded rows qualifies for WHOIS. Only the ranking
  changes, not the pipeline's workload.
- Evaluation is out-of-sample twice over: background from a different day, and
  positives from the half not used for fitting (split by a hash of the domain).

Data retention: the spool days this reads are pruned after 7 days by
ops/launchd/prune_spool.sh (SPOOL_KEEP_DAYS), so --fit-day / --eval-day must be
recent. A past fit (see weights_provenance in config/triage.json) cannot be re-run
on its original days once they age out; re-fit on fresh traffic instead.

Known ceiling (measured 2026-09-24, 30 label partitions)
-------------------------------------------------------
~45% of OpenPhish/URLHaus domains fire NO triage rule, and no reweighting can
rank them: at triage time only the hostname exists, and theirs look ordinary.
62% of those carry the malicious part in the URL PATH (/index.php kits,
.exe/.apk/.hta payloads) on an ordinary or compromised domain -- and CT only
ever sees hostnames. Looking them up by age/hosting isn't a fix either:
zero-rule names are ~80% of the CT stream (~33M/day), so with no name signal
to choose which to look up, any affordable number of lookups finds ~none.
These belong to URL-level sources (URLHaus/MISP feeds, crawlers), not to a
certificate-issuance pipeline.

Run:
    python -m ml.core.fit_triage_weights --fit-day 2026-09-22 --eval-day 2026-09-23 \
        --collected-with /path/to/triage.json.at-collection-time            # report only
    ... --write                                                              # also update configs
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import zlib
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

from ct.ingest import triage

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
TRIAGE_CFG_PATH = os.path.join(REPO_ROOT, "config", "triage.json")
ENRICH_CFG_PATH = os.path.join(REPO_ROOT, "config", "enrichment.json")
RAW_DIR = os.path.join(REPO_ROOT, "ct", "data", "raw")
SPOOL_DIR = os.path.join(REPO_ROOT, "ct", "data", "low_priority")
LABELS_DIR = os.path.join(REPO_ROOT, "silver", "labels_union")

DAILY_BUDGET_DEFAULT = 7200  # hot_path.max_domains (600) x 12 two-hour cycles


# ---------- data ----------

def _stable_frac(s: str) -> float:
    return (zlib.crc32(s.encode("utf-8")) % 10_000) / 10_000.0


def load_positives(n_partitions: int = 30) -> pd.Series:
    files = sorted(glob.glob(os.path.join(LABELS_DIR, "ingest_date=*", "labels_union.parquet")))[-n_partitions:]
    lab = pd.concat(pd.read_parquet(f, columns=["domain", "source"]) for f in files)
    d = lab.loc[lab["source"].isin(["openphish", "urlhaus"]), "domain"].dropna()
    d = d.str.strip().str.lower().str.rstrip(".").drop_duplicates()
    d = d[d.str.contains(r"[a-z]") & ~d.str.match(r"^\d+(\.\d+){3}$")]
    return d.reset_index(drop=True)


def load_background(day: str, collected_cfg: dict, raw_keep: int = 5, spool_keep: int = 20) -> pd.DataFrame:
    """One day of CT as the forwarder saw it, re-weighted to the full stream.

    raw (forwarded) rows are thinned 1-in-`raw_keep`, spool rows 1-in-
    `spool_keep` (deterministically). Each kept row carries:
      thin -- how many REAL collected rows it stands for (the thinning factor)
      w    -- how many rows of the full, unsampled stream it stands for
              (thin / P(collection-time config sampled it))
      src  -- "raw" (was forwarded to Kafka) or "spool" (was deferred)"""
    rows, weights, thins, srcs = [], [], [], []
    rate = float(collected_cfg.get("sampling", {}).get("sample_rate", 1.0))

    def w_sample(d: str) -> float:
        # should_sample is deterministic per domain; for domains it kept, the
        # population they stand in for is 1/rate unless they hit a bypass.
        s = collected_cfg.get("sampling", {})
        bypass = (s.get("always_include_suspicious_tld", True) and triage.has_suspicious_tld(d, collected_cfg)) or \
                 (s.get("always_include_brand_match", True) and bool(triage.brand_matches(d, collected_cfg)))
        return 1.0 if (bypass or rate >= 1.0) else 1.0 / rate

    raw_files = glob.glob(os.path.join(RAW_DIR, f"ds={day}", "*.parquet"))
    for f in raw_files:
        try:
            df = pd.read_parquet(f, columns=["domain"])
        except Exception:
            continue  # a file Spark is still writing
        for d in df["domain"].dropna():
            if zlib.crc32(d.encode()) % raw_keep == 0:
                rows.append(d); thins.append(raw_keep); srcs.append("raw")
                weights.append(raw_keep * w_sample(d))

    spool = os.path.join(SPOOL_DIR, f"ds={day}.jsonl")
    if os.path.exists(spool):
        with open(spool) as fh:
            for i, line in enumerate(fh):
                if i % spool_keep:
                    continue
                try:
                    d = json.loads(line)["domain"]
                except Exception:
                    continue
                rows.append(d); thins.append(spool_keep); srcs.append("spool")
                weights.append(spool_keep * w_sample(d))

    if not rows:
        raise SystemExit(f"no CT data found for {day} under {RAW_DIR} / {SPOOL_DIR}")
    return pd.DataFrame({"domain": rows, "w": weights, "thin": thins, "src": srcs})


def rule_matrix(domains, cfg: dict) -> np.ndarray:
    return np.array([[1 if r in hits else 0 for r in triage.RULES]
                     for hits in (triage.rule_hits(d, cfg) for d in domains)], dtype=np.int8)


def legacy_rule_matrix(domains, cfg: dict) -> np.ndarray:
    """Rule matrix as the pre-split code saw it: real brands and generic
    sensitive words were ONE rule, brand_match, counted once even when both
    kinds fired. Scoring the collection-time config with the split matrix
    would double-count those domains and misstate the "before" baseline."""
    X = rule_matrix(domains, cfg)
    b, g = triage.RULES.index("brand_match"), triage.RULES.index("sensitive_word")
    X[:, b] |= X[:, g]
    X[:, g] = 0
    return X


# ---------- scoring / thresholds ----------

def scores(X: np.ndarray, weights: dict) -> np.ndarray:
    w = np.array([weights.get(r, 0.0) for r in triage.RULES])
    return np.clip(X @ w, 0.0, 1.0)


def threshold_for_volume(s: np.ndarray, w: np.ndarray, target: float) -> float:
    """Smallest score threshold t with weighted volume(score >= t) <= target."""
    levels = np.unique(s)[::-1]
    for t in levels:
        if w[s >= t].sum() > target:
            idx = np.searchsorted(levels[::-1], t)
            return float(levels[::-1][idx + 1]) if idx + 1 < len(levels) else float(t) + 1e-9
    return float(levels[-1])


def budget_recall(pos_s, pos_admit, bg_s, bg_w, bg_admit, budget: float) -> float:
    """Share of positives that land in the top-`budget` of admitted background,
    with ties at the cutoff score shared proportionally (the hot path's sort
    is arbitrary among equal scores)."""
    s, w = bg_s[bg_admit], bg_w[bg_admit]
    order = np.argsort(-s)
    s, w = s[order], w[order]
    cum = np.cumsum(w)
    if cum[-1] <= budget:
        return float(np.mean(pos_admit))
    cut = s[np.searchsorted(cum, budget)]
    above = w[s > cut].sum()
    at = w[s == cut].sum()
    tie_share = max(budget - above, 0.0) / at if at else 0.0
    admit = np.where(pos_s > cut, 1.0, np.where(pos_s == cut, tie_share, 0.0))
    return float(np.mean(admit * pos_admit))


# ---------- main ----------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fit-day", required=True)
    ap.add_argument("--eval-day", required=True)
    ap.add_argument("--collected-with", required=True,
                    help="triage.json that was live when the CT days were collected (for sampling weights and the old baseline)")
    ap.add_argument("--daily-budget", type=float, default=DAILY_BUDGET_DEFAULT)
    ap.add_argument("--budget-curve", default="7200,36000,72000,144000,288000",
                    help="comma-separated daily budgets to report recall at (the curve shows what raising hot_path.max_domains buys)")
    ap.add_argument("--write", action="store_true", help="update config/triage.json and config/enrichment.json")
    args = ap.parse_args(argv)

    old_cfg = json.load(open(args.collected_with))
    cfg = json.load(open(TRIAGE_CFG_PATH))            # current rules/lists (allowlist, rule split)
    enrich_cfg = json.load(open(ENRICH_CFG_PATH))
    old_tier2 = float(enrich_cfg["tiers"]["triage_threshold"])

    pos = load_positives()
    is_fit = pos.map(_stable_frac) < 0.5
    print(f"[info] positives: {len(pos):,} (fit {int(is_fit.sum()):,} / eval {int((~is_fit).sum()):,})")

    fit_bg = load_background(args.fit_day, old_cfg)
    print(f"[info] fit background {args.fit_day}: {len(fit_bg):,} rows ~ {fit_bg.w.sum():,.0f} domains/day (unsampled estimate)")

    Xp = rule_matrix(pos, cfg)
    Xb = rule_matrix(fit_bg["domain"], cfg)

    # --- fit: balance classes so positives carry the same total mass as background
    Xf = np.vstack([Xp[is_fit.values], Xb])
    yf = np.r_[np.ones(int(is_fit.sum())), np.zeros(len(Xb))]
    wf = np.r_[np.full(int(is_fit.sum()), fit_bg.w.sum() / max(int(is_fit.sum()), 1)), fit_bg.w.values]
    lr = LogisticRegression(max_iter=2000, C=1.0)
    lr.fit(Xf, yf, sample_weight=wf / wf.mean())
    coef = dict(zip(triage.RULES, lr.coef_[0]))
    pos_coef = {r: max(c, 0.0) for r, c in coef.items()}
    total = sum(pos_coef.values()) or 1.0
    new_weights = {r: round(pos_coef[r] / total, 4) for r in triage.RULES}

    # --- hold load constant, measured on the fit day. What the old config
    # forwarded is known exactly: the raw rows (volume = thinning factor, no
    # sampling expansion -- sampling already happened). What the NEW flow
    # would forward is estimated over the full stream (weight w), since
    # score-then-sample forwards high scorers whether or not they're sampled.
    old_s_fit = scores(legacy_rule_matrix(fit_bg["domain"], old_cfg), old_cfg["triage"]["weights"])
    was_fwd = (fit_bg["src"] == "raw").values
    old_fwd_volume = fit_bg["thin"].values[was_fwd].sum()
    old_tier2_share = fit_bg["thin"].values[was_fwd & (old_s_fit >= old_tier2)].sum() / max(old_fwd_volume, 1)
    below = int((old_s_fit[was_fwd] < old_cfg["triage"]["pass_threshold"] - 1e-9).sum())
    if below:
        print(f"[warn] {below} forwarded rows score below the collection-time pass_threshold "
              "under --collected-with; is it really the config that was live?")

    new_s_fit = scores(Xb, new_weights)
    new_pass = threshold_for_volume(new_s_fit, fit_bg.w.values, old_fwd_volume)
    new_fwd = new_s_fit >= new_pass
    new_tier2 = threshold_for_volume(new_s_fit[new_fwd], fit_bg.w.values[new_fwd],
                                     old_tier2_share * fit_bg.w.values[new_fwd].sum())

    # --- evaluate out-of-sample: other day, other half of positives
    ev_bg = load_background(args.eval_day, old_cfg)
    pe = pos[~is_fit.values]
    Xpe_new, Xpe_old = Xp[~is_fit.values], legacy_rule_matrix(pe, old_cfg)
    Xbe_new, Xbe_old = rule_matrix(ev_bg["domain"], cfg), legacy_rule_matrix(ev_bg["domain"], old_cfg)
    bw = ev_bg.w.values

    old_pt = old_cfg["triage"]["pass_threshold"]
    old_pos_s, old_bg_s = scores(Xpe_old, old_cfg["triage"]["weights"]), scores(Xbe_old, old_cfg["triage"]["weights"])
    old_pos_admit = (old_pos_s >= old_pt) & np.array([triage.should_sample(d, old_cfg) for d in pe])
    # old candidates = what was actually forwarded that day, at real-row volume
    old_bg_admit = (ev_bg["src"] == "raw").values
    old_bg_w = ev_bg["thin"].values.astype(float)

    new_pos_s, new_bg_s = scores(Xpe_new, new_weights), scores(Xbe_new, new_weights)
    new_pos_admit, new_bg_admit = new_pos_s >= new_pass, new_bg_s >= new_pass

    def report(name, ps, pa, bs, ba, vw):
        return {
            "config": name,
            "reaches_kafka": round(float(np.mean(pa)), 4),
            "budget_recall": round(budget_recall(ps, pa, bs, vw, ba, args.daily_budget), 4),
            "est_forwarded_per_day": int(vw[ba].sum()),
        }

    results = [
        report("before (hand weights, sample-then-score)", old_pos_s, old_pos_admit, old_bg_s, old_bg_admit, old_bg_w),
        report("after (fitted weights, score-then-sample)", new_pos_s, new_pos_admit, new_bg_s, new_bg_admit, bw),
    ]

    print("\n[fit] logistic coefficients -> clipped, normalized weights")
    for r in triage.RULES:
        print(f"  {r:24} coef {coef[r]:+6.2f}   hand {old_cfg['triage']['weights'].get(r, 0.0):.2f}   fitted {new_weights[r]:.4f}")
    print(f"\n[load] pass_threshold {old_pt} -> {new_pass:.4f}  (target <= ~{old_fwd_volume:,.0f}/day forwarded, "
          f"achieved ~{fit_bg.w.values[new_fwd].sum():,.0f}/day on {args.fit_day}; scores are discrete, so the "
          "threshold lands on the nearest level at or under the target)")
    print(f"[load] WHOIS tier threshold {old_tier2} -> {new_tier2:.4f}  (share of forwarded held at {old_tier2_share:.1%})")
    print(f"\n[eval] {args.eval_day} background, {len(pe):,} held-out malicious, daily budget {args.daily_budget:,.0f}")
    for r in results:
        print(f"  {r['config']:44} reaches Kafka {r['reaches_kafka']:6.1%}   in scoring budget {r['budget_recall']:6.2%}   est forwarded/day {r['est_forwarded_per_day']:>10,}")

    curve = []
    for b in [float(x) for x in args.budget_curve.split(",") if x]:
        row = {"daily_budget": int(b),
               "before": round(budget_recall(old_pos_s, old_pos_admit, old_bg_s, old_bg_w, old_bg_admit, b), 4),
               "after": round(budget_recall(new_pos_s, new_pos_admit, new_bg_s, bw, new_bg_admit, b), 4)}
        curve.append(row)
    print("\n[curve] share of held-out malicious inside the daily scoring budget")
    print(f"  {'budget/day':>11}  {'per 2h cycle':>12}  {'before':>8}  {'after':>8}")
    for row in curve:
        print(f"  {row['daily_budget']:>11,}  {row['daily_budget'] // 12:>12,}  {row['before']:>8.2%}  {row['after']:>8.2%}")

    if args.write:
        cfg["triage"]["weights"] = new_weights
        cfg["triage"]["pass_threshold"] = round(new_pass, 4)
        cfg["weights_provenance"] = {
            "fitted_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "script": "ml/core/fit_triage_weights.py",
            "fit_day": args.fit_day, "eval_day": args.eval_day,
            "n_positives": int(len(pos)), "daily_budget": args.daily_budget,
            "logistic_coefficients": {r: round(float(c), 4) for r, c in coef.items()},
            "eval": results,
            "budget_curve": curve,
        }
        with open(TRIAGE_CFG_PATH, "w") as f:
            json.dump(cfg, f, indent=2); f.write("\n")
        enrich_cfg["tiers"]["triage_threshold"] = round(new_tier2, 4)
        with open(ENRICH_CFG_PATH, "w") as f:
            json.dump(enrich_cfg, f, indent=2); f.write("\n")
        print(f"\n[write] updated {os.path.relpath(TRIAGE_CFG_PATH, REPO_ROOT)} and {os.path.relpath(ENRICH_CFG_PATH, REPO_ROOT)}")
    return results


if __name__ == "__main__":
    main()
