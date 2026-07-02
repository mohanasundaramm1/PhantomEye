# ml/core/promotion_gate.py
"""Model promotion gate: decides whether a freshly-trained ("challenger")
model is allowed to overwrite the production ("champion") model pointers
(ct_risk_*_latest.*) that api/main.py and ct/score/score_ct_with_latest.py
actually read from.

Before this existed, ml/core/train_model.py's _copy_latest() ran
unconditionally on every training run -- a bad run (data quality issue,
degenerate split, unlucky hyperparameters, a bug) could silently replace a
good production model with a worse one, with no check and no record. This
is a pure-function module (no import-time side effects, unlike
train_model.py) so it's independently testable; train_model.py imports and
calls it right before its _copy_latest() calls.

Gating rules, deliberately minimal and conservative rather than exhaustive:
  1. Hard floor: challenger's primary ROC-AUC must be >= MIN_AUC_FLOOR.
     Catches a genuinely broken/degenerate training run. Set below the
     honest cross-source-generalization number found by
     ml/core/eval_provenance.py (~0.70-0.73), not the inflated same-
     distribution number (~0.93-0.99) -- a model performing at realistic
     generalization levels should still be promotable.
  2. No-regression: if a champion exists, the challenger's primary ROC-AUC
     must not be more than MAX_REGRESSION_TOLERANCE worse than the
     champion's own primary ROC-AUC. Protects the live production model
     from being silently downgraded by a worse run.
  3. Sanity: both classes must be present in the challenger's training data
     (n_pos > 0 and n_neg > 0) -- catches a collapsed/degenerate dataset.
  4. Warning (non-blocking): if the challenger wasn't evaluated on a
     genuine temporal split (used_temporal_split is False/missing), that's
     surfaced as an explicit warning on the decision record, not silently
     hidden -- but doesn't block promotion by itself, since a temporal
     split can legitimately be degenerate for benign reasons (sparse recent
     label data). See ml/core/train_model.py's temporal-split fallback.

A first-ever run (no existing champion) always passes rules 1 and 3 (no
regression check possible) -- bootstrapping the registry is expected to
succeed, not get stuck with nothing to compare against.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

MIN_AUC_FLOOR = 0.70
MAX_REGRESSION_TOLERANCE = 0.02


def primary_metric(meta: dict | None) -> tuple[str, float] | None:
    """Returns (model_name, roc_auc) for whichever model this project treats
    as primary -- LightGBM full if its metrics are present, else Logistic
    Regression full -- matching the precedence already used in
    ct/score/score_ct_with_latest.py and api/main.py. None if meta is
    missing/malformed or neither model's roc_auc is available."""
    if not meta or not isinstance(meta, dict):
        return None
    metrics = meta.get("metrics") or {}
    for name in ("lgbm_full", "logreg_full"):
        m = metrics.get(name)
        if isinstance(m, dict) and isinstance(m.get("roc_auc"), (int, float)):
            return name, float(m["roc_auc"])
    return None


def load_champion_meta(model_dir: str, filename: str = "ct_risk_meta_latest.json") -> dict | None:
    path = os.path.join(model_dir, filename)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def decide_promotion(
    champion_meta: dict | None,
    challenger_meta: dict,
    min_auc_floor: float = MIN_AUC_FLOOR,
    max_regression_tolerance: float = MAX_REGRESSION_TOLERANCE,
) -> dict:
    """Returns a decision dict: {promote, reason, warnings, challenger_primary,
    champion_primary, checked_utc}. Never raises -- a malformed input is
    itself grounds for rejection (fail closed, don't promote something we
    can't evaluate)."""
    checked_utc = datetime.now(timezone.utc).isoformat()
    warnings = []

    if not challenger_meta.get("used_temporal_split"):
        warnings.append(
            "challenger was NOT evaluated on a genuine temporal split (used_temporal_split "
            "is False/missing) -- its ROC-AUC reflects same-distribution performance, not "
            "demonstrated forward-looking generalization. Not blocking promotion on this "
            "alone, but treat the reported AUC with reduced confidence."
        )

    if int(challenger_meta.get("n_pos", 0)) <= 0 or int(challenger_meta.get("n_neg", 0)) <= 0:
        return {
            "promote": False,
            "reason": f"REJECTED: challenger training data is degenerate "
                     f"(n_pos={challenger_meta.get('n_pos')}, n_neg={challenger_meta.get('n_neg')}) -- "
                     f"both classes must be present.",
            "warnings": warnings, "challenger_primary": None, "champion_primary": None,
            "checked_utc": checked_utc,
        }

    challenger_primary = primary_metric(challenger_meta)
    if challenger_primary is None:
        return {
            "promote": False,
            "reason": "REJECTED: could not determine challenger's primary ROC-AUC "
                     "(missing/malformed metrics.lgbm_full and metrics.logreg_full).",
            "warnings": warnings, "challenger_primary": None, "champion_primary": None,
            "checked_utc": checked_utc,
        }
    challenger_name, challenger_auc = challenger_primary

    if challenger_auc < min_auc_floor:
        return {
            "promote": False,
            "reason": f"REJECTED: challenger {challenger_name} ROC-AUC={challenger_auc:.4f} "
                     f"is below the minimum floor ({min_auc_floor}).",
            "warnings": warnings,
            "challenger_primary": {"model": challenger_name, "roc_auc": challenger_auc},
            "champion_primary": None, "checked_utc": checked_utc,
        }

    champion_primary = primary_metric(champion_meta)
    if champion_primary is None:
        # No existing champion (first run) or champion meta unreadable/malformed --
        # nothing to regress against, so a challenger clearing the floor is promotable.
        return {
            "promote": True,
            "reason": f"PROMOTED: {challenger_name} ROC-AUC={challenger_auc:.4f} clears the floor "
                     f"({min_auc_floor}); no existing champion to compare against.",
            "warnings": warnings,
            "challenger_primary": {"model": challenger_name, "roc_auc": challenger_auc},
            "champion_primary": None, "checked_utc": checked_utc,
        }
    champion_name, champion_auc = champion_primary

    regression = champion_auc - challenger_auc
    if regression > max_regression_tolerance:
        return {
            "promote": False,
            "reason": (
                f"REJECTED: challenger {challenger_name} ROC-AUC={challenger_auc:.4f} regresses "
                f"{regression:.4f} below champion {champion_name} ROC-AUC={champion_auc:.4f} "
                f"(tolerance={max_regression_tolerance}). Keeping existing champion in production."
            ),
            "warnings": warnings,
            "challenger_primary": {"model": challenger_name, "roc_auc": challenger_auc},
            "champion_primary": {"model": champion_name, "roc_auc": champion_auc},
            "checked_utc": checked_utc,
        }

    return {
        "promote": True,
        "reason": (
            f"PROMOTED: challenger {challenger_name} ROC-AUC={challenger_auc:.4f} vs champion "
            f"{champion_name} ROC-AUC={champion_auc:.4f} (delta={-regression:+.4f}, within tolerance)."
        ),
        "warnings": warnings,
        "challenger_primary": {"model": challenger_name, "roc_auc": challenger_auc},
        "champion_primary": {"model": champion_name, "roc_auc": champion_auc},
        "checked_utc": checked_utc,
    }


def append_promotion_log(decision: dict, log_path: str) -> None:
    """Durable, append-only audit trail of every promotion decision -- so
    "why is the production model what it is today" is always answerable,
    not just the current state."""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a") as f:
        f.write(json.dumps(decision, default=str) + "\n")


def verify_latest_decision(log_path: str, max_age_hours: float = 24.0) -> tuple[bool, str]:
    """Checks that the gate itself actually ran recently and produced a
    real decision -- NOT whether that decision was to promote or reject.
    A rejection is the safety mechanism working correctly and should never
    fail a pipeline run; a missing, malformed, or stale log entry means the
    gate silently didn't execute (e.g. a swallowed exception), which is the
    actual integrity risk worth failing loudly on -- the same "don't let a
    green run mean nothing happened" principle as
    scripts/check_ct_freshness.py's event_ts check.

    Returns (ok, message)."""
    if not os.path.exists(log_path):
        return False, f"NO promotion log at {log_path} -- the gate has never run."
    try:
        with open(log_path) as f:
            lines = [l for l in f if l.strip()]
        if not lines:
            return False, f"promotion log at {log_path} exists but is empty."
        last = json.loads(lines[-1])
    except Exception as e:
        return False, f"could not parse the last line of {log_path}: {e}"

    if "promote" not in last or "checked_utc" not in last:
        return False, f"last log entry is missing required keys (promote/checked_utc): {last}"

    try:
        checked = datetime.fromisoformat(last["checked_utc"])
    except Exception as e:
        return False, f"last log entry has an unparseable checked_utc: {e}"

    now = datetime.now(timezone.utc)
    age_hours = (now - checked).total_seconds() / 3600.0
    if age_hours > max_age_hours:
        return False, (
            f"last promotion decision is {age_hours:.1f}h old (> {max_age_hours}h threshold) -- "
            f"the gate may not have run on the most recent training attempt."
        )

    verdict = "PROMOTED" if last["promote"] else "REJECTED (champion unchanged -- this is expected/healthy behavior, not a failure)"
    return True, f"gate ran {age_hours:.2f}h ago -- {verdict}: {last.get('reason', '')}"


def _cli(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Verify the model promotion gate actually ran recently.")
    ap.add_argument("--log-path", default=None)
    ap.add_argument("--max-age-hours", type=float, default=24.0)
    args = ap.parse_args(argv)

    this_dir = os.path.dirname(os.path.abspath(__file__))
    default_log = os.path.join(this_dir, "..", "models", "registry", "promotion_log.jsonl")
    log_path = args.log_path or default_log

    ok, message = verify_latest_decision(log_path, args.max_age_hours)
    print(f"[{'OK' if ok else 'FAIL'}] {message}")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
