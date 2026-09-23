# ct/score/rescore_ct_observations.py
"""Rescore existing CtObservation rows in Postgres with the currently-
promoted model, WITHOUT re-running enrichment -- reuses whatever DNS/WHOIS
data is already stored on each row. Exists because ct/score/score_ct_with_
latest.py only ever scores the current enriched-parquet pointer (a scoring
RUN), never queries already-ingested Postgres rows directly: every row
scored before a model retrain keeps that retrain's stale risk_score
forever unless something does this.

Found live: all 8,270 rows in ct_observations were still scored by the
pre-retrain model (the one that gave a VW dealership 0.9985) even after
today's benign-FPR retrain (see ml/core/seed_benign_feedback.py) had
already promoted a fixed model -- retraining alone doesn't touch stored
scores.

Scoped to a full backfill (not just currently-open-cluster members):
rescoring is cheap (feature-building + two .predict() calls, no network),
and leaving old scores on rows outside today's visible queue just moves
the "quietly wrong number" problem one layer down (future clustering
passes, any raw risk_score sort/filter outside the campaign view).

Column mapping note: build_features() (imported from score_ct_with_latest,
canonical for both training and live scoring) expects a specific input
shape that doesn't match CtObservation's own column names 1:1:
  - age_days/days_to_expiry/created_isnull/expires_isnull are DERIVED from
    whois_created/whois_expires here, the same formula
    ml/core/train_model.py uses against its separate WHOIS lookups table
    (days since/until now, in days; isnull flags for missing timestamps).
  - has_error and has_ipv6 have no CtObservation-level equivalent (this
    table never stored a WHOIS-lookup-error flag or an IPv6-presence
    flag) -- default to 0, an honest "we don't have this signal here,"
    not a guess.
  - `status` (WHOIS domain status, read by build_features()'s cat_row())
    maps from CtObservation.whois_status.

Run:
    python -m ct.score.rescore_ct_observations                 # dry run, reports deltas
    python -m ct.score.rescore_ct_observations --apply         # writes risk_score/model_used/risk_label_final/decision_reason
"""
from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone

import pandas as pd
from sqlalchemy import select

from ct.score.score_ct_with_latest import build_features, choose_threshold, load_models, model_version_tag
from ml.core.features import derive_whois_numeric
from product.db import SessionLocal
from product.models import CtObservation

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
RESCORE_AUDIT_PATH_DEFAULT = os.path.join(REPO_ROOT, "product", "logs", "rescore_audit.parquet")


def observations_to_feature_df(rows) -> pd.DataFrame:
    """Reshapes CtObservation ORM rows into the exact columns
    build_features() expects. See module docstring for the column-mapping
    rationale."""
    now = datetime.now(timezone.utc)
    records = []
    for r in rows:
        wn = derive_whois_numeric({
            "registrar": r.registrar, "whois_status": r.whois_status,
            "whois_created": r.whois_created, "whois_expires": r.whois_expires,
        }, now)
        records.append({
            "id": r.id,
            "registered_domain": r.registered_domain or "",
            "num_unique_ips": r.num_unique_ips or 0,
            "has_ipv6": 0,
            "num_countries": r.num_countries or 0,
            "num_asns": r.num_asns or 0,
            "sample_asn": r.sample_asn,
            "sample_isp": r.sample_isp,
            "sample_country": r.sample_country,
            "registrar": r.registrar,
            "status": r.whois_status,
            # Raw dates too: build_features() re-derives WHOIS numerics from
            # raw fields (prepare_whois_columns), and without these it would
            # overwrite the values below with "no creation date".
            "whois_created": r.whois_created,
            "whois_expires": r.whois_expires,
            "age_days": wn["age_days"],
            "days_to_expiry": wn["days_to_expiry"],
            "created_isnull": wn["created_isnull"],
            "expires_isnull": wn["expires_isnull"],
            "has_error": wn["has_error"],
            "ti_misp_hit": r.ti_misp_hit or 0,
        })
    return pd.DataFrame.from_records(records)


def _decision_reason(risk_label: int, ti_misp_hit: int) -> str:
    """Mirrors score_ct_with_latest.py's main()::_reason() exactly, reusing
    each row's OWN already-stored ti_misp_hit rather than re-querying
    MISP silver -- MISP fusion isn't stale the way the ML score is (it
    isn't a function of which model trained when), so there's nothing to
    refresh there."""
    if ti_misp_hit:
        return "MISP_AND_ML" if risk_label else "MISP_IOC"
    return "ML_SCORE" if risk_label else "BENIGN_BASELINE"


def rescore_all(session, batch_size: int = 5000) -> pd.DataFrame:
    """Scores every CtObservation with the currently-promoted model.
    Returns a before/after audit DataFrame; does not write anything --
    that's main()'s job, gated on --apply."""
    logreg, booster, meta = load_models()
    primary_name = "lgbm_full" if booster is not None else "logreg_full"
    model_used = model_version_tag(primary_name, meta)
    thr = choose_threshold(meta, primary_name=primary_name)

    all_rows = session.execute(select(CtObservation)).scalars().all()
    if not all_rows:
        return pd.DataFrame(columns=["id", "old_risk_score", "new_risk_score", "old_model_used", "new_model_used"])

    audits = []
    for start in range(0, len(all_rows), batch_size):
        batch = all_rows[start:start + batch_size]
        df = observations_to_feature_df(batch)
        X = build_features(df)

        if booster is not None:
            new_scores = booster.predict(X)
        else:
            new_scores = logreg.predict_proba(X)[:, 1]

        for r, score, ti_misp_hit in zip(batch, new_scores, df["ti_misp_hit"]):
            new_risk_label = int(score >= thr)
            audits.append({
                "id": r.id,
                "registered_domain": r.registered_domain,
                "old_risk_score": r.risk_score,
                "new_risk_score": float(score),
                "old_model_used": r.model_used,
                "new_model_used": model_used,
                "old_risk_label_final": r.risk_label_final,
                "new_risk_label_final": max(new_risk_label, int(ti_misp_hit or 0)),
                "old_decision_reason": r.decision_reason,
                "new_decision_reason": _decision_reason(new_risk_label, int(ti_misp_hit or 0)),
            })
    return pd.DataFrame.from_records(audits)


def apply_rescore(session, audit_df: pd.DataFrame) -> int:
    """Writes new_risk_score/new_model_used/new_risk_label_final/
    new_decision_reason back onto each CtObservation. Returns rows updated."""
    n = 0
    for row in audit_df.itertuples():
        obs = session.get(CtObservation, row.id)
        if obs is None:
            continue
        obs.risk_score = row.new_risk_score
        obs.model_used = row.new_model_used
        obs.risk_label_final = row.new_risk_label_final
        obs.decision_reason = row.new_decision_reason
        n += 1
    session.commit()
    return n


def _atomic_write_parquet(df: pd.DataFrame, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    df.to_parquet(tmp, index=False)
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Actually write new scores. Without this, dry-run only.")
    ap.add_argument("--audit-output", default=RESCORE_AUDIT_PATH_DEFAULT)
    args = ap.parse_args(argv)

    with SessionLocal() as session:
        audit_df = rescore_all(session)
        if audit_df.empty:
            print("[info] no observations to rescore.")
            return 0

        delta = (audit_df["new_risk_score"] - audit_df["old_risk_score"].fillna(0)).abs()
        print(f"[info] {len(audit_df)} observations scored with model {audit_df['new_model_used'].iloc[0]}")
        print(f"[info] mean |delta|={delta.mean():.4f}, max delta={delta.max():.4f}, "
              f"rows with |delta|>0.1: {(delta > 0.1).sum()}")

        if args.apply:
            n = apply_rescore(session, audit_df)
            print(f"[info] applied: updated {n} rows.")
        else:
            print("[info] dry run only -- re-run with --apply to write the new scores.")

    _atomic_write_parquet(audit_df, args.audit_output)
    print(f"[info] audit trail written to {args.audit_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
