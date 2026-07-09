# product/export_analyst_labels.py
"""Export confirmed/suppressed dispositions as labeled training signal.

DUAL-WRITE. The detailed export (ml/data/analyst_labels/latest.parquet, full
schema below) was originally scoped as export-only and NOT wired into
retraining. It now also writes a second, schema-adapted parquet to
ml/data/feedback/feedback_labels_analyst.parquet -- ml/core/train_model.py's
existing feedback-ingestion hook (load_all_labels(), lines ~129-137) already
auto-concatenates ANY parquet matching ml/data/feedback/feedback_labels_*.parquet
with columns [domain, label, source, ingest_date], so this needed zero changes
to train_model.py itself, just writing the right file in the right shape.
This closes the loop the analyst disposition workflow was built toward: when
an analyst marks a false positive (e.g. a legitimate business wrongly scored
high-risk) as "suppressed" or "benign", that becomes a real negative training
example for the next retrain, not just a UI-only annotation.

One row per cluster's MOST RECENT disposition, joined to its member raw_hosts
(one row per member -- a disposition covers every domain in the campaign).
label = 1 for verdict="confirmed", 0 for "suppressed"/"benign" ("suppressed"
means noise, "benign" means analyst-reviewed-and-cleared -- both are negative
signal for "is this a real threat", distinct only in reason, which the
verdict column itself preserves for anyone who wants that distinction later).

Run:
    python -m product.export_analyst_labels [--output ml/data/analyst_labels/latest.parquet]
                                             [--feedback-output ml/data/feedback/feedback_labels_analyst.parquet]
"""
from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone

import pandas as pd
from sqlalchemy import func, select

from product.db import SessionLocal
from product.models import AnalystDisposition, CampaignCluster, ClusterMember, CtObservation

OUTPUT_PATH_DEFAULT = "ml/data/analyst_labels/latest.parquet"
FEEDBACK_OUTPUT_DEFAULT = "ml/data/feedback/feedback_labels_analyst.parquet"


def _latest_disposition_ids(session):
    return (
        select(AnalystDisposition.cluster_id, func.max(AnalystDisposition.id).label("max_id"))
        .group_by(AnalystDisposition.cluster_id)
        .subquery()
    )


def build_export(session) -> pd.DataFrame:
    sub = _latest_disposition_ids(session)
    rows = session.execute(
        select(
            CtObservation.raw_host, CtObservation.registered_domain, CtObservation.risk_score,
            CampaignCluster.id.label("cluster_id"), CampaignCluster.target_brand,
            AnalystDisposition.verdict, AnalystDisposition.analyst, AnalystDisposition.created_at,
        )
        .select_from(AnalystDisposition)
        .join(sub, AnalystDisposition.id == sub.c.max_id)
        .join(CampaignCluster, CampaignCluster.id == AnalystDisposition.cluster_id)
        .join(ClusterMember, ClusterMember.cluster_id == CampaignCluster.id)
        .join(CtObservation, CtObservation.id == ClusterMember.observation_id)
    ).all()

    records = [{
        "raw_host": r.raw_host,
        "registered_domain": r.registered_domain,
        "risk_score": r.risk_score,
        "cluster_id": r.cluster_id,
        "target_brand": r.target_brand,
        "verdict": r.verdict,
        "label": 1 if r.verdict == "confirmed" else 0,
        "analyst": r.analyst,
        "disposed_at": r.created_at,
    } for r in rows]
    return pd.DataFrame.from_records(records)


def to_feedback_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Adapt the detailed export schema to what train_model.py's feedback
    loader expects: [domain, label, source, ingest_date]. Falls back to
    raw_host when registered_domain is missing -- train_model.py's own
    reg_domain() will re-derive the registered domain from whichever we give
    it, same as it does for every other label source."""
    domain = df["registered_domain"].where(df["registered_domain"].notna(), df["raw_host"])
    return pd.DataFrame({
        "domain": domain,
        "label": df["label"],
        "source": "analyst_disposition",
        "ingest_date": pd.to_datetime(df["disposed_at"]).dt.strftime("%Y-%m-%d"),
    })


def _atomic_write_parquet(df: pd.DataFrame, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    df.to_parquet(tmp, index=False)
    os.replace(tmp, path)


def export(output_path: str = OUTPUT_PATH_DEFAULT,
          feedback_output_path: str = FEEDBACK_OUTPUT_DEFAULT) -> dict:
    with SessionLocal() as s:
        df = build_export(s)
    if len(df) == 0:
        return {"ok": True, "n_rows": 0, "reason": "no dispositions recorded yet",
                "output_path": None, "feedback_output_path": None}

    _atomic_write_parquet(df, output_path)
    _atomic_write_parquet(to_feedback_schema(df), feedback_output_path)

    return {
        "ok": True,
        "n_rows": len(df),
        "n_confirmed": int((df["label"] == 1).sum()),
        "n_negative": int((df["label"] == 0).sum()),
        "exported_utc": datetime.now(timezone.utc).isoformat(),
        "output_path": output_path,
        "feedback_output_path": feedback_output_path,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default=OUTPUT_PATH_DEFAULT)
    ap.add_argument("--feedback-output", default=FEEDBACK_OUTPUT_DEFAULT)
    args = ap.parse_args(argv)
    print(export(args.output, args.feedback_output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
