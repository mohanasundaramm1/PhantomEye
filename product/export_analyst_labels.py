# product/export_analyst_labels.py
"""Export confirmed/suppressed dispositions as labeled training signal.

Scoped as EXPORT ONLY -- this writes a parquet file of analyst-confirmed
ground truth; it does not wire into ml/core's feature selection or retraining
pipeline. That integration (deciding how much weight analyst labels should
carry vs. the existing MISP-fusion labels, whether they need a minimum sample
size before use, etc.) is a real ML-engineering decision deserving its own
scoped work, not a side effect of a metrics day.

One row per cluster's MOST RECENT disposition, joined to its member raw_hosts
(one row per member -- a disposition covers every domain in the campaign).
label = 1 for verdict="confirmed", 0 for "suppressed"/"benign" ("suppressed"
means noise, "benign" means analyst-reviewed-and-cleared -- both are negative
signal for "is this a real threat", distinct only in reason, which the
verdict column itself preserves for anyone who wants that distinction later).

Run:
    python -m product.export_analyst_labels [--output ml/data/analyst_labels/latest.parquet]
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


def export(output_path: str = OUTPUT_PATH_DEFAULT) -> dict:
    with SessionLocal() as s:
        df = build_export(s)
    if len(df) == 0:
        return {"ok": True, "n_rows": 0, "reason": "no dispositions recorded yet", "output_path": None}
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    tmp = output_path + ".tmp"
    df.to_parquet(tmp, index=False)
    os.replace(tmp, output_path)
    return {
        "ok": True,
        "n_rows": len(df),
        "n_confirmed": int((df["label"] == 1).sum()),
        "n_negative": int((df["label"] == 0).sum()),
        "exported_utc": datetime.now(timezone.utc).isoformat(),
        "output_path": output_path,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default=OUTPUT_PATH_DEFAULT)
    args = ap.parse_args(argv)
    print(export(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
