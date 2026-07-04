# product/ingest_observations.py
"""Project scored CT observations (gold/threat_scores/*.parquet) into the
`ct_observations` application table.

Upsert semantics (the "observation mutability" decision, W4):
    Keyed by (raw_host, event_ts). The CT enrichment pipeline fills DNS/geo in
    the <5s hot path and WHOIS minutes-to-hours later via the cold backfill, so
    the SAME observation is re-scored and re-ingested with more enrichment over
    time. On conflict we therefore:
      - overwrite SCORING fields (risk/label/reason/model) with the newest pass,
      - COALESCE ENRICHMENT fields (registrar/whois/asn/...) -- take the new
        value when present, else keep the previously-filled one, so a later hot
        pass with a null registrar never wipes a WHOIS value the cold path
        already backfilled.
    The row is the current best state; the immutable per-evidence timeline is a
    separate table (evidence_events) added in a later track.

Run:
    python -m product.ingest_observations                 # newest scored file
    python -m product.ingest_observations --file X.parquet
    python -m product.ingest_observations --min-risk 0.5  # candidate gate
"""
from __future__ import annotations

import argparse
import glob
import math
import os

import pandas as pd
from sqlalchemy import func, select, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert

from product.db import SessionLocal
from product.models import ClusterMember, CtObservation
from product.stage_engine import apply_stage_transition

GOLD_DIR = os.getenv("CT_SCORED_DIR", "gold/threat_scores")

# scoring/decision columns: newest pass wins on conflict
_SCORE_COLS = [
    "registered_domain", "source", "source_file",
    "triage_score", "risk_score", "risk_label_final",
    "decision_reason", "model_used", "ti_misp_hit",
]
# enrichment columns: coalesce(new, existing) on conflict (never wipe with null)
_ENRICH_COLS = [
    "enrichment_level", "registrar", "whois_status", "whois_created",
    "whois_expires", "sample_asn", "sample_isp", "sample_country",
    "num_unique_ips", "num_countries", "num_asns",
]


def get_latest_scored_parquet() -> str | None:
    files = glob.glob(os.path.join(GOLD_DIR, "*.parquet"))
    return max(files, key=os.path.getmtime) if files else None


def _clean(v):
    """pandas/numpy scalar -> JSON/psycopg2-safe python value (NaN/NaT -> None)."""
    if v is None:
        return None
    try:
        if isinstance(v, float) and math.isnan(v):
            return None
    except (TypeError, ValueError):
        pass
    if v is pd.NaT or (isinstance(v, float) and math.isnan(v)):
        return None
    # numpy scalar -> python
    if hasattr(v, "item"):
        try:
            return v.item()
        except Exception:
            return v
    return v


def _dt(v):
    """Parse a value to a tz-aware python datetime, or None."""
    if v is None:
        return None
    ts = pd.to_datetime(v, utc=True, errors="coerce")
    return None if ts is pd.NaT or pd.isna(ts) else ts.to_pydatetime()


def _is_candidate(rec: dict, min_risk: float) -> bool:
    """Candidate gate: a confirmed decision, a MISP hit, or risk over the bar."""
    if _clean(rec.get("risk_label_final")) in (1, True):
        return True
    if _clean(rec.get("ti_misp_hit")) in (1, True):
        return True
    rs = _clean(rec.get("risk_score"))
    return rs is not None and float(rs) >= min_risk


def rows_from_df(df: pd.DataFrame, source_file: str, min_risk: float) -> tuple[list[dict], int]:
    """Project + filter a scored dataframe into ct_observations row dicts.
    Returns (rows, skipped) where skipped counts rows with no usable key."""
    rows: list[dict] = []
    skipped = 0
    for rec in df.to_dict(orient="records"):
        if not _is_candidate(rec, min_risk):
            continue
        raw_host = _clean(rec.get("domain_sample")) or _clean(rec.get("registered_domain"))
        event_ts = _dt(rec.get("event_ts"))
        if not raw_host or event_ts is None:
            skipped += 1  # cannot form the (raw_host, event_ts) upsert key
            continue
        rows.append({
            "raw_host": str(raw_host),
            "registered_domain": _clean(rec.get("registered_domain")),
            "event_ts": event_ts,
            "source": _clean(rec.get("source")),
            "source_file": source_file,
            "triage_score": _clean(rec.get("triage_score")),
            "risk_score": _clean(rec.get("risk_score")),
            "risk_label_final": _clean(rec.get("risk_label_final")),
            "decision_reason": _clean(rec.get("decision_reason")),
            "model_used": _clean(rec.get("model_used")),
            "ti_misp_hit": _clean(rec.get("ti_misp_hit")),
            "enrichment_level": _clean(rec.get("enrichment_level")),
            "registrar": _clean(rec.get("registrar")),
            "whois_status": _clean(rec.get("whois_status")),
            "whois_created": _dt(rec.get("whois_created")),
            "whois_expires": _dt(rec.get("whois_expires")),
            "sample_asn": _clean(rec.get("sample_asn")),
            "sample_isp": _clean(rec.get("sample_isp")),
            "sample_country": _clean(rec.get("sample_country")),
            "num_unique_ips": _clean(rec.get("num_unique_ips")),
            "num_countries": _clean(rec.get("num_countries")),
            "num_asns": _clean(rec.get("num_asns")),
        })
    return rows, skipped


def upsert_observations(session, rows: list[dict], chunk: int = 500) -> int:
    """Upsert row dicts into ct_observations by (raw_host, event_ts). Returns
    the number of rows sent (inserted-or-updated)."""
    if not rows:
        return 0
    total = 0
    for i in range(0, len(rows), chunk):
        batch = rows[i:i + chunk]
        stmt = pg_insert(CtObservation).values(batch)
        set_ = {c: stmt.excluded[c] for c in _SCORE_COLS}
        for c in _ENRICH_COLS:
            # prefer the new value, keep the existing one when the new is null
            set_[c] = func.coalesce(stmt.excluded[c], getattr(CtObservation, c))
        set_["updated_at"] = func.now()
        stmt = stmt.on_conflict_do_update(constraint="uq_obs_host_eventts", set_=set_)
        session.execute(stmt)
        total += len(batch)
    session.commit()
    return total


def reevaluate_stage_for_enriched_members(session, rows: list[dict]) -> int:
    """Call site 2/4 of the stage engine (product/stage_engine.py): after an
    upsert, find clusters whose membership includes any just-ingested
    observation with enrichment_level in (tier1, tier2), and re-evaluate them.

    Deliberately does NOT try to diff "did enrichment_level change tier for
    THIS row" against the pre-upsert value -- the bulk INSERT...ON CONFLICT
    DO UPDATE doesn't cheaply return per-row old values, and
    apply_stage_transition()'s own idempotency guard already makes an
    unnecessary re-evaluation call a safe, cheap no-op (proven live: repeated
    calls against an already-warming cluster write nothing new). Simpler and
    equally correct to just check the CURRENT stored value, which is exactly
    what evaluate_stage() reads anyway.

    Returns the number of distinct clusters re-evaluated."""
    if not rows:
        return 0
    keys = [(r["raw_host"], r["event_ts"]) for r in rows if r.get("enrichment_level") in ("tier1", "tier2")]
    if not keys:
        return 0
    # composite (raw_host, event_ts) tuple match -- NOT separate .in_() clauses
    # on each column, which would cross-match unrelated pairs (e.g. host A's
    # raw_host with host B's event_ts) since raw_host/event_ts are only
    # meaningful as a pair (the table's actual unique key).
    cluster_ids = session.execute(
        select(ClusterMember.cluster_id.distinct())
        .join(CtObservation, CtObservation.id == ClusterMember.observation_id)
        .where(
            tuple_(CtObservation.raw_host, CtObservation.event_ts).in_(keys),
            CtObservation.enrichment_level.in_(("tier1", "tier2")),
        )
    ).scalars().all()
    for cid in cluster_ids:
        apply_stage_transition(session, cid)
    return len(cluster_ids)


def ingest_file(path: str | None = None, min_risk: float = 0.5) -> dict:
    path = path or get_latest_scored_parquet()
    if not path or not os.path.exists(path):
        return {"ok": False, "reason": f"no scored parquet found under {GOLD_DIR}"}
    df = pd.read_parquet(path)
    rows, skipped = rows_from_df(df, os.path.basename(path), min_risk)
    with SessionLocal() as session:
        upserted = upsert_observations(session, rows)
        reevaluated = reevaluate_stage_for_enriched_members(session, rows)
    return {
        "ok": True, "file": os.path.basename(path), "scored_rows": len(df),
        "candidates": len(rows), "upserted": upserted, "skipped_no_key": skipped,
        "clusters_reevaluated": reevaluated,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Ingest scored CT parquet into ct_observations.")
    ap.add_argument("--file", default=None, help="scored parquet path (default: newest under CT_SCORED_DIR)")
    ap.add_argument("--min-risk", type=float, default=float(os.getenv("OBS_MIN_RISK", "0.5")),
                    help="candidate gate: keep observations with risk_score >= this (default 0.5). "
                         "risk_label_final==1 and MISP hits are always kept.")
    args = ap.parse_args(argv)
    result = ingest_file(args.file, args.min_risk)
    print(result)
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
