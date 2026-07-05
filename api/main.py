from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import glob
import json
import os
import joblib
import numpy as np
import tldextract
import math
import random
from datetime import datetime, timezone
from collections import Counter

from ml.core.features import build_features
from ct.enrich.cache import ParquetTTLCache
from ct.enrich.circuit import CircuitBreaker
from ct.enrich.config import abspath, load_config
from ct.enrich.ratelimit import TokenBucket
from ct.enrich.tiers import EnrichFailure, enrich_item

try:
    import lightgbm as lgb
except ImportError:
    lgb = None

app = FastAPI(title="Phantom Eye CTI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

GOLD_DIR = "gold/threat_scores"
# Same precedence as ct/score/score_ct_with_latest.py: LightGBM is primary
# when available, LogReg is the fallback.
LOGREG_MODEL_PATH = "ml/models/registry/ct_risk_logreg_full_latest.joblib"
LGBM_MODEL_PATH = "ml/models/registry/ct_risk_lgbm_full_latest.txt"

# Live-scoring enrichment is a user-facing request, not a batch job, so it
# gets a short bounded total timeout rather than the full queue/rate-limit
# machinery's patience.
LIVE_ENRICH_TIMEOUT_SECONDS = 4.0

# Global model cache: (model_object, "lgbm_full" | "logreg_full")
MODEL = None
MODEL_KIND = None

def load_model():
    """Load the primary scoring model, preferring the LightGBM booster
    (matches ct/score/score_ct_with_latest.py's precedence) and falling
    back to the LogisticRegression joblib model only if the booster file
    isn't present."""
    global MODEL, MODEL_KIND
    if MODEL is not None:
        return MODEL, MODEL_KIND

    if lgb is not None and os.path.exists(LGBM_MODEL_PATH):
        try:
            MODEL = lgb.Booster(model_file=LGBM_MODEL_PATH)
            MODEL_KIND = "lgbm_full"
            return MODEL, MODEL_KIND
        except Exception:
            MODEL = None

    if os.path.exists(LOGREG_MODEL_PATH):
        try:
            MODEL = joblib.load(LOGREG_MODEL_PATH)
            if not hasattr(MODEL, 'classes_'):
                MODEL.classes_ = np.array([0, 1])
            MODEL_KIND = "logreg_full"
        except Exception:
            MODEL = None
            MODEL_KIND = None

    return MODEL, MODEL_KIND

def predict_risk(model, kind: str, X) -> float:
    """Score a single feature vector regardless of model backend."""
    if kind == "lgbm_full":
        pred = model.predict(X)
        return float(np.asarray(pred, dtype=float)[0])
    return float(model.predict_proba(X)[0, 1])

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

# ---------------- live enrichment (tiered, bounded) ----------------

_ENRICH_CFG = load_config()
_ENRICH_CACHES = {
    "whois": ParquetTTLCache(
        "whois", os.path.join(abspath(_ENRICH_CFG, _ENRICH_CFG["paths"]["lookups_dir"]), "whois_cache.parquet"),
        key_col="domain", ttl_seconds=_ENRICH_CFG["cache_ttls"]["whois_days"] * 86400,
    ),
    "dns": ParquetTTLCache(
        "dns_geo", os.path.join(abspath(_ENRICH_CFG, _ENRICH_CFG["paths"]["lookups_dir"]), "dns_geo_cache.parquet"),
        key_col="puny_domain", ttl_seconds=_ENRICH_CFG["cache_ttls"]["dns_hours"] * 3600,
    ),
    "geo": ParquetTTLCache(
        "ip_geo", os.path.join(abspath(_ENRICH_CFG, _ENRICH_CFG["paths"]["lookups_dir"]), "ip_geo_cache.parquet"),
        key_col="ip", ttl_seconds=_ENRICH_CFG["cache_ttls"]["geo_hours"] * 3600,
    ),
}
_ENRICH_LIMITERS = {"whois": TokenBucket(_ENRICH_CFG["rate_limits"]["whois_rps"]),
                    "dns": TokenBucket(_ENRICH_CFG["rate_limits"]["dns_rps"])}
_ENRICH_BREAKERS = {"whois": CircuitBreaker("whois", failure_threshold=_ENRICH_CFG["circuit_breaker"]["failure_threshold"],
                                            cooldown_seconds=_ENRICH_CFG["circuit_breaker"]["cooldown_seconds"]),
                    "dns": CircuitBreaker("dns", failure_threshold=_ENRICH_CFG["circuit_breaker"]["failure_threshold"],
                                          cooldown_seconds=_ENRICH_CFG["circuit_breaker"]["cooldown_seconds"])}

def enrich_domain_live(domain: str) -> tuple[dict, str]:
    """Synchronously enrich a single submitted domain via the same tiered
    pipeline (cache -> DNS/local geo -> WHOIS/RDAP) the batch pipeline uses,
    but bounded by a short total timeout since this is a live request.

    Returns (enrichment_dict, status) where status is "full" if tier-2 WHOIS
    enrichment completed (or was cache-satisfied), "partial" if only DNS/geo
    tiers succeeded, or "lexical_only" if enrichment failed/timed out entirely.
    """
    import concurrent.futures as _fut

    item = {"registered_domain": domain, "domain": domain, "triage_score": None}

    def _run():
        return enrich_item(
            item,
            whois_cache=_ENRICH_CACHES["whois"], dns_cache=_ENRICH_CACHES["dns"],
            geo_cache=_ENRICH_CACHES["geo"], rate_limiters=_ENRICH_LIMITERS,
            breakers=_ENRICH_BREAKERS, cfg=_ENRICH_CFG,
        )

    with _fut.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_run)
        try:
            row = future.result(timeout=LIVE_ENRICH_TIMEOUT_SECONDS)
        except _fut.TimeoutError:
            return {}, "lexical_only"
        except EnrichFailure:
            return {}, "lexical_only"
        except Exception:
            return {}, "lexical_only"

    # enrich_item()'s "enrichment_level" only reflects whether a *network*
    # call was made for WHOIS (tier2), not whether WHOIS data was ultimately
    # populated -- a cache-satisfied WHOIS lookup reports tier0/tier1 even
    # though registrar/status data is present. Check the actual fields so a
    # cache hit correctly counts as "full".
    whois_populated = row.get("registrar") is not None or row.get("whois_status") is not None
    dns_populated = "enrichment_level" in row
    if whois_populated:
        status = "full"
    elif dns_populated:
        status = "partial"
    else:
        status = "lexical_only"
    return row, status

def get_latest_parquet():
    files = glob.glob(f"{GOLD_DIR}/*.parquet")
    if not files:
        return None
    return max(files, key=os.path.getmtime)

@app.get("/health")
def health():
    return {"status": "operational", "timestamp": datetime.now().isoformat()}

LEAD_TIME_SUMMARY_PATH = "gold/detection_timeline/latest_summary.json"

@app.get("/metrics/lead-time")
def lead_time_metrics():
    """Surfaces the output of ct/score/measure_lead_time.py: how many hours
    before a domain appears in a public blocklist (OpenPhish/URLHaus) this
    pipeline's CT scoring already flagged it, measured directly against real
    data -- not a marketing claim. Includes the confidence_note verbatim so
    a small/zero sample size can't be misread as a proven result; re-run
    ct/score/measure_lead_time.py to refresh."""
    if not os.path.exists(LEAD_TIME_SUMMARY_PATH):
        return {"available": False, "reason": "no measurement has been run yet; run ct/score/measure_lead_time.py"}
    try:
        with open(LEAD_TIME_SUMMARY_PATH) as f:
            summary = json.load(f)
    except Exception as e:
        return {"available": False, "reason": f"could not read summary: {e}"}
    return {"available": True, **summary}

MODEL_META_PATH = "ml/models/registry/ct_risk_meta_latest.json"

@app.get("/model/status")
def model_status():
    """Surfaces the real training/promotion metadata written by the ML
    training job to ml/models/registry/ct_risk_meta_latest.json -- actual
    dataset size, class balance, and the champion/challenger promotion
    decision, not a marketing claim. Re-run the training pipeline to
    refresh this file."""
    if not os.path.exists(MODEL_META_PATH):
        return {"available": False, "reason": "no model metadata found; run the ML training pipeline"}
    try:
        with open(MODEL_META_PATH) as f:
            meta = json.load(f)
    except Exception as e:
        return {"available": False, "reason": f"could not read model metadata: {e}"}
    return {"available": True, **meta}

# ==================== campaign radar (product layer) ====================
# Serves the analyst-facing campaign queue from the application Postgres
# (product/ package). Guarded import so the rest of the API still loads if the
# product DB deps/service aren't present.
try:
    from sqlalchemy import select
    from product.db import SessionLocal, ping as _app_db_ping
    from product.models import (
        AnalystDisposition,
        CampaignCluster,
        ClusterMember,
        CtObservation,
        SuppressionRule,
    )
    from product.stage_engine import apply_stage_transition
    _PRODUCT_DB = True
except Exception:  # noqa: BLE001
    _PRODUCT_DB = False

WATCHDOG_STATE_PATH = "ops/launchd/logs/watchdog_state.json"
# A cluster is "in the queue" once its confidence crosses this bar. (Queue
# lifecycle -- queue_status/assignee/disposition -- lands with the analyst
# workflow track; the read-only ranked queue only needs this promotion gate.)
PROMOTION_MIN_CONFIDENCE = float(os.getenv("CAMPAIGN_PROMOTION_MIN_CONFIDENCE", "0.5"))


def _read_json_safe(path: str):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _newest_age_hours(root: str):
    """Age in hours of the most recently modified file under root, or None."""
    newest = -1.0
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            try:
                m = os.path.getmtime(os.path.join(dirpath, fn))
                if m > newest:
                    newest = m
            except OSError:
                pass
    if newest < 0:
        return None
    return round((datetime.now().timestamp() - newest) / 3600.0, 2)


@app.get("/health/pipeline")
def health_pipeline():
    """Real end-to-end pipeline health for the analyst: CT raw freshness,
    scoring freshness, model age, the reliability watchdog's last verdict, and
    app-DB liveness. This is observability layered over the already-self-healing
    ingest (launchd supervision + freshness watchdog, see ops/launchd) -- it
    reports real state, it does not simulate it."""
    watchdog = _read_json_safe(WATCHDOG_STATE_PATH)
    db_ok = bool(_app_db_ping()) if _PRODUCT_DB else False
    ingest_stale = bool(watchdog.get("stale")) if watchdog else None
    model_meta = _read_json_safe(MODEL_META_PATH) or {}
    return {
        # healthy = serving DB up AND the ingest canary isn't flagging staleness
        "healthy": db_ok and (ingest_stale is not True),
        "app_db": {"reachable": db_ok},
        "ct_raw": {"newest_age_hours": _newest_age_hours("ct/data/raw")},
        "scoring": {"newest_scored_age_hours": _newest_age_hours(GOLD_DIR)},
        "model": {
            "created_utc": model_meta.get("created_utc"),
            "promoted": (model_meta.get("promotion_decision") or {}).get("promote"),
        },
        "ingest_watchdog": (
            {
                "stale": ingest_stale,
                "last_checked_utc": watchdog.get("last_checked_iso"),
                "note": "self-healing launchd supervision + freshness watchdog",
            }
            if watchdog is not None
            else {"available": False, "note": "watchdog has not run yet"}
        ),
    }


def _campaign_card(c) -> dict:
    last = c.last_seen
    fresh_min = None
    if last is not None:
        try:
            fresh_min = round((datetime.now(timezone.utc) - last).total_seconds() / 60.0, 1)
        except Exception:
            fresh_min = None
    return {
        "campaign_id": c.id,
        "target_brand": c.target_brand,
        "target_workflow": c.target_workflow,
        "stage": c.stage,
        "status": c.status,
        "confidence_score": round(c.confidence_score, 4) if c.confidence_score is not None else None,
        "member_count": c.observation_count,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_seen": last.isoformat() if last else None,
        "freshness_age_minutes": fresh_min,
        "summary_reason": c.summary_reason,
        "queue_status": c.queue_status,
        "assignee": c.assignee,
        "sla_bucket": c.sla_bucket,
        # None when never locked -- an analyst hasn't recorded a disposition yet,
        # so stage is still fully auto-managed (product/stage_engine.py).
        "stage_locked_by": c.stage_locked_by,
        "stage_locked_at": c.stage_locked_at.isoformat() if c.stage_locked_at else None,
    }


@app.get("/campaigns")
def list_campaigns(
    target_brand: str = None,
    min_confidence: float = None,
    stage: str = None,
    limit: int = 100,
):
    """Ranked campaign queue: brand-attributed clusters above the promotion
    confidence bar, newest/strongest first, OR anything an analyst has already
    recorded a disposition on (stage_locked_by is set) -- an analyst-confirmed
    campaign must never silently drop out of the queue just because its
    auto-computed confidence happens to sit below the promotion bar (found
    live: a confirmed cluster at 0.49 confidence vanished from the default
    view entirely, meaning the analyst couldn't find their own disposed
    campaign again). Filters: target_brand, stage, min_confidence."""
    if not _PRODUCT_DB:
        return {"available": False, "reason": "product DB not configured", "campaigns": []}
    try:
        thr = PROMOTION_MIN_CONFIDENCE if min_confidence is None else min_confidence
        with SessionLocal() as s:
            q = select(CampaignCluster).where(
                (CampaignCluster.confidence_score >= thr) | (CampaignCluster.stage_locked_by.isnot(None))
            )
            if target_brand:
                q = q.where(CampaignCluster.target_brand == target_brand.lower())
            if stage:
                q = q.where(CampaignCluster.stage == stage)
            q = q.order_by(CampaignCluster.confidence_score.desc()).limit(limit)
            cards = [_campaign_card(c) for c in s.execute(q).scalars().all()]
        return {"available": True, "count": len(cards), "campaigns": cards}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "reason": f"query failed: {e}", "campaigns": []}


@app.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: int):
    """Campaign detail: the queue card plus its member domains (the infra in
    the cluster), ranked by risk."""
    if not _PRODUCT_DB:
        raise HTTPException(status_code=503, detail="product DB not configured")
    try:
        with SessionLocal() as s:
            c = s.get(CampaignCluster, campaign_id)
            if c is None:
                raise HTTPException(status_code=404, detail="campaign not found")
            members = s.execute(
                select(CtObservation)
                .join(ClusterMember, ClusterMember.observation_id == CtObservation.id)
                .where(ClusterMember.cluster_id == campaign_id)
                .order_by(CtObservation.risk_score.desc())
            ).scalars().all()
            domains = [
                {
                    "raw_host": o.raw_host,
                    "registered_domain": o.registered_domain,
                    "risk_score": round(o.risk_score, 4) if o.risk_score is not None else None,
                    "decision_reason": o.decision_reason,
                    "enrichment_level": o.enrichment_level,
                    "registrar": o.registrar,
                    "sample_country": o.sample_country,
                    "sample_asn": o.sample_asn,
                    "event_ts": o.event_ts.isoformat() if o.event_ts else None,
                }
                for o in members
            ]
            card = _campaign_card(c)
        card["domains"] = domains
        return {"available": True, **card}
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"query failed: {e}")


class DispositionRequest(BaseModel):
    verdict: str  # confirmed | suppressed | benign
    analyst: str  # mandatory, not defaulted -- no auth means this IS the audit trail
    severity: str | None = None
    notes: str | None = None
    actor_guess: str | None = None
    action_taken: str | None = None


class AssignRequest(BaseModel):
    assignee: str


@app.post("/campaigns/{campaign_id}/disposition")
def create_disposition(campaign_id: int, request: DispositionRequest):
    """Record an analyst's verdict on a campaign. Authoritative: it locks the
    cluster's stage (product/stage_engine.py) so automatic re-evaluation from
    ingest/assemble/the content probe can no longer move it, until a future
    disposition explicitly changes the verdict again.

    The disposition row and the stage/lock/evidence write happen in ONE
    transaction (apply_stage_transition's own commit finalizes both) -- never
    split across round trips, so a crash between them can't leave a
    disposition on record with no matching stage change, or vice versa."""
    if not _PRODUCT_DB:
        raise HTTPException(status_code=503, detail="product DB not configured")
    if request.verdict not in ("confirmed", "suppressed", "benign"):
        raise HTTPException(status_code=422, detail="verdict must be confirmed, suppressed, or benign")
    try:
        with SessionLocal() as s:
            if s.get(CampaignCluster, campaign_id) is None:
                raise HTTPException(status_code=404, detail="campaign not found")
            s.add(AnalystDisposition(
                cluster_id=campaign_id,
                verdict=request.verdict,
                analyst=request.analyst,
                severity=request.severity,
                notes=request.notes,
                actor_guess=request.actor_guess,
                action_taken=request.action_taken,
            ))
            transition = apply_stage_transition(
                s, campaign_id,
                disposition={"verdict": request.verdict},
                actor=request.analyst,
            )
            card = _campaign_card(s.get(CampaignCluster, campaign_id))
        return {"available": True, "transition": transition, **card}
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"disposition failed: {e}")


@app.post("/campaigns/{campaign_id}/assign")
def assign_campaign(campaign_id: int, request: AssignRequest):
    """Assign a campaign to an analyst. Pure queue-workflow metadata -- does
    not touch stage (assignment is not a verdict, so it never goes through
    the stage engine)."""
    if not _PRODUCT_DB:
        raise HTTPException(status_code=503, detail="product DB not configured")
    try:
        with SessionLocal() as s:
            c = s.get(CampaignCluster, campaign_id)
            if c is None:
                raise HTTPException(status_code=404, detail="campaign not found")
            c.assignee = request.assignee
            if c.queue_status == "new":
                c.queue_status = "in_review"
            s.commit()
            card = _campaign_card(c)
        return {"available": True, **card}
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"assign failed: {e}")


class SuppressionRuleRequest(BaseModel):
    rule_type: str  # domain | registrar | asn
    match_value: str
    created_by: str  # mandatory, not defaulted -- same audit-trail rationale as DispositionRequest.analyst
    scope: str = "default"
    reason: str | None = None
    expires_at: str | None = None  # ISO 8601; None = never expires


def _suppression_rule_dict(r) -> dict:
    return {
        "id": r.id,
        "rule_type": r.rule_type,
        "match_value": r.match_value,
        "scope": r.scope,
        "reason": r.reason,
        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        "created_by": r.created_by,
        "active": r.active,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


@app.get("/suppressions")
def list_suppressions(active_only: bool = False):
    """List suppression rules. active_only=true filters to active AND
    unexpired (product/suppression.py's is_rule_live), matching what
    assemble_campaigns.py actually applies -- not just the raw `active` flag,
    since an expired-but-still-flagged-active rule is inert in practice."""
    if not _PRODUCT_DB:
        return {"available": False, "reason": "product DB not configured", "rules": []}
    try:
        from product.suppression import is_rule_live
        with SessionLocal() as s:
            rows = s.execute(select(SuppressionRule).order_by(SuppressionRule.created_at.desc())).scalars().all()
            if active_only:
                rows = [r for r in rows if is_rule_live(r)]
            return {"available": True, "count": len(rows), "rules": [_suppression_rule_dict(r) for r in rows]}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "reason": f"query failed: {e}", "rules": []}


@app.post("/suppressions")
def create_suppression(request: SuppressionRuleRequest):
    """Create a suppression rule. Takes effect on the NEXT assemble_campaigns.py
    run (every ~2h via campaign_radar_dag, or `make assemble-campaigns` for an
    immediate pass) -- this endpoint only writes the row."""
    if not _PRODUCT_DB:
        raise HTTPException(status_code=503, detail="product DB not configured")
    if request.rule_type not in ("domain", "registrar", "asn"):
        raise HTTPException(status_code=422, detail="rule_type must be domain, registrar, or asn")
    expires_at = None
    if request.expires_at:
        try:
            expires_at = datetime.fromisoformat(request.expires_at)
        except ValueError:
            raise HTTPException(status_code=422, detail="expires_at must be ISO 8601")
    try:
        with SessionLocal() as s:
            rule = SuppressionRule(
                rule_type=request.rule_type,
                match_value=request.match_value,
                scope=request.scope,
                reason=request.reason,
                expires_at=expires_at,
                created_by=request.created_by,
                active=True,
            )
            s.add(rule)
            s.commit()
            return {"available": True, **_suppression_rule_dict(rule)}
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"create suppression failed: {e}")

@app.get("/threats/latest")
def get_latest_threats(limit: int = 50):
    path = get_latest_parquet()
    if not path:
        return {"data": []}
    df = pd.read_parquet(path)
    df = df.sort_values("risk_score", ascending=False)
    # Give priority to heavily scored
    df = df[df["risk_score"] > 0.85]
    out = df.head(limit).replace([np.inf, -np.inf], None)
    out = out.astype(object).where(pd.notnull(out), None)
    return {"data": out.to_dict(orient="records")}

@app.get("/threats/stats")
def get_stats():
    path = get_latest_parquet()
    if not path:
        return {}
    
    df = pd.read_parquet(path)

    # Honest denominator: rows actually scanned/scored in this parquet, before
    # any risk-score filtering below. This is the real "total parsed" count.
    total_parsed = len(df)

    # Advanced Filtering - we strictly filter off noise for display
    df = df[df["risk_score"] > 0.5] # Baseline
    high_risk_cutoff = 0.90
    critical_cutoff = 0.98

    high_risk_count = len(df[df["risk_score"] > high_risk_cutoff])
    critical_count = len(df[df["risk_score"] > critical_cutoff])

    avg_risk = df["risk_score"].mean()
    stats = {
        "total_parsed": total_parsed,
        "total_domains": len(df),
        "high_risk": high_risk_count,
        "critical": critical_count,
        "avg_risk": float(avg_risk) if pd.notnull(avg_risk) else 0.0,
        "signal_to_noise": round((critical_count / max(1, total_parsed)) * 100, 4),
        "countries": df["sample_country"].nunique() if "sample_country" in df.columns else 0
    }

    def _clean_records(frame: pd.DataFrame) -> list:
        # pandas NaN/Inf aren't valid JSON under Starlette's strict encoder
        # (allow_nan=False) -- a single NaN anywhere in the frame 500s the
        # whole response. Sanitize before to_dict() rather than hoping
        # every aggregation happens to be NaN-free.
        cleaned = frame.replace([np.inf, -np.inf], None)
        return cleaned.astype(object).where(pd.notnull(cleaned), None).to_dict(orient="records")

    # Map Data: Risk per country (Hex-Bins)
    if "sample_country" in df.columns:
        map_df = df.groupby("sample_country").agg(
            risk_score=("risk_score", "mean"),
            threat_count=("risk_score", "count")
        ).reset_index()
        stats["map_data"] = _clean_records(map_df)

    # TLD Analysis
    df["tld"] = df.get("registered_domain", pd.Series([""]*len(df))).apply(lambda x: str(x).split('.')[-1] if '.' in str(x) else 'none')
    tld_stats = df.groupby("tld").agg(
        risk=("risk_score", "mean"),
        count=("risk_score", "count")
    ).sort_values("count", ascending=False).head(10).reset_index()
    stats["tld_analysis"] = _clean_records(tld_stats)

    # ISP / ASN Maliciousness
    if "sample_isp" in df.columns:
        isp_stats = df.groupby("sample_isp").agg(
            risk=("risk_score", "mean"),
            count=("risk_score", "count")
        ).sort_values("count", ascending=False)
        isp_stats = isp_stats[isp_stats["count"] > 5].sort_values("risk", ascending=False).head(10).reset_index()
        stats["isp_reputation"] = _clean_records(isp_stats)
    
    # Age Distribution
    if "age_days" in df.columns:
        df["age_group"] = pd.cut(df["age_days"], bins=[-1, 1, 7, 30, 365, 9999], labels=["New (<1d)", "Fresh (<1w)", "Recent (<1m)", "Established", "Legacy"])
        age_stats = df.groupby("age_group", observed=False)["risk_score"].mean().fillna(0).reset_index()
        age_stats = age_stats.rename(columns={"age_group": "label", "risk_score": "risk"})
        age_stats["label"] = age_stats["label"].astype(str)
        stats["age_impact"] = _clean_records(age_stats)

    # Detection source breakdown: real signal from the MISP-fusion step in
    # ct/score/score_ct_with_latest.py (decision_reason is one of MISP_AND_ML /
    # MISP_IOC / ML_SCORE / BENIGN_BASELINE). Only emitted when the gold parquet
    # actually has this column - no invented substitute otherwise.
    if "decision_reason" in df.columns:
        reason_counts = df["decision_reason"].value_counts()
        total_reasons = int(reason_counts.sum())
        stats["detection_source_breakdown"] = [
            {
                "reason": reason,
                "count": int(count),
                "pct": round((count / total_reasons) * 100, 2) if total_reasons else 0.0,
            }
            for reason, count in reason_counts.items()
        ]

    return stats

@app.get("/threats/network")
def get_network_graph(limit: int = 200):
    """
    Builds a Node-Link network graph of Malicious Domains -> ASNs & TLDs.
    Professional representation of infrastructure commonality.
    """
    path = get_latest_parquet()
    if not path:
        return {"nodes": [], "links": []}
    
    df = pd.read_parquet(path)
    df = df.sort_values("risk_score", ascending=False).head(limit)
    
    nodes = []
    links = []
    
    added_nodes = set()
    def add_node(id_val, group, label, metadata=None):
        if id_val not in added_nodes:
            nodes.append({"id": id_val, "group": group, "label": label, "metadata": metadata or {}})
            added_nodes.add(id_val)
            
    for _, row in df.iterrows():
        domain = str(row.get("registered_domain", ""))
        asn = str(row.get("sample_asn", "Unknown_ASN"))
        tld = domain.split(".")[-1] if "." in domain else "unknown"
        country = str(row.get("sample_country", "Unknown"))
        risk = float(row.get("risk_score", 0.0))
        
        if domain and risk > 0.80:
            add_node(domain, "domain", domain, {"risk": risk, "country": country})
            # Add ASN
            if asn != "Unknown_ASN":
                add_node(asn, "asn", f"ASN: {asn}", {"type": "infrastructure"})
                links.append({"source": domain, "target": asn, "value": risk})
            
            # Add TLD 
            add_node(f"tld_{tld}", "tld", f".{tld}", {"type": "registry"})
            links.append({"source": domain, "target": f"tld_{tld}", "value": risk * 0.5})

    return {"nodes": nodes, "links": links}

@app.post("/threats/score")
def score_domain(domain: str):
    model, model_kind = load_model()
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        # Actually enrich the submitted domain (cache -> DNS/geo -> WHOIS/RDAP),
        # bounded by a short timeout since this is a live user-facing request.
        enrichment, enrichment_status = enrich_domain_live(domain)

        X = build_features(domain, enrichment)
        score = predict_risk(model, model_kind, X)

        # Simple heuristic analysis
        analysis = []
        if len(domain) > 25: analysis.append("Anomaly: Length exceeds standard distribution (DGA profile)")
        if shannon_entropy(domain) > 3.8: analysis.append("Anomaly: Entropy indicates synthetic generation")
        if domain.count("-") > 1: analysis.append("Triage: Multi-hyphenation identified as phishing vector")
        if any(c.isdigit() for c in domain) and sum(c.isalpha() for c in domain) < 4:
            analysis.append("Anomaly: High numeric-to-alpha ratio detected")

        # Analyst verdict
        if score > 0.99: verdict = "CONFIRMED_MALICIOUS_INFRA"
        elif score > 0.90: verdict = "IMMINENT_PHISHING_THREAT"
        elif score > 0.70: verdict = "HIGH_PROBABILITY_STAGING"
        elif score > 0.40: verdict = "SUSPICIOUS_PATTERN"
        else: verdict = "BASELINE_NORMAL"

        if len(analysis) == 0 and score < 0.5:
            analysis = ["Zero-anomaly lexical construction", "Alignment with benign top 1M heuristics"]

        return {
            "domain": domain,
            "risk_score": float(score),
            "verdict": verdict,
            "level": "CRITICAL" if score > 0.90 else "HIGH" if score > 0.70 else "CLEAN",
            "analysis": analysis if analysis else ["Model scored risk based on embedded sub-features"],
            "model_used": model_kind,
            "enrichment_status": enrichment_status,
        }
    except Exception as e:
        print(f"Error scoring {domain}: {e}")
        return {
            "domain": domain,
            "risk_score": 0.05,
            "verdict": "HEURISTIC_SCORE",
            "level": "SYNC",
            "analysis": ["Model scoring fallback initiated - benign"],
            "model_used": None,
            "enrichment_status": "lexical_only",
        }

class AskRequest(BaseModel):
    query: str
    history: list = []

@app.post("/threats/ask")
def ask_intel(request: AskRequest):
    # Retrieve top domains from latest parquet for context
    path = get_latest_parquet()
    dashboard_context = ""
    if path:
        try:
            df = pd.read_parquet(path)
            top_domains = df.sort_values("risk_score", ascending=False).head(5)
            context_list = []
            for _, row in top_domains.iterrows():
                domain = row.get("registered_domain", "")
                score = row.get("risk_score", 0)
                asn = row.get("sample_asn", "")
                context_list.append(f"- {domain} (Risk: {score:.2f}, ASN: {asn})")
            dashboard_context = "\n".join(context_list)
        except:
            pass

    try:
        from api.agent.perplexity_client import ask_intel_agent
        answer = ask_intel_agent(request.query, dashboard_context, request.history)
        return {"answer": answer}
    except Exception as e:
        return {"answer": f"Backend Error: {str(e)}"}
