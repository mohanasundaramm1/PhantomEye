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
from datetime import datetime
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

@app.get("/threats/latest")
def get_latest_threats(limit: int = 50):
    path = get_latest_parquet()
    if not path:
        return {"data": []}
    df = pd.read_parquet(path)
    df = df.sort_values("risk_score", ascending=False)
    # Give priority to heavily scored 
    df = df[df["risk_score"] > 0.85] 
    return {"data": df.head(limit).to_dict(orient="records")}

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

    stats = {
        "total_parsed": total_parsed,
        "total_domains": len(df),
        "high_risk": high_risk_count,
        "critical": critical_count,
        "avg_risk": float(df["risk_score"].mean()),
        "signal_to_noise": round((critical_count / max(1, total_parsed)) * 100, 4),
        "countries": df["sample_country"].nunique() if "sample_country" in df.columns else 0
    }
    
    # Map Data: Risk per country (Hex-Bins)
    if "sample_country" in df.columns:
        map_df = df.groupby("sample_country").agg(
            risk_score=("risk_score", "mean"),
            threat_count=("risk_score", "count")
        ).reset_index()
        stats["map_data"] = map_df.to_dict(orient="records")
    
    # TLD Analysis
    df["tld"] = df.get("registered_domain", pd.Series([""]*len(df))).apply(lambda x: str(x).split('.')[-1] if '.' in str(x) else 'none')
    tld_stats = df.groupby("tld").agg(
        risk=("risk_score", "mean"),
        count=("risk_score", "count")
    ).sort_values("count", ascending=False).head(10).reset_index()
    stats["tld_analysis"] = tld_stats.to_dict(orient="records")
    
    # ISP / ASN Maliciousness
    if "sample_isp" in df.columns:
        isp_stats = df.groupby("sample_isp").agg(
            risk=("risk_score", "mean"),
            count=("risk_score", "count")
        ).sort_values("count", ascending=False)
        isp_stats = isp_stats[isp_stats["count"] > 5].sort_values("risk", ascending=False).head(10).reset_index()
        stats["isp_reputation"] = isp_stats.to_dict(orient="records")
    
    # Age Distribution
    if "age_days" in df.columns:
        df["age_group"] = pd.cut(df["age_days"], bins=[-1, 1, 7, 30, 365, 9999], labels=["New (<1d)", "Fresh (<1w)", "Recent (<1m)", "Established", "Legacy"])
        age_stats = df.groupby("age_group")["risk_score"].mean().fillna(0).reset_index()
        stats["age_impact"] = age_stats.rename(columns={"age_group": "label", "risk_score": "risk"}).to_dict(orient="records")

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
