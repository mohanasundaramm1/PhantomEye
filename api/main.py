from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import glob
import os
import joblib
import numpy as np
import tldextract
import math
from datetime import datetime
from collections import Counter
from sklearn.feature_extraction.text import HashingVectorizer

app = FastAPI(title="Phantom Eye CTI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

GOLD_DIR = "gold/threat_scores"
MODEL_PATH = "ml/models/registry/ct_risk_logreg_full_latest.joblib"

# Global model cache
MODEL = None
CHAR_VECT = HashingVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    n_features=4096,
    lowercase=True,
    alternate_sign=False,
)

def load_model():
    global MODEL
    if MODEL is None and os.path.exists(MODEL_PATH):
        try:
            MODEL = joblib.load(MODEL_PATH)
            # Ensure model has expected attributes for scoring (fix for sklearn version mismatch)
            if not hasattr(MODEL, 'classes_'):
                MODEL.classes_ = np.array([0, 1])
        except:
            pass
    return MODEL

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def extract_lexical(domain: str):
    d = domain.lower().strip()
    feats = {}
    feats["len"] = len(d)
    feats["digits"] = sum(ch.isdigit() for ch in d)
    feats["hyphens"] = d.count("-")
    feats["dots"] = d.count(".")
    feats["digit_ratio"] = feats["digits"] / (feats["len"] + 1e-6)
    feats["hyphen_ratio"] = feats["hyphens"] / (feats["len"] + 1e-6)
    feats["entropy"] = shannon_entropy(d)
    feats["xn_punycode"] = int("xn--" in d)
    parts = d.split(".")
    feats["labels"] = len([p for p in parts if p])
    feats["tld_len"] = len(parts[-1]) if parts else 0
    
    # Vectorize
    X_char = CHAR_VECT.transform([d])
    
    # Static numeric feats
    S = np.array([[feats[k] for k in ["len", "digits", "hyphens", "dots", "digit_ratio", "hyphen_ratio", "entropy", "xn_punycode", "labels", "tld_len"]]])
    
    # Combine (just lexical part of the full model for real-time)
    from scipy.sparse import hstack, csr_matrix
    X_lex = hstack([X_char, csr_matrix(S)])
    X_pad = csr_matrix((1, 4 + 256 + 5))
    X_full = hstack([X_lex, X_pad]).tocsr()
    
    return X_full

def get_latest_parquet():
    files = glob.glob(f"{GOLD_DIR}/*.parquet")
    if not files:
        return None
    return max(files, key=os.path.getmtime)

@app.get("/health")
def health():
    return {"status": "operational", "timestamp": datetime.now().isoformat()}

@app.get("/threats/latest")
def get_latest_threats(limit: int = 50):
    path = get_latest_parquet()
    if not path:
        return {"data": []}
    df = pd.read_parquet(path)
    df = df.sort_values("risk_score", ascending=False)
    return {"data": df.head(limit).to_dict(orient="records")}

@app.get("/threats/stats")
def get_stats():
    path = get_latest_parquet()
    if not path:
        return {"total_domains": 0, "high_risk": 0, "critical": 0, "avg_risk": 0, "map_data": []}
    
    df = pd.read_parquet(path)
    
    # Precise Analyst Thresholds
    # In a professional setting, we only alert on >0.90 (High) and >0.98 (Critical)
    # The 0.70 range is "Baseline Noise" or "Initial Triage"
    high_risk_cutoff = 0.90
    critical_cutoff = 0.99
    
    stats = {
        "total_domains": len(df),
        "high_risk": len(df[df["risk_score"] > high_risk_cutoff]),
        "critical": len(df[df["risk_score"] > critical_cutoff]),
        "avg_risk": float(df["risk_score"].mean()),
        "signal_to_noise": round((len(df[df["risk_score"] > 0.85]) / len(df)) * 100, 1),
        "countries": df["sample_country"].nunique() if "sample_country" in df.columns else 0
    }
    
    # Map Data: Risk per country
    if "sample_country" in df.columns:
        map_df = df.groupby("sample_country").agg(
            risk_score=("risk_score", "mean"),
            threat_count=("risk_score", "count")
        ).reset_index()
        stats["map_data"] = map_df.to_dict(orient="records")
    
    # TLD Analysis
    df["tld"] = df["registered_domain"].apply(lambda x: x.split('.')[-1] if '.' in str(x) else 'none')
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

    return stats

@app.post("/threats/score")
def score_domain(domain: str):
    model = load_model()
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        X = extract_lexical(domain)
        # Use decision_function or manual sigmoid if predict_proba is being difficult 
        # but classes_ fix above should handle it.
        score = model.predict_proba(X)[0, 1]
        
        # Simple heuristic analysis
        analysis = []
        if len(domain) > 25: analysis.append("Anomaly: Length exceeds standard distribution")
        if shannon_entropy(domain) > 4.2: analysis.append("Anomaly: Entropy indicates synthetic generation (DGA)")
        if domain.count("-") > 1: analysis.append("Triage: Multi-hyphenation identified as phishing vector")
        
        # Analyst verdict
        if score > 0.99: verdict = "CONFIRMED_MALICIOUS_INFRA"
        elif score > 0.95: verdict = "IMMINENT_PHISHING_THREAT"
        elif score > 0.85: verdict = "HIGH_PROBABILITY_STAGING"
        elif score > 0.70: verdict = "SUSPICIOUS_PATTERN"
        else: verdict = "BASELINE_NORMAL"
        
        return {
            "domain": domain,
            "risk_score": float(score),
            "verdict": verdict,
            "level": "CRITICAL" if score > 0.95 else "HIGH" if score > 0.85 else "CLEAN",
            "analysis": analysis if analysis else ["Zero-anomaly lexical construction"]
        }
    except Exception as e:
        # Fallback if predict_proba fails due to some obscure sklearn error
        try:
            val = model.decision_function(X)[0]
            score = 1 / (1 + np.exp(-val)) # Sigmoid
            return {
                "domain": domain,
                "risk_score": float(score),
                "verdict": "HEURISTIC_SCORE",
                "level": "SYNC",
                "analysis": ["Model scoring fallback initiated"]
            }
        except:
            raise HTTPException(status_code=500, detail=f"Scoring Engine Failure: {str(e)}")
