import os
import glob
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

app = FastAPI(title="Elite CTI Backend")

# Enable CORS for the Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify the actual origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Path to Gold Layer
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(REPO_ROOT, "gold", "threat_scores")

def get_latest_df():
    paths = sorted(glob.glob(os.path.join(DATA_DIR, "ct_scored_*.parquet")))
    if not paths:
        return None
    latest = paths[-1]
    return pd.read_parquet(latest), os.path.basename(latest)

@app.get("/health")
def health():
    return {"status": "operational", "timestamp": datetime.now().isoformat()}

@app.get("/threats/latest")
def get_latest_threats(limit: int = 100):
    df, filename = get_latest_df()
    if df is None:
        raise HTTPException(status_code=404, detail="No threat data found")
    
    # Sort for high risk first
    df = df.sort_values("risk_score", ascending=False).head(limit)
    return {
        "source_file": filename,
        "count": len(df),
        "data": df.to_dict(orient="records")
    }

@app.get("/threats/stats")
def get_stats():
    df, _ = get_latest_df()
    if df is None:
        raise HTTPException(status_code=404, detail="No threat data found")
    
    high_risk = (df["risk_score"] >= 0.90).sum()
    critical = (df["risk_score"] >= 0.98).sum()
    
    stats = {
        "total_domains": len(df),
        "high_risk": int(high_risk),
        "critical": int(critical),
        "avg_risk": float(df["risk_score"].mean()),
        "countries": int(df["sample_country"].nunique()) if "sample_country" in df.columns else 0
    }
    return stats

@app.get("/threats/details/{domain}")
def get_threat_details(domain: str):
    df, _ = get_latest_df()
    if df is None:
        raise HTTPException(status_code=404, detail="No threat data found")
    
    match = df[df["registered_domain"] == domain.lower().strip()]
    if match.empty:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    return match.iloc[0].to_dict()
