#!/usr/bin/env python
"""
ct/analysis/analyze_scored_ct.py

Offline analysis of scored CT data, with a security engineer mindset.

- Loads latest scored CT parquet from gold/threat_scores
- Computes high-level stats (risk distribution, TLD, ASN, country breakdown)
- Builds a feature matrix and runs PCA + KMeans clustering
- Optionally uses UMAP for nicer 2D embeddings if installed
- Saves plots under ct/data/reports and a clustered parquet for drilling down

Usage:
    python ct/analysis/analyze_scored_ct.py

Optional env vars:
    CT_SCORED_DIR   - override scored directory (default: gold/threat_scores)
    CT_SCORED_FILE  - force a specific scored parquet file
"""

import os
import glob
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans

# Optional UMAP (nicer low-dim embeddings for cluster plots)
try:
    import umap
    HAS_UMAP = True
except ImportError:
    HAS_UMAP = False


# ---------- paths ----------

THIS_DIR  = os.path.dirname(__file__)
CT_DIR    = os.path.abspath(os.path.join(THIS_DIR, ".."))
REPO_ROOT = os.path.abspath(os.path.join(CT_DIR, ".."))
DATA_DIR  = os.path.join(CT_DIR, "data")
SCORED_DEFAULT = os.path.join(REPO_ROOT, "gold", "threat_scores")
REPORT_DIR     = os.path.join(DATA_DIR, "reports")

os.makedirs(REPORT_DIR, exist_ok=True)

CT_SCORED_DIR  = os.getenv("CT_SCORED_DIR", SCORED_DEFAULT)
CT_SCORED_FILE = os.getenv("CT_SCORED_FILE")  # optional single-file override
LATEST_SCORED_PTR = os.path.join(CT_SCORED_DIR, "_latest_scored.json")


# ---------- helpers ----------

def resolve_scored_path() -> str:
    """
    Choose which scored CT parquet to analyze.

    Priority:
      1. CT_SCORED_FILE env var (if set and exists)
      2. _latest_scored.json pointer (if present and valid)
      3. Newest ct_scored_*.parquet by filename
    """
    if CT_SCORED_FILE and os.path.exists(CT_SCORED_FILE):
        print("[info] using scored file via CT_SCORED_FILE:", CT_SCORED_FILE)
        return CT_SCORED_FILE

    if os.path.exists(LATEST_SCORED_PTR):
        try:
            import json
            with open(LATEST_SCORED_PTR, "r") as f:
                j = json.load(f)
            p = j.get("path")
            if p and os.path.exists(p):
                print("[info] using scored file via _latest_scored.json:", p)
                return p
        except Exception as e:
            print("[warn] failed to parse _latest_scored.json:", e)

    pattern = os.path.join(CT_SCORED_DIR, "ct_scored_*.parquet")
    paths = sorted(glob.glob(pattern))
    if not paths:
        raise SystemExit(f"[error] no ct_scored_*.parquet files under {CT_SCORED_DIR}")
    latest = paths[-1]
    print(f"[info] using newest scored file by name: {latest}")
    return latest


def safe_quantile(series, q):
    try:
        return float(series.quantile(q))
    except Exception:
        return np.nan


# ---------- high-level descriptive analysis ----------

def basic_overview(df: pd.DataFrame):
    """
    Print headline metrics a staff security engineer would care about.
    """
    print("\n=== CT scored overview ===")
    print(f"rows: {len(df)}")

    if "event_ts" in df.columns:
        try:
            ts = pd.to_datetime(df["event_ts"], utc=True, errors="coerce")
            print("event_ts window:", ts.min(), "→", ts.max())
        except Exception:
            pass

    # Risk label distribution
    if "risk_label" in df.columns:
        counts = df["risk_label"].value_counts(dropna=False).sort_index()
        print("\nRisk label distribution (0=benign-ish, 1=high risk):")
        print(counts)
        frac_high = counts.get(1, 0) / max(len(df), 1)
        print(f"fraction high-risk: {frac_high:.3%}")

    # Risk score basic stats
    if "risk_score" in df.columns:
        rs = df["risk_score"]
        print("\nRisk score summary:")
        print(
            f"min={rs.min():.3f}, "
            f"p50={safe_quantile(rs, 0.5):.3f}, "
            f"p90={safe_quantile(rs, 0.9):.3f}, "
            f"p99={safe_quantile(rs, 0.99):.3f}, "
            f"max={rs.max():.3f}"
        )

    # Top TLDs by high-risk hit rate
    if "registered_domain" in df.columns:
        df["tld"] = df["registered_domain"].str.split(".").str[-1]
    elif "domain_sample" in df.columns:
        df["tld"] = df["domain_sample"].str.split(".").str[-1]

    if "tld" in df.columns and "risk_label" in df.columns:
        tld_stats = (
            df.groupby("tld")["risk_label"]
            .agg(["count", "mean"])
            .rename(columns={"count": "n", "mean": "high_risk_rate"})
            .sort_values("high_risk_rate", ascending=False)
        )
        print("\nTop TLDs by high-risk rate (min 20 observations):")
        print(tld_stats[tld_stats["n"] >= 20].head(15))

    # Top ASNs by risk
    if "sample_asn" in df.columns and "risk_score" in df.columns:
        asn_stats = (
            df.dropna(subset=["sample_asn"])
            .groupby("sample_asn")["risk_score"]
            .agg(["count", "mean"])
            .rename(columns={"count": "n", "mean": "avg_risk_score"})
            .sort_values("avg_risk_score", ascending=False)
        )
        print("\nTop ASNs by average risk_score (min 20 domains):")
        print(asn_stats[asn_stats["n"] >= 20].head(15))

    # Countries
    if "sample_country" in df.columns and "risk_label" in df.columns:
        country_stats = (
            df.dropna(subset=["sample_country"])
            .groupby("sample_country")["risk_label"]
            .agg(["count", "mean"])
            .rename(columns={"count": "n", "mean": "high_risk_rate"})
            .sort_values("high_risk_rate", ascending=False)
        )
        print("\nCountries with elevated high-risk rates (min 20 domains):")
        print(country_stats[country_stats["n"] >= 20].head(15))


# ---------- plotting helpers ----------

def savefig(path: str, title: str = None):
    if title:
        plt.title(title)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    print("[info] saved plot:", path)
    plt.close()


def plot_distributions(df: pd.DataFrame, outdir: str):
    """
    Univariate and simple bivariate views.
    """
    sns.set(style="whitegrid")

    # Risk score histogram
    if "risk_score" in df.columns:
        plt.figure(figsize=(8, 4))
        sns.histplot(df["risk_score"], bins=50, kde=True)
        savefig(os.path.join(outdir, "risk_score_hist.png"), "Risk score distribution")

        if "risk_label" in df.columns:
            plt.figure(figsize=(8, 4))
            sns.histplot(
                data=df, x="risk_score", hue="risk_label",
                bins=50, kde=True, stat="density", common_norm=False
            )
            savefig(
                os.path.join(outdir, "risk_score_hist_by_label.png"),
                "Risk score by label",
            )

    # TLD vs high-risk rate
    if "tld" in df.columns and "risk_label" in df.columns:
        tld_stats = (
            df.groupby("tld")["risk_label"]
            .agg(["count", "mean"])
            .rename(columns={"count": "n", "mean": "high_risk_rate"})
        )
        tld_stats = tld_stats[tld_stats["n"] >= 20].sort_values(
            "high_risk_rate", ascending=False
        ).head(20)

        plt.figure(figsize=(10, 5))
        sns.barplot(
            data=tld_stats.reset_index(),
            x="tld",
            y="high_risk_rate",
        )
        plt.xticks(rotation=45, ha="right")
        savefig(
            os.path.join(outdir, "tld_high_risk_rate.png"),
            "Top TLDs by high-risk rate (n>=20)",
        )

    # Countries with high-risk rates
    if "sample_country" in df.columns and "risk_label" in df.columns:
        country_stats = (
            df.dropna(subset=["sample_country"])
            .groupby("sample_country")["risk_label"]
            .agg(["count", "mean"])
            .rename(columns={"count": "n", "mean": "high_risk_rate"})
        )
        country_stats = country_stats[country_stats["n"] >= 20].sort_values(
            "high_risk_rate", ascending=False
        ).head(20)

        plt.figure(figsize=(10, 5))
        sns.barplot(
            data=country_stats.reset_index(),
            x="sample_country",
            y="high_risk_rate",
        )
        plt.xticks(rotation=45, ha="right")
        savefig(
            os.path.join(outdir, "country_high_risk_rate.png"),
            "Countries by high-risk rate (n>=20)",
        )


# ---------- clustering & embeddings ----------

def build_feature_matrix_for_clustering(df: pd.DataFrame):
    """
    Build a feature matrix focused on DNS + risk + WHOIS-ish numeric features.
    This is intentionally a smaller subset than the model uses.
    """
    candidate_cols = [
        "risk_score",
        "risk_score_logreg",
        "num_unique_ips",
        "has_ipv6",
        "num_countries",
        "num_asns",
        "age_days",
        "days_to_expiry",
        "created_isnull",
        "expires_isnull",
        "has_error",
    ]

    cols = [c for c in candidate_cols if c in df.columns]
    if not cols:
        raise SystemExit("[error] no suitable numeric columns found for clustering.")

    X = df[cols].copy()
    X = X.fillna(0.0).astype(float)
    print("[info] clustering feature columns:", cols)
    return X, cols


def compute_embedding_and_clusters(X: pd.DataFrame, n_clusters: int = 6):
    """
    Standardize, reduce dimensionality with PCA (and optionally UMAP),
    and perform KMeans clustering in the reduced space.
    """
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X.values)

    # PCA to 10 dimensions
    pca = PCA(n_components=min(10, X_scaled.shape[1]))
    X_pca = pca.fit_transform(X_scaled)
    print("[info] PCA explained_variance_ratio_:", pca.explained_variance_ratio_)

    # Low-dimensional embedding for visualization
    if HAS_UMAP:
        reducer = umap.UMAP(
            n_neighbors=30,
            min_dist=0.1,
            metric="euclidean",
            random_state=42,
        )
        embedding = reducer.fit_transform(X_pca)
        method = "UMAP"
    else:
        # fallback: just use first two PCs
        embedding = X_pca[:, :2]
        method = "PCA-2D"

    # KMeans clustering on PCA space
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init="auto")
    clusters = kmeans.fit_predict(X_pca)

    print(f"[info] computed {n_clusters} clusters using KMeans on PCA space")
    return embedding, clusters, method


def plot_clusters(df: pd.DataFrame, outdir: str, method: str):
    """
    Scatter plots of the 2D embedding, colored by:
      - cluster id
      - risk_label (if present)
    """
    sns.set(style="white", rc={"figure.figsize": (8, 6)})

    if {"embed_x", "embed_y", "cluster"}.issubset(df.columns):
        plt.figure()
        sns.scatterplot(
            data=df.sample(min(len(df), 5000), random_state=42),
            x="embed_x",
            y="embed_y",
            hue="cluster",
            s=10,
            linewidth=0,
            palette="tab10",
        )
        savefig(
            os.path.join(outdir, "clusters_by_cluster.png"),
            f"{method} embedding, colored by cluster",
        )

    if {"embed_x", "embed_y", "risk_label"}.issubset(df.columns):
        plt.figure()
        sns.scatterplot(
            data=df.sample(min(len(df), 5000), random_state=42),
            x="embed_x",
            y="embed_y",
            hue="risk_label",
            s=10,
            linewidth=0,
            palette="coolwarm",
        )
        savefig(
            os.path.join(outdir, "clusters_by_risk_label.png"),
            f"{method} embedding, colored by risk_label",
        )


def describe_clusters(df: pd.DataFrame):
    """
    Print per-cluster summary: size, average risk, and some interpretable stats.
    """
    if "cluster" not in df.columns:
        print("[warn] no cluster column present; skipping cluster summary.")
        return

    print("\n=== Cluster-level summary ===")
    group_cols = ["cluster"]
    agg_dict = {
        "risk_score": ["count", "mean", "max"],
    }

    for col in ["num_unique_ips", "num_countries", "age_days", "days_to_expiry"]:
        if col in df.columns:
            agg_dict[col] = ["mean"]

    summary = df.groupby(group_cols).agg(agg_dict)
    summary.columns = ["_".join(col).strip() for col in summary.columns.values]
    summary = summary.sort_values("risk_score_mean", ascending=False)
    print(summary)

    # Give a few top examples per cluster
    if "registered_domain" in df.columns:
        print("\nSample high-risk domains per cluster:")
        for cluster_id in sorted(df["cluster"].unique()):
            sub = df[df["cluster"] == cluster_id].sort_values(
                "risk_score", ascending=False
            )
            print(f"\nCluster {cluster_id}:")
            for _, row in sub.head(5).iterrows():
                dom = row.get("registered_domain") or row.get("domain_sample")
                rs = row.get("risk_score", np.nan)
                cc = row.get("sample_country", None)
                asn = row.get("sample_asn", None)
                print(f"  {dom:50s}  risk={rs:.3f}  cc={cc}  asn={asn}")


# ---------- main ----------

def main():
    scored_path = resolve_scored_path()
    df = pd.read_parquet(scored_path)
    print(f"[info] loaded scored CT: {scored_path} (rows={len(df)})")

    # Ensure we have TLD derived
    if "registered_domain" in df.columns and "tld" not in df.columns:
        df["tld"] = df["registered_domain"].astype(str).str.split(".").str[-1]

    # 1) High-level descriptive stats
    basic_overview(df)

    # 2) Distribution plots
    plot_distributions(df, REPORT_DIR)

    # 3) Clustering & embeddings
    X, feat_cols = build_feature_matrix_for_clustering(df)
    embedding, clusters, method = compute_embedding_and_clusters(X)

    df["cluster"] = clusters
    df["embed_x"] = embedding[:, 0]
    df["embed_y"] = embedding[:, 1]

    # 4) Cluster-level plots
    plot_clusters(df, REPORT_DIR, method)
    describe_clusters(df)

    # 5) Save enriched/clustered dataset for further investigation
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_parquet = os.path.join(REPORT_DIR, f"ct_scored_clustered_{ts}.parquet")
    df.to_parquet(out_parquet, index=False)
    print(f"\n[info] wrote clustered scored CT to: {out_parquet}")
    print("[info] analysis complete. Inspect PNGs under:", REPORT_DIR)


if __name__ == "__main__":
    main()
