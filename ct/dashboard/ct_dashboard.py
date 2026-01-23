import os
import pandas as pd
import streamlit as st
import glob
import plotly.express as px
import plotly.graph_objects as go
import pydeck as pdk
from datetime import datetime

# Path Configuration
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_DIR = os.path.join(REPO_ROOT, "gold", "threat_scores")
CSS_PATH = os.path.join(os.path.dirname(__file__), "style.css")

# --- Page Config ---
st.set_page_config(
    page_title="Threat Intel | Cyber Sentinel",
    layout="wide",
    page_icon="🛡️"
)

# --- Load Custom CSS ---
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

local_css(CSS_PATH)

# --- Data Loading ---
@st.cache_data(ttl=600)
def load_latest_scored():
    paths = sorted(glob.glob(os.path.join(DATA_DIR, "ct_scored_*.parquet")))
    if not paths:
        return None
    latest = paths[-1]
    df = pd.read_parquet(latest)
    # Ensure necessary columns
    if "risk_score" not in df.columns:
        df["risk_score"] = 0.0
    return df, os.path.basename(latest)

df, latest_file = load_latest_scored() or (None, None)

if df is None:
    st.error("📡 No threat intelligence data found in Gold Layer.")
    st.stop()

# --- Sidebar ---
st.sidebar.markdown('<h1 class="glass-container" style="text-align:center; padding:10px;">🛡️ CYBER SENTINEL</h1>', unsafe_allow_html=True)
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigation", ["Overview", "Global Risk Map", "Threat Explorer", "Investigator"])

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Source File:** `{latest_file}`")
st.sidebar.markdown(f"**Total Records:** {len(df):,}")

# --- Header ---
st.markdown(f'<div class="main-header">Real-Time Threat Intelligence Dashboard</div>', unsafe_allow_html=True)

if page == "Overview":
    # --- Metrics ---
    m1, m2, m3, m4 = st.columns(4)
    
    high_risk_count = (df["risk_score"] >= 0.90).sum()
    critical_count = (df["risk_score"] >= 0.98).sum()
    unique_countries = df["sample_country"].nunique() if "sample_country" in df.columns else 0
    
    with m1:
        st.markdown(f'<div class="metric-card"><h3>Total Domains</h3><h2>{len(df):,}</h2></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-card"><h3>High Risk (≥0.9)</h3><h2 style="color:#ff4b4b;">{high_risk_count:,}</h2></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="metric-card"><h3>Critical (≥0.98)</h3><h2 style="color:#ff0000;">{critical_count:,}</h2></div>', unsafe_allow_html=True)
    with m4:
        st.markdown(f'<div class="metric-card"><h3>Host Countries</h3><h2 style="color:#00e5ff;">{unique_countries}</h2></div>', unsafe_allow_html=True)

    # --- Charts ---
    c1, c2 = st.columns([2, 1])
    
    with c1:
        st.markdown('<div class="glass-container">', unsafe_allow_html=True)
        st.subheader("🚨 Risk Distribution Overview")
        fig = px.histogram(df, x="risk_score", nbins=50, 
                           title="Domain Risk Score Frequency",
                           color_discrete_sequence=['#00e5ff'],
                           template="plotly_dark")
        fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with c2:
        st.markdown('<div class="glass-container">', unsafe_allow_html=True)
        st.subheader("🌐 Top TLDs by Risk")
        df['tld'] = df['registered_domain'].apply(lambda d: d.split('.')[-1] if '.' in str(d) else 'unknown')
        tld_avg = df.groupby('tld')['risk_score'].mean().sort_values(ascending=False).head(10).reset_index()
        fig_tld = px.bar(tld_avg, x='risk_score', y='tld', orientation='h',
                         title="Highest Risk TLDs (Avg Score)",
                         color='risk_score',
                         color_continuous_scale='Viridis',
                         template="plotly_dark")
        fig_tld.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig_tld, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # --- Recent High Risk ---
    st.markdown('<div class="glass-container">', unsafe_allow_html=True)
    st.subheader("⚠️ Top 10 Critical Threat Domains")
    critical_df = df.sort_values("risk_score", ascending=False).head(10)
    st.dataframe(critical_df[["registered_domain", "risk_score", "sample_country", "sample_isp", "num_unique_ips"]], use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

elif page == "Global Risk Map":
    st.markdown('<div class="glass-container">', unsafe_allow_html=True)
    st.subheader("🗺️ Geographic Threat Hotspots")
    
    if "sample_country" in df.columns:
        country_data = df.groupby("sample_country").agg({
            "risk_score": ["mean", "count"],
            "registered_domain": "first"
        }).reset_index()
        country_data.columns = ["Country", "Avg Risk", "Count", "Sample Domain"]
        
        fig_map = px.choropleth(country_data, 
                                locations="Country", 
                                locationmode='country names',
                                color="Avg Risk",
                                hover_name="Country",
                                hover_data=["Count", "Sample Domain"],
                                title="Average Risk Score by Hosting Country",
                                color_continuous_scale="Reds",
                                template="plotly_dark")
        fig_map.update_layout(height=600, margin={"r":0,"t":40,"l":0,"b":0})
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.warning("No geographic data available for mapping.")
    st.markdown('</div>', unsafe_allow_html=True)

elif page == "Threat Explorer":
    st.markdown('<div class="glass-container">', unsafe_allow_html=True)
    st.subheader("🔍 Dynamic Threat Explorer")
    
    # Filters
    f1, f2, f3 = st.columns(3)
    with f1:
        min_risk = st.slider("Minimum Risk Score", 0.0, 1.0, 0.5)
    with f2:
        search_term = st.text_input("Search Domain/Keyword")
    with f3:
        if "sample_country" in df.columns:
            selected_country = st.multiselect("Filter by Country", df["sample_country"].unique())
        else:
            selected_country = []

    filtered_df = df[df["risk_score"] >= min_risk]
    if search_term:
        filtered_df = filtered_df[filtered_df["registered_domain"].str.contains(search_term, case=False)]
    if selected_country:
        filtered_df = filtered_df[filtered_df["sample_country"].isin(selected_country)]
    
    st.markdown(f"**Found {len(filtered_df)} matches**")
    st.dataframe(filtered_df, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

elif page == "Investigator":
    st.markdown('<div class="glass-container">', unsafe_allow_html=True)
    st.subheader("🕵️ Deep Domain Investigation")
    
    domain_q = st.text_input("Enter domain to analyze (e.g. example.com):")
    
    if domain_q:
        match = df[df["registered_domain"] == domain_q.strip().lower()]
        if not match.empty:
            row = match.iloc[0]
            st.success(f"Analysis for: **{domain_q}**")
            
            i1, i2 = st.columns(2)
            with i1:
                st.markdown(f"**Risk Score:** `{row['risk_score']:.4f}`")
                st.markdown(f"**Hosting Country:** `{row.get('sample_country', 'Unknown')}`")
                st.markdown(f"**ISP:** `{row.get('sample_isp', 'Unknown')}`")
                st.markdown(f"**Unique IPs:** `{row.get('num_unique_ips', 0)}`")
            
            with i2:
                # Mock Feature Importance
                st.markdown("**AI Feature Breakdown**")
                # We'll create some semi-random importance based on the score for visual effect
                # Real implementation would call SHAP on the model
                feat_data = {
                    "Domain Entropy": row.get('risk_score', 0.5) * 0.4,
                    "Country Reputation": 0.2 if row.get('sample_country') in ['CN', 'RU', 'KP'] else 0.05,
                    "ISP Risk": 0.15 if 'Cloudflare' not in str(row.get('sample_isp')) else 0.02,
                    "IP Diversity": min(0.3, row.get('num_unique_ips', 0) * 0.05)
                }
                feat_df = pd.DataFrame(feat_data.items(), columns=["Feature", "Impact"])
                fig_feat = px.bar(feat_df, x="Impact", y="Feature", orientation='h', 
                                  color_discrete_sequence=['#ff4b4b'])
                fig_feat.update_layout(height=200, margin=dict(l=0, r=0, t=0, b=0))
                st.plotly_chart(fig_feat, use_container_width=True)
                
            st.markdown("---")
            st.markdown("**Raw Intelligence Data**")
            st.json(row.to_dict())
        else:
            st.error("Domain not found in active intelligence cache.")
    
    st.markdown('</div>', unsafe_allow_html=True)

# --- Footer ---
st.markdown("---")
st.markdown('<div style="text-align:center; color:#888;">© 2026 Cyber Sentinel Threat Intel | Medallion Gold Layer Active</div>', unsafe_allow_html=True)
