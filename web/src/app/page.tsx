"use client";

import React, { useState, useEffect, useRef, useMemo } from "react";
import {
  Shield, Activity, Globe, Search, AlertTriangle,
  Terminal as TerminalIcon, ChevronRight, Zap, Target,
  Database, Cpu, Wifi, Lock, Eye, BarChart3, Radio,
  Server, HardDrive, Map as MapIcon, Crosshair, ArrowDown, Info,
  Layers, Clock, Fingerprint, BarChart, TrendingUp, Filter
} from "lucide-react";
import { motion, AnimatePresence, useScroll, useTransform } from "framer-motion";
import {
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, AreaChart, Area, LineChart, Line,
  BarChart as ReBarChart, Bar, Cell,
  PieChart, Pie
} from 'recharts';
import dynamic from 'next/dynamic';
import { scaleLinear } from "d3-scale";

// Dynamic import for 3D Globe to avoid SSR issues
const TacticalGlobe = dynamic(() => import('@/components/TacticalGlobe'), { ssr: false });
const NetworkGraph = dynamic(() => import('@/components/NetworkGraph'), { ssr: false });
const IntelChat = dynamic(() => import('@/components/IntelChat'), { ssr: false });

// --- Types ---
interface Threat {
  registered_domain: string;
  risk_score: number;
  sample_country: string;
  sample_isp: string;
}

interface MapData {
  sample_country: string;
  risk_score: number;
  threat_count: number;
}

interface AnalystMetric {
  tld?: string;
  sample_isp?: string;
  risk: number;
  count: number;
  label?: string;
}

interface Stats {
  total_parsed: number;
  total_domains: number;
  high_risk: number;
  critical: number;
  avg_risk: number;
  signal_to_noise: number;
  countries: number;
  map_data: MapData[];
  tld_analysis: AnalystMetric[];
  isp_reputation: AnalystMetric[];
  age_impact: AnalystMetric[];
  detection_source_breakdown?: { reason: string, count: number, pct: number }[];
}

// Mirrors the GET /campaigns queue-card contract (api/main.py _campaign_card).
interface Campaign {
  campaign_id: number;
  target_brand: string | null;
  target_workflow: string | null;
  stage: string;
  status: string;
  confidence_score: number | null;
  member_count: number;
  first_seen: string | null;
  last_seen: string | null;
  freshness_age_minutes: number | null;
  summary_reason: string | null;
  queue_status: string | null;
  assignee: string | null;
  sla_bucket: string | null;
  stage_locked_by: string | null;
  stage_locked_at: string | null;
}

interface CampaignDomain {
  raw_host: string;
  registered_domain: string | null;
  risk_score: number | null;
  decision_reason: string | null;
  enrichment_level: string | null;
  registrar: string | null;
  sample_country: string | null;
  sample_asn: string | null;
  event_ts: string | null;
}

interface CampaignDetail extends Campaign {
  domains: CampaignDomain[];
}

// Mirrors GET /health/pipeline — real freshness/DB/watchdog state, the
// observability layer over the already-self-healing ingest (ops/launchd).
interface PipelineHealth {
  healthy: boolean;
  app_db: { reachable: boolean };
  ct_raw: { newest_age_hours: number | null };
  scoring: { newest_scored_age_hours: number | null };
  model: { created_utc: string | null; promoted: boolean | null };
  ingest_watchdog: { stale?: boolean | null; last_checked_utc?: string; note?: string; available?: boolean };
}

// Mirrors ml/models/registry/ct_risk_meta_latest.json via GET /model/status —
// real training/promotion metadata, not a marketing claim.
interface ModelStatus {
  available: boolean;
  reason?: string;
  created_utc?: string;
  n_rows?: number;
  n_pos?: number;
  n_neg?: number;
  promotion_decision?: {
    promote: boolean;
    reason: string;
    checked_utc?: string;
  };
}

// --- Configuration ---
// Backend base URL — override with NEXT_PUBLIC_API_BASE (e.g. for non-localhost
// or IPv4-only environments); defaults to localhost:8000 for local dev.
const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";
const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

// decision_reason values emitted by the MISP-fusion step in
// ct/score/score_ct_with_latest.py — real detection provenance, not attribution.
const SOURCE_LABELS: Record<string, string> = {
  MISP_AND_ML: "MISP + ML",
  MISP_IOC: "MISP IOC",
  ML_SCORE: "ML score",
  BENIGN_BASELINE: "Benign baseline",
};
const SOURCE_COLORS: Record<string, string> = {
  MISP_AND_ML: "#ff0000",
  MISP_IOC: "#ff8800",
  ML_SCORE: "#00ffff",
  BENIGN_BASELINE: "#333333",
};

const nameMapping: { [key: string]: string } = {
  "United States": "United States of America",
  "The Netherlands": "Netherlands",
  "Russia": "Russia",
};

const STAGE_COLORS: Record<string, string> = {
  new: "text-white/50 bg-white/5",
  warming: "text-yellow-400 bg-yellow-400/10",
  active: "text-cyan-400 bg-cyan-400/10",
  confirmed: "text-tactical-red bg-tactical-red/10",
  suppressed: "text-white/20 bg-white/5",
};

function formatFreshness(minutes: number | null): string {
  if (minutes == null) return "unknown";
  if (minutes < 60) return `${Math.round(minutes)}m ago`;
  if (minutes < 1440) return `${(minutes / 60).toFixed(1)}h ago`;
  return `${(minutes / 1440).toFixed(1)}d ago`;
}

// --- Specialized Components ---

const SectionHeader = ({ title, subtitle, icon: Icon }: { title: string, subtitle: string, icon: any }) => (
  <div className="flex flex-col gap-4 mb-12">
    <div className="flex items-center gap-4">
      <div className="p-3 border border-tactical-red/30 bg-tactical-red/5">
        <Icon className="w-8 h-8 text-tactical-red" />
      </div>
      <div>
        <h2 className="text-3xl font-black tracking-[0.3em] italic uppercase text-glow-red">{title}</h2>
        <div className="h-1 w-24 bg-tactical-red mt-2" />
      </div>
    </div>
    <p className="max-w-2xl text-white/40 text-[12px] font-bold tracking-widest leading-relaxed uppercase italic">
      {subtitle}
    </p>
  </div>
);

const TacticalCard = ({ title, children, className = "", status = "ONLINE", subTitle = "" }: { title: string, children: React.ReactNode, className?: string, status?: string, subTitle?: string }) => (
  <div className={`tactical-border p-6 flex flex-col group ${className} relative overflow-hidden bg-[#080808]/50 backdrop-blur-xl transition-all hover:bg-[#0a0a0a]/80 shadow-[inset_0_0_20px_rgba(0,0,0,0.5)]`}>
    <div className="flex justify-between items-start mb-5 border-b border-white/10 pb-3 relative z-10">
      <div className="flex flex-col">
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 bg-tactical-red animate-pulse" />
          <span className="text-[10px] uppercase tracking-[0.4em] font-black text-white/60">{title}</span>
        </div>
        {subTitle && <span className="text-[8px] text-white/20 font-bold uppercase mt-1 tracking-widest">{subTitle}</span>}
      </div>
      <span className="text-[8px] text-cyan-400 font-bold tracking-widest bg-cyan-400/10 px-2 py-0.5">{status}</span>
    </div>
    <div className="relative flex-1 z-10 min-h-0">
      {children}
    </div>
  </div>
);

// --- Main Application ---

export default function PhantomEyeAdvancedDashboard() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [network, setNetwork] = useState<any>(null);
  const [modelStatus, setModelStatus] = useState<ModelStatus | null>(null);
  const [mounted, setMounted] = useState(false);

  // Campaign Queue state — the analyst-grade "bring your own brand" surface.
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null);
  const [pipelineHealth, setPipelineHealth] = useState<PipelineHealth | null>(null);
  const [brandFilter, setBrandFilter] = useState<string | null>(null);
  const [expandedCampaignId, setExpandedCampaignId] = useState<number | null>(null);
  const [campaignDetail, setCampaignDetail] = useState<CampaignDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Analyst workflow state: no auth in this system, so the analyst identity
  // that goes on every disposition/assignment IS the audit trail — persisted
  // locally so it's not retyped every action, but always explicit (never a
  // silent server-side default; see api/main.py's DispositionRequest).
  const [analystName, setAnalystName] = useState("");
  const [dispositionNotes, setDispositionNotes] = useState("");
  const [assigneeInput, setAssigneeInput] = useState("");
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    const saved = window.localStorage.getItem("phantomeye_analyst_name");
    if (saved) setAnalystName(saved);
  }, []);
  useEffect(() => {
    if (analystName) window.localStorage.setItem("phantomeye_analyst_name", analystName);
  }, [analystName]);

  // Real-time Scanner State
  const [scanTarget, setScanTarget] = useState("");
  const [scanResult, setScanResult] = useState<any>(null);
  const [isScanning, setIsScanning] = useState(false);

  const scannerRef = useRef<HTMLDivElement>(null);

  const { scrollYProgress } = useScroll();
  const opacity = useTransform(scrollYProgress, [0, 0.1], [1, 0]);

  useEffect(() => {
    setMounted(true);
    async function fetchData() {
      try {
        const [threatRes, statsRes, networkRes, campaignsRes, healthRes] = await Promise.all([
          fetch(`${API_BASE}/threats/latest?limit=50`),
          fetch(`${API_BASE}/threats/stats`),
          fetch(`${API_BASE}/threats/network`),
          fetch(`${API_BASE}/campaigns?limit=50`),
          fetch(`${API_BASE}/health/pipeline`),
        ]);
        // Skip this cycle on any bad response — keep last-good data rather than
        // poisoning state with an error body (e.g. {detail:"Not Found"}).
        if (!threatRes.ok || !statsRes.ok || !networkRes.ok) {
          console.error("Sync skipped — backend status:", threatRes.status, statsRes.status, networkRes.status);
          return;
        }
        const threatData = await threatRes.json();
        const statsData = await statsRes.json();
        const networkData = await networkRes.json();
        if (Array.isArray(threatData?.data)) setThreats(threatData.data);
        if (statsData && typeof statsData.total_parsed === "number") setStats(statsData);
        if (networkData && Array.isArray(networkData.nodes)) setNetwork(networkData);
        // Campaign queue + pipeline health are additive surfaces — a bad/absent
        // response (e.g. product DB not configured) must not block the rest of
        // the dashboard, so these are checked independently rather than folded
        // into the guard above.
        if (campaignsRes.ok) {
          const campaignsData = await campaignsRes.json();
          if (Array.isArray(campaignsData?.campaigns)) setCampaigns(campaignsData.campaigns);
        }
        if (healthRes.ok) {
          const healthData = await healthRes.json();
          if (healthData && typeof healthData.healthy === "boolean") setPipelineHealth(healthData);
        }
      } catch (err) {
        console.error("Global Sync Error:", err);
      }
    }
    fetchData();
    const interval = setInterval(fetchData, 10000);

    // Model metadata only changes when the training pipeline re-runs, so it's
    // fetched once here rather than on the 10s live-threat poll cadence above.
    async function fetchModelStatus() {
      try {
        const res = await fetch(`${API_BASE}/model/status`);
        if (!res.ok) return;
        const data = await res.json();
        setModelStatus(data);
      } catch (err) {
        console.error("Model status sync error:", err);
      }
    }
    fetchModelStatus();

    return () => clearInterval(interval);
  }, []);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanTarget) return;
    setIsScanning(true);
    setScanResult(null);
    try {
      const res = await fetch(`${API_BASE}/threats/score?domain=${encodeURIComponent(scanTarget)}`, { method: "POST" });
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      console.error("Scan failed:", err);
    } finally {
      setIsScanning(false);
    }
  };

  // Distinct brands actually present in the queue right now — derived from
  // live campaign data, not a hardcoded list, so it stays honest as the
  // watchlist changes (make seed-brands).
  const availableBrands = useMemo(() => {
    if (!campaigns) return [];
    return Array.from(new Set(campaigns.map(c => c.target_brand).filter((b): b is string => !!b))).sort();
  }, [campaigns]);

  const filteredCampaigns = useMemo(() => {
    if (!campaigns) return null;
    const filtered = brandFilter ? campaigns.filter(c => c.target_brand === brandFilter) : campaigns;
    return [...filtered].sort((a, b) => (b.confidence_score ?? 0) - (a.confidence_score ?? 0));
  }, [campaigns, brandFilter]);

  const toggleCampaign = async (id: number) => {
    if (expandedCampaignId === id) {
      setExpandedCampaignId(null);
      setCampaignDetail(null);
      return;
    }
    setExpandedCampaignId(id);
    setCampaignDetail(null);
    setDispositionNotes("");
    setAssigneeInput("");
    setActionError(null);
    setDetailLoading(true);
    try {
      const res = await fetch(`${API_BASE}/campaigns/${id}`);
      if (res.ok) {
        const data = await res.json();
        if (data?.available) {
          setCampaignDetail(data);
          setAssigneeInput(data.assignee ?? "");
        }
      }
    } catch (err) {
      console.error("Campaign detail fetch failed:", err);
    } finally {
      setDetailLoading(false);
    }
  };

  // Shared by disposition/assign: refresh both the open drawer and the
  // background queue-list row so confidence/stage/queue_status/lock state
  // stay in sync without waiting for the next 10s poll.
  const refreshCampaign = async (id: number) => {
    try {
      const res = await fetch(`${API_BASE}/campaigns/${id}`);
      if (!res.ok) return;
      const data = await res.json();
      if (!data?.available) return;
      setCampaignDetail(data);
      setCampaigns(prev => prev ? prev.map(c => (c.campaign_id === id ? { ...c, ...data } : c)) : prev);
    } catch (err) {
      console.error("Campaign refresh failed:", err);
    }
  };

  const submitDisposition = async (id: number, verdict: "confirmed" | "suppressed" | "benign") => {
    if (!analystName.trim()) {
      setActionError("Enter your analyst name first.");
      return;
    }
    setActionLoading(true);
    setActionError(null);
    try {
      const res = await fetch(`${API_BASE}/campaigns/${id}/disposition`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verdict, analyst: analystName.trim(), notes: dispositionNotes || undefined }),
      });
      const data = await res.json();
      if (!res.ok) {
        setActionError(data?.detail ? JSON.stringify(data.detail) : `Request failed (${res.status})`);
        return;
      }
      setDispositionNotes("");
      await refreshCampaign(id);
    } catch (err) {
      setActionError("Disposition request failed — see console.");
      console.error("Disposition failed:", err);
    } finally {
      setActionLoading(false);
    }
  };

  const submitAssign = async (id: number) => {
    if (!assigneeInput.trim()) return;
    setActionLoading(true);
    setActionError(null);
    try {
      const res = await fetch(`${API_BASE}/campaigns/${id}/assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ assignee: assigneeInput.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setActionError(data?.detail ? JSON.stringify(data.detail) : `Request failed (${res.status})`);
        return;
      }
      await refreshCampaign(id);
    } catch (err) {
      setActionError("Assign request failed — see console.");
      console.error("Assign failed:", err);
    } finally {
      setActionLoading(false);
    }
  };

  if (!mounted) return <div className="bg-[#050505] min-h-screen" />;

  return (
    <main className="min-h-screen bg-[#050505] text-white font-mono selection:bg-tactical-red selection:text-white pb-32">
      <div className="scanline pointer-events-none" />
      <div className="bg-grid fixed inset-0 opacity-20 pointer-events-none" />

      {/* --- HERO SECTION --- */}
      <section className="h-screen flex flex-col items-center justify-center p-12 relative overflow-hidden border-b border-white/5">
        <motion.div style={{ opacity }} className="flex flex-col items-center z-10">
          <motion.div
            animate={{ scale: [1, 1.1, 1], rotate: 360 }}
            transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
            className="mb-8 p-10 border-2 border-tactical-red/20 rounded-full relative"
          >
            <Eye className="w-32 h-32 text-tactical-red drop-shadow-[0_0_20px_#ff0000]" />
            <div className="absolute inset-0 border-t-4 border-tactical-red rounded-full animate-spin [animation-duration:3s]" />
          </motion.div>

          <h1 className="text-8xl font-black tracking-[0.8em] italic text-glow-red mt-4 ml-8 select-none uppercase">PHANTOM_EYE</h1>
          <p className="text-[14px] text-white/40 tracking-[1em] mt-8 uppercase font-bold text-center max-w-3xl">
            Predictive infra reconnaissance // High-value target stream
          </p>

          <div className="mt-24 flex flex-col items-center gap-4">
            <span className="text-[10px] text-white/20 font-black tracking-widest uppercase animate-pulse">Scroll to initialize analytics sequence</span>
            <ArrowDown className="w-10 h-10 animate-bounce opacity-20" />
          </div>
        </motion.div>

        <div className="absolute top-10 left-10 flex flex-col gap-2 text-[10px] text-white/10 uppercase italic font-black">
          <span>STATION_ID: MORDOR_ALPHA_01</span>
          <span>UPLINK_STRENGTH: 98.4%</span>
          <span>VERSION: 2.9.1_PRO_ANALYST</span>
        </div>
      </section>

      {/* --- 0. CAMPAIGN QUEUE (primary analyst workflow) --- */}
      <section className="max-w-[1600px] mx-auto p-12 mt-20">
        <SectionHeader
          title="Campaign Queue"
          subtitle="Clustered, brand-attributed infrastructure ranked by confidence — not a flat domain list. Add a brand via `make seed-brands` to bring your own coverage."
          icon={Target}
        />

        {/* Pipeline health strip — real freshness/DB/watchdog state, not decoration */}
        <div className="mb-8 flex flex-wrap items-center gap-x-8 gap-y-2 p-4 border border-white/10 bg-white/[0.02] text-[10px] uppercase font-black tracking-widest">
          <span className={`flex items-center gap-2 ${pipelineHealth ? (pipelineHealth.healthy ? "text-cyan-400" : "text-tactical-red") : "text-white/20"}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${pipelineHealth ? (pipelineHealth.healthy ? "bg-cyan-400 animate-pulse" : "bg-tactical-red animate-pulse") : "bg-white/20"}`} />
            {pipelineHealth ? (pipelineHealth.healthy ? "PIPELINE HEALTHY" : "PIPELINE DEGRADED") : "HEALTH_SYNC..."}
          </span>
          {pipelineHealth && (
            <>
              <span className="text-white/30">CT_RAW: {pipelineHealth.ct_raw.newest_age_hours != null ? `${pipelineHealth.ct_raw.newest_age_hours.toFixed(1)}h old` : "n/a"}</span>
              <span className="text-white/30">SCORING: {pipelineHealth.scoring.newest_scored_age_hours != null ? `${pipelineHealth.scoring.newest_scored_age_hours.toFixed(1)}h old` : "n/a"}</span>
              <span className="text-white/30">APP_DB: {pipelineHealth.app_db.reachable ? "REACHABLE" : "UNREACHABLE"}</span>
              {pipelineHealth.ingest_watchdog?.stale === true && (
                <span className="text-tactical-red">[warn] INGEST WATCHDOG REPORTS STALE</span>
              )}
            </>
          )}
          <span className="flex items-center gap-2 ml-auto normal-case">
            <span className="text-white/20">analyst:</span>
            <input
              value={analystName}
              onChange={e => setAnalystName(e.target.value)}
              placeholder="your name"
              className="bg-white/5 border border-white/10 px-2 py-1 text-white/70 text-[10px] w-32 focus:outline-none focus:border-tactical-red/50"
            />
          </span>
        </div>

        {/* Brand filter — derived from campaigns actually in the queue, not hardcoded */}
        {availableBrands.length > 0 && (
          <div className="mb-8 flex flex-wrap items-center gap-3">
            <Filter className="w-4 h-4 text-white/30" />
            <button
              onClick={() => setBrandFilter(null)}
              className={`px-3 py-1.5 text-[10px] uppercase font-black tracking-widest border transition-colors ${brandFilter === null ? "border-tactical-red text-tactical-red bg-tactical-red/10" : "border-white/10 text-white/40 hover:text-white/70"}`}
            >
              All ({campaigns?.length ?? 0})
            </button>
            {availableBrands.map(brand => (
              <button
                key={brand}
                onClick={() => setBrandFilter(brand)}
                className={`px-3 py-1.5 text-[10px] uppercase font-black tracking-widest border transition-colors ${brandFilter === brand ? "border-tactical-red text-tactical-red bg-tactical-red/10" : "border-white/10 text-white/40 hover:text-white/70"}`}
              >
                {brand} ({campaigns?.filter(c => c.target_brand === brand).length ?? 0})
              </button>
            ))}
          </div>
        )}

        {/* Ranked queue */}
        {campaigns === null ? (
          <div className="h-[200px] flex items-center justify-center opacity-20 italic text-[10px] uppercase font-black tracking-widest border border-white/10">
            SYNCING_CAMPAIGN_QUEUE...
          </div>
        ) : filteredCampaigns && filteredCampaigns.length === 0 ? (
          <div className="h-[200px] flex flex-col items-center justify-center gap-2 opacity-40 italic text-[10px] uppercase font-black tracking-widest border border-white/10">
            <span>{brandFilter ? `NO CAMPAIGNS FOR ${brandFilter} ABOVE CONFIDENCE THRESHOLD` : "NO CAMPAIGNS ABOVE CONFIDENCE THRESHOLD IN CURRENT BATCH"}</span>
            <span className="text-white/20 normal-case">candidate observations exist but haven't clustered into a queue-worthy campaign yet</span>
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            {filteredCampaigns?.map(c => (
              <div key={c.campaign_id} className="tactical-border bg-[#080808]/50 backdrop-blur-xl">
                <button
                  onClick={() => toggleCampaign(c.campaign_id)}
                  className="w-full flex items-center gap-6 p-5 text-left hover:bg-white/[0.03] transition-colors"
                >
                  <div className="flex flex-col items-center justify-center w-20 shrink-0">
                    <span className="text-2xl font-black text-tactical-red text-glow-red">
                      {c.confidence_score != null ? `${Math.round(c.confidence_score * 100)}%` : "--"}
                    </span>
                    <span className="text-[8px] text-white/20 uppercase font-black tracking-widest">confidence</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <span className="text-lg font-black uppercase tracking-widest italic">{c.target_brand ?? "unattributed"}</span>
                      <span className={`px-2 py-0.5 text-[9px] uppercase font-black tracking-widest ${STAGE_COLORS[c.stage] ?? "text-white/40 bg-white/5"}`}>{c.stage}</span>
                      {c.stage_locked_by && (
                        <span className="flex items-center gap-1 text-[9px] uppercase font-black tracking-widest text-white/30">
                          <Lock className="w-3 h-3" /> {c.stage_locked_by}
                        </span>
                      )}
                      {c.assignee && (
                        <span className="text-[9px] uppercase font-black tracking-widest text-cyan-400/70">→ {c.assignee}</span>
                      )}
                    </div>
                    <p className="text-[11px] text-white/40 font-bold uppercase tracking-wide truncate">{c.summary_reason ?? "no summary available"}</p>
                  </div>
                  <div className="flex flex-col items-end gap-1 shrink-0 text-[10px] uppercase font-black tracking-widest text-white/30">
                    <span>{c.member_count} domain{c.member_count === 1 ? "" : "s"}</span>
                    <span>{formatFreshness(c.freshness_age_minutes)}</span>
                  </div>
                  <ChevronRight className={`w-5 h-5 text-white/20 shrink-0 transition-transform ${expandedCampaignId === c.campaign_id ? "rotate-90" : ""}`} />
                </button>

                <AnimatePresence>
                  {expandedCampaignId === c.campaign_id && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="overflow-hidden border-t border-white/10"
                    >
                      <div className="p-5">
                        {detailLoading ? (
                          <div className="opacity-20 italic text-[10px] uppercase font-black tracking-widest py-8 text-center">LOADING_EVIDENCE...</div>
                        ) : campaignDetail && campaignDetail.campaign_id === c.campaign_id ? (
                          <table className="w-full text-[10px]">
                            <thead>
                              <tr className="text-white/20 uppercase font-black tracking-widest border-b border-white/10">
                                <th className="text-left pb-2 font-black">Domain</th>
                                <th className="text-left pb-2 font-black">Risk</th>
                                <th className="text-left pb-2 font-black">Decision</th>
                                <th className="text-left pb-2 font-black">Enrichment</th>
                                <th className="text-left pb-2 font-black">Registrar</th>
                                <th className="text-left pb-2 font-black">Country / ASN</th>
                              </tr>
                            </thead>
                            <tbody>
                              {campaignDetail.domains.map((d, i) => (
                                <tr key={i} className="border-b border-white/5 text-white/60">
                                  <td className="py-2 pr-4 font-bold text-white/80 break-all">{d.raw_host}</td>
                                  <td className="py-2 pr-4 text-tactical-red font-bold">{d.risk_score != null ? d.risk_score.toFixed(3) : "--"}</td>
                                  <td className="py-2 pr-4 uppercase">{d.decision_reason ?? "--"}</td>
                                  <td className="py-2 pr-4 uppercase text-cyan-400">{d.enrichment_level ?? "--"}</td>
                                  <td className="py-2 pr-4">{d.registrar ?? "--"}</td>
                                  <td className="py-2 pr-4">{d.sample_country ?? "--"}{d.sample_asn ? ` / ${d.sample_asn}` : ""}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        ) : (
                          <div className="opacity-20 italic text-[10px] uppercase font-black tracking-widest py-8 text-center">EVIDENCE_UNAVAILABLE</div>
                        )}

                        {/* Analyst actions — disposition + assignment. Disabled
                            once locked by a disposition until a new verdict is
                            recorded (product/stage_engine.py never auto-clears
                            a lock; only a fresh disposition call here can). */}
                        {campaignDetail && campaignDetail.campaign_id === c.campaign_id && (
                          <div className="mt-6 pt-5 border-t border-white/10 flex flex-col gap-4">
                            <div className="flex items-center justify-between">
                              <span className="text-[9px] uppercase font-black tracking-widest text-white/30">Analyst Actions</span>
                              {c.stage_locked_by && (
                                <span className="text-[9px] uppercase font-black tracking-widest text-white/30 flex items-center gap-1">
                                  <Lock className="w-3 h-3" /> locked by {c.stage_locked_by}
                                  {c.stage_locked_at ? ` · ${new Date(c.stage_locked_at).toISOString().slice(0, 16).replace("T", " ")}Z` : ""}
                                </span>
                              )}
                            </div>

                            <textarea
                              value={dispositionNotes}
                              onChange={e => setDispositionNotes(e.target.value)}
                              placeholder="notes for this disposition (optional)..."
                              rows={2}
                              className="w-full bg-white/5 border border-white/10 px-3 py-2 text-[11px] text-white/70 focus:outline-none focus:border-tactical-red/50 resize-none"
                            />

                            <div className="flex flex-wrap gap-3">
                              <button
                                disabled={actionLoading}
                                onClick={() => submitDisposition(c.campaign_id, "confirmed")}
                                className="px-4 py-2 text-[10px] uppercase font-black tracking-widest border border-tactical-red/40 text-tactical-red hover:bg-tactical-red/10 transition-colors disabled:opacity-30"
                              >
                                Confirm
                              </button>
                              <button
                                disabled={actionLoading}
                                onClick={() => submitDisposition(c.campaign_id, "suppressed")}
                                className="px-4 py-2 text-[10px] uppercase font-black tracking-widest border border-white/10 text-white/50 hover:bg-white/5 transition-colors disabled:opacity-30"
                              >
                                Suppress
                              </button>
                              <button
                                disabled={actionLoading}
                                onClick={() => submitDisposition(c.campaign_id, "benign")}
                                className="px-4 py-2 text-[10px] uppercase font-black tracking-widest border border-white/10 text-white/50 hover:bg-white/5 transition-colors disabled:opacity-30"
                              >
                                Mark Benign
                              </button>

                              <div className="flex items-center gap-2 ml-auto">
                                <input
                                  value={assigneeInput}
                                  onChange={e => setAssigneeInput(e.target.value)}
                                  placeholder="assignee"
                                  className="bg-white/5 border border-white/10 px-2 py-2 text-[10px] text-white/70 w-28 focus:outline-none focus:border-tactical-red/50"
                                />
                                <button
                                  disabled={actionLoading}
                                  onClick={() => submitAssign(c.campaign_id)}
                                  className="px-3 py-2 text-[10px] uppercase font-black tracking-widest border border-cyan-400/30 text-cyan-400 hover:bg-cyan-400/10 transition-colors disabled:opacity-30"
                                >
                                  Assign
                                </button>
                              </div>
                            </div>

                            {actionError && (
                              <p className="text-[10px] uppercase font-black tracking-widest text-tactical-red">{actionError}</p>
                            )}
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* --- 1. GLOBAL SITUATION ROOM --- */}
      <section className="max-w-[1600px] mx-auto p-12 mt-20">
        <SectionHeader
          title="Triage Situational Overwatch"
          subtitle="Analysis of the high-value reconnaissance stream. Note: Flagging density is high as this stream has been pre-filtered for suspicious telemetry."
          icon={Globe}
        />

        <div className="grid grid-cols-12 gap-10">
          <div className="col-span-8 h-[600px] bg-white/5 border border-white/10 relative group overflow-hidden tactical-border">
            <div className="absolute top-4 left-6 flex items-center gap-4 z-20">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-tactical-red shadow-[0_0_8px_#ff0000]" />
                <span className="text-[10px] font-black tracking-widest uppercase">Verified Malicious</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-cyan-400" />
                <span className="text-[10px] font-black tracking-widest uppercase">Triage Hubs</span>
              </div>
            </div>

            <div className="absolute inset-x-0 bottom-4 px-8 text-[9px] text-white/30 italic flex justify-between z-20 pointer-events-none">
              <span>PROJECTION: ORBITAL_HOLOGRAPHY</span>
              <span>STREAM_ID: HV_TRIAGE_B1000</span>
            </div>

            <div className="w-full h-full p-4 relative">
              {stats ? (
                <>
                  <TacticalGlobe data={stats.map_data} />
                  {stats.map_data.length === 0 && (
                    <div className="absolute inset-0 flex items-center justify-center pointer-events-none px-6">
                      <span className="text-[10px] tracking-[0.2em] font-black italic opacity-40 bg-black/60 px-4 py-2 border border-white/10 text-center break-words">
                        NO GEO ENRICHMENT IN CURRENT BATCH
                      </span>
                    </div>
                  )}
                </>
              ) : (
                <div className="w-full h-full flex flex-col items-center justify-center gap-4 opacity-20">
                  <Radio className="w-16 h-16 animate-pulse" />
                  <span className="text-[10px] tracking-[0.5em] font-black italic">LINKING_GEOSPATIAL_CLUSTER...</span>
                </div>
              )}
            </div>
          </div>

          <div className="col-span-4 flex flex-col gap-8 h-[600px]">
            <TacticalCard title="Triage Aggregate" subTitle="High-Value reconnaissance" status="FILTERED">
              <div className="grid grid-cols-1 gap-6 pt-4">
                <div className="flex flex-col gap-2">
                  <span className="text-[11px] font-black text-white/20 tracking-widest">NOISE_REJECTION_RATE</span>
                  <span className="text-6xl font-black italic text-cyan-400 tabular-nums leading-none tracking-tighter">{(100 - (stats?.signal_to_noise || 0.001)).toFixed(3)}%</span>
                  <span className="text-[9px] text-white/10 font-bold uppercase italic mt-1 font-mono">Filtered from {stats?.total_parsed != null ? stats.total_parsed.toLocaleString() : "--"} domains in latest scan batch</span>
                </div>
                <div className="h-px bg-white/10 w-full" />
                <div className="grid grid-cols-2 gap-6">
                  <div className="flex flex-col">
                    <span className="text-[10px] text-white/40 font-bold mb-1">CRITICAL ( {'>'} 0.99)</span>
                    <span className="text-2xl font-black text-tactical-red italic tabular-nums">{stats?.critical || "---"}</span>
                  </div>
                  <div className="flex flex-col text-right">
                    <span className="text-[10px] text-white/40 font-bold mb-1">HIGH ( {'>'} 0.90)</span>
                    <span className="text-2xl font-black text-white italic tabular-nums">{stats?.high_risk || "---"}</span>
                  </div>
                </div>
              </div>
            </TacticalCard>

            <TacticalCard title="Intelligence Stream" className="flex-1 overflow-hidden min-h-0" status="STREAMING">
              <div className="flex-1 overflow-y-auto pr-4 space-y-3 scrollbar-custom min-h-0">
                {threats.slice(0, 50).map((t, i) => (
                  <div key={t.registered_domain + i} className="p-3 bg-white/5 border border-white/5 flex justify-between items-center group hover:bg-white/10 transition-all cursor-crosshair">
                    <div className="flex flex-col">
                      <span className="text-[12px] font-black italic uppercase tracking-tighter group-hover:text-cyan-400">{t.registered_domain}</span>
                      <span className="text-[9px] text-white/20 font-black tracking-widest">{t.sample_country}</span>
                    </div>
                    <span className={`text-[11px] font-black tabular-nums ${t.risk_score > 0.98 ? 'text-tactical-red' : t.risk_score > 0.90 ? 'text-orange-500' : 'text-white/40'}`}>
                      {(t.risk_score * 100).toFixed(1)}%
                    </span>
                  </div>
                ))}
              </div>
            </TacticalCard>
          </div>
        </div>
      </section>

      {/* --- INFRASTRUCTURE DNA & VECTORS --- */}
      <section className="max-w-[1600px] mx-auto p-12 mt-40">
        <SectionHeader
          title="Infrastructure DNA & Vectors"
          subtitle="Advanced forensic breakdown of infrastructure lifeblood: TLD saturation, ISP reputation, and temporal risk decay."
          icon={Layers}
        />

        <div className="grid grid-cols-12 gap-10">
          <div className="col-span-4">
            <TacticalCard title="TLD Pollution Index" subTitle="Malicious saturation by suffix" status="ANALYTIC">
              <div className="h-[350px] w-full mt-4">
                {!stats ? (
                  <div className="h-full flex items-center justify-center opacity-20 italic">SYNC_TLD_VECTOR...</div>
                ) : stats.tld_analysis.length === 0 ? (
                  <div className="h-full flex items-center justify-center opacity-30 italic text-center px-6 text-[10px] break-words leading-relaxed">NO TLD DATA IN CURRENT BATCH</div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <ReBarChart data={stats.tld_analysis} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                      <XAxis type="number" domain={[0, 1]} hide />
                      <YAxis dataKey="tld" type="category" width={60} stroke="#fff" fontSize={10} fontStyle="italic" fontWeight="bold" />
                      <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ backgroundColor: "#000", border: "1px solid #ff0000", fontSize: "10px" }} />
                      <Bar dataKey="risk">
                        {stats.tld_analysis.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.risk > 0.95 ? '#ff0000' : '#ff8800'} fillOpacity={0.8} />
                        ))}
                      </Bar>
                    </ReBarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </TacticalCard>
          </div>

          <div className="col-span-4">
            <TacticalCard title="Network Origin Reputation" subTitle="High-Correlation mal-hosting" status="SUSPICIOUS">
              <div className="flex flex-col gap-4 mt-4 h-[350px] overflow-y-auto pr-2 scrollbar-custom">
                {!stats ? (
                  <div className="h-full flex items-center justify-center opacity-20 italic">SYNC_ISP_REPUTATION...</div>
                ) : stats.isp_reputation.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center gap-2 opacity-30 italic text-center px-4">
                    <span className="text-[10px] break-words leading-relaxed">INSUFFICIENT ISP DIVERSITY IN CURRENT BATCH</span>
                    <span className="text-[9px] not-italic tracking-widest opacity-70 break-words leading-relaxed">sample_isp unpopulated for current high-risk set</span>
                  </div>
                ) : stats.isp_reputation.map((isp, i) => (
                  <div key={i} className="flex flex-col gap-2 p-3 bg-white/5 border border-white/5 group hover:border-tactical-red transition-all">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] font-black italic text-white/60 truncate max-w-[200px] uppercase group-hover:text-white transition-colors">
                        {isp.sample_isp}
                      </span>
                      <span className={`text-[10px] font-black tabular-nums ${isp.risk > 0.95 ? 'text-tactical-red' : 'text-white'}`}>
                        {(isp.risk * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="h-1 bg-white/10 w-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        whileInView={{ width: `${isp.risk * 100}%` }}
                        className={`h-full ${isp.risk > 0.95 ? 'bg-tactical-red' : 'bg-white/40'}`}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </TacticalCard>
          </div>

          <div className="col-span-4 flex flex-col gap-10">
            <TacticalCard title="Temporal Risk Decay" subTitle="Age-Correlated maliciousness" status="LOGISTIC">
              <div className="h-[200px] w-full mt-4 flex flex-col justify-between">
                <div className="flex-1">
                  {!stats ? (
                    <div className="h-full flex items-center justify-center opacity-20 italic">SYNC_TEMPORAL_DATA...</div>
                  ) : stats.age_impact.length === 0 ? (
                    <div className="h-full flex items-center justify-center opacity-30 italic text-center px-6 text-[10px] break-words leading-relaxed">NO AGE DATA IN CURRENT BATCH</div>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={stats.age_impact}>
                        <defs>
                          <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#ff0000" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="#ff0000" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                        <XAxis dataKey="label" stroke="#fff" fontSize={8} />
                        <YAxis domain={[0, 1]} hide />
                        <Tooltip contentStyle={{ backgroundColor: "#000", border: "1px solid #ff0000", fontSize: "10px" }} />
                        <Area type="monotone" dataKey="risk" stroke="#ff0000" fillOpacity={1} fill="url(#colorRisk)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </div>
            </TacticalCard>

            <TacticalCard title="Model Training Status" subTitle="Real metadata from latest training run" status="STATION_ID">
              {modelStatus?.available ? (
                <div className="space-y-4 pt-2">
                  <div className="flex items-center gap-4 p-3 bg-white/5 border border-white/10 italic">
                    <TrendingUp className="w-5 h-5 text-cyan-400" />
                    <div>
                      <p className="text-[10px] font-black text-white/80">TRAINING_SET_COMPOSITION</p>
                      <p className="text-[9px] text-white/40 font-bold uppercase tracking-widest">
                        {modelStatus.n_rows?.toLocaleString() ?? "--"} rows &middot; {modelStatus.n_pos?.toLocaleString() ?? "--"} positive &middot; {modelStatus.n_neg?.toLocaleString() ?? "--"} negative
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 p-3 bg-white/5 border border-white/10 italic">
                    <Lock className={`w-5 h-5 ${modelStatus.promotion_decision?.promote ? 'text-cyan-400' : 'text-tactical-red'}`} />
                    <div>
                      <p className="text-[10px] font-black text-white/80">
                        {modelStatus.promotion_decision?.promote ? "CHALLENGER_PROMOTED" : "CHALLENGER_REJECTED"}
                      </p>
                      <p className="text-[9px] text-white/40 font-bold uppercase tracking-widest">
                        {modelStatus.created_utc ? `Trained ${new Date(modelStatus.created_utc).toISOString().slice(0, 10)}` : "Promotion outcome from latest eval"}
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center opacity-20 italic min-h-[150px]">
                  {modelStatus?.reason ?? "SYNC_MODEL_STATUS..."}
                </div>
              )}
            </TacticalCard>
          </div>
        </div>
      </section>

      {/* --- INFRASTRUCTURE TOPOLOGY & ATTRIBUTION --- */}
      <section className="max-w-[1600px] mx-auto p-12 mt-40 pt-32 border-t border-white/5">
        <SectionHeader
          title="Topology & Attribution"
          subtitle="Advanced Node-Link mapping of highly-scored infrastructure vectors, cross-correlated with known Advanced Persistent Threat (APT) demographics and MITRE ATT&CK probabilistic modeling."
          icon={Cpu}
        />

        <div className="grid grid-cols-12 gap-10">
          <div className="col-span-8 h-[700px] bg-white/5 border border-white/10 relative overflow-hidden tactical-border">
            <TacticalCard title="Malicious Infrastructure Topology" status="NODE-LINK MAPPING" className="h-full">
              <div className="h-full w-full">
                <NetworkGraph data={network} />
              </div>
            </TacticalCard>
          </div>
          
          <div className="col-span-4 flex flex-col gap-10 h-[700px]">
            <TacticalCard title="Detection Source" subTitle="How high-risk domains were flagged" status="MISP + ML FUSION" className="flex-1">
              {stats?.detection_source_breakdown && stats.detection_source_breakdown.length > 0 ? (
                <>
                  <div className="w-full h-[200px] mt-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={stats.detection_source_breakdown}
                          cx="50%" cy="50%" innerRadius={40} outerRadius={70}
                          paddingAngle={5} dataKey="count" stroke="none"
                        >
                          {stats.detection_source_breakdown.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={SOURCE_COLORS[entry.reason] ?? '#333333'} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: "#000", border: "1px solid #333", fontSize: "10px" }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="flex flex-col gap-2 mt-4 overflow-y-auto w-full h-[70px] scrollbar-custom">
                    {stats.detection_source_breakdown.map((src, idx) => (
                      <div key={idx} className="flex justify-between items-center text-[10px]">
                        <div className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: SOURCE_COLORS[src.reason] ?? '#333333'}}></div>
                          <span className="font-bold text-white/70 uppercase tracking-wider">{SOURCE_LABELS[src.reason] ?? src.reason}</span>
                        </div>
                        <span className="font-black italic tabular-nums">{src.pct}%</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : <div className="h-full flex items-center justify-center opacity-20 italic">NO_DETECTION_SOURCE_DATA</div>}
            </TacticalCard>
          </div>
        </div>
      </section>

      {/* --- SINGLE-DOMAIN DRILLDOWN (secondary tool — the campaign queue above
           is the primary workflow; this is for ad-hoc lookups outside it) --- */}
      <section ref={scannerRef} className="max-w-[1200px] mx-auto p-12 mt-40">
        <SectionHeader
          title="Single-Domain Drilldown"
          subtitle="Secondary tool: audit one domain outside the campaign queue. Confidence reflects live enrichment depth, not a promised full profile."
          icon={Crosshair}
        />

        <div className="bg-white/5 border border-white/10 p-12 tactical-border relative overflow-hidden bg-[#0a0a0a]/50 backdrop-blur-3xl shadow-[0_0_50px_rgba(0,0,0,0.8)]">
          <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
            <Zap className="w-48 h-48" />
          </div>

          <form onSubmit={handleScan} className="max-w-3xl mx-auto relative z-10">
            <div className="flex flex-col gap-4">
              <label className="text-[11px] font-black tracking-[0.4em] text-cyan-400 italic mb-2">TARGET_ID_ENTRY : REQUIRED</label>
              <div className="flex gap-4">
                <input
                  type="text"
                  placeholder="ENTER_DOMAIN.XYZ..."
                  className="flex-1 bg-white/[0.03] border-2 border-white/10 p-5 text-xl font-black italic tracking-[0.2em] outline-none focus:border-tactical-red transition-all placeholder:text-white/10"
                  value={scanTarget}
                  onChange={(e) => setScanTarget(e.target.value)}
                />
                <button
                  type="submit"
                  disabled={isScanning}
                  className="bg-tactical-red px-12 py-5 font-black italic tracking-widest text-white hover:bg-tactical-red/80 active:scale-95 transition-all disabled:opacity-50 shadow-[0_0_20px_rgba(255,0,0,0.3)]"
                >
                  {isScanning ? "SHADOW_SCANNING..." : "SCAN_DOMAIN"}
                </button>
              </div>
            </div>
          </form>

          <AnimatePresence>
            {scanResult && (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="mt-12 pt-12 border-t border-white/10 grid grid-cols-12 gap-12"
              >
                <div className="col-span-4 flex flex-col gap-6">
                  <div className="p-8 bg-black border-2 border-tactical-red critical-glow shadow-[0_0_30px_rgba(255,0,0,0.2)]">
                    <div className="text-[12px] font-black text-tactical-red italic mb-2 tracking-[0.4em] uppercase">Audit Result</div>
                    <div className="text-5xl font-black italic tabular-nums leading-none">{(scanResult.risk_score * 100).toFixed(2)}%</div>
                    <div className={`mt-6 text-[10px] font-black px-4 py-1 bg-tactical-red/20 text-tactical-red inline-block tracking-[0.5em] border border-tactical-red/30 uppercase`}>
                      {scanResult.verdict}
                    </div>
                  </div>
                </div>
                <div className="col-span-8 space-y-6">
                  <div className="text-[12px] font-black text-cyan-400 italic tracking-[0.4em] mb-4">ANALYST_HEURISTIC_BREAKDOWN</div>
                  <div className="grid grid-cols-1 gap-4">
                    {scanResult.analysis.map((msg: string, i: number) => (
                      <div key={i} className="flex items-center gap-4 text-white/50 text-[11px] font-bold tracking-widest uppercase italic bg-white/[0.02] p-4 border-l-4 border-cyan-400">
                        <Shield className="w-5 h-5 text-cyan-400" />
                        <span>{msg}</span>
                      </div>
                    ))}
                  </div>
                  <div className={`mt-10 p-6 bg-white/5 border border-white/10 text-[11px] italic leading-relaxed uppercase font-black tracking-widest border-l-4 ${scanResult.enrichment_status === 'lexical_only' ? 'border-yellow-500 text-yellow-500/70' : 'border-cyan-400 text-white/40'}`}>
                    <div>Model: {scanResult.model_used ?? 'unavailable'}</div>
                    <div>Enrichment: {scanResult.enrichment_status ?? 'unknown'}</div>
                    {scanResult.enrichment_status === 'lexical_only'
                      ? <div className="mt-2 not-italic normal-case tracking-normal">⚠ Live enrichment timed out — scored on domain text alone. Lower-confidence than a fully enriched result.</div>
                      : scanResult.enrichment_status === 'partial'
                      ? <div className="mt-2 not-italic normal-case tracking-normal">DNS/GeoIP resolved; WHOIS unavailable. Partial-confidence score.</div>
                      : <div className="mt-2 not-italic normal-case tracking-normal">Fully enriched (DNS, GeoIP, WHOIS) — full model feature set.</div>}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </section>

      {/* --- PREDICTIVE TRENDS --- */}
      <section className="max-w-[1400px] mx-auto p-12 mt-40 border-t border-white/5 pt-32">
        <SectionHeader
          title="Predictive Trends"
          subtitle="Longitudinal analysis of infrastructure creation patterns across localized ISPs and data centers."
          icon={BarChart3}
        />

        <div className="grid grid-cols-2 gap-10">
          <TacticalCard title="Risk Volatility Index" status="CALCULATED" subTitle="Temporal probability drift">
            <div className="h-[300px] w-full mt-4">
              {mounted && threats.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={threats.slice(0, 20).reverse()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                    <XAxis dataKey="registered_domain" hide />
                    <YAxis domain={[0.92, 1.0]} hide />
                    <Tooltip contentStyle={{ backgroundColor: "#000", border: "1px solid #ff0000", fontSize: "10px" }} />
                    <Line type="monotone" dataKey="risk_score" stroke="#ff0000" strokeWidth={3} dot={false} strokeDasharray="5 5" />
                  </LineChart>
                </ResponsiveContainer>
              ) : <div className="h-full flex items-center justify-center opacity-20 italic">ANALYTIC_SYNC...</div>}
            </div>
          </TacticalCard>

          <TacticalCard title="System Status" status={stats ? "STABLE" : "SYNCING"} subTitle="Live pipeline & model telemetry — no simulated events">
            <div className="space-y-4 pt-4 h-[300px] overflow-hidden flex flex-col justify-end">
              <div className="h-px bg-white/10 w-full mb-4" />
              <div className="space-y-2 opacity-70 text-[10px] uppercase font-black tracking-widest transition-opacity">
                <p className="text-cyan-400">[info] GOLD_LAYER_PARSED_ROWS: {stats?.total_parsed != null ? stats.total_parsed.toLocaleString() : "--"}</p>
                <p>[info] HIGH_RISK_DOMAINS: {stats?.total_domains != null ? stats.total_domains.toLocaleString() : "--"}</p>
                <p>[info] NETWORK_GRAPH_NODES: {network?.nodes?.length ?? "--"} / LINKS: {network?.links?.length ?? "--"}</p>
                {stats && stats.countries === 0 && (
                  <p className="text-tactical-red">[warn] GEO_ENRICHMENT: 0 COUNTRIES POPULATED IN CURRENT BATCH</p>
                )}
                <p>
                  [info] MODEL_LAST_CHECKED: {modelStatus?.promotion_decision?.checked_utc
                    ? new Date(modelStatus.promotion_decision.checked_utc).toISOString().replace("T", " ").slice(0, 19) + "Z"
                    : "unavailable"}
                </p>
                <p>[info] HEALTH_ENDPOINT: {stats ? "REACHABLE" : "AWAITING_SYNC"}</p>
              </div>
            </div>
          </TacticalCard>
        </div>
      </section>

      {/* --- FOOTER --- */}
      <footer className="mt-32 p-14 border-t border-white/10 bg-black/80 backdrop-blur-3xl relative overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-[1px] bg-gradient-to-r from-transparent via-tactical-red to-transparent opacity-30" />
        <div className="max-w-[1600px] mx-auto flex justify-between items-start">
          <div className="flex flex-col gap-6">
            <div className="flex items-center gap-4">
              <Eye className="w-10 h-10 text-tactical-red shadow-[0_0_15px_#ff0000]" />
              <h3 className="text-3xl font-black italic tracking-[0.4em] uppercase">PHANTOM_EYE</h3>
            </div>
            <p className="max-w-md text-white/20 text-[10px] font-bold tracking-widest leading-loose uppercase italic mt-4">
              Advanced reconnaissance platform for the identification and evaluation of global threat infrastructure.
              Powered by Medallion Gold Layer intelligence clusters and neural-weighted lexical auditing.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-20">
            <div className="flex flex-col gap-4">
              <span className="text-[12px] font-black text-cyan-400 italic tracking-[0.3em]">RESOURCES</span>
              <nav className="flex flex-col gap-2 text-[10px] text-white/30 font-bold tracking-widest uppercase italic font-mono">
                <a href="#" className="hover:text-white transition-colors">Documentation</a>
                <a href="#" className="hover:text-white transition-colors">API References</a>
                <a href="#" className="hover:text-white transition-colors">Security Audit</a>
              </nav>
            </div>
            <div className="flex flex-col gap-4 text-right">
              <span className="text-[12px] font-black text-tactical-red italic tracking-[0.3em]">OPERATIONAL_ID</span>
              <div className="text-[10px] text-white/30 font-bold tracking-widest uppercase italic flex flex-col gap-1">
                <span>MORDOR_ALPHA_NODE_099</span>
                <span>LVL_15_ANALYST_CLEARANCE</span>
                <span>© 2026 CORE_INTEL_SYSTEMS</span>
              </div>
            </div>
          </div>
        </div>
      </footer>
      
      {/* Live AI Intel Chat Interface */}
      <IntelChat />
    </main>
  );
}
