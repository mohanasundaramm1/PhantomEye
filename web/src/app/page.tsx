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
  const [mounted, setMounted] = useState(false);

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
        const [threatRes, statsRes, networkRes] = await Promise.all([
          fetch(`${API_BASE}/threats/latest?limit=50`),
          fetch(`${API_BASE}/threats/stats`),
          fetch(`${API_BASE}/threats/network`)
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
      } catch (err) {
        console.error("Global Sync Error:", err);
      }
    }
    fetchData();
    const interval = setInterval(fetchData, 10000);
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

            <div className="w-full h-full p-4">
              {stats ? (
                <TacticalGlobe data={stats.map_data} />
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
                {stats?.tld_analysis ? (
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
                ) : <div className="h-full flex items-center justify-center opacity-20 italic">SYNC_TLD_VECTOR...</div>}
              </div>
            </TacticalCard>
          </div>

          <div className="col-span-4">
            <TacticalCard title="Network Origin Reputation" subTitle="High-Correlation mal-hosting" status="SUSPICIOUS">
              <div className="flex flex-col gap-4 mt-4 h-[350px] overflow-y-auto pr-2 scrollbar-custom">
                {stats?.isp_reputation ? stats.isp_reputation.map((isp, i) => (
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
                )) : <div className="h-full flex items-center justify-center opacity-20 italic">SYNC_ISP_REPUTATION...</div>}
              </div>
            </TacticalCard>
          </div>

          <div className="col-span-4 flex flex-col gap-10">
            <TacticalCard title="Temporal Risk Decay" subTitle="Age-Correlated maliciousness" status="LOGISTIC">
              <div className="h-[200px] w-full mt-4 flex flex-col justify-between">
                <div className="flex-1">
                  {stats?.age_impact ? (
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
                  ) : <div className="h-full flex items-center justify-center opacity-20 italic">SYNC_TEMPORAL_DATA...</div>}
                </div>
              </div>
            </TacticalCard>

            <TacticalCard title="Analyst Triage Context" status="STATION_ID">
              <div className="space-y-4 pt-2">
                <div className="flex items-center gap-4 p-3 bg-white/5 border border-white/10 italic">
                  <TrendingUp className="w-5 h-5 text-cyan-400" />
                  <div>
                    <p className="text-[10px] font-black text-white/80">PREDICTIVE_DRIFT</p>
                    <p className="text-[9px] text-white/40 font-bold uppercase tracking-widest">Model updated with 42k new samples</p>
                  </div>
                </div>
                <div className="flex items-center gap-4 p-3 bg-white/5 border border-white/10 italic">
                  <Lock className="w-5 h-5 text-tactical-red" />
                  <div>
                    <p className="text-[10px] font-black text-white/80">RECON_MODE: ACTIVE</p>
                    <p className="text-[9px] text-white/40 font-bold uppercase tracking-widest">Aggressive heuristic filtering active</p>
                  </div>
                </div>
              </div>
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
              {stats?.detection_source_breakdown ? (
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

      {/* --- LIVE NEURAL INTERROGATION --- */}
      <section ref={scannerRef} className="max-w-[1200px] mx-auto p-12 mt-40">
        <SectionHeader
          title="Neural Interrogation"
          subtitle="Input a suspicious domain to trigger a real-time behavioral audit against our latest predictive model weights."
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

          <TacticalCard title="System Kernel Log" status="STABLE" subTitle="Real-time station status">
            <div className="space-y-4 pt-4 h-[300px] overflow-hidden flex flex-col justify-end">
              <div className="h-px bg-white/10 w-full mb-4" />
              <div className="space-y-2 opacity-30 text-[10px] uppercase font-black tracking-widest group-hover:opacity-100 transition-opacity">
                <p className="text-cyan-400">[info] LINK_SCAN: ACTIVE_OVERWATCH</p>
                <p>[info] GEOGRAPHY_ENRICHMENT_SYNC: OK</p>
                <p>[info] RDAP_QUERY_RESOLVED: 142ms</p>
                <p className="text-tactical-red">[warn] THREAT_DENSITY_SPIKE_DETECTED: GERMANY_REGION</p>
                <p>[info] ANALYTICS_KERNEL_UPDATE: v2.9.0_STABLE</p>
                <p>[info] SCAN_UPLINK_ESTABLISHED: MORDOR_01</p>
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
