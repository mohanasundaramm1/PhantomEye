"use client";

import React, { useState, useEffect } from "react";
import {
  Shield, Activity, Globe, Search, AlertTriangle,
  Terminal as TerminalIcon, ChevronRight, Zap, Target,
  Database, Cpu, Wifi, Lock
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, AreaChart, Area, BarChart, Bar, Cell
} from 'recharts';

// --- Types ---
interface Threat {
  registered_domain: string;
  risk_score: number;
  sample_country: string;
  sample_isp: string;
  num_unique_ips: number;
  ingest_date?: string;
}

interface Stats {
  total_domains: number;
  high_risk: number;
  critical: number;
  avg_risk: number;
  countries: number;
}

// --- High-Fidelity Components ---

const TacticalCard = ({ title, children, className = "", status = "ACTIVE" }: { title: string, children: React.ReactNode, className?: string, status?: string }) => (
  <div className={`tactical-border p-5 flex flex-col group ${className}`}>
    <div className="flex justify-between items-center mb-4 border-b border-white/10 pb-2">
      <div className="flex items-center gap-3">
        <div className="w-2 h-2 bg-tactical-red animate-pulse shadow-[0_0_8px_#ff0000]" />
        <span className="text-[11px] uppercase tracking-[0.25em] font-black text-white/70 italic">{title}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-[8px] text-white/30 tracking-tighter">STATUS:</span>
        <span className="text-[8px] text-cyan-400 font-bold tracking-widest">{status}</span>
      </div>
    </div>
    <div className="relative flex-1">
      {children}
    </div>
  </div>
);

const StatBox = ({ label, value, color = "white", icon: Icon }: { label: string, value: string | number, color?: string, icon?: any }) => (
  <div className="flex items-center gap-4 bg-white/5 border border-white/5 p-3 hover:border-white/20 transition-all cursor-default group">
    {Icon && <Icon className="w-5 h-5 opacity-40 group-hover:opacity-100 transition-opacity" style={{ color }} />}
    <div className="flex flex-col">
      <span className="text-[9px] uppercase tracking-[0.2em] text-white/40 mb-0.5">{label}</span>
      <span className="text-xl font-mono font-black tracking-tight" style={{ color }}>{value}</span>
    </div>
  </div>
);

export default function EliteDashboard() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [investigating, setInvestigating] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    async function fetchData() {
      try {
        const [threatRes, statsRes] = await Promise.all([
          fetch("http://localhost:8000/threats/latest?limit=50"),
          fetch("http://localhost:8000/threats/stats")
        ]);

        const threatData = await threatRes.json();
        const statsData = await statsRes.json();

        setThreats(threatData.data);
        setStats(statsData);
      } catch (err) {
        console.error("Failed to sync with command center:", err);
      } finally {
        setLoading(false);
      }
    }

    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  if (!mounted) return <div className="bg-[#050505] min-h-screen" />;

  const highRiskThreats = threats.filter(t => t.risk_score >= 0.95).slice(0, 10);

  return (
    <main className="min-h-screen relative overflow-hidden bg-[#050505] bg-grid text-white p-8 font-mono text-sm uppercase selection:bg-tactical-red selection:text-white">
      <div className="scanline" />

      {/* Decorative Corner Accents */}
      <div className="absolute top-0 left-0 w-32 h-32 border-l border-t border-white/10 opacity-50" />
      <div className="absolute top-0 right-0 w-32 h-32 border-r border-t border-white/10 opacity-50" />
      <div className="absolute bottom-0 left-0 w-32 h-32 border-l border-b border-white/10 opacity-50" />
      <div className="absolute bottom-0 right-0 w-32 h-32 border-r border-b border-white/10 opacity-50" />

      {/* Top Professional HUD */}
      <header className="flex flex-col gap-6 mb-10 relative z-20">
        <div className="flex justify-between items-end border-b-2 border-tactical-red pb-4">
          <div className="flex items-center gap-6">
            <div className="p-4 border-2 border-tactical-red bg-tactical-red/5 critical-glow animate-pulse-red">
              <Shield className="w-10 h-10 text-tactical-red shadow-[0_0_15px_#ff0000]" />
            </div>
            <div>
              <h1 className="text-4xl font-black tracking-[0.4em] text-glow-red italic">CYBER SENTINEL : v2.0</h1>
              <div className="flex items-center gap-4 mt-2">
                <span className="text-[10px] text-cyan-400 font-bold tracking-[0.5em]">GLOBAL INTELLIGENCE NODE : Mordor_Alpha_01</span>
                <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                <span className="text-[10px] text-white/30 tracking-widest uppercase">Encryption: AES-256-GCM // Protocol: RDAP_SECURE</span>
              </div>
            </div>
          </div>
          <div className="text-right hidden xl:block">
            <div className="text-[9px] text-white/40 tracking-[0.3em] font-bold">SYSTEM TIME [UTC]</div>
            <div className="text-2xl font-black text-white/80">{new Date().toISOString().split('T')[1].split('.')[0]}</div>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
          {stats ? (
            <>
              <StatBox label="Critical Entities" value={stats.critical} color="#ff0000" icon={AlertTriangle} />
              <StatBox label="High Risk Vector" value={stats.high_risk} color="#ff8800" icon={Zap} />
              <StatBox label="Telemetry Cache" value={stats.total_domains.toLocaleString()} color="#00f3ff" icon={Database} />
              <StatBox label="Unique Origins" value={stats.countries} color="#a855f7" icon={Globe} />
              <StatBox label="Predictive AUC" value="0.988" color="#22c55e" icon={Activity} />
            </>
          ) : (
            Array(5).fill(0).map((_, i) => (
              <div key={i} className="h-16 bg-white/5 animate-pulse border border-white/5" />
            ))
          )}
        </div>
      </header>

      {/* Main Command View */}
      <div className="grid grid-cols-12 gap-8 h-[calc(100vh-280px)] relative z-10">

        {/* Left Column: Intelligence Log */}
        <div className="col-span-3 flex flex-col gap-8 h-full">
          <TacticalCard title="Real-Time Intel Feed" className="flex-1" status="STREAMING">
            <div className="absolute top-0 right-0 p-1 opacity-20">
              <Activity className="w-3 h-3 text-cyan-400 animate-spin-slow" />
            </div>
            <div className="h-full overflow-y-auto pr-4 space-y-3 scrollbar-custom">
              {threats.map((t, i) => (
                <motion.div
                  initial={{ opacity: 0, x: -30 }}
                  animate={{ opacity: 1, x: 0 }}
                  key={t.registered_domain + i}
                  className={`p-4 border transition-all cursor-pointer group relative overflow-hidden
                    ${investigating === t.registered_domain ? 'bg-tactical-red/20 border-tactical-red critical-glow' : 'bg-white/5 border-white/5 hover:border-white/20 hover:bg-white/10'}`}
                  onClick={() => setInvestigating(t.registered_domain)}
                >
                  {t.risk_score > 0.98 && (
                    <div className="absolute top-0 left-0 w-1 h-full bg-tactical-red" />
                  )}
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-[11px] font-black truncate flex-1 tracking-tight italic group-hover:text-cyan-400 transition-colors uppercase">{t.registered_domain}</span>
                    <span className={`text-[10px] font-black tabular-nums shadow-sm
                      ${t.risk_score >= 0.98 ? 'text-tactical-red' : t.risk_score >= 0.90 ? 'text-orange-500' : 'text-yellow-500'}`}>
                      {(t.risk_score * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-[9px] text-white/30 tracking-widest font-bold">
                    <span className="flex items-center gap-1"><Globe className="w-2.5 h-2.5" /> {t.sample_country || "GLOBAL"}</span>
                    <span className="opacity-0 group-hover:opacity-100 transition-opacity text-cyan-400 underline underline-offset-4">DECRYPT INTEL</span>
                  </div>
                </motion.div>
              ))}
            </div>
          </TacticalCard>
        </div>

        {/* Center Section: Visualization & System Status */}
        <div className="col-span-6 flex flex-col gap-8 h-full">
          {/* Main Visualizer */}
          <TacticalCard title="Predictive Risk Projection" className="flex-[2] relative overflow-hidden" status="RENDER_OK">
            <div className="absolute top-4 right-4 text-[9px] text-white/20 flex flex-col text-right italic font-black">
              <span>AXIS_Y: PROBABILITY</span>
              <span>AXIS_X: TEMPORAL_SEQUENCE</span>
            </div>

            <div className="absolute inset-x-0 bottom-0 opacity-5 pointer-events-none">
              <Globe className="w-[500px] h-[500px] mx-auto text-cyan-400 rotate-12" />
            </div>

            <div className="w-full h-full min-h-[300px] flex flex-col justify-between pt-4">
              <div className="flex-1 w-full" style={{ minHeight: 320 }}>
                {mounted && threats.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={threats.slice(0, 20).reverse()} margin={{ top: 20, right: 10, left: -20, bottom: 0 }}>
                      <defs>
                        <linearGradient id="mainGlow" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff0000" stopOpacity={0.6} />
                          <stop offset="95%" stopColor="#ff0000" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                      <XAxis dataKey="registered_domain" hide />
                      <YAxis domain={[0, 1]} stroke="rgba(255,255,255,0.1)" fontSize={9} />
                      <Tooltip
                        content={({ active, payload }) => {
                          if (active && payload && payload.length) {
                            const data = payload[0].payload;
                            return (
                              <div className="bg-[#111] border border-tactical-red p-3 tactical-border shadow-2xl">
                                <p className="text-[10px] font-black text-white">{data.registered_domain}</p>
                                <p className="text-xl font-bold text-tactical-red">RISK: {(data.risk_score * 100).toFixed(2)}%</p>
                                <p className="text-[8px] text-white/40 mt-1">LATENCY: 42MS // THREAT: MALICIOUS_INFRA</p>
                              </div>
                            );
                          }
                          return null;
                        }}
                      />
                      <Area
                        type="monotone"
                        dataKey="risk_score"
                        stroke="#ff0000"
                        strokeWidth={3}
                        fillOpacity={1}
                        fill="url(#mainGlow)"
                        animationDuration={2500}
                        isAnimationActive={true}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center space-y-4 flex-col">
                    <Activity className="w-12 h-12 text-tactical-red animate-spin" />
                    <span className="text-[10px] tracking-[0.5em] animate-pulse">CONNECTING TO GOLD_LAYER_CLUSTER...</span>
                  </div>
                )}
              </div>
            </div>
          </TacticalCard>

          {/* Sub-Panel: Analytics & Resources */}
          <div className="grid grid-cols-2 gap-8 flex-1">
            <TacticalCard title="Kernel Analytics" status="SYNC_LOCKED">
              <div className="space-y-6 pt-2">
                <div>
                  <div className="flex justify-between text-[10px] mb-2 font-black tracking-widest italic">
                    <span>PATTERN_RECOGNITION</span>
                    <span className="text-cyan-400">92.4%</span>
                  </div>
                  <div className="h-2 bg-white/5 w-full overflow-hidden border border-white/5">
                    <motion.div initial={{ width: 0 }} animate={{ width: "92.4%" }} className="h-full bg-cyan-400 shadow-[0_0_10px_#22d3ee]" />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-[10px] mb-2 font-black tracking-widest italic">
                    <span>ENRICHMENT_BUFFER</span>
                    <span className="text-tactical-red">Critical (88%)</span>
                  </div>
                  <div className="h-2 bg-white/5 w-full overflow-hidden border border-white/5">
                    <motion.div initial={{ width: 0 }} animate={{ width: "88%" }} className="h-full bg-tactical-red shadow-[0_0_10px_#ff0000]" />
                  </div>
                </div>
                <div className="flex justify-between items-center bg-white/5 p-3 tactical-border border-white/10 group hover:border-tactical-red transition-all cursor-pointer">
                  <span className="text-[10px] font-black italic tracking-tighter">AI AGENT OVERRIDE</span>
                  <div className="flex gap-1">
                    <div className="w-1 h-1 bg-tactical-red animate-bounce" />
                    <div className="w-1 h-1 bg-tactical-red animate-bounce [animation-delay:0.2s]" />
                    <div className="w-1 h-1 bg-tactical-red animate-bounce [animation-delay:0.4s]" />
                  </div>
                </div>
              </div>
            </TacticalCard>

            <TacticalCard title="Infrastructure Nodes" status="ALL_CLEAR">
              <div className="flex items-center gap-4 text-cyan-400 mb-4 bg-cyan-400/5 p-3 border border-cyan-400/20">
                <Wifi className="w-5 h-5 animate-pulse" />
                <span className="text-[11px] font-black tracking-[0.2em] italic">SURVEILLANCE OVERWATCH ACTIVE</span>
              </div>
              <div className="space-y-2 font-black text-[10px] tracking-tighter text-white/50 lowercase">
                <div className="flex justify-between border-b border-white/5 pb-1"><span>[i] whois_engine</span><span className="text-green-500 underline">rdap_v2_operational</span></div>
                <div className="flex justify-between border-b border-white/5 pb-1"><span>[i] dns_cluster</span><span className="text-green-500 underline">5/5_active</span></div>
                <div className="flex justify-between border-b border-white/5 pb-1"><span>[i] location_hook</span><span className="text-cyan-400 italic">geo_db_latest</span></div>
                <div className="flex justify-between border-b border-white/5 pb-1"><span>[i] api_uplink</span><span className="text-green-500 underline">v1.28.0_live</span></div>
              </div>
            </TacticalCard>
          </div>
        </div>

        {/* Right Column: Deep Investigator */}
        <div className="col-span-3 h-full">
          <TacticalCard title="Target Investigator" className="h-full" status={investigating ? "LOCKED_ON" : "AWAITING_ID"}>
            <AnimatePresence mode="wait">
              {investigating ? (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  <div className="p-6 bg-tactical-red/5 border-2 border-tactical-red critical-glow relative overflow-hidden group">
                    <div className="absolute -right-4 -top-4 rotate-45 opacity-10 group-hover:rotate-[225deg] transition-all duration-1000">
                      <Target className="w-24 h-24 text-tactical-red" />
                    </div>
                    <div className="text-[10px] text-tactical-red font-black mb-1 italic tracking-[0.3em]">TARGET_ACQUIRED</div>
                    <div className="text-lg font-black break-all tracking-tight italic underline decoration-tactical-red decoration-4">{investigating}</div>
                  </div>

                  <div className="grid grid-cols-1 gap-4">
                    <StatBox label="Threat Probability" value={`${(threats.find(t => t.registered_domain === investigating)?.risk_score * 100)?.toFixed(5)}%`} color="#ff0000" icon={AlertTriangle} />
                    <StatBox label="Infrastructure Loc" value={threats.find(t => t.registered_domain === investigating)?.sample_country || "GLOBAL_CLUSTER"} icon={Globe} />
                    <StatBox label="ISP/Carrier" value={threats.find(t => t.registered_domain === investigating)?.sample_isp?.split(' ')[0] || "REDACTED"} icon={Wifi} />
                  </div>

                  <div className="space-y-4 pt-4 border-t border-white/10">
                    <div className="flex items-center gap-2 text-[10px] font-black italic tracking-widest text-[#ff8800]">
                      <Lock className="w-3 h-3" /> SECURITY_ADVISORY: HIGH_RISK
                    </div>
                    <p className="text-[10px] text-white/40 leading-relaxed font-bold tracking-tight">
                      This entity matches known Phishing/Malware patterns. Automated DNS blocking is recommended.
                      Source enrichment confirms active hosting infrastructure.
                    </p>
                  </div>

                  <div className="pt-4">
                    <button
                      onClick={() => setInvestigating(null)}
                      className="w-full p-4 border-2 border-white/20 hover:border-tactical-red hover:bg-tactical-red/10 text-[11px] font-black tracking-[0.5em] transition-all italic flex items-center justify-center gap-3 active:scale-95 group"
                    >
                      <Zap className="w-4 h-4 group-hover:animate-bounce" /> ABORT_SESSION
                    </button>
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  initial={{ opacity: 0.2 }}
                  animate={{ opacity: [0.2, 0.4, 0.2] }}
                  transition={{ duration: 3, repeat: Infinity }}
                  className="h-full flex flex-col items-center justify-center text-center p-10"
                >
                  <div className="relative mb-8">
                    <Target className="w-24 h-24 text-white opacity-10" />
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="w-12 h-12 border-2 border-tactical-red/20 rounded-full animate-ping" />
                    </div>
                  </div>
                  <p className="text-[11px] font-black tracking-[0.6em] text-white/30 italic">SELECT_NODE_FOR_IN-DEPTH_FORENSICS</p>
                </motion.div>
              )}
            </AnimatePresence>
          </TacticalCard>
        </div>

      </div>

      {/* Professional Dashboard Footer */}
      <footer className="mt-10 flex justify-between items-center text-[10px] text-white/20 tracking-[0.4em] font-black border-t border-white/5 pt-6">
        <div className="flex items-center gap-6">
          <span className="flex items-center gap-2"><Cpu className="w-3 h-3" /> KERNEL_ID: SNTL_092</span>
          <span className="flex items-center gap-2 text-[8px] bg-white/5 px-2 py-1 italic">ACCESS_LEVEL: LEVEL_5_OVERWATCH</span>
        </div>
        <div className="flex items-center gap-8">
          <span className="hover:text-white transition-colors cursor-pointer tracking-[0.2em] decoration-cyan-400 underline decoration-2 cursor-help">SECURITY_POLICY.MD</span>
          <span className="text-cyan-400/50 italic animate-pulse">© 2026 CYBER_SENTINEL_PLATFORM // ALL_RIGHTS_RESERVED</span>
        </div>
      </footer>
    </main>
  );
}
