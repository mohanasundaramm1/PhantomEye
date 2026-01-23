"use client";

import React, { useState, useEffect } from "react";
import { Shield, Activity, Globe, Search, AlertTriangle, Terminal as TerminalIcon, ChevronRight } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';

// --- Types ---
interface Threat {
  registered_domain: string;
  risk_score: number;
  sample_country: string;
  sample_isp: string;
  num_unique_ips: number;
}

interface Stats {
  total_domains: number;
  high_risk: number;
  critical: number;
  avg_risk: number;
  countries: number;
}

// --- Components ---

const TacticalCard = ({ title, children, className = "" }: { title: string, children: React.ReactNode, className?: string }) => (
  <div className={`tactical-border bg-tactical-gray/50 p-4 ${className}`}>
    <div className="flex items-center gap-2 mb-4 border-b border-white/10 pb-2">
      <div className="w-1.5 h-1.5 bg-tactical-red" />
      <span className="text-[10px] uppercase tracking-[0.2em] font-bold text-white/50">{title}</span>
    </div>
    {children}
  </div>
);

const StatBox = ({ label, value, color = "white" }: { label: string, value: string | number, color?: string }) => (
  <div className="flex flex-col">
    <span className="text-[9px] uppercase tracking-wider text-white/40 mb-1">{label}</span>
    <span className="text-2xl font-mono font-bold" style={{ color }}>{value}</span>
  </div>
);

export default function EliteDashboard() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [investigating, setInvestigating] = useState<string | null>(null);

  useEffect(() => {
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
    const interval = setInterval(fetchData, 10000); // Poll every 10s
    return () => clearInterval(interval);
  }, []);

  return (
    <main className="min-h-screen relative overflow-hidden bg-[#050505] text-white p-6 font-mono text-sm uppercase">
      <div className="scanline" />

      {/* Header */}
      <header className="flex justify-between items-center mb-8 border-b border-white/10 pb-4">
        <div className="flex items-center gap-4">
          <div className="p-2 border border-tactical-red bg-tactical-red/10 critical-glow">
            <Shield className="w-6 h-6 text-tactical-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-[0.3em]">CYBER SENTINEL : COMMAND</h1>
            <p className="text-[10px] text-white/40 tracking-widest mt-1">ACTIVE SURVEILLANCE NODE // MEDALLION GOLD LAYER</p>
          </div>
        </div>

        <div className="flex gap-8 items-center bg-tactical-gray/40 border border-white/5 p-4 tactical-border">
          {stats ? (
            <>
              <StatBox label="Active Threats" value={stats.high_risk} color="#ff0000" />
              <StatBox label="Nodes Tracked" value={stats.total_domains} color="#00f3ff" />
              <StatBox label="Avg Risk Vector" value={stats.avg_risk.toFixed(3)} />
            </>
          ) : (
            <div className="text-white/20">SYSTEM INITIALIZING...</div>
          )}
        </div>
      </header>

      {/* Main Grid */}
      <div className="grid grid-cols-12 gap-6 h-[calc(100vh-180px)]">

        {/* Left Column: Live Intel Feed */}
        <div className="col-span-3 flex flex-col gap-6 h-full">
          <TacticalCard title="Intelligence Feed" className="flex-1 overflow-hidden flex flex-col">
            <div className="overflow-y-auto pr-2 space-y-3 flex-1 scrollbar-hide">
              {threats.map((t, i) => (
                <motion.div
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  key={t.registered_domain}
                  className="p-3 bg-white/5 border border-white/10 hover:border-tactical-red/50 cursor-pointer group transition-all"
                  onClick={() => setInvestigating(t.registered_domain)}
                >
                  <div className="flex justify-between items-start mb-1">
                    <span className="text-[11px] font-bold truncate flex-1">{t.registered_domain}</span>
                    <span className={`text-[10px] px-1 ${t.risk_score > 0.95 ? 'text-tactical-red' : 'text-yellow-500'}`}>
                      {(t.risk_score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between text-[9px] text-white/30">
                    <span>{t.sample_country || "UNK"}</span>
                    <span className="group-hover:text-tactical-red transition-colors flex items-center gap-1">
                      ANALYSIS <ChevronRight className="w-2 h-2" />
                    </span>
                  </div>
                </motion.div>
              ))}
            </div>
          </TacticalCard>
        </div>

        {/* Center: Tactical Map & Analytics */}
        <div className="col-span-6 flex flex-col gap-6">
          <TacticalCard title="Tactical Risk Projection" className="flex-1 relative">
            <div className="absolute inset-0 flex items-center justify-center opacity-10">
              <Globe className="w-64 h-64 text-cyan-400 animate-pulse" />
            </div>
            <div className="relative z-10 w-full h-full flex flex-col justify-end">
              <div className="h-48 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={threats.slice(0, 20).reverse()}>
                    <defs>
                      <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ff0000" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#ff0000" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="risk_score" stroke="#ff0000" fillOpacity={1} fill="url(#colorRisk)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </TacticalCard>

          <div className="grid grid-cols-2 gap-6 h-48">
            <TacticalCard title="System Resources">
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-[10px] mb-1">
                    <span>NEURAL KERNEL LOAD</span>
                    <span>84%</span>
                  </div>
                  <div className="h-1 bg-white/10 w-full overflow-hidden">
                    <motion.div initial={{ width: 0 }} animate={{ width: "84%" }} className="h-full bg-cyan-400" />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-[10px] mb-1">
                    <span>ANALYTICS BUFFER</span>
                    <span>42%</span>
                  </div>
                  <div className="h-1 bg-white/10 w-full overflow-hidden">
                    <motion.div initial={{ width: 0 }} animate={{ width: "42%" }} className="h-full bg-tactical-red" />
                  </div>
                </div>
              </div>
            </TacticalCard>
            <TacticalCard title="Network Status">
              <div className="flex items-center gap-3 text-cyan-400 mb-2">
                <Activity className="w-4 h-4 animate-bounce" />
                <span className="text-[10px]">ALL RECON NODES ACTIVE</span>
              </div>
              <p className="text-[9px] text-white/30 leading-relaxed">
                WHOIS PROTOCOL: RDAP-ENHANCED<br />
                DNS RESOLVER: GEOGRAPHIC-DISTRIBUTED<br />
                ENRICHMENT LATENCY: 142MS
              </p>
            </TacticalCard>
          </div>
        </div>

        {/* Right Column: Investigator */}
        <div className="col-span-3 h-full">
          <TacticalCard title="Domain Investigator" className="h-full">
            {investigating ? (
              <div className="space-y-6">
                <div className="p-4 bg-tactical-red/10 border border-tactical-red/30">
                  <div className="text-[9px] text-tactical-red font-bold mb-1">TARGET_IDENTIFIER</div>
                  <div className="text-sm font-bold break-all">{investigating}</div>
                </div>

                <div className="space-y-4">
                  <StatBox label="Probability Score" value={(threats.find(t => t.registered_domain === investigating)?.risk_score)?.toFixed(5) || "???"} color="#ff0000" />
                  <StatBox label="Hosting Country" value={threats.find(t => t.registered_domain === investigating)?.sample_country || "UNKNOWN"} />
                  <StatBox label="ISP Provider" value={threats.find(t => t.registered_domain === investigating)?.sample_isp || "UNKNOWN"} />
                </div>

                <div className="border-t border-white/10 pt-4">
                  <button
                    onClick={() => setInvestigating(null)}
                    className="w-full p-2 border border-white/10 hover:bg-white/10 text-[10px] tracking-widest transition-all"
                  >
                    TERMINATE ANALYSIS
                  </button>
                </div>
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center opacity-20">
                <TerminalIcon className="w-12 h-12 mb-4" />
                <p className="text-[10px] tracking-widest">AWAITING TARGET SELECTION</p>
              </div>
            )}
          </TacticalCard>
        </div>

      </div>

      {/* Footer */}
      <footer className="mt-8 flex justify-between items-center text-[9px] text-white/30 tracking-[0.2em]">
        <span>SYSTEM_ID : SENTINEL_ALPHA_09</span>
        <span>© 2026 CYBER_SENTINEL.PLATFORM</span>
        <span>LOCAL_STATION : MORDOR_NET_01</span>
      </footer>
    </main>
  );
}
