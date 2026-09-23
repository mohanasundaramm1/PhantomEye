"use client";

import React, { useState, useEffect } from "react";
import { Activity, Globe, Cpu, Lock, Fingerprint, TrendingUp } from "lucide-react";
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area, BarChart as ReBarChart, Bar, Cell, PieChart, Pie } from 'recharts';
import dynamic from "next/dynamic";
import { SectionHeader, TacticalCard } from "@/components/Tactical";
import { API_BASE, SHOW_GEO_PANELS, SOURCE_LABELS, SOURCE_COLORS } from "@/lib/config";
import type { Threat, Stats, ModelStatus } from "@/lib/types";

const NetworkGraph = dynamic(() => import("@/components/NetworkGraph"), { ssr: false });

export default function AnalysisPage() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [network, setNetwork] = useState<any>(null);
  const [modelStatus, setModelStatus] = useState<ModelStatus | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [t, s, n, m] = await Promise.all([
          fetch(`${API_BASE}/threats/latest?limit=50`),
          fetch(`${API_BASE}/threats/stats`),
          fetch(`${API_BASE}/threats/network`),
          fetch(`${API_BASE}/model/status`),
        ]);
        if (t.ok) setThreats((await t.json()).data ?? []);
        if (s.ok) setStats(await s.json());
        if (n.ok) setNetwork(await n.json());
        if (m.ok) setModelStatus(await m.json());
      } catch { /* panels carry their own empty states */ }
    })();
  }, []);

  return (
    <div className="pt-10 pb-24">
      {/* --- TRIAGE OVERWATCH --- */}
      <section className="max-w-[1600px] mx-auto p-12">
        <SectionHeader
          title="Triage Situational Overwatch"
          subtitle="Analysis of the high-value reconnaissance stream. Note: flagging density is high as this stream has been pre-filtered for suspicious telemetry."
          icon={Activity}
        />

        {/* Phase 0.1 -- the 600px globe panel here rendered nothing but a
            "geo disabled" message, because no stage of the CT lane geo-enriches
            the IPs it resolves (see Phase 3). Replaced with a one-line notice so
            the live Raw Signal feed gets the space the dead globe was holding. */}
        {!SHOW_GEO_PANELS && (
          <div className="mb-8 inline-flex items-center gap-2 px-3 py-1.5 border border-white/10 bg-white/[0.02] text-[10px] font-black uppercase tracking-widest text-white/40">
            <Globe className="w-3.5 h-3.5" />
            Geo map hidden — CT-lane IPs are not geo-enriched yet
          </div>
        )}

        <div className="grid grid-cols-12 gap-10">
          <div className="col-span-12 lg:col-span-4">
<TacticalCard title="Triage Aggregate" subTitle="High-Value reconnaissance" status="FILTERED">
  <div className="grid grid-cols-1 gap-6 pt-4">
    <div className="flex flex-col gap-2">
      <span className="text-[11px] font-black text-white/20 tracking-widest">NOISE_REJECTION_RATE</span>
      <span className="text-4xl xl:text-5xl font-black italic text-cyan-400 tabular-nums leading-none tracking-tight break-all">{stats?.signal_to_noise != null ? (100 - stats.signal_to_noise).toFixed(1) : "--"}%</span>
      <span className="text-[9px] text-white/10 font-bold uppercase italic mt-1 font-mono">Filtered from {stats?.total_parsed != null ? stats.total_parsed.toLocaleString() : "--"} domains in latest scan batch</span>
    </div>
    <div className="h-px bg-white/10 w-full" />
    <div className="grid grid-cols-2 gap-6">
      <div className="flex flex-col">
        <span className="text-[10px] text-white/40 font-bold mb-1">CRITICAL ( {'>'} 0.98)</span>
        <span className="text-2xl font-black text-tactical-red italic tabular-nums">{stats?.critical != null ? stats.critical : "---"}</span>
      </div>
      <div className="flex flex-col text-right">
        <span className="text-[10px] text-white/40 font-bold mb-1">HIGH ( {'>'} 0.90)</span>
        <span className="text-2xl font-black text-white italic tabular-nums">{stats?.high_risk != null ? stats.high_risk : "---"}</span>
      </div>
    </div>
  </div>
</TacticalCard>
          </div>

          <div className="col-span-12 lg:col-span-8">
            <TacticalCard title="Raw Signal (unclustered)" subTitle="Freshest high-risk hits, before the next cluster-assembly pass" className="h-[600px] overflow-hidden min-h-0" status="STREAMING">
              <div className="h-full overflow-y-auto pr-4 space-y-3 scrollbar-custom min-h-0">
                {threats.length === 0 && (
                  <div className="h-full flex items-center justify-center opacity-20 italic text-[10px] uppercase font-black tracking-widest">
                    NO HIGH-RISK HITS IN CURRENT BATCH
                  </div>
                )}
                {threats.slice(0, 50).map((t, i) => (
                  <div key={t.registered_domain + i} className="p-3 bg-white/5 border border-white/5 flex justify-between items-center gap-4 group hover:bg-white/10 transition-all cursor-crosshair">
                    {/* Phase 0.6 -- domains render lowercase in a mono face and are
                        allowed to wrap. Uppercasing mangled punycode ("xn--..." became
                        an unreadable "XN—") and tracking-tighter clipped long labels. */}
                    <div className="flex flex-col min-w-0 flex-1">
                      <span className="text-[12px] font-bold font-mono lowercase break-all group-hover:text-cyan-400" title={t.registered_domain}>
                        {t.registered_domain}
                      </span>
                      {t.sample_country && (
                        <span className="text-[9px] text-white/20 font-black tracking-widest">{t.sample_country}</span>
                      )}
                    </div>
                    <span className={`shrink-0 text-[11px] font-black tabular-nums ${t.risk_score > 0.98 ? 'text-tactical-red' : t.risk_score > 0.90 ? 'text-orange-500' : 'text-white/40'}`}>
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
      <section className="max-w-[1600px] mx-auto p-12 mt-16">
        <SectionHeader
          title="Infrastructure DNA & Vectors"
          subtitle="Forensic breakdown of infrastructure: TLD saturation and temporal risk decay. ISP reputation is omitted while sample_isp is unpopulated."
          icon={Fingerprint}
        />
        <div className="grid grid-cols-12 gap-10">
<div className="col-span-6">
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


<div className="col-span-6 flex flex-col gap-10">
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


  <section className="max-w-[1600px] mx-auto p-12 mt-40 pt-32 border-t border-white/5">
    <SectionHeader
      title="Topology & Attribution"
      subtitle="Node-link mapping of highly-scored infrastructure, with detection-source breakdown (MISP hit vs. ML score) for each."
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
        <TacticalCard title="Detection Source" subTitle="How flagged domains were detected (risk > 0.5)" status="MISP + ML FUSION" className="flex-1">
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

    </div>
  );
}
