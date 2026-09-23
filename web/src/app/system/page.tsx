"use client";

import React, { useEffect, useState } from "react";
import { BarChart3 } from "lucide-react";
import { SectionHeader, TacticalCard } from "@/components/Tactical";
import { API_BASE } from "@/lib/config";
import type { Stats, ModelStatus, PipelineHealth } from "@/lib/types";

export default function SystemPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [network, setNetwork] = useState<any>(null);
  const [modelStatus, setModelStatus] = useState<ModelStatus | null>(null);
  const [health, setHealth] = useState<PipelineHealth | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [s, n, m, h] = await Promise.all([
          fetch(`${API_BASE}/threats/stats`),
          fetch(`${API_BASE}/threats/network`),
          fetch(`${API_BASE}/model/status`),
          fetch(`${API_BASE}/health/pipeline`),
        ]);
        if (s.ok) setStats(await s.json());
        if (n.ok) setNetwork(await n.json());
        if (m.ok) setModelStatus(await m.json());
        if (h.ok) setHealth(await h.json());
      } catch { /* panels render "--" rather than throwing */ }
    })();
  }, []);

  return (
    <div className="pt-10 pb-24">
  <section className="max-w-[1400px] mx-auto p-12 mt-40 border-t border-white/5 pt-32">
    <SectionHeader
      title="System Status"
      subtitle="Live pipeline & model telemetry — no simulated events."
      icon={BarChart3}
    />

    <TacticalCard title="System Status" status={stats ? "STABLE" : "SYNCING"} subTitle="Live pipeline & model telemetry — no simulated events">
      <div className="space-y-4 pt-4 flex flex-col">
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
  </section>


      {/* Ingest watchdog detail -- previously only implied by the campaign-queue
          banner, which was invisible from anywhere else in the app. */}
      <section className="max-w-[1400px] mx-auto px-12">
        <TacticalCard title="Ingest Watchdog" status={health?.ingest_watchdog?.stale ? "STALE" : "OK"}>
          <div className="space-y-2 pt-4 text-[10px] uppercase font-black tracking-widest opacity-70">
            <p>[info] CT_RAW_AGE: {health?.ct_raw?.newest_age_hours != null ? `${health.ct_raw.newest_age_hours.toFixed(2)}h` : "--"}</p>
            <p>[info] SCORING_AGE: {health?.scoring?.newest_scored_age_hours != null ? `${health.scoring.newest_scored_age_hours.toFixed(2)}h` : "--"}</p>
            <p>[info] APP_DB: {health?.app_db?.reachable ? "REACHABLE" : "UNREACHABLE"}</p>
            <p className={health?.ingest_watchdog?.stale ? "text-tactical-red" : "text-cyan-400"}>
              [info] WATCHDOG: {health?.ingest_watchdog?.stale ? "REPORTS STALE" : "FRESH"}
            </p>
          </div>
        </TacticalCard>
      </section>
    </div>
  );
}
