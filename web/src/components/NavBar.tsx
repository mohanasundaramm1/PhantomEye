"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Eye, Target, Layers, Activity, BarChart3, Search, Server } from "lucide-react";
import { API_BASE } from "@/lib/config";
import type { PipelineHealth } from "@/lib/types";

const ROUTES = [
  { href: "/", label: "Queue", icon: Target },
  { href: "/watchlist", label: "Watchlist", icon: Layers },
  { href: "/analysis", label: "Analysis", icon: Activity },
  { href: "/metrics", label: "Metrics", icon: BarChart3 },
  { href: "/scan", label: "Scan", icon: Search },
  { href: "/system", label: "System", icon: Server },
];

/**
 * Persistent top bar. Replaces the former full-screen hero splash, which
 * pushed the actual work surface 863px down the page and had to be scrolled
 * past on every visit. The pipeline-health chip lives here (not buried inside
 * the campaign queue) so staleness is visible from every route -- the whole
 * point of having a freshness watchdog is that you see it without looking.
 */
export default function NavBar() {
  const pathname = usePathname();
  const [health, setHealth] = useState<PipelineHealth | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await fetch(`${API_BASE}/health/pipeline`);
        if (!res.ok) return;
        const j = await res.json();
        if (!cancelled) setHealth(j);
      } catch { /* health chip degrades to "syncing", never blocks the page */ }
    };
    load();
    const t = setInterval(load, 60_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  const healthy = health?.healthy;
  const chipColor = health == null
    ? "text-white/30 border-white/10"
    : healthy
      ? "text-cyan-400 border-cyan-400/30 bg-cyan-400/5"
      : "text-tactical-red border-tactical-red/40 bg-tactical-red/5";
  const chipLabel = health == null ? "SYNCING" : healthy ? "PIPELINE HEALTHY" : "PIPELINE DEGRADED";

  return (
    <header className="sticky top-0 z-50 border-b border-white/10 bg-black/80 backdrop-blur-xl">
      <div className="max-w-[1600px] mx-auto px-6 h-14 flex items-center gap-6">
        <Link href="/" className="flex items-center gap-2 shrink-0 group">
          <Eye className="w-5 h-5 text-tactical-red" />
          <span className="text-[13px] font-black tracking-[0.3em] italic uppercase group-hover:text-tactical-red transition-colors">
            Phantom_Eye
          </span>
        </Link>

        <nav className="flex items-center gap-1 overflow-x-auto">
          {ROUTES.map(({ href, label, icon: Icon }) => {
            const active = pathname === href;
            return (
              <Link
                key={href}
                href={href}
                className={`flex items-center gap-2 px-3 py-1.5 text-[10px] font-black uppercase tracking-widest whitespace-nowrap transition-colors border ${
                  active
                    ? "text-tactical-red border-tactical-red/40 bg-tactical-red/5"
                    : "text-white/40 border-transparent hover:text-white/80"
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {label}
              </Link>
            );
          })}
        </nav>

        <div className={`ml-auto shrink-0 flex items-center gap-2 px-3 py-1.5 border text-[9px] font-black uppercase tracking-widest ${chipColor}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${health == null ? "bg-white/30" : healthy ? "bg-cyan-400" : "bg-tactical-red animate-pulse"}`} />
          {chipLabel}
          {health?.ct_raw?.newest_age_hours != null && (
            <span className="text-white/30 normal-case font-bold">
              · ct {health.ct_raw.newest_age_hours < 1
                ? `${Math.round(health.ct_raw.newest_age_hours * 60)}m`
                : `${health.ct_raw.newest_age_hours.toFixed(1)}h`} old
            </span>
          )}
        </div>
      </div>
    </header>
  );
}
