"use client";

import React, { useState, useEffect } from "react";
import { BarChart3, Clock } from "lucide-react";
import { SectionHeader, TacticalCard } from "@/components/Tactical";
import { API_BASE } from "@/lib/config";
import type { OperationsMetrics, LeadTimeMetrics, PrecisionAtKMetrics } from "@/lib/types";

export default function MetricsPage() {
  const [operationsMetrics, setOperationsMetrics] = useState<OperationsMetrics | null>(null);
  const [leadTimeMetrics, setLeadTimeMetrics] = useState<LeadTimeMetrics | null>(null);
  const [precisionAtK, setPrecisionAtK] = useState<PrecisionAtKMetrics | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const [o, l, p] = await Promise.all([
          fetch(`${API_BASE}/metrics/operations`),
          fetch(`${API_BASE}/metrics/lead-time`),
          fetch(`${API_BASE}/metrics/precision-at-k`),
        ]);
        if (o.ok) setOperationsMetrics(await o.json());
        if (l.ok) setLeadTimeMetrics(await l.json());
        if (p.ok) setPrecisionAtK(await p.json());
      } catch { /* empty state below handles this */ }
      finally { setLoaded(true); }
    })();
  }, []);

  // Phase 0.2 -- a section titled "Proof" rendering four "NOT YET MEASURED"
  // tiles is worse than no section. Only render the grid once at least one
  // metric has a real sample behind it.
  const anyAvailable = Boolean(
    precisionAtK?.available || leadTimeMetrics?.available || operationsMetrics?.available
  );

  // Phase 2.1 -- metrics are computed by a batch job, not live. Say when,
  // explicitly, rather than letting the page imply "now".
  const computedAt = [
    (precisionAtK as any)?.computed_utc,
    (leadTimeMetrics as any)?.computed_utc,
    (operationsMetrics as any)?.computed_utc,
  ].filter(Boolean).sort().pop() as string | undefined;

  const staleness = (() => {
    if (!computedAt) return null;
    const ageH = (Date.now() - new Date(computedAt).getTime()) / 3_600_000;
    const stale = ageH > 24;
    return {
      label: `computed ${new Date(computedAt).toISOString().replace("T", " ").slice(0, 16)}Z`,
      ageLabel: ageH < 1 ? `${Math.round(ageH * 60)}m ago` : ageH < 48 ? `${ageH.toFixed(1)}h ago` : `${(ageH / 24).toFixed(1)}d ago`,
      stale,
    };
  })();

  return (
    <div className="pt-10 pb-24">
      <section className="max-w-[1600px] mx-auto p-12">
        <SectionHeader
          title="Metrics & Proof"
          subtitle="Real measurements, not marketing claims — precision, lead-time, analyst throughput, and enrichment coverage, each with its own honesty check for small/zero sample sizes."
          icon={BarChart3}
        />

        {staleness && (
          <div className={`mb-8 inline-flex items-center gap-2 px-3 py-1.5 border text-[10px] font-black uppercase tracking-widest ${
            staleness.stale ? "text-yellow-400 border-yellow-400/30 bg-yellow-400/5" : "text-cyan-400 border-cyan-400/30 bg-cyan-400/5"
          }`}>
            <Clock className="w-3.5 h-3.5" />
            {staleness.label} · {staleness.ageLabel}
            {staleness.stale && <span className="text-white/40 normal-case">— batch job has not re-run since</span>}
          </div>
        )}

        {!loaded ? (
          <div className="h-[200px] flex items-center justify-center opacity-20 italic text-[11px] uppercase font-black tracking-widest">
            SYNC_METRICS...
          </div>
        ) : !anyAvailable ? (
          <div className="border border-white/10 bg-white/[0.02] p-10 text-center">
            <p className="text-[12px] font-black uppercase tracking-widest text-white/50">No measurable sample yet</p>
            <p className="text-[10px] text-white/30 mt-3 max-w-xl mx-auto leading-relaxed normal-case">
              Precision, lead-time and throughput each need a real sample before they mean anything.
              Rather than render four empty tiles under a heading called &ldquo;Proof&rdquo;, this section
              stays hidden until the metrics job has something honest to report.
            </p>
          </div>
        ) : (

<div className="grid grid-cols-12 gap-10">
  <div className="col-span-3">
    <TacticalCard title="Precision @ K" subTitle="vs. ti_misp_hit (independent ground truth)" status="ML_PROOF">
      {!precisionAtK ? (
        <div className="h-[200px] flex items-center justify-center opacity-20 italic text-[10px] uppercase font-black tracking-widest">SYNC_PRECISION...</div>
      ) : !precisionAtK.available ? (
        <div className="h-[200px] flex items-center justify-center opacity-30 italic text-center px-4 text-[10px] uppercase font-black tracking-widest break-words">{precisionAtK.reason ?? "NOT YET MEASURED"}</div>
      ) : (
        <div className="space-y-3 pt-2">
          {precisionAtK.precision_at_k?.map(p => (
            <div key={p.k} className="flex items-center justify-between p-2 bg-white/5 border border-white/10">
              <span className="text-[10px] uppercase font-black tracking-widest text-white/50">P@{p.k}</span>
              <span className="text-sm font-black text-tactical-red">{p.precision != null ? `${(p.precision * 100).toFixed(0)}%` : "--"}</span>
            </div>
          ))}
          {precisionAtK.confidence_note && (
            <p className="text-[9px] text-white/30 italic leading-relaxed pt-1">{precisionAtK.confidence_note}</p>
          )}
        </div>
      )}
    </TacticalCard>
  </div>

  <div className="col-span-3">
    <TacticalCard title="Lead-Time Breakdown" subTitle="CT ahead of public blocklists" status="DETECTION">
      {!leadTimeMetrics ? (
        <div className="h-[200px] flex items-center justify-center opacity-20 italic text-[10px] uppercase font-black tracking-widest">SYNC_LEAD_TIME...</div>
      ) : !leadTimeMetrics.available ? (
        <div className="h-[200px] flex items-center justify-center opacity-30 italic text-center px-4 text-[10px] uppercase font-black tracking-widest break-words">{leadTimeMetrics.reason ?? "NOT YET MEASURED"}</div>
      ) : (
        <div className="space-y-3 pt-2 text-[10px]">
          <div className="flex justify-between p-2 bg-white/5 border border-white/10">
            <span className="uppercase font-black tracking-widest text-white/50">Exact hostname</span>
            <span className="font-black text-cyan-400">{leadTimeMetrics.n_matched_exact_hostname ?? 0}</span>
          </div>
          <div className="flex justify-between p-2 bg-white/5 border border-white/10">
            <span className="uppercase font-black tracking-widest text-white/50">Apex-only</span>
            <span className="font-black text-white/60">{leadTimeMetrics.n_matched_registered_domain_only ?? 0}</span>
          </div>
          <div className="flex justify-between p-2 bg-white/5 border border-white/10">
            <span className="uppercase font-black tracking-widest text-white/50">Median lead (ahead)</span>
            <span className="font-black text-tactical-red">{leadTimeMetrics.median_lead_time_hours_when_ahead != null ? `${leadTimeMetrics.median_lead_time_hours_when_ahead.toFixed(1)}h` : "--"}</span>
          </div>
          <p className="text-[9px] text-white/30 italic leading-relaxed pt-1">{leadTimeMetrics.confidence_note}</p>
        </div>
      )}
    </TacticalCard>
  </div>

  <div className="col-span-3">
    <TacticalCard title="Analyst Throughput" subTitle="Confirmation rate & review speed" status="WORKFLOW">
      {!operationsMetrics ? (
        <div className="h-[200px] flex items-center justify-center opacity-20 italic text-[10px] uppercase font-black tracking-widest">SYNC_METRICS...</div>
      ) : !operationsMetrics.available ? (
        <div className="h-[200px] flex items-center justify-center opacity-30 italic text-center px-4 text-[10px] uppercase font-black tracking-widest break-words">{operationsMetrics.reason ?? "PRODUCT DB UNAVAILABLE"}</div>
      ) : (
        <div className="space-y-3 pt-2 text-[10px]">
          <div className="flex justify-between p-2 bg-white/5 border border-white/10">
            <span className="uppercase font-black tracking-widest text-white/50">Confirmation rate</span>
            <span className="font-black text-cyan-400">
              {operationsMetrics.analyst_confirmation?.rate != null ? `${(operationsMetrics.analyst_confirmation.rate * 100).toFixed(0)}%` : "n/a"}
              <span className="text-white/30 font-bold"> ({operationsMetrics.analyst_confirmation?.n_dispositions ?? 0})</span>
            </span>
          </div>
          <div className="flex justify-between p-2 bg-white/5 border border-white/10">
            <span className="uppercase font-black tracking-widest text-white/50">Median time to review</span>
            <span className="font-black text-white/60">{operationsMetrics.median_time_to_first_review?.median_hours != null ? `${operationsMetrics.median_time_to_first_review.median_hours.toFixed(1)}h` : "n/a"}</span>
          </div>
          <div className="flex justify-between p-2 bg-white/5 border border-white/10">
            <span className="uppercase font-black tracking-widest text-white/50">Suppression rate</span>
            <span className="font-black text-white/60">{operationsMetrics.suppression?.rate != null ? `${(operationsMetrics.suppression.rate * 100).toFixed(0)}%` : "n/a"}</span>
          </div>
          <div className="flex justify-between p-2 bg-white/5 border border-white/10">
            <span className="uppercase font-black tracking-widest text-white/50">Campaigns/day</span>
            <span className="font-black text-white/60">{operationsMetrics.campaigns_created?.per_day ?? "n/a"}</span>
          </div>
          {operationsMetrics.analyst_confirmation?.confidence_note && (
            <p className="text-[9px] text-white/30 italic leading-relaxed pt-1">{operationsMetrics.analyst_confirmation.confidence_note}</p>
          )}
        </div>
      )}
    </TacticalCard>
  </div>

  <div className="col-span-3">
    <TacticalCard title="Enrichment Coverage" subTitle="Pipeline depth, not analyst workflow" status="PIPELINE">
      {!operationsMetrics ? (
        <div className="h-[200px] flex items-center justify-center opacity-20 italic text-[10px] uppercase font-black tracking-widest">SYNC_COVERAGE...</div>
      ) : !operationsMetrics.available ? (
        <div className="h-[200px] flex items-center justify-center opacity-30 italic text-center px-4 text-[10px] uppercase font-black tracking-widest break-words">{operationsMetrics.reason ?? "PRODUCT DB UNAVAILABLE"}</div>
      ) : (
        <div className="pt-4">
          <div className="flex flex-col items-center justify-center gap-2 py-6">
            <span className="text-4xl font-black text-tactical-red text-glow-red">
              {operationsMetrics.enrichment_completeness?.rate != null ? `${(operationsMetrics.enrichment_completeness.rate * 100).toFixed(0)}%` : "--"}
            </span>
            <span className="text-[9px] uppercase font-black tracking-widest text-white/30">carry WHOIS data (registrar / creation date)</span>
          </div>
          <p className="text-[9px] text-white/30 italic text-center leading-relaxed">
            {operationsMetrics.enrichment_completeness?.n_whois ?? 0} of {operationsMetrics.enrichment_completeness?.n_total ?? 0} observations
          </p>
        </div>
      )}
    </TacticalCard>
  </div>
</div>
        )}
      </section>
    </div>
  );
}
