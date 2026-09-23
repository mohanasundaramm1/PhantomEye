"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import { ChevronRight, Target, Lock, Filter } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { SectionHeader } from "@/components/Tactical";
import { API_BASE, STAGE_COLORS, decomposeConfidence, formatFreshness } from "@/lib/config";
import type { Stats, Campaign, CampaignDetail, PipelineHealth, DispositionProvenance } from "@/lib/types";

export default function QueuePage() {
  const [mounted, setMounted] = useState(false);
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null);
  const [pipelineHealth, setPipelineHealth] = useState<PipelineHealth | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [brandFilter, setBrandFilter] = useState<string | null>(null);
  const [myQueueOnly, setMyQueueOnly] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulkActionPending, setBulkActionPending] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState(0);
  const [expandedCampaignId, setExpandedCampaignId] = useState<number | null>(null);
  const [campaignDetail, setCampaignDetail] = useState<CampaignDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [analystName, setAnalystName] = useState("");
  const [dispositionNotes, setDispositionNotes] = useState("");
  const [assigneeInput, setAssigneeInput] = useState("");
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [provenance, setProvenance] = useState<DispositionProvenance | null>(null);
  const [provenanceLoading, setProvenanceLoading] = useState(false);

  useEffect(() => {
    const saved = window.localStorage.getItem("phantomeye_analyst_name");
    if (saved) setAnalystName(saved);
  }, []);
  useEffect(() => {
    if (analystName) window.localStorage.setItem("phantomeye_analyst_name", analystName);
  }, [analystName]);

  useEffect(() => { setMounted(true); }, []);

  useEffect(() => {
    async function fetchData() {
      try {
        const [campaignsRes, healthRes, statsRes] = await Promise.all([
          fetch(`${API_BASE}/campaigns?limit=50`),
          fetch(`${API_BASE}/health/pipeline`),
          fetch(`${API_BASE}/threats/stats`),
        ]);
        if (campaignsRes.ok) {
          const d = await campaignsRes.json();
          if (Array.isArray(d?.campaigns)) setCampaigns(d.campaigns);
        }
        if (healthRes.ok) {
          const d = await healthRes.json();
          if (d && typeof d.healthy === "boolean") setPipelineHealth(d);
        }
        if (statsRes.ok) setStats(await statsRes.json());
      } catch (err) {
        console.error("Queue sync error:", err);
      }
    }
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const availableBrands = useMemo(() => {
    if (!campaigns) return [];
    return Array.from(new Set(campaigns.map(c => c.target_brand).filter((b): b is string => !!b))).sort();
  }, [campaigns]);

  const filteredCampaigns = useMemo(() => {
    if (!campaigns) return null;
    let filtered = brandFilter ? campaigns.filter(c => c.target_brand === brandFilter) : campaigns;
    if (myQueueOnly && analystName.trim()) {
      filtered = filtered.filter(c => c.assignee === analystName.trim());
    }
    return [...filtered].sort((a, b) => (b.confidence_score ?? 0) - (a.confidence_score ?? 0));
  }, [campaigns, brandFilter, myQueueOnly, analystName]);

  const fetchProvenance = async (id: number) => {
    setProvenanceLoading(true);
    try {
      const res = await fetch(`${API_BASE}/campaigns/${id}/disposition-provenance`);
      if (res.ok) {
        const data = await res.json();
        if (data?.available) setProvenance(data);
      }
    } catch (err) {
      console.error("Provenance fetch failed:", err);
    } finally {
      setProvenanceLoading(false);
    }
  };

  const toggleCampaign = async (id: number) => {
    if (expandedCampaignId === id) {
      setExpandedCampaignId(null);
      setCampaignDetail(null);
      setProvenance(null);
      return;
    }
    setExpandedCampaignId(id);
    setCampaignDetail(null);
    setDispositionNotes("");
    setAssigneeInput("");
    setActionError(null);
    setProvenance(null);
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

  // Bulk disposition: N sequential-in-parallel POSTs (Promise.allSettled),
  // not a dedicated bulk endpoint — apply_stage_transition() already
  // row-locks per-cluster, so a "real" bulk endpoint would just loop
  // server-side instead of client-side for no real gain at today's queue
  // size. Partial failure is surfaced (not silently swallowed): if 3 of 5
  // succeed, the analyst sees exactly which 2 didn't and can retry those.
  const submitBulkDisposition = async (verdict: "confirmed" | "suppressed" | "benign") => {
    if (!analystName.trim()) {
      setActionError("Enter your analyst name first.");
      return;
    }
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    setBulkActionPending(true);
    setActionError(null);
    const results = await Promise.allSettled(
      ids.map(async id => {
        const res = await fetch(`${API_BASE}/campaigns/${id}/disposition`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ verdict, analyst: analystName.trim() }),
        });
        if (!res.ok) throw new Error(`campaign ${id}: ${res.status}`);
        return id;
      })
    );
    const failedIds = results
      .map((r, i) => (r.status === "rejected" ? ids[i] : null))
      .filter((id): id is number => id !== null);
    await Promise.all(ids.filter(id => !failedIds.includes(id)).map(refreshCampaign));
    if (failedIds.length > 0) {
      setActionError(`${failedIds.length} of ${ids.length} failed (campaign IDs: ${failedIds.join(", ")}) — still selected, retry or investigate.`);
      setSelectedIds(new Set(failedIds));
    } else {
      setSelectedIds(new Set());
    }
    setBulkActionPending(false);
  };

  const toggleSelected = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
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

  // Keep the keyboard-focused row in range as the filtered set changes size
  // (e.g. switching brand filters) so it never points past the end.
  useEffect(() => {
    if (!filteredCampaigns) return;
    setFocusedIndex(prev => Math.min(Math.max(prev, 0), Math.max(filteredCampaigns.length - 1, 0)));
  }, [filteredCampaigns]);

  // Keyboard shortcuts: j/k walk the queue, c/s confirm/suppress whichever
  // row is focused. Suppressed while typing in any form field (analyst name,
  // notes, scanner input, etc.) so shortcut letters can still be typed there.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || target?.isContentEditable) return;
      if (!filteredCampaigns || filteredCampaigns.length === 0) return;

      if (e.key === "j" || e.key === "k") {
        e.preventDefault();
        setFocusedIndex(prev => {
          const clamped = Math.min(Math.max(prev, 0), filteredCampaigns.length - 1);
          const next = e.key === "j" ? Math.min(clamped + 1, filteredCampaigns.length - 1) : Math.max(clamped - 1, 0);
          const id = filteredCampaigns[next]?.campaign_id;
          if (id != null) {
            document.getElementById(`campaign-row-${id}`)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
          }
          return next;
        });
      } else if (e.key === "c" || e.key === "s") {
        const idx = Math.min(Math.max(focusedIndex, 0), filteredCampaigns.length - 1);
        const id = filteredCampaigns[idx]?.campaign_id;
        if (id != null) submitDisposition(id, e.key === "c" ? "confirmed" : "suppressed");
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [filteredCampaigns, focusedIndex, submitDisposition]);

  if (!mounted) return <div className="bg-[#050505] min-h-screen" />;

  return (
    <div className="pt-10 pb-24">

  <section className="max-w-[1600px] mx-auto p-12 mt-20">
    <SectionHeader
      title="Campaign Queue"
      subtitle={`Clustered, brand-attributed infrastructure ranked by confidence. Tracking ${stats?.watchlist_brand_count ?? "—"} brand${stats?.watchlist_brand_count === 1 ? "" : "s"} today — add more via \`make seed-brands\`.`}
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
        <button
          onClick={() => setMyQueueOnly(v => !v)}
          disabled={!analystName.trim()}
          title={!analystName.trim() ? "Enter your analyst name above to use this filter" : undefined}
          className={`px-3 py-1.5 text-[10px] uppercase font-black tracking-widest border transition-colors disabled:opacity-30 disabled:cursor-not-allowed ${myQueueOnly ? "border-cyan-400 text-cyan-400 bg-cyan-400/10" : "border-white/10 text-white/40 hover:text-white/70"}`}
        >
          My Queue ({analystName.trim() ? (campaigns?.filter(c => c.assignee === analystName.trim()).length ?? 0) : 0})
        </button>
        <span className="ml-auto text-[9px] uppercase font-black tracking-widest text-white/15 normal-case">
          <kbd className="text-white/30">j</kbd>/<kbd className="text-white/30">k</kbd> navigate · <kbd className="text-white/30">c</kbd> confirm · <kbd className="text-white/30">s</kbd> suppress
        </span>
      </div>
    )}

    {/* Bulk action bar — appears once anything is selected. Sequential
        client-side POSTs (see submitBulkDisposition), not a bulk
        endpoint. */}
    {selectedIds.size > 0 && (
      <div className="mb-4 p-4 border border-cyan-400/30 bg-cyan-400/5 flex flex-wrap items-center gap-4">
        <span className="text-[10px] uppercase font-black tracking-widest text-cyan-400">
          {selectedIds.size} selected
        </span>
        <div className="flex gap-3">
          <button
            disabled={bulkActionPending}
            onClick={() => submitBulkDisposition("confirmed")}
            className="px-4 py-2 text-[10px] uppercase font-black tracking-widest border border-tactical-red/40 text-tactical-red hover:bg-tactical-red/10 transition-colors disabled:opacity-30"
          >
            Confirm All
          </button>
          <button
            disabled={bulkActionPending}
            onClick={() => submitBulkDisposition("suppressed")}
            className="px-4 py-2 text-[10px] uppercase font-black tracking-widest border border-white/10 text-white/50 hover:bg-white/5 transition-colors disabled:opacity-30"
          >
            Suppress All
          </button>
          <button
            disabled={bulkActionPending}
            onClick={() => submitBulkDisposition("benign")}
            className="px-4 py-2 text-[10px] uppercase font-black tracking-widest border border-white/10 text-white/50 hover:bg-white/5 transition-colors disabled:opacity-30"
          >
            Mark Benign All
          </button>
        </div>
        <button
          onClick={() => setSelectedIds(new Set())}
          className="ml-auto text-[10px] uppercase font-black tracking-widest text-white/30 hover:text-white/60"
        >
          Clear selection
        </button>
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
        {filteredCampaigns?.map((c, i) => (
          <div
            key={c.campaign_id}
            id={`campaign-row-${c.campaign_id}`}
            className={`tactical-border bg-[#080808]/50 backdrop-blur-xl flex items-stretch ${selectedIds.has(c.campaign_id) ? "ring-1 ring-cyan-400/40" : ""} ${i === focusedIndex ? "outline outline-2 outline-amber-400/60 outline-offset-[-2px]" : ""}`}
          >
            <label className="flex items-center px-4 cursor-pointer border-r border-white/5 hover:bg-white/[0.03]">
              <input
                type="checkbox"
                checked={selectedIds.has(c.campaign_id)}
                onChange={() => toggleSelected(c.campaign_id)}
                onClick={e => e.stopPropagation()}
                className="w-4 h-4 accent-cyan-400 cursor-pointer"
              />
            </label>
            <button
              onClick={() => toggleCampaign(c.campaign_id)}
              className="flex-1 flex items-center gap-6 p-5 text-left hover:bg-white/[0.03] transition-colors min-w-0"
            >
              <div
                className="flex flex-col items-center justify-center w-20 shrink-0"
                title={(() => {
                  const d = decomposeConfidence(c.confidence_score, c.member_count);
                  if (!d) return undefined;
                  return `${d.clamped ? "risk >= " : "risk = "}${(d.maxRisk * 100).toFixed(0)}% `
                    + `x corroboration ${(d.corroboration * 100).toFixed(0)}% (${c.member_count} member${c.member_count === 1 ? "" : "s"})`;
                })()}
              >
                <span className="text-2xl font-black text-tactical-red text-glow-red">
                  {c.confidence_score != null ? `${Math.min(99, Math.round(c.confidence_score * 100))}%` : "--"}
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
                <p className="text-[11px] text-white/40 font-bold uppercase tracking-wide line-clamp-2 leading-relaxed" title={c.summary_reason ?? undefined}>{c.summary_reason ?? "no summary available"}</p>
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

                        {/* Disposition → retrain provenance: does the analyst's
                            verdict on this campaign show up as training signal
                            for a later model? Lazily fetched (not every campaign
                            has a disposition, so no reason to call this on every
                            expand). */}
                        {c.stage_locked_by && (
                          <div className="text-[10px]">
                            {!provenance && !provenanceLoading && (
                              <button
                                onClick={() => fetchProvenance(c.campaign_id)}
                                className="uppercase font-black tracking-widest text-cyan-400/70 hover:text-cyan-400 transition-colors"
                              >
                                → Did this disposition retrain the model?
                              </button>
                            )}
                            {provenanceLoading && (
                              <span className="uppercase font-black tracking-widest text-white/20 italic">checking...</span>
                            )}
                            {provenance && provenance.has_disposition && (
                              <div className="p-3 bg-white/5 border border-white/10 flex flex-col gap-1 text-white/50 not-italic normal-case tracking-normal">
                                <span>
                                  Disposition <span className="text-white/80 font-black">{provenance.disposition!.verdict}</span> by{" "}
                                  {provenance.disposition!.analyst} on{" "}
                                  {new Date(provenance.disposition!.created_at).toISOString().slice(0, 10)}
                                </span>
                                {provenance.eligible_training_run ? (
                                  <span>
                                    Earliest eligible retrain:{" "}
                                    {new Date(provenance.eligible_training_run.created_utc).toISOString().slice(0, 10)}
                                    {" "}({provenance.eligible_training_run.n_pos ?? "?"} pos / {provenance.eligible_training_run.n_neg ?? "?"} neg,{" "}
                                    {provenance.eligible_training_run.promoted ? "promoted" : "not promoted"})
                                  </span>
                                ) : (
                                  <span className="text-white/30">No training run has occurred since this disposition yet.</span>
                                )}
                                <span className="text-white/20 italic">{provenance.note}</span>
                              </div>
                            )}
                          </div>
                        )}

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

      <section className="max-w-[1600px] mx-auto px-12 -mt-4">
        <details className="border border-white/10 bg-white/[0.02] px-4 py-3">
          <summary className="cursor-pointer text-[10px] font-black uppercase tracking-widest text-white/40 hover:text-white/70">
            Where this data comes from
          </summary>
          <div className="mt-3 text-[10px] text-white/40 normal-case leading-relaxed space-y-2 max-w-3xl">
            <p>
              <span className="text-cyan-400 font-black">This queue</span> reads the campaign-radar
              Postgres store (analyst state: observations, clusters, dispositions, watchlist) —
              {stats?.total_parsed != null ? ` currently backing ${stats.total_parsed.toLocaleString()} parsed rows.` : " the serving store."}
            </p>
            <p>
              <span className="text-cyan-400 font-black">Analysis &amp; Scan</span> read the detection
              lake directly — the newest scored parquet, filtered to risk_score &gt; 0.85. That is a
              different store with different recency, by design: the lake is the pipeline&rsquo;s source
              of truth, the DB is the interaction surface.
            </p>
            <p className="text-white/25">
              A campaign appears here only after the bridge job (campaign_radar_dag) has run, which is
              offset 15 minutes behind scoring. Short lag between the two views is expected, not a fault.
            </p>
          </div>
        </details>
      </section>

    </div>
  );
}
