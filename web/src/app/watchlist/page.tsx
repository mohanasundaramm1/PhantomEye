"use client";

import React, { useState, useEffect } from "react";
import { Layers } from "lucide-react";
import { SectionHeader } from "@/components/Tactical";
import { API_BASE } from "@/lib/config";
import type { WatchlistBrandRow } from "@/lib/types";

export default function WatchlistPage() {
  const [watchlistBrands, setWatchlistBrands] = useState<WatchlistBrandRow[] | null>(null);
  const [showInactiveBrands, setShowInactiveBrands] = useState(false);
  const [newBrandName, setNewBrandName] = useState("");
  const [newBrandAliases, setNewBrandAliases] = useState("");
  const [newBrandPriority, setNewBrandPriority] = useState("100");
  const [newBrandSelfDomains, setNewBrandSelfDomains] = useState("");
  const [watchlistActionError, setWatchlistActionError] = useState<string | null>(null);
  const [watchlistActionPending, setWatchlistActionPending] = useState(false);
  const [editingBrandId, setEditingBrandId] = useState<number | null>(null);
  const [editAliases, setEditAliases] = useState("");
  const [editPriority, setEditPriority] = useState("");
  const [editSelfDomains, setEditSelfDomains] = useState("");

  const fetchWatchlist = async () => {
    try {
      const res = await fetch(`${API_BASE}/watchlist`);
      if (res.ok) {
        const data = await res.json();
        if (data?.available) setWatchlistBrands(data.brands);
      }
    } catch (err) {
      console.error("Watchlist fetch failed:", err);
    }
  };

  useEffect(() => {
    fetchWatchlist();
  }, []);

  const createWatchlistBrand = async () => {
    if (!newBrandName.trim()) return;
    setWatchlistActionPending(true);
    setWatchlistActionError(null);
    try {
      const res = await fetch(`${API_BASE}/watchlist`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          brand_name: newBrandName.trim(),
          aliases: newBrandAliases.split(",").map(a => a.trim()).filter(Boolean),
          priority: parseInt(newBrandPriority, 10) || 100,
          self_domains: newBrandSelfDomains.split(",").map(d => d.trim()).filter(Boolean),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setWatchlistActionError(data?.detail ? JSON.stringify(data.detail) : `Request failed (${res.status})`);
        return;
      }
      setNewBrandName("");
      setNewBrandAliases("");
      setNewBrandPriority("100");
      setNewBrandSelfDomains("");
      await fetchWatchlist();
    } catch (err) {
      setWatchlistActionError("Create request failed — see console.");
      console.error("Create watchlist brand failed:", err);
    } finally {
      setWatchlistActionPending(false);
    }
  };

  const startEditingBrand = (b: WatchlistBrandRow) => {
    setEditingBrandId(b.id);
    setEditAliases(b.aliases.join(", "));
    setEditPriority(String(b.priority));
    setEditSelfDomains(b.self_domains.join(", "));
    setWatchlistActionError(null);
  };

  const saveEditingBrand = async (id: number) => {
    setWatchlistActionPending(true);
    setWatchlistActionError(null);
    try {
      const res = await fetch(`${API_BASE}/watchlist/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          aliases: editAliases.split(",").map(a => a.trim()).filter(Boolean),
          priority: parseInt(editPriority, 10) || 100,
          self_domains: editSelfDomains.split(",").map(d => d.trim()).filter(Boolean),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setWatchlistActionError(data?.detail ? JSON.stringify(data.detail) : `Request failed (${res.status})`);
        return;
      }
      setEditingBrandId(null);
      await fetchWatchlist();
    } catch (err) {
      setWatchlistActionError("Update request failed — see console.");
      console.error("Update watchlist brand failed:", err);
    } finally {
      setWatchlistActionPending(false);
    }
  };

  const setBrandActive = async (id: number, active: boolean) => {
    if (!active && !window.confirm("Deactivate this brand? It will stop being tracked as a campaign target.")) return;
    setWatchlistActionPending(true);
    setWatchlistActionError(null);
    try {
      const res = active
        ? await fetch(`${API_BASE}/watchlist/${id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ active: true }),
          })
        : await fetch(`${API_BASE}/watchlist/${id}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) {
        setWatchlistActionError(data?.detail ? JSON.stringify(data.detail) : `Request failed (${res.status})`);
        return;
      }
      await fetchWatchlist();
    } catch (err) {
      setWatchlistActionError("Request failed — see console.");
      console.error("Set brand active failed:", err);
    } finally {
      setWatchlistActionPending(false);
    }
  };

  return (
    <div className="pt-10 pb-24">

  <section className="max-w-[1600px] mx-auto p-12 mt-20">
    <SectionHeader
      title="Watchlist"
      subtitle="Brands tracked as campaign targets. Add a brand, edit priority/aliases, or manage self-owned domains (false-positive exoneration) — no CLI or JSON editing required."
      icon={Layers}
    />

    {watchlistActionError && (
      <div className="mb-4 p-3 border border-tactical-red/40 bg-tactical-red/5 text-[10px] text-tactical-red uppercase font-bold tracking-widest">
        {watchlistActionError}
      </div>
    )}

    <div className="tactical-border bg-[#080808]/50 backdrop-blur-xl p-5 mb-6">
      <div className="text-[10px] uppercase font-black tracking-widest text-white/40 mb-3">Add a brand</div>
      <div className="flex flex-wrap gap-3 items-end">
        <div className="flex flex-col gap-1">
          <label className="text-[9px] uppercase font-black tracking-widest text-white/30">Brand name</label>
          <input
            value={newBrandName}
            onChange={e => setNewBrandName(e.target.value)}
            placeholder="e.g. shopify"
            className="bg-white/5 border border-white/10 px-2 py-1.5 text-white/70 text-[11px] w-40 focus:outline-none focus:border-tactical-red/50"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-[9px] uppercase font-black tracking-widest text-white/30">Aliases (comma-sep)</label>
          <input
            value={newBrandAliases}
            onChange={e => setNewBrandAliases(e.target.value)}
            placeholder="e.g. shopify-support"
            className="bg-white/5 border border-white/10 px-2 py-1.5 text-white/70 text-[11px] w-52 focus:outline-none focus:border-tactical-red/50"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-[9px] uppercase font-black tracking-widest text-white/30">Priority</label>
          <input
            type="number"
            value={newBrandPriority}
            onChange={e => setNewBrandPriority(e.target.value)}
            className="bg-white/5 border border-white/10 px-2 py-1.5 text-white/70 text-[11px] w-20 focus:outline-none focus:border-tactical-red/50"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-[9px] uppercase font-black tracking-widest text-white/30">Self-owned domains (comma-sep)</label>
          <input
            value={newBrandSelfDomains}
            onChange={e => setNewBrandSelfDomains(e.target.value)}
            placeholder="e.g. shopify.com,shopifycdn.com"
            className="bg-white/5 border border-white/10 px-2 py-1.5 text-white/70 text-[11px] w-64 focus:outline-none focus:border-tactical-red/50"
          />
        </div>
        <button
          disabled={watchlistActionPending || !newBrandName.trim()}
          onClick={createWatchlistBrand}
          className="px-4 py-2 text-[10px] uppercase font-black tracking-widest border border-tactical-red/40 text-tactical-red hover:bg-tactical-red/10 transition-colors disabled:opacity-30"
        >
          Add brand
        </button>
      </div>
    </div>

    <div className="flex items-center gap-3 mb-4">
      <button
        onClick={() => setShowInactiveBrands(v => !v)}
        className={`px-3 py-1.5 text-[10px] uppercase font-black tracking-widest border transition-colors ${showInactiveBrands ? "border-cyan-400 text-cyan-400 bg-cyan-400/10" : "border-white/10 text-white/40 hover:text-white/70"}`}
      >
        {showInactiveBrands ? "Showing inactive" : "Show inactive"}
      </button>
    </div>

    {watchlistBrands === null ? (
      <div className="h-[100px] flex items-center justify-center opacity-20 italic text-[10px] uppercase font-black tracking-widest border border-white/10">
        SYNCING_WATCHLIST...
      </div>
    ) : (
      <div className="flex flex-col gap-3">
        {watchlistBrands.filter(b => showInactiveBrands || b.active).map(b => (
          <div key={b.id} className={`tactical-border bg-[#080808]/50 backdrop-blur-xl p-5 ${!b.active ? "opacity-40" : ""}`}>
            {editingBrandId === b.id ? (
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <span className="text-lg font-black uppercase tracking-widest italic">{b.brand_name}</span>
                  <span className="text-[9px] uppercase font-black tracking-widest text-white/30">editing</span>
                </div>
                <div className="flex flex-wrap gap-3 items-end">
                  <div className="flex flex-col gap-1">
                    <label className="text-[9px] uppercase font-black tracking-widest text-white/30">Aliases</label>
                    <input
                      value={editAliases}
                      onChange={e => setEditAliases(e.target.value)}
                      className="bg-white/5 border border-white/10 px-2 py-1.5 text-white/70 text-[11px] w-52 focus:outline-none focus:border-tactical-red/50"
                    />
                  </div>
                  <div className="flex flex-col gap-1">
                    <label className="text-[9px] uppercase font-black tracking-widest text-white/30">Priority</label>
                    <input
                      type="number"
                      value={editPriority}
                      onChange={e => setEditPriority(e.target.value)}
                      className="bg-white/5 border border-white/10 px-2 py-1.5 text-white/70 text-[11px] w-20 focus:outline-none focus:border-tactical-red/50"
                    />
                  </div>
                  <div className="flex flex-col gap-1">
                    <label className="text-[9px] uppercase font-black tracking-widest text-white/30">Self-owned domains</label>
                    <input
                      value={editSelfDomains}
                      onChange={e => setEditSelfDomains(e.target.value)}
                      className="bg-white/5 border border-white/10 px-2 py-1.5 text-white/70 text-[11px] w-64 focus:outline-none focus:border-tactical-red/50"
                    />
                  </div>
                  <button
                    disabled={watchlistActionPending}
                    onClick={() => saveEditingBrand(b.id)}
                    className="px-4 py-2 text-[10px] uppercase font-black tracking-widest border border-tactical-red/40 text-tactical-red hover:bg-tactical-red/10 transition-colors disabled:opacity-30"
                  >
                    Save
                  </button>
                  <button
                    onClick={() => setEditingBrandId(null)}
                    className="px-4 py-2 text-[10px] uppercase font-black tracking-widest border border-white/10 text-white/50 hover:bg-white/5 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-6">
                <div className="flex flex-col items-center justify-center w-16 shrink-0">
                  <span className="text-xl font-black text-tactical-red text-glow-red">{b.priority}</span>
                  <span className="text-[8px] text-white/20 uppercase font-black tracking-widest">priority</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-1">
                    <span className="text-lg font-black uppercase tracking-widest italic">{b.brand_name}</span>
                    {!b.active && (
                      <span className="px-2 py-0.5 text-[9px] uppercase font-black tracking-widest text-white/40 bg-white/5">inactive</span>
                    )}
                  </div>
                  <p className="text-[10px] text-white/40 font-bold uppercase tracking-wide truncate">
                    {b.aliases.length > 0 ? `aliases: ${b.aliases.join(", ")}` : "no aliases"}
                    {b.self_domains.length > 0 ? ` · self-owned: ${b.self_domains.join(", ")}` : ""}
                  </p>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button
                    onClick={() => startEditingBrand(b)}
                    className="px-3 py-1.5 text-[10px] uppercase font-black tracking-widest border border-white/10 text-white/50 hover:bg-white/5 transition-colors"
                  >
                    Edit
                  </button>
                  <button
                    disabled={watchlistActionPending}
                    onClick={() => setBrandActive(b.id, !b.active)}
                    className="px-3 py-1.5 text-[10px] uppercase font-black tracking-widest border border-white/10 text-white/50 hover:bg-white/5 transition-colors disabled:opacity-30"
                  >
                    {b.active ? "Deactivate" : "Reactivate"}
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
        {watchlistBrands.filter(b => showInactiveBrands || b.active).length === 0 && (
          <div className="h-[100px] flex items-center justify-center opacity-40 italic text-[10px] uppercase font-black tracking-widest border border-white/10">
            NO BRANDS TRACKED YET
          </div>
        )}
      </div>
    )}
  </section>
    </div>
  );
}
