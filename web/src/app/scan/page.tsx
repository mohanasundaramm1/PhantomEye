"use client";

import React, { useState, useEffect } from "react";
import { Shield, Zap, Crosshair } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { SectionHeader } from "@/components/Tactical";
import { API_BASE } from "@/lib/config";

export default function ScanPage() {
  const [scanTarget, setScanTarget] = useState("");
  const [scanResult, setScanResult] = useState<any>(null);
  const [isScanning, setIsScanning] = useState(false);

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

  return (
    <div className="pt-10 pb-24">
  <section className="max-w-[1200px] mx-auto p-12 mt-40">
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

    </div>
  );
}
