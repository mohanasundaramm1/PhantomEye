"use client";
import React from "react";

// --- Specialized Components ---

export const SectionHeader = ({ title, subtitle, icon: Icon }: { title: string, subtitle: string, icon: any }) => (
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

export const TacticalCard = ({ title, children, className = "", status = "ONLINE", subTitle = "" }: { title: string, children: React.ReactNode, className?: string, status?: string, subTitle?: string }) => (
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
