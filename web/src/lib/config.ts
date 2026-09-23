// --- Configuration --- (extracted from page.tsx)
// Backend base URL — override with NEXT_PUBLIC_API_BASE (e.g. for non-localhost
// or IPv4-only environments); defaults to localhost:8000 for local dev.
export const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";
export const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

// Geo/ISP enrichment is structurally at 0% coverage today (tier2 WHOIS/geo
// lookups never fire on the hot path -- see product plan Phase 3), so these
// panels are permanently empty rather than occasionally sparse. Hidden until
// that's fixed, rather than showing a panel that can never have data.
export const SHOW_GEO_PANELS = false;
// Perplexity backend (no API key configured, errored on every message) was
// replaced in Phase 6 by api/agent/internal_agent.py -- a fixed, always-on,
// no-external-dependency intent-matched query agent. Safe to show.
export const SHOW_INTEL_CHAT = true;

// decision_reason values emitted by the MISP-fusion step in
// ct/score/score_ct_with_latest.py — real detection provenance, not attribution.
export const SOURCE_LABELS: Record<string, string> = {
  MISP_AND_ML: "MISP + ML",
  MISP_IOC: "MISP IOC",
  ML_SCORE: "ML score",
  BENIGN_BASELINE: "Benign baseline",
};
export const SOURCE_COLORS: Record<string, string> = {
  MISP_AND_ML: "#ff0000",
  MISP_IOC: "#ff8800",
  ML_SCORE: "#00ffff",
  BENIGN_BASELINE: "#333333",
};

export const nameMapping: { [key: string]: string } = {
  "United States": "United States of America",
  "The Netherlands": "Netherlands",
  "Russia": "Russia",
};

export const STAGE_COLORS: Record<string, string> = {
  new: "text-white/50 bg-white/5",
  warming: "text-yellow-400 bg-yellow-400/10",
  active: "text-cyan-400 bg-cyan-400/10",
  confirmed: "text-tactical-red bg-tactical-red/10",
  suppressed: "text-white/20 bg-white/5",
};

// Mirrors product/assemble_campaigns.py::_confidence() exactly:
//   confidence = min(1.0, max_risk * (0.7 + 0.3 * min(count, 10) / 10.0))
// Backed out algebraically (no extra API field needed) so the tooltip can
// show *why* a confidence number is what it is -- risk contributes 70% on
// its own, corroboration (more independently-observed members) only adds
// up to another 30%, capped past 10 members. Only exact when confidence
// isn't clamped at 1.0 (true for every real cluster today -- highest
// confidence post-rescore is ~0.70 -- clamped clusters just show ">=" on
// the reconstructed risk instead of claiming false precision.
export function decomposeConfidence(confidence: number | null, memberCount: number): { maxRisk: number; corroboration: number; clamped: boolean } | null {
  if (confidence == null) return null;
  const corroboration = 0.7 + (0.3 * Math.min(memberCount, 10)) / 10.0;
  const maxRisk = Math.min(1.0, confidence / corroboration);
  return { maxRisk, corroboration, clamped: confidence >= 0.9999 };
}

export function formatFreshness(minutes: number | null): string {
  if (minutes == null) return "unknown";
  if (minutes < 60) return `${Math.round(minutes)}m ago`;
  if (minutes < 1440) return `${(minutes / 60).toFixed(1)}h ago`;
  return `${(minutes / 1440).toFixed(1)}d ago`;
}
