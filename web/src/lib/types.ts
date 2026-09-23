// Extracted from the former single-page dashboard. Shared by all routes.
// --- Types ---
export interface Threat {
  registered_domain: string;
  risk_score: number;
  sample_country: string;
  sample_isp: string;
}

export interface MapData {
  sample_country: string;
  risk_score: number;
  threat_count: number;
}

export interface AnalystMetric {
  tld?: string;
  sample_isp?: string;
  risk: number;
  count: number;
  label?: string;
}

export interface Stats {
  total_parsed: number;
  total_domains: number;
  high_risk: number;
  critical: number;
  avg_risk: number;
  signal_to_noise: number;
  countries: number;
  watchlist_brand_count: number | null;
  map_data: MapData[];
  tld_analysis: AnalystMetric[];
  isp_reputation: AnalystMetric[];
  age_impact: AnalystMetric[];
  detection_source_breakdown?: { reason: string, count: number, pct: number }[];
}

// Mirrors the GET /campaigns queue-card contract (api/main.py _campaign_card).
export interface Campaign {
  campaign_id: number;
  target_brand: string | null;
  target_workflow: string | null;
  stage: string;
  status: string;
  confidence_score: number | null;
  member_count: number;
  first_seen: string | null;
  last_seen: string | null;
  freshness_age_minutes: number | null;
  summary_reason: string | null;
  queue_status: string | null;
  assignee: string | null;
  sla_bucket: string | null;
  stage_locked_by: string | null;
  stage_locked_at: string | null;
}

export interface CampaignDomain {
  raw_host: string;
  registered_domain: string | null;
  risk_score: number | null;
  decision_reason: string | null;
  enrichment_level: string | null;
  registrar: string | null;
  sample_country: string | null;
  sample_asn: string | null;
  event_ts: string | null;
}

export interface CampaignDetail extends Campaign {
  domains: CampaignDomain[];
}

// Mirrors GET /campaigns/{id}/disposition-provenance.
export interface DispositionProvenance {
  available: boolean;
  has_disposition: boolean;
  reason?: string;
  disposition?: { verdict: string; analyst: string; created_at: string };
  eligible_training_run?: { created_utc: string; n_pos: number | null; n_neg: number | null; promoted: boolean | null } | null;
  note?: string;
}

// Mirrors GET /watchlist -- the "bring your own brand" tracked-brand config.
export interface WatchlistBrandRow {
  id: number;
  brand_name: string;
  aliases: string[];
  priority: number;
  customer_scope: string;
  self_domains: string[];
  active: boolean;
  created_at: string | null;
}

// Mirrors GET /health/pipeline — real freshness/DB/watchdog state, the
// observability layer over the already-self-healing ingest (ops/launchd).
export interface PipelineHealth {
  healthy: boolean;
  app_db: { reachable: boolean };
  ct_raw: { newest_age_hours: number | null };
  scoring: { newest_scored_age_hours: number | null };
  model: { created_utc: string | null; promoted: boolean | null };
  ingest_watchdog: { stale?: boolean | null; last_checked_utc?: string; note?: string; available?: boolean };
}

// Mirrors ml/models/registry/ct_risk_meta_latest.json via GET /model/status —
// real training/promotion metadata, not a marketing claim.
export interface ModelStatus {
  available: boolean;
  reason?: string;
  created_utc?: string;
  n_rows?: number;
  n_pos?: number;
  n_neg?: number;
  promotion_decision?: {
    promote: boolean;
    reason: string;
    checked_utc?: string;
  };
}

// Mirrors GET /metrics/operations (product/metrics.py) -- real SQL aggregates
// over the campaign-radar tables, not simulated.
export interface OperationsMetrics {
  available: boolean;
  reason?: string;
  analyst_confirmation?: { rate: number | null; n_dispositions: number; n_confirmed: number };
  median_time_to_first_review?: { median_hours: number | null; n: number };
  suppression?: { rate: number | null; n_total: number; n_suppressed: number };
  campaigns_created?: { per_day: number | null; window_days: number; n_in_window: number };
  enrichment_completeness?: { rate: number | null; n_total: number; n_whois?: number; n_tier2: number };
}

// Mirrors GET /metrics/lead-time (ct/score/measure_lead_time.py) -- exact-
// hostname vs. apex-only breakdown already computed server-side.
export interface LeadTimeMetrics {
  available: boolean;
  reason?: string;
  n_matched_exact_hostname?: number;
  n_matched_registered_domain_only?: number;
  pct_of_matches_ct_was_ahead?: number;
  median_lead_time_hours_when_ahead?: number | null;
  confidence_note?: string;
}

// Mirrors GET /metrics/precision-at-k (ml/core/eval_precision_at_k.py).
export interface PrecisionAtKMetrics {
  available: boolean;
  reason?: string;
  n_misp_hits_total?: number;
  confidence_note?: string;
  precision_at_k?: { k: number; precision: number | null; n_evaluated: number; n_hits: number }[];
}
