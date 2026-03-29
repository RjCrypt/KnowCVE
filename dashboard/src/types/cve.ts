/* ── TypeScript types mirroring backend Pydantic models ─── */

export interface EnrichmentData {
  in_kev: boolean;
  epss_score: number;
  epss_percentile: number;
  poc_urls: string[];
  has_poc: boolean;
  greynoise_scanner_count: number;
  is_being_scanned: boolean;
}

export interface AIExplanation {
  summary: string;
  technical_detail: string;
  impact: string;
  remediation: string;
  tags: string[];
  affected_tech: string[];
}

export interface CVEReference {
  url: string;
  source?: string;
}

export interface ProcessedCVE {
  cve_id: string;
  description: string;
  published_date: string | null;
  last_modified: string | null;
  cvss_score: number;
  cvss_vector: string;
  cvss_version: string;
  enrichment: EnrichmentData;
  priority_score: number;
  priority_label: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  ai_explanation?: AIExplanation | null;
  references: string[];
  weaknesses: string[];
  processed_at: string;
}

export interface StatsResponse {
  total_cves_processed: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  last_poll_time: string | null;
  next_poll_time: string | null;
  subscribers_count: number;
  kev_catalog_size: number;
}

export interface PollResponse {
  status: string;
  new_cves_found: number;
  cves_processed: number;
  alerts_sent: number;
  errors: string[];
}

export interface HealthResponse {
  status: string;
  service: string;
  poller_active: boolean;
  telegram_active: boolean;
}

export type PriorityLabel = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type FilterState = {
  priority: PriorityLabel;
  kev_only: boolean;
  has_poc: boolean;
  search: string;
};
