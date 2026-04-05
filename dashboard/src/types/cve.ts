/* ── TypeScript types mirroring backend Pydantic models ─── */

export interface EnrichmentData {
  in_kev: boolean;
  epss_score: number;
  epss_percentile: number;
  poc_urls: string[];
  has_poc: boolean;
  greynoise_scanner_count: number;
  is_being_scanned: boolean;
  // Trend tracking
  previous_epss_score: number;
  previous_scanner_count: number;
  epss_trend: 'rising' | 'falling' | 'stable';
  scanner_trend: 'rising' | 'falling' | 'stable' | 'new';
  // Nuclei template (Phase 4)
  has_nuclei_template: boolean;
  nuclei_template_url?: string;
}

export interface AIExplanation {
  summary: string;
  technical_detail: string;
  impact: string;
  remediation: string;
  tags: string[];
  affected_tech: string[];
  mitre_techniques: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
    url: string;
  }>;
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
  priority_label: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  ai_explanation?: AIExplanation | null;
  references: string[];
  weaknesses: string[];
  processed_at: string;
  // Dynamic scoring & categories
  categories: string[];
  dynamic_score: number;
  last_rescored_at?: string;
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

export type CVECategory =
  | 'ACTIVELY_EXPLOITED'
  | 'TRENDING'
  | 'JUST_DROPPED'
  | 'HIGH_EXPLOITABILITY'
  | 'NO_AUTH_REQUIRED';

export type PriorityLabel = 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type CategoryLabel = 'ALL' | CVECategory;

export type FilterState = {
  priority: PriorityLabel;
  category: CategoryLabel;
  kev_only: boolean;
  has_poc: boolean;
  search: string;
};

// Phase 4 — Community Intelligence

export interface WildReportSummary {
  cve_id: string;
  report_count: number;
  last_reported_at?: string;
}

export interface ResearcherNoteItem {
  id: number;
  cve_id: string;
  note: string;
  author_alias?: string;
  created_at: string;
}

export interface NucleiInfo {
  cve_id: string;
  has_template: boolean;
  template_url?: string;
  nuclei_command?: string;
}

// Phase 4.5 — Exploit Intelligence

export interface ExploitEntry {
  id: string;
  description: string;
  date: string;
  type: string;
  platform: string;
  url: string;
}

export interface PoCRepo {
  url: string;
  stars: number;
  forks: number;
  last_updated?: string;
}

export interface ExploitIntelligence {
  cve_id: string;
  has_metasploit_module: boolean;
  metasploit_module_url?: string;
  metasploit_module_path?: string;
  exploitdb_entries: ExploitEntry[];
  poc_repos: PoCRepo[];
  ems_score: number;
  ems_label: 'WEAPONIZED' | 'FUNCTIONAL' | 'THEORETICAL' | 'RESEARCH';
  metasploit_command?: string;
  nuclei_command?: string;
  searchsploit_command?: string;
  last_updated: string;
}

export interface ExploitIntelSummary {
  cve_id: string;
  ems_score: number;
  ems_label: string;
  has_metasploit_module: boolean;
  has_nuclei_template: boolean;
  has_exploitdb_entry: boolean;
  poc_count: number;
  max_poc_stars: number;
  priority_score: number;
  priority_label: string;
  cvss_score: number;
  description: string;
  published: string;
}
