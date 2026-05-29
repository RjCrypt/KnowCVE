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

export interface AttackTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tactic_phase: number;
  description: string;
  is_pivot: boolean;
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
  // Phase 5.5 — AI Depth Upgrade fields
  vulnerability_class_analysis?: string;
  adversarial_context?: string;
  exploit_narrative?: string;
  attack_techniques?: AttackTechnique[];
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

// ── Phase 5: Threat Intelligence Types ──────────────────────────────────────

export interface ThreatActor {
  id?: number;
  slug: string;
  name: string;
  aliases: string[];
  origin_country?: string;
  motivation: string;
  sophistication: string;
  description: string;
  targeted_sectors: string[];
  targeted_countries: string[];
  mitre_group_id?: string;
  mitre_url?: string;
  first_seen?: string;
  last_active?: string;
  is_active: boolean;
  cve_count?: number;
}

export interface ThreatActorDetail extends ThreatActor {
  exploited_cves: Array<{
    cve_id: string;
    confirmed: boolean;
    notes?: string;
    source_url?: string;
  }>;
}

export interface RansomwareCampaign {
  id?: number;
  actor_slug: string;
  actor_name?: string;
  campaign_name: string;
  cve_ids: string[];
  cves?: string[]; // alias for cve_ids in matrix view
  sectors: string[];
  countries: string[];
  status: "active" | "recent" | "historical";
  description: string;
  motivation?: string;
  origin_country?: string;
  source_url?: string;
}

export interface IOCResult {
  indicator: string;
  ioc_type: "ip" | "domain" | "url" | "hash";
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  risk_score: number;
  sources: {
    threatfox?: { hit: boolean; malware_family?: string; tags?: string[] };
    abuseipdb?: {
      confidence: number;
      reports: number;
      country?: string;
      isp?: string;
    };
    urlhaus?: { status?: string; tags?: string[]; urls_count?: number };
    greynoise?: {
      noise: boolean;
      riot: boolean;
      classification?: string;
      name?: string;
    };
  };
  related_cves: string[];
  cached: boolean;
}

export interface IOCFeedEntry {
  indicator: string;
  ioc_type: string;
  malware_family: string;
  tags: string[];
  threat_type: string;
  reported_at: string;
}

export interface SecurityNewsItem {
  id: number;
  title: string;
  url: string;
  source: string;
  published_at: string;
  summary?: string;
  mentioned_cves: string[];
  mentioned_actors: string[];
  tags: string[];
}

export interface BreachRecord {
  id: number;
  company_name: string;
  breach_date?: string;
  disclosed_date?: string;
  actor_slug?: string;
  actor_name?: string;
  cve_ids: string[];
  data_exposed: string[];
  records_count?: number;
  sectors: string[];
  description: string;
  source_urls: string[];
  verified: boolean;
}

export interface CVEContext {
  threat_actors: ThreatActor[];
  ransomware_groups: RansomwareCampaign[];
  news_articles: SecurityNewsItem[];
  breaches: BreachRecord[];
}

export interface FullCVEContext {
  cve: ProcessedCVE;
  context: CVEContext;
}

// ── Phase 7: Watchlist & Exposure Types ─────────────────────────────────────

export interface WatchlistItem {
  id: string;
  user_id: string;
  cpe_string: string;
  display_name: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  created_at: string;
}

export interface ExposureScore {
  score: number;
  critical_count: number;
  high_count: number;
  actively_exploited_count: number;
  top_cves: Array<{
    cve_id: string;
    priority_score: number;
    priority_label: string;
    description: string;
    in_kev: boolean;
    ai_summary: string;
  }>;
  calculated_at: string;
}

// ── Phase 8: Org, Asset, Triage, MSSP Types ─────────────────────────────────

export type OrgType = 'team' | 'mssp';
export type OrgRole = 'owner' | 'admin' | 'member' | 'viewer';
export type TriageStatus = 'new' | 'investigating' | 'remediation_planned' | 'mitigated' | 'wont_fix';

export interface Organization {
  id: string;
  name: string;
  org_type: OrgType;
  owner_id: string;
  created_at: string;
  updated_at: string;
  // Enriched by backend
  user_role?: OrgRole;
  members?: OrgMember[];
  member_count?: number;
  asset_count?: number;
  plan_limits?: { assets: number; members: number };
}

export interface OrgMember {
  id: string;
  org_id: string;
  user_id: string;
  member_role: OrgRole;
  joined_at: string;
  // Enriched from user_profiles
  email?: string;
  display_name?: string;
  avatar_url?: string;
}

export interface OrgInvite {
  id: string;
  org_id: string;
  email: string;
  role: OrgRole;
  token: string;
  expires_at: string;
  accepted: boolean;
  created_at: string;
}

export interface Asset {
  id: string;
  org_id: string;
  display_name: string;
  cpe_string: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  owner_name: string;
  notes: string;
  client_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface TriageItem {
  id: string;
  org_id: string;
  cve_id: string;
  client_id: string | null;
  status: TriageStatus;
  assignee_id: string | null;
  notes: string;
  sla_hours: number;
  sla_started_at: string | null;
  sla_due_at: string | null;
  created_at: string;
  updated_at: string;
  // Enriched by backend
  cve_data?: {
    description: string;
    priority_score: number;
    priority_label: string;
    cvss_score: number;
    in_kev: boolean;
    ai_summary: string;
  } | null;
  is_overdue?: boolean;
  assignee_name?: string;
  assignee_avatar?: string;
  matched_assets?: string[];
}

export interface TriageActivity {
  id: string;
  triage_item_id: string;
  user_id: string | null;
  action: string;
  detail: string;
  created_at: string;
}

export interface SLAConfig {
  priority: string;
  sla_hours: number;
  org_id?: string;
}

export interface OrgClient {
  id: string;
  org_id: string;
  name: string;
  contact_name: string;
  contact_email: string;
  created_at: string;
  updated_at: string;
}

export interface OrgExposureScore {
  score: number;
  critical_count: number;
  high_count: number;
  actively_exploited_count: number;
  top_cves: Array<{
    cve_id: string;
    priority_score: number;
    priority_label: string;
    description: string;
    in_kev: boolean;
    matched_assets?: string[];
  }>;
  calculated_at: string;
  client_id?: string | null;
}

export interface ComplianceSnapshot {
  cves: Array<{
    cve_id: string;
    severity: string;
    in_kev: boolean;
    first_detected: string;
    triage_status: TriageStatus;
    days_to_remediate: number | null;
    matched_assets: string[];
  }>;
  stats: {
    total_cves: number;
    critical_high_count: number;
    kev_count: number;
    mitigated_count: number;
    remediation_rate: number;
    sla_compliance_rate: number;
    avg_remediation_days: number;
  };
  date_range: { days: number; from: string };
}

export interface ClientSummary {
  client_id: string;
  exposure_score: number;
  open_triage: number;
  overdue_count: number;
}

