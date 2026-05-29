import type {
  CVECategory,
  HealthResponse,
  PollResponse,
  ProcessedCVE,
  StatsResponse,
  WildReportSummary,
  ResearcherNoteItem,
  NucleiInfo,
  ExploitIntelligence,
  ExploitIntelSummary,
  ThreatActor,
  ThreatActorDetail,
  RansomwareCampaign,
  IOCResult,
  IOCFeedEntry,
  SecurityNewsItem,
  BreachRecord,
  FullCVEContext,
  WatchlistItem,
  ExposureScore,
} from "@/types/cve";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!res.ok) {
    let errorMsg = `API ${res.status}: ${res.statusText}`;
    try {
      const errBody = await res.json();
      if (errBody && errBody.detail) {
        errorMsg = typeof errBody.detail === "string" ? errBody.detail : JSON.stringify(errBody.detail);
      } else if (errBody && errBody.error) {
        errorMsg = errBody.error;
      }
    } catch (e) {
      // Ignore JSON parse errors for non-JSON responses
    }
    throw new Error(errorMsg);
  }
  return res.json() as Promise<T>;
}

/* ── endpoints ─────────────────────────────────────── */

export async function getHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>("/health");
}

export async function getStats(): Promise<StatsResponse> {
  return apiFetch<StatsResponse>("/api/stats");
}

export async function getCVEs(params?: {
  page?: number;
  page_size?: number;
  priority?: string;
  min_score?: number;
  category?: string;
  search?: string;
}): Promise<ProcessedCVE[]> {
  const sp = new URLSearchParams();
  if (params?.page) sp.set("page", String(params.page));
  if (params?.page_size) sp.set("page_size", String(params.page_size));
  if (params?.priority) sp.set("priority", params.priority);
  if (params?.min_score !== undefined) sp.set("min_score", String(params.min_score));
  if (params?.category) sp.set("category", params.category);
  if (params?.search) sp.set("search", params.search);
  const qs = sp.toString();
  return apiFetch<ProcessedCVE[]>(`/api/cves${qs ? `?${qs}` : ""}`);
}

export async function getCVE(id: string): Promise<ProcessedCVE> {
  return apiFetch<ProcessedCVE>(`/api/cves/${encodeURIComponent(id)}`);
}

export async function triggerPoll(secretKey?: string): Promise<PollResponse> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (secretKey) {
    headers["Authorization"] = `Bearer ${secretKey}`;
  }
  return apiFetch<PollResponse>("/api/poll", { method: "POST", headers });
}

export async function getThreats(limit = 20): Promise<ProcessedCVE[]> {
  return apiFetch<ProcessedCVE[]>(`/api/threats?limit=${limit}`);
}

/* ── New category-based endpoints ─────────────────── */

export async function getCVEsByCategory(
  category: CVECategory,
  limit = 20
): Promise<ProcessedCVE[]> {
  return apiFetch<ProcessedCVE[]>(
    `/api/cves/category/${category}?limit=${limit}`
  );
}

export async function getTrendingCVEs(): Promise<ProcessedCVE[]> {
  return apiFetch<ProcessedCVE[]>("/api/cves/trending");
}

export async function getFreshCVEs(limit = 20): Promise<ProcessedCVE[]> {
  return apiFetch<ProcessedCVE[]>(`/api/cves/fresh?limit=${limit}`);
}

/* ── Phase 4 — Community Intelligence ─────────────── */

export async function reportSeenInWild(
  cveId: string,
  context?: string
): Promise<{ message: string; duplicate: boolean }> {
  return apiFetch<{ message: string; duplicate: boolean }>(
    `/api/cves/${encodeURIComponent(cveId)}/report-wild`,
    {
      method: "POST",
      body: JSON.stringify({ cve_id: cveId, context }),
    }
  );
}

export async function getWildReports(
  cveId: string
): Promise<WildReportSummary> {
  return apiFetch<WildReportSummary>(
    `/api/cves/${encodeURIComponent(cveId)}/wild-reports`
  );
}

export async function getNotes(
  cveId: string
): Promise<ResearcherNoteItem[]> {
  return apiFetch<ResearcherNoteItem[]>(
    `/api/cves/${encodeURIComponent(cveId)}/notes`
  );
}

export async function addNote(
  cveId: string,
  note: string,
  authorAlias?: string
): Promise<ResearcherNoteItem> {
  return apiFetch<ResearcherNoteItem>(
    `/api/cves/${encodeURIComponent(cveId)}/notes`,
    {
      method: "POST",
      body: JSON.stringify({
        cve_id: cveId,
        note,
        author_alias: authorAlias || null,
      }),
    }
  );
}

export async function getNucleiInfo(
  cveId: string
): Promise<NucleiInfo> {
  return apiFetch<NucleiInfo>(
    `/api/cves/${encodeURIComponent(cveId)}/nuclei`
  );
}

export async function getKRSFormula(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/api/krs/formula");
}

/* ── Phase 4.5 — Exploit Intelligence ───────────── */

export async function getExploitIntelFeed(params?: {
  limit?: number;
  offset?: number;
  ems_label?: string;
  has_metasploit?: boolean;
  has_nuclei?: boolean;
}): Promise<ExploitIntelSummary[]> {
  const sp = new URLSearchParams();
  if (params?.limit) sp.set("limit", String(params.limit));
  if (params?.offset) sp.set("offset", String(params.offset));
  if (params?.ems_label) sp.set("ems_label", params.ems_label);
  if (params?.has_metasploit) sp.set("has_metasploit", "true");
  if (params?.has_nuclei) sp.set("has_nuclei", "true");
  const qs = sp.toString();
  return apiFetch<ExploitIntelSummary[]>(
    `/api/exploit-intel${qs ? `?${qs}` : ""}`
  );
}

export async function getExploitIntel(
  cveId: string
): Promise<ExploitIntelligence> {
  return apiFetch<ExploitIntelligence>(
    `/api/exploit-intel/${encodeURIComponent(cveId)}`
  );
}

/* ── Phase 5 — Threat Intelligence ──────────────── */

// — Threat Actors —

export async function getThreatActors(params?: {
  active_only?: boolean;
  motivation?: string;
  sophistication?: string;
}): Promise<ThreatActor[]> {
  const sp = new URLSearchParams();
  if (params?.active_only) sp.set("active_only", "true");
  if (params?.motivation) sp.set("motivation", params.motivation);
  if (params?.sophistication) sp.set("sophistication", params.sophistication);
  const qs = sp.toString();
  return apiFetch<ThreatActor[]>(`/api/threat-actors${qs ? `?${qs}` : ""}`);
}

export async function getThreatActor(slug: string): Promise<ThreatActorDetail> {
  return apiFetch<ThreatActorDetail>(`/api/threat-actors/${encodeURIComponent(slug)}`);
}

export async function getThreatActorCVEs(slug: string): Promise<unknown[]> {
  return apiFetch<unknown[]>(`/api/threat-actors/${encodeURIComponent(slug)}/cves`);
}

export async function getCVEThreatActors(cveId: string): Promise<ThreatActor[]> {
  return apiFetch<ThreatActor[]>(`/api/cves/${encodeURIComponent(cveId)}/threat-actors`);
}

// — Ransomware —

export async function getRansomwareCampaigns(params?: {
  status?: string;
  actor_slug?: string;
}): Promise<RansomwareCampaign[]> {
  const sp = new URLSearchParams();
  if (params?.status) sp.set("status", params.status);
  if (params?.actor_slug) sp.set("actor_slug", params.actor_slug);
  const qs = sp.toString();
  return apiFetch<RansomwareCampaign[]>(`/api/ransomware/campaigns${qs ? `?${qs}` : ""}`);
}

export async function getRansomwareMatrix(): Promise<RansomwareCampaign[]> {
  return apiFetch<RansomwareCampaign[]>("/api/ransomware/matrix");
}

// — IOC —

export async function lookupIOC(indicator: string): Promise<IOCResult> {
  return apiFetch<IOCResult>(`/api/ioc/lookup?q=${encodeURIComponent(indicator)}`);
}

export async function getIOCFeed(): Promise<IOCFeedEntry[]> {
  return apiFetch<IOCFeedEntry[]>("/api/ioc/feed");
}

export async function getIOCStats(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/api/ioc/stats");
}

// — News —

export async function getSecurityNews(params?: {
  limit?: number;
  source?: string;
  has_cves?: boolean;
}): Promise<SecurityNewsItem[]> {
  const sp = new URLSearchParams();
  if (params?.limit) sp.set("limit", String(params.limit));
  if (params?.source) sp.set("source", params.source);
  if (params?.has_cves) sp.set("has_cves", "true");
  const qs = sp.toString();
  return apiFetch<SecurityNewsItem[]>(`/api/news${qs ? `?${qs}` : ""}`);
}

export async function getNewsBriefing(): Promise<{ briefing: string }> {
  return apiFetch<{ briefing: string }>("/api/news/briefing");
}

export async function getNewsSources(): Promise<{ name: string; url: string; article_count: number }[]> {
  return apiFetch<{ name: string; url: string; article_count: number }[]>("/api/news/sources");
}

// — Breaches —

export async function getBreaches(params?: {
  limit?: number;
  actor_slug?: string;
  cve_id?: string;
  category?: string;
}): Promise<BreachRecord[]> {
  const sp = new URLSearchParams();
  if (params?.limit) sp.set("limit", String(params.limit));
  if (params?.actor_slug) sp.set("actor_slug", params.actor_slug);
  if (params?.cve_id) sp.set("cve_id", params.cve_id);
  if (params?.category) sp.set("category", params.category);
  const qs = sp.toString();
  return apiFetch<BreachRecord[]>(`/api/breaches${qs ? `?${qs}` : ""}`);
}

export async function searchBreaches(query: string): Promise<BreachRecord[]> {
  return apiFetch<BreachRecord[]>(`/api/breaches/search?q=${encodeURIComponent(query)}`);
}

export async function getBreachStats(params?: { category?: string; query?: string }): Promise<Record<string, unknown>> {
  const sp = new URLSearchParams();
  if (params?.category) sp.set("category", params.category);
  if (params?.query) sp.set("q", params.query);
  const qs = sp.toString();
  return apiFetch<Record<string, unknown>>(`/api/breaches/stats${qs ? `?${qs}` : ""}`);
}

// — CVE Full Context —

export async function getCVEFull(cveId: string): Promise<FullCVEContext> {
  return apiFetch<FullCVEContext>(`/api/cves/${encodeURIComponent(cveId)}/full`);
}

// — Phase 5.5: CVE Assistant —

export async function askCVEAssistant(
  cveId: string,
  message: string,
  history: Array<{ role: string; content: string }>
): Promise<{ reply: string }> {
  return apiFetch<{ reply: string }>('/api/cve-assistant', {
    method: 'POST',
    body: JSON.stringify({ cve_id: cveId, message, history }),
  });
}

/* ── Phase 7 — Watchlist, Exposure, Digest ────────── */

export async function getWatchlist(userId: string): Promise<WatchlistItem[]> {
  return apiFetch<WatchlistItem[]>(`/api/watchlist/${userId}`);
}

export async function addWatchlistItem(params: {
  user_id: string;
  cpe_string: string;
  display_name: string;
  criticality: string;
}): Promise<WatchlistItem> {
  return apiFetch<WatchlistItem>('/api/watchlist', {
    method: 'POST',
    body: JSON.stringify(params),
  });
}

export async function removeWatchlistItem(userId: string, itemId: string): Promise<void> {
  await apiFetch<{ status: string }>(`/api/watchlist/${userId}/${itemId}`, {
    method: 'DELETE',
  });
}

export async function getExposureScore(userId: string): Promise<ExposureScore> {
  return apiFetch<ExposureScore>(`/api/exposure/${userId}`);
}

export async function recalculateExposure(userId: string): Promise<ExposureScore> {
  return apiFetch<ExposureScore>(`/api/exposure/${userId}/recalculate`, {
    method: 'POST',
  });
}

export async function getWatchlistCVEs(
  userId: string,
  page = 1,
  pageSize = 20
): Promise<{ cves: ProcessedCVE[]; total: number; page: number }> {
  return apiFetch(`/api/watchlist/${userId}/cves?page=${page}&page_size=${pageSize}`);
}

export async function setDigestEnabled(userId: string, enabled: boolean): Promise<void> {
  if (enabled) {
    await apiFetch(`/api/digest/resubscribe/${userId}`, { method: 'PATCH' });
  } else {
    await apiFetch(`/api/digest/unsubscribe/${userId}`);
  }
}

export async function sendTestDigest(userId: string): Promise<{ sent: boolean }> {
  return apiFetch<{ sent: boolean }>(`/api/digest/test/${userId}`, {
    method: 'POST',
  });
}

/* ── Phase 8 — Org, Assets, Triage, MSSP ─────── */

import type {
  Organization,
  OrgMember,
  OrgInvite,
  Asset,
  TriageItem,
  TriageActivity,
  SLAConfig,
  OrgClient,
  OrgExposureScore,
  ComplianceSnapshot,
  ClientSummary,
} from "@/types/cve";

// ── Org CRUD ──

export async function createOrg(params: {
  name: string;
  org_type: string;
  owner_id: string;
}): Promise<Organization> {
  return apiFetch<Organization>('/api/orgs', {
    method: 'POST',
    body: JSON.stringify(params),
  });
}

export async function getOrg(orgId: string, userId: string): Promise<Organization> {
  return apiFetch<Organization>(`/api/orgs/${orgId}?user_id=${userId}`);
}

export async function updateOrg(orgId: string, userId: string, name: string): Promise<Organization> {
  return apiFetch<Organization>(`/api/orgs/${orgId}?user_id=${userId}`, {
    method: 'PATCH',
    body: JSON.stringify({ name }),
  });
}

export async function getUserOrgs(userId: string): Promise<{ data: Organization[]; total: number }> {
  return apiFetch<{ data: Organization[]; total: number }>(`/api/orgs/user/${userId}`);
}

// ── Members ──

export async function inviteMember(orgId: string, userId: string, params: {
  email: string;
  role: string;
  inviter_name?: string;
}): Promise<{ token: string; email: string; expires_at: string }> {
  return apiFetch(`/api/orgs/${orgId}/members/invite?user_id=${userId}`, {
    method: 'POST',
    body: JSON.stringify(params),
  });
}

export async function listMembers(orgId: string, userId: string): Promise<{ data: OrgMember[]; total: number }> {
  return apiFetch(`/api/orgs/${orgId}/members?user_id=${userId}`);
}

export async function updateMemberRole(orgId: string, targetUserId: string, userId: string, role: string): Promise<{ status: string }> {
  return apiFetch(`/api/orgs/${orgId}/members/${targetUserId}?user_id=${userId}`, {
    method: 'PATCH',
    body: JSON.stringify({ role }),
  });
}

export async function removeMember(orgId: string, targetUserId: string, userId: string): Promise<{ status: string }> {
  return apiFetch(`/api/orgs/${orgId}/members/${targetUserId}?user_id=${userId}`, {
    method: 'DELETE',
  });
}

export async function acceptInvite(token: string, userId?: string): Promise<{
  org_id?: string;
  org_name?: string;
  requires_signup?: boolean;
  email?: string;
}> {
  const sp = new URLSearchParams();
  if (userId) sp.set("user_id", userId);
  const qs = sp.toString();
  return apiFetch(`/api/invites/accept/${token}${qs ? `?${qs}` : ""}`);
}

export async function listInvites(orgId: string, userId: string): Promise<{ data: OrgInvite[]; total: number }> {
  return apiFetch(`/api/orgs/${orgId}/invites?user_id=${userId}`);
}

export async function revokeInvite(orgId: string, inviteId: string, userId: string): Promise<{ status: string }> {
  return apiFetch(`/api/orgs/${orgId}/invites/${inviteId}?user_id=${userId}`, {
    method: 'DELETE',
  });
}

// ── Assets ──

export async function listAssets(orgId: string, userId: string, clientId?: string): Promise<{
  data: Asset[];
  total: number;
  asset_count: number;
  asset_limit: number;
}> {
  const sp = new URLSearchParams({ user_id: userId });
  if (clientId) sp.set("client_id", clientId);
  return apiFetch(`/api/orgs/${orgId}/assets?${sp.toString()}`);
}

export async function addAsset(orgId: string, userId: string, params: {
  display_name: string;
  cpe_string: string;
  criticality?: string;
  owner_name?: string;
  notes?: string;
  client_id?: string;
}): Promise<Asset> {
  return apiFetch(`/api/orgs/${orgId}/assets?user_id=${userId}`, {
    method: 'POST',
    body: JSON.stringify(params),
  });
}

export async function updateAsset(orgId: string, assetId: string, userId: string, params: {
  display_name?: string;
  cpe_string?: string;
  criticality?: string;
  owner_name?: string;
  notes?: string;
}): Promise<Asset> {
  return apiFetch(`/api/orgs/${orgId}/assets/${assetId}?user_id=${userId}`, {
    method: 'PATCH',
    body: JSON.stringify(params),
  });
}

export async function deleteAsset(orgId: string, assetId: string, userId: string): Promise<{ status: string }> {
  return apiFetch(`/api/orgs/${orgId}/assets/${assetId}?user_id=${userId}`, {
    method: 'DELETE',
  });
}

export async function getAssetCVEs(orgId: string, userId: string, params?: {
  page?: number;
  page_size?: number;
  client_id?: string;
}): Promise<{ cves: ProcessedCVE[]; total: number; page: number }> {
  const sp = new URLSearchParams({ user_id: userId });
  if (params?.page) sp.set("page", String(params.page));
  if (params?.page_size) sp.set("page_size", String(params.page_size));
  if (params?.client_id) sp.set("client_id", params.client_id);
  return apiFetch(`/api/orgs/${orgId}/assets/cves?${sp.toString()}`);
}

// ── Triage ──

export async function listTriageItems(orgId: string, userId: string, params?: {
  status?: string;
  client_id?: string;
  assignee_id?: string;
  severity?: string;
  overdue_only?: boolean;
}): Promise<{ data: TriageItem[]; total: number }> {
  const sp = new URLSearchParams({ user_id: userId });
  if (params?.status) sp.set("status", params.status);
  if (params?.client_id) sp.set("client_id", params.client_id);
  if (params?.assignee_id) sp.set("assignee_id", params.assignee_id);
  if (params?.severity) sp.set("severity", params.severity);
  if (params?.overdue_only) sp.set("overdue_only", "true");
  return apiFetch(`/api/orgs/${orgId}/triage?${sp.toString()}`);
}

export async function createTriageItem(orgId: string, userId: string, params: {
  cve_id: string;
  client_id?: string;
  notes?: string;
}): Promise<TriageItem> {
  return apiFetch(`/api/orgs/${orgId}/triage?user_id=${userId}`, {
    method: 'POST',
    body: JSON.stringify(params),
  });
}

export async function updateTriageItem(orgId: string, itemId: string, userId: string, params: {
  status?: string;
  assignee_id?: string;
  notes?: string;
}): Promise<TriageItem> {
  return apiFetch(`/api/orgs/${orgId}/triage/${itemId}?user_id=${userId}`, {
    method: 'PATCH',
    body: JSON.stringify({ ...params, user_id: userId }),
  });
}

export async function deleteTriageItem(orgId: string, itemId: string, userId: string): Promise<{ status: string }> {
  return apiFetch(`/api/orgs/${orgId}/triage/${itemId}?user_id=${userId}`, {
    method: 'DELETE',
  });
}

export async function getTriageActivity(orgId: string, itemId: string, userId: string): Promise<{ data: TriageActivity[] }> {
  return apiFetch(`/api/orgs/${orgId}/triage/${itemId}/activity?user_id=${userId}`);
}

export async function autoPopulateTriage(orgId: string, userId: string, clientId?: string): Promise<{ status: string; items_added: number }> {
  const sp = new URLSearchParams({ user_id: userId });
  if (clientId) sp.set("client_id", clientId);
  return apiFetch(`/api/orgs/${orgId}/triage/auto-populate?${sp.toString()}`, {
    method: 'POST',
  });
}

// ── SLA ──

export async function getSLAConfig(orgId: string, userId: string): Promise<{ data: SLAConfig[] }> {
  return apiFetch(`/api/orgs/${orgId}/sla?user_id=${userId}`);
}

export async function upsertSLAConfig(orgId: string, userId: string, config: {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
}): Promise<{ status: string }> {
  return apiFetch(`/api/orgs/${orgId}/sla?user_id=${userId}`, {
    method: 'POST',
    body: JSON.stringify(config),
  });
}

// ── MSSP Clients ──

export async function listClients(orgId: string, userId: string): Promise<{ data: OrgClient[]; total: number }> {
  return apiFetch(`/api/orgs/${orgId}/clients?user_id=${userId}`);
}

export async function createClient(orgId: string, userId: string, params: {
  name: string;
  contact_name?: string;
  contact_email?: string;
}): Promise<OrgClient> {
  return apiFetch(`/api/orgs/${orgId}/clients?user_id=${userId}`, {
    method: 'POST',
    body: JSON.stringify(params),
  });
}

export async function updateClient(orgId: string, clientId: string, userId: string, params: {
  name?: string;
  contact_name?: string;
  contact_email?: string;
}): Promise<OrgClient> {
  return apiFetch(`/api/orgs/${orgId}/clients/${clientId}?user_id=${userId}`, {
    method: 'PATCH',
    body: JSON.stringify(params),
  });
}

export async function deleteClient(orgId: string, clientId: string, userId: string): Promise<{ status: string }> {
  return apiFetch(`/api/orgs/${orgId}/clients/${clientId}?user_id=${userId}`, {
    method: 'DELETE',
  });
}

export async function getClientSummary(orgId: string, clientId: string, userId: string): Promise<ClientSummary> {
  return apiFetch(`/api/orgs/${orgId}/clients/${clientId}/summary?user_id=${userId}`);
}

// ── Org Exposure & Compliance ──

export async function getOrgExposure(orgId: string, userId: string): Promise<OrgExposureScore> {
  return apiFetch(`/api/orgs/${orgId}/exposure?user_id=${userId}`);
}

export async function recalculateOrgExposure(orgId: string, userId: string): Promise<{ status: string; scores: OrgExposureScore[] }> {
  return apiFetch(`/api/orgs/${orgId}/exposure/recalculate?user_id=${userId}`, {
    method: 'POST',
  });
}

export async function getComplianceData(orgId: string, userId: string, params?: {
  days?: number;
  client_id?: string;
}): Promise<ComplianceSnapshot> {
  const sp = new URLSearchParams({ user_id: userId });
  if (params?.days) sp.set("days", String(params.days));
  if (params?.client_id) sp.set("client_id", params.client_id);
  return apiFetch(`/api/orgs/${orgId}/compliance?${sp.toString()}`);
}
