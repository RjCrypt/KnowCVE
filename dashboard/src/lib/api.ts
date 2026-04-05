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
    throw new Error(`API ${res.status}: ${res.statusText}`);
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
}): Promise<ProcessedCVE[]> {
  const sp = new URLSearchParams();
  if (params?.page) sp.set("page", String(params.page));
  if (params?.page_size) sp.set("page_size", String(params.page_size));
  if (params?.priority) sp.set("priority", params.priority);
  if (params?.min_score !== undefined) sp.set("min_score", String(params.min_score));
  if (params?.category) sp.set("category", params.category);
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
