/* ── API Client — calls KnowCVE FastAPI backend ─── */

import type {
  HealthResponse,
  PollResponse,
  ProcessedCVE,
  StatsResponse,
} from "@/types/cve";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
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
}): Promise<ProcessedCVE[]> {
  const sp = new URLSearchParams();
  if (params?.page) sp.set("page", String(params.page));
  if (params?.page_size) sp.set("page_size", String(params.page_size));
  if (params?.priority) sp.set("priority", params.priority);
  if (params?.min_score !== undefined) sp.set("min_score", String(params.min_score));
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
