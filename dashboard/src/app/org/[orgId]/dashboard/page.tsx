"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  AlertTriangle,
  Clock,
  RefreshCw,
  ArrowRight,
  Server,
  Columns3,
  FileCheck,
  Users,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import {
  getOrg,
  getOrgExposure,
  recalculateOrgExposure,
  listTriageItems,
  listClients,
  getClientSummary,
} from "@/lib/api";
import type { Organization, OrgExposureScore, TriageItem, OrgClient, ClientSummary } from "@/types/cve";
import Footer from "@/components/layout/Footer";

function scoreColor(score: number) {
  if (score < 30) return { text: "text-emerald-400", bg: "bg-emerald-500/15", border: "border-emerald-500/30", glow: "shadow-emerald-500/20" };
  if (score <= 70) return { text: "text-amber-400", bg: "bg-amber-500/15", border: "border-amber-500/30", glow: "shadow-amber-500/20" };
  return { text: "text-red-400", bg: "bg-red-500/15", border: "border-red-500/30", glow: "shadow-red-500/20" };
}

export default function OrgDashboardPage() {
  const { user } = useAuth();
  const params = useParams();
  const orgId = params.orgId as string;

  const [org, setOrg] = useState<Organization | null>(null);
  const [exposure, setExposure] = useState<OrgExposureScore | null>(null);
  const [triageItems, setTriageItems] = useState<TriageItem[]>([]);
  const [clients, setClients] = useState<OrgClient[]>([]);
  const [clientSummaries, setClientSummaries] = useState<Record<string, ClientSummary>>({});
  const [recalculating, setRecalculating] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user?.id) return;
    setLoading(true);
    Promise.all([
      getOrg(orgId, user.id).catch(() => null),
      getOrgExposure(orgId, user.id).catch(() => null),
      listTriageItems(orgId, user.id).catch(() => ({ data: [] })),
      listClients(orgId, user.id).catch(() => ({ data: [] })),
    ]).then(async ([orgData, exp, triage, clientList]) => {
      setOrg(orgData);
      setExposure(exp);
      setTriageItems((triage as { data: TriageItem[] }).data || []);
      const cls = (clientList as { data: OrgClient[] }).data || [];
      setClients(cls);

      // Fetch client summaries for MSSP
      if (orgData?.org_type === "mssp" && cls.length > 0) {
        const summaries: Record<string, ClientSummary> = {};
        for (const c of cls) {
          try {
            summaries[c.id] = await getClientSummary(orgId, c.id, user.id);
          } catch { /* skip */ }
        }
        setClientSummaries(summaries);
      }
      setLoading(false);
    });
  }, [user?.id, orgId]);

  const handleRecalculate = async () => {
    if (!user?.id) return;
    setRecalculating(true);
    try {
      const result = await recalculateOrgExposure(orgId, user.id);
      if (result.scores?.[0]) {
        setExposure(result.scores[0]);
      }
    } catch { /* fail */ }
    setRecalculating(false);
  };

  if (loading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-32 skeleton rounded-xl" />
        <div className="h-48 skeleton rounded-xl" />
      </div>
    );
  }

  const overdueCount = triageItems.filter((i) => i.is_overdue).length;
  const openTriageCount = triageItems.filter(
    (i) => !["mitigated", "wont_fix"].includes(i.status)
  ).length;
  const sc = exposure ? scoreColor(exposure.score) : null;
  const isMSSP = org?.org_type === "mssp";

  return (
    <>
      {/* ── Exposure Overview ── */}
      <div
        className={cn(
          "card p-6 mb-6 border transition-all duration-500",
          sc ? `${sc.border} shadow-lg ${sc.glow}` : "border-l-border dark:border-border"
        )}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-acid" />
            <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
              Organization Exposure
            </h2>
          </div>
          <button
            onClick={handleRecalculate}
            disabled={recalculating}
            className="btn-ghost text-xs flex items-center gap-1.5"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", recalculating && "animate-spin")} />
            Recalculate
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {/* Score */}
          <div className="text-center">
            <div className={cn("text-4xl font-display font-extrabold leading-none", sc?.text)}>
              {exposure?.score ?? "—"}
            </div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">Exposure Score</p>
          </div>

          {/* Open Triage */}
          <div className="text-center">
            <div className="text-4xl font-display font-extrabold leading-none text-amber-400">
              {openTriageCount}
            </div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">Open Triage Items</p>
          </div>

          {/* Overdue */}
          <div className="text-center">
            <div className={cn(
              "text-4xl font-display font-extrabold leading-none",
              overdueCount > 0 ? "text-red-400 animate-pulse" : "text-emerald-400"
            )}>
              {overdueCount}
            </div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">Overdue SLA</p>
          </div>

          {/* Assets */}
          <div className="text-center">
            <div className="text-4xl font-display font-extrabold leading-none text-l-text dark:text-gray-200">
              {org?.asset_count ?? 0}
            </div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">
              Assets ({org?.asset_count ?? 0}/{org?.plan_limits?.assets ?? 50})
            </p>
          </div>
        </div>
      </div>

      {/* ── MSSP Client Overview ── */}
      {isMSSP && (
        <div className="card p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Users className="h-5 w-5 text-purple-400" />
              <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
                Client Overview
              </h2>
            </div>
            <Link href={`/org/${orgId}/clients`} className="text-xs font-mono text-acid hover:text-acid-dim transition-colors">
              Manage clients →
            </Link>
          </div>

          {clients.length > 0 ? (
            <>
              {/* Risk heatmap (for 3+ clients) */}
              {clients.length >= 3 && (
                <div className="flex flex-wrap gap-2 mb-4">
                  {clients.map((client) => {
                    const summary = clientSummaries[client.id];
                    const score = summary?.exposure_score ?? 0;
                    const sc2 = scoreColor(score);
                    return (
                      <Link
                        key={client.id}
                        href={`/org/${orgId}/clients/${client.id}/dashboard`}
                        className={cn(
                          "h-10 w-10 rounded-lg border flex items-center justify-center text-xs font-mono font-bold transition-all hover:scale-110",
                          sc2.bg, sc2.border, sc2.text
                        )}
                        title={`${client.name}: ${score}`}
                      >
                        {score}
                      </Link>
                    );
                  })}
                </div>
              )}

              {/* Client table */}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-l-border dark:border-border">
                      <th className="text-left py-2 text-xs font-mono text-l-sub dark:text-gray-500 font-medium">Client</th>
                      <th className="text-center py-2 text-xs font-mono text-l-sub dark:text-gray-500 font-medium">Exposure</th>
                      <th className="text-center py-2 text-xs font-mono text-l-sub dark:text-gray-500 font-medium">Open Triage</th>
                      <th className="text-center py-2 text-xs font-mono text-l-sub dark:text-gray-500 font-medium">Overdue</th>
                      <th className="text-right py-2 text-xs font-mono text-l-sub dark:text-gray-500 font-medium"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {clients.map((client) => {
                      const summary = clientSummaries[client.id];
                      const score = summary?.exposure_score ?? 0;
                      const csc = scoreColor(score);
                      return (
                        <tr key={client.id} className="border-b border-l-border/50 dark:border-border/50 hover:bg-l-panel/50 dark:hover:bg-panel/50">
                          <td className="py-3 text-l-text dark:text-gray-200 font-medium">{client.name}</td>
                          <td className="py-3 text-center">
                            <span className={cn("font-mono font-bold text-sm", csc.text)}>{score}</span>
                          </td>
                          <td className="py-3 text-center font-mono text-l-sub dark:text-gray-400">
                            {summary?.open_triage ?? 0}
                          </td>
                          <td className="py-3 text-center">
                            {(summary?.overdue_count ?? 0) > 0 ? (
                              <span className="font-mono text-red-400 font-medium">{summary?.overdue_count}</span>
                            ) : (
                              <span className="font-mono text-emerald-400">0</span>
                            )}
                          </td>
                          <td className="py-3 text-right">
                            <Link
                              href={`/org/${orgId}/clients/${client.id}/dashboard`}
                              className="text-xs text-acid hover:text-acid-dim transition-colors"
                            >
                              View <ArrowRight className="h-3 w-3 inline" />
                            </Link>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="text-center py-8">
              <Users className="h-8 w-8 mx-auto mb-2 text-l-muted dark:text-muted" />
              <p className="text-sm text-l-sub dark:text-gray-500 mb-3">No clients added yet.</p>
              <Link href={`/org/${orgId}/clients`} className="btn-primary text-xs">
                Add Your First Client
              </Link>
            </div>
          )}
        </div>
      )}

      {/* ── Quick Actions (Team orgs) ── */}
      {!isMSSP && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
          <Link href={`/org/${orgId}/assets`} className="card card-hover p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
              <Server className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-l-text dark:text-gray-200">Asset Register</p>
              <p className="text-[11px] text-l-sub dark:text-gray-500">{org?.asset_count ?? 0} assets tracked</p>
            </div>
            <ArrowRight className="h-4 w-4 ml-auto text-l-muted dark:text-muted" />
          </Link>

          <Link href={`/org/${orgId}/triage`} className="card card-hover p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20">
              <Columns3 className="h-5 w-5 text-amber-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-l-text dark:text-gray-200">Triage Board</p>
              <p className="text-[11px] text-l-sub dark:text-gray-500">{openTriageCount} open items</p>
            </div>
            <ArrowRight className="h-4 w-4 ml-auto text-l-muted dark:text-muted" />
          </Link>

          <Link href={`/org/${orgId}/compliance`} className="card card-hover p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20">
              <FileCheck className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-l-text dark:text-gray-200">Compliance</p>
              <p className="text-[11px] text-l-sub dark:text-gray-500">Generate snapshot PDF</p>
            </div>
            <ArrowRight className="h-4 w-4 ml-auto text-l-muted dark:text-muted" />
          </Link>
        </div>
      )}

      {/* ── Top CVEs ── */}
      {exposure?.top_cves && exposure.top_cves.length > 0 && (
        <div className="card p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="h-5 w-5 text-red-400" />
            <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
              Highest Risk CVEs
            </h2>
          </div>
          <div className="space-y-2">
            {exposure.top_cves.map((cve) => (
              <Link
                key={cve.cve_id}
                href={`/cve/${cve.cve_id}`}
                className="card card-hover p-3 flex items-center justify-between gap-3 block"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className="font-mono text-sm text-acid font-medium shrink-0">{cve.cve_id}</span>
                  <span className={cn(
                    "badge text-[10px] py-0.5 shrink-0",
                    cve.priority_label === "CRITICAL" && "bg-red-500/15 border-red-500/30 text-red-400",
                    cve.priority_label === "HIGH" && "bg-amber-500/15 border-amber-500/30 text-amber-400",
                  )}>
                    {cve.priority_label}
                  </span>
                  {cve.in_kev && (
                    <span className="badge text-[10px] py-0.5 bg-red-500/10 border-red-500/30 text-red-400">KEV</span>
                  )}
                  <span className="text-xs text-l-sub dark:text-gray-500 truncate hidden sm:inline">
                    {cve.description?.slice(0, 80)}…
                  </span>
                </div>
                <ArrowRight className="h-3.5 w-3.5 text-l-sub dark:text-gray-600 shrink-0" />
              </Link>
            ))}
          </div>
        </div>
      )}

      <div className="mt-12" />
      <Footer />
    </>
  );
}
