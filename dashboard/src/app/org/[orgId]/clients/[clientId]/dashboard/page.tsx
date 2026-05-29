"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Shield, AlertTriangle, RefreshCw, ArrowRight, Server, Columns3 } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import { getClientSummary, getOrgExposure, listTriageItems, getAssetCVEs } from "@/lib/api";
import type { ClientSummary, TriageItem } from "@/types/cve";
import Footer from "@/components/layout/Footer";

function scoreColor(score: number) {
  if (score < 30) return { text: "text-emerald-400", border: "border-emerald-500/30", glow: "shadow-emerald-500/20" };
  if (score <= 70) return { text: "text-amber-400", border: "border-amber-500/30", glow: "shadow-amber-500/20" };
  return { text: "text-red-400", border: "border-red-500/30", glow: "shadow-red-500/20" };
}

export default function ClientDashboardPage() {
  const { user } = useAuth();
  const params = useParams();
  const orgId = params.orgId as string;
  const clientId = params.clientId as string;

  const [summary, setSummary] = useState<ClientSummary | null>(null);
  const [triageItems, setTriageItems] = useState<TriageItem[]>([]);
  const [topCVEs, setTopCVEs] = useState<Array<{ cve_id: string; priority_score: number; priority_label: string }>>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user?.id) return;
    setLoading(true);
    Promise.all([
      getClientSummary(orgId, clientId, user.id).catch(() => null),
      listTriageItems(orgId, user.id, { client_id: clientId }).catch(() => ({ data: [] })),
      getAssetCVEs(orgId, user.id, { client_id: clientId, page_size: 5 }).catch(() => ({ cves: [] })),
    ]).then(([sum, triage, cves]) => {
      setSummary(sum);
      setTriageItems((triage as { data: TriageItem[] }).data || []);
      setTopCVEs((cves as { cves: Array<{ cve_id: string; priority_score: number; priority_label: string }> }).cves || []);
      setLoading(false);
    });
  }, [user?.id, orgId, clientId]);

  if (loading) {
    return <div className="space-y-4 animate-pulse"><div className="h-32 skeleton rounded-xl" /></div>;
  }

  const sc = summary ? scoreColor(summary.exposure_score) : null;
  const overdueCount = triageItems.filter((i) => i.is_overdue).length;
  const openCount = triageItems.filter((i) => !["mitigated", "wont_fix"].includes(i.status)).length;

  return (
    <>
      {/* Exposure */}
      <div className={cn("card p-6 mb-6 border transition-all", sc ? `${sc.border} shadow-lg ${sc.glow}` : "")}>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="h-5 w-5 text-acid" />
          <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">Client Exposure</h2>
        </div>
        <div className="grid grid-cols-3 gap-4">
          <div className="text-center">
            <div className={cn("text-4xl font-display font-extrabold leading-none", sc?.text)}>{summary?.exposure_score ?? 0}</div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">Exposure Score</p>
          </div>
          <div className="text-center">
            <div className="text-4xl font-display font-extrabold leading-none text-amber-400">{openCount}</div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">Open Triage</p>
          </div>
          <div className="text-center">
            <div className={cn("text-4xl font-display font-extrabold leading-none", overdueCount > 0 ? "text-red-400 animate-pulse" : "text-emerald-400")}>{overdueCount}</div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">Overdue SLA</p>
          </div>
        </div>
      </div>

      {/* Quick actions */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <Link href={`/org/${orgId}/clients/${clientId}/assets`} className="card card-hover p-4 flex items-center gap-3">
          <Server className="h-5 w-5 text-purple-400" />
          <span className="text-sm font-medium text-l-text dark:text-gray-200">Assets</span>
          <ArrowRight className="h-4 w-4 ml-auto text-l-muted dark:text-muted" />
        </Link>
        <Link href={`/org/${orgId}/clients/${clientId}/triage`} className="card card-hover p-4 flex items-center gap-3">
          <Columns3 className="h-5 w-5 text-amber-400" />
          <span className="text-sm font-medium text-l-text dark:text-gray-200">Triage Board</span>
          <ArrowRight className="h-4 w-4 ml-auto text-l-muted dark:text-muted" />
        </Link>
      </div>

      {/* Top CVEs */}
      {topCVEs.length > 0 && (
        <div className="card p-6 mb-6">
          <h3 className="font-display font-semibold text-sm text-l-text dark:text-gray-200 mb-3 flex items-center gap-1.5">
            <AlertTriangle className="h-4 w-4 text-red-400" /> Top CVEs
          </h3>
          <div className="space-y-2">
            {topCVEs.map((cve) => (
              <Link key={cve.cve_id} href={`/cve/${cve.cve_id}`} className="card card-hover p-2 flex items-center gap-2 text-xs block">
                <span className="font-mono text-acid font-medium">{cve.cve_id}</span>
                <span className={cn("badge text-[9px] py-0.5",
                  cve.priority_label === "CRITICAL" && "bg-red-500/15 border-red-500/30 text-red-400",
                  cve.priority_label === "HIGH" && "bg-amber-500/15 border-amber-500/30 text-amber-400",
                )}>{cve.priority_label}</span>
                <span className="font-mono text-l-sub dark:text-gray-500">KRS {cve.priority_score}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      <Footer />
    </>
  );
}
