"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { FileCheck, Download, Calendar, AlertTriangle, CheckCircle2 } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import { getComplianceData } from "@/lib/api";
import type { ComplianceSnapshot } from "@/types/cve";
import Footer from "@/components/layout/Footer";

export default function ClientCompliancePage() {
  const { user } = useAuth();
  const params = useParams();
  const orgId = params.orgId as string;
  const clientId = params.clientId as string;

  const [data, setData] = useState<ComplianceSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(30);
  const [generating, setGenerating] = useState(false);

  const fetchData = useCallback(async () => {
    if (!user?.id) return;
    setLoading(true);
    try {
      const result = await getComplianceData(orgId, user.id, { days, client_id: clientId });
      setData(result);
    } catch { /* fail */ }
    setLoading(false);
  }, [user?.id, orgId, clientId, days]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleExportPDF = async () => {
    setGenerating(true);
    try {
      const [{ default: jsPDF }, { default: html2canvas }] = await Promise.all([
        import("jspdf"),
        import("html2canvas"),
      ]);
      const el = document.getElementById("client-compliance-report");
      if (!el) return;
      const canvas = await html2canvas(el, { backgroundColor: "#080a0f", scale: 2 });
      const imgData = canvas.toDataURL("image/png");
      const pdf = new jsPDF("p", "mm", "a4");
      const imgWidth = 210;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      pdf.addImage(imgData, "PNG", 0, 0, imgWidth, imgHeight);
      pdf.save(`knowcve-client-compliance-${days}d-${new Date().toISOString().slice(0, 10)}.pdf`);
    } catch (e) { console.error("PDF export failed:", e); }
    setGenerating(false);
  };

  if (loading) return <div className="h-64 skeleton rounded-xl animate-pulse" />;

  const stats = data?.stats || { total_cves: 0, critical_high_count: 0, kev_count: 0, mitigated_count: 0, remediation_rate: 0, sla_compliance_rate: 0, avg_remediation_days: 0 };

  return (
    <>
      <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <FileCheck className="h-5 w-5 text-blue-400" />
          <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">Client Compliance</h2>
        </div>
        <div className="flex items-center gap-3">
          <select value={days} onChange={(e) => setDays(parseInt(e.target.value))} className="input-base text-xs py-1">
            <option value={7}>7 days</option><option value={30}>30 days</option><option value={90}>90 days</option>
          </select>
          <button onClick={handleExportPDF} disabled={generating} className="btn-primary text-xs flex items-center gap-1.5">
            <Download className="h-3.5 w-3.5" /> {generating ? "Generating…" : "Export PDF"}
          </button>
        </div>
      </div>

      <div id="client-compliance-report">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
          <div className="card p-4 text-center">
            <div className="text-2xl font-display font-extrabold text-l-text dark:text-gray-200">{stats.total_cves}</div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">Total CVEs</p>
          </div>
          <div className="card p-4 text-center">
            <div className={cn("text-2xl font-display font-extrabold", stats.remediation_rate >= 80 ? "text-emerald-400" : "text-amber-400")}>{stats.remediation_rate}%</div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">Remediation Rate</p>
          </div>
          <div className="card p-4 text-center">
            <div className={cn("text-2xl font-display font-extrabold", stats.sla_compliance_rate >= 80 ? "text-emerald-400" : "text-amber-400")}>{stats.sla_compliance_rate}%</div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">SLA Compliance</p>
          </div>
          <div className="card p-4 text-center">
            <div className="text-2xl font-display font-extrabold text-amber-400">{stats.avg_remediation_days}d</div>
            <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 mt-1">Avg Fix Time</p>
          </div>
        </div>

        {data?.cves && data.cves.length > 0 && (
          <div className="card p-6 mb-6">
            <h3 className="font-display font-semibold text-sm text-l-text dark:text-gray-200 mb-3">CVE History</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-l-border dark:border-border">
                  <th className="text-left py-2 text-xs font-mono text-l-sub dark:text-gray-500">CVE</th>
                  <th className="text-center py-2 text-xs font-mono text-l-sub dark:text-gray-500">Severity</th>
                  <th className="text-center py-2 text-xs font-mono text-l-sub dark:text-gray-500">Status</th>
                  <th className="text-right py-2 text-xs font-mono text-l-sub dark:text-gray-500">Days</th>
                </tr></thead>
                <tbody>
                  {data.cves.map((cve, i) => (
                    <tr key={`${cve.cve_id}-${i}`} className="border-b border-l-border/50 dark:border-border/50">
                      <td className="py-2 font-mono text-xs text-acid">{cve.cve_id}</td>
                      <td className="py-2 text-center"><span className={cn("badge text-[9px] py-0.5",
                        cve.severity === "CRITICAL" && "bg-red-500/15 border-red-500/30 text-red-400",
                        cve.severity === "HIGH" && "bg-amber-500/15 border-amber-500/30 text-amber-400",
                      )}>{cve.severity}</span></td>
                      <td className="py-2 text-center text-xs text-l-sub dark:text-gray-400">{cve.triage_status?.replace(/_/g, " ")}</td>
                      <td className="py-2 text-right font-mono text-xs text-l-sub dark:text-gray-400">{cve.days_to_remediate !== null ? `${cve.days_to_remediate}d` : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
      <Footer />
    </>
  );
}
