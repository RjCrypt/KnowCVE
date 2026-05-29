"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { Columns3, Plus, Zap } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import { listTriageItems, createTriageItem, updateTriageItem, autoPopulateTriage } from "@/lib/api";
import type { TriageItem, TriageStatus } from "@/types/cve";
import TriageCard from "@/components/TriageCard";
import CVESearchInput from "@/components/CVESearchInput";
import SLATimer from "@/components/SLATimer";
import Footer from "@/components/layout/Footer";
import type { ProcessedCVE } from "@/types/cve";

const COLUMNS: { id: TriageStatus; label: string; color: string }[] = [
  { id: "new", label: "New", color: "border-t-blue-500/50" },
  { id: "investigating", label: "Investigating", color: "border-t-amber-500/50" },
  { id: "remediation_planned", label: "Remediation", color: "border-t-purple-500/50" },
  { id: "mitigated", label: "Mitigated", color: "border-t-emerald-500/50" },
  { id: "wont_fix", label: "Won't Fix", color: "border-t-gray-500/50" },
];

export default function ClientTriagePage() {
  const { user } = useAuth();
  const params = useParams();
  const orgId = params.orgId as string;
  const clientId = params.clientId as string;

  const [items, setItems] = useState<TriageItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [showSearch, setShowSearch] = useState(false);

  const fetchData = useCallback(async () => {
    if (!user?.id) return;
    setLoading(true);
    try {
      const result = await listTriageItems(orgId, user.id, { client_id: clientId });
      setItems(result.data || []);
    } catch { /* fail */ }
    setLoading(false);
  }, [user?.id, orgId, clientId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleAddCVE = async (cve: ProcessedCVE) => {
    if (!user?.id) return;
    try {
      await createTriageItem(orgId, user.id, { cve_id: cve.cve_id, client_id: clientId });
      setShowSearch(false);
      await fetchData();
    } catch { /* fail */ }
  };

  const handleAutoPop = async () => {
    if (!user?.id) return;
    try {
      await autoPopulateTriage(orgId, user.id, clientId);
      await fetchData();
    } catch { /* fail */ }
  };

  const handleStatusChange = async (itemId: string, newStatus: string) => {
    if (!user?.id) return;
    try {
      await updateTriageItem(orgId, itemId, user.id, { status: newStatus });
      await fetchData();
    } catch { /* fail */ }
  };

  if (loading) return <div className="h-64 skeleton rounded-xl animate-pulse" />;

  const grouped = COLUMNS.map((col) => ({
    ...col,
    items: items.filter((i) => i.status === col.id),
  }));

  return (
    <>
      <div className="flex items-center justify-between gap-4 mb-4 flex-wrap">
        <div className="flex items-center gap-2">
          <Columns3 className="h-5 w-5 text-amber-400" />
          <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">Client Triage</h2>
          <span className="text-xs font-mono text-l-sub dark:text-gray-500">{items.length} items</span>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowSearch(!showSearch)} className="btn-primary text-xs flex items-center gap-1.5">
            <Plus className="h-3.5 w-3.5" /> Add CVE
          </button>
          <button onClick={handleAutoPop} className="btn-ghost text-xs flex items-center gap-1.5 border border-l-border dark:border-border">
            <Zap className="h-3.5 w-3.5" /> Auto-populate
          </button>
        </div>
      </div>

      {showSearch && (
        <div className="mb-4 animate-fade-in">
          <CVESearchInput onSelect={handleAddCVE} placeholder="Search CVEs to add…" />
        </div>
      )}

      {/* Simple list view for client triage (no drag — use status dropdown) */}
      <div className="grid gap-3 md:grid-cols-5 mb-8">
        {grouped.map((col) => (
          <div key={col.id} className={cn("rounded-xl border-t-2 min-h-[200px]", col.color)}>
            <div className="px-3 py-2 border-b border-l-border/50 dark:border-border/50 flex items-center justify-between">
              <h3 className="text-xs font-medium text-l-text dark:text-gray-200">{col.label}</h3>
              <span className="text-[10px] font-mono text-l-sub dark:text-gray-500 bg-l-panel dark:bg-panel rounded-full px-2 py-0.5">{col.items.length}</span>
            </div>
            <div className="p-2 space-y-2">
              {col.items.map((item) => (
                <div key={item.id} className="card p-2.5">
                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span className="font-mono text-[11px] text-acid font-medium">{item.cve_id}</span>
                    <SLATimer slaDueAt={item.sla_due_at} status={item.status} compact />
                  </div>
                  <select
                    value={item.status}
                    onChange={(e) => handleStatusChange(item.id, e.target.value)}
                    className="input-base text-[10px] w-full py-0.5"
                  >
                    {COLUMNS.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
                  </select>
                </div>
              ))}
              {col.items.length === 0 && (
                <p className="text-center py-4 text-[11px] text-l-sub dark:text-gray-600">No items</p>
              )}
            </div>
          </div>
        ))}
      </div>

      <Footer />
    </>
  );
}
