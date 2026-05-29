"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { Server, Plus, Trash2 } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import { listAssets, addAsset, deleteAsset } from "@/lib/api";
import type { Asset } from "@/types/cve";
import Footer from "@/components/layout/Footer";

export default function ClientAssetsPage() {
  const { user } = useAuth();
  const params = useParams();
  const orgId = params.orgId as string;
  const clientId = params.clientId as string;

  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [cpe, setCpe] = useState("");
  const [criticality, setCriticality] = useState("MEDIUM");
  const [adding, setAdding] = useState(false);

  const fetchData = useCallback(async () => {
    if (!user?.id) return;
    setLoading(true);
    try {
      const result = await listAssets(orgId, user.id, clientId);
      setAssets(result.data || []);
    } catch { /* fail */ }
    setLoading(false);
  }, [user?.id, orgId, clientId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleAdd = async () => {
    if (!user || !name.trim()) return;
    setAdding(true);
    try {
      await addAsset(orgId, user.id, {
        display_name: name.trim(),
        cpe_string: cpe.trim() || name.trim().toLowerCase().replace(/\s+/g, ":"),
        criticality,
        client_id: clientId,
      });
      setName(""); setCpe(""); setCriticality("MEDIUM"); setShowForm(false);
      await fetchData();
    } catch { /* fail */ }
    setAdding(false);
  };

  const handleDelete = async (assetId: string) => {
    if (!user?.id) return;
    try { await deleteAsset(orgId, assetId, user.id); await fetchData(); } catch { /* fail */ }
  };

  const critColors: Record<string, string> = {
    CRITICAL: "bg-red-500/15 border-red-500/30 text-red-400",
    HIGH: "bg-amber-500/15 border-amber-500/30 text-amber-400",
    MEDIUM: "bg-yellow-500/15 border-yellow-500/30 text-yellow-300",
    LOW: "bg-blue-500/15 border-blue-500/30 text-blue-400",
  };

  if (loading) return <div className="h-64 skeleton rounded-xl animate-pulse" />;

  return (
    <>
      <div className="card p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5 text-purple-400" />
            <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">Client Assets</h2>
            <span className="text-xs font-mono text-l-sub dark:text-gray-500">{assets.length} assets</span>
          </div>
          <button onClick={() => setShowForm(!showForm)} className="btn-primary text-xs flex items-center gap-1.5">
            <Plus className="h-3.5 w-3.5" /> Add Asset
          </button>
        </div>

        {showForm && (
          <div className="mb-4 p-4 rounded-lg border border-acid/20 bg-acid/5 animate-fade-in">
            <div className="grid gap-3 sm:grid-cols-3">
              <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Display Name" className="input-base w-full" autoFocus />
              <input type="text" value={cpe} onChange={(e) => setCpe(e.target.value)} placeholder="CPE string" className="input-base w-full font-mono text-xs" />
              <select value={criticality} onChange={(e) => setCriticality(e.target.value)} className="input-base text-xs w-full">
                <option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option>
              </select>
            </div>
            <div className="flex gap-2 mt-3">
              <button onClick={handleAdd} disabled={adding || !name.trim()} className="btn-primary text-xs">{adding ? "Adding…" : "Add"}</button>
              <button onClick={() => setShowForm(false)} className="btn-ghost text-xs">Cancel</button>
            </div>
          </div>
        )}

        {assets.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-l-border dark:border-border">
                <th className="text-left py-2 text-xs font-mono text-l-sub dark:text-gray-500">Name</th>
                <th className="text-left py-2 text-xs font-mono text-l-sub dark:text-gray-500 hidden sm:table-cell">CPE</th>
                <th className="text-center py-2 text-xs font-mono text-l-sub dark:text-gray-500">Criticality</th>
                <th className="text-right py-2"></th>
              </tr></thead>
              <tbody>
                {assets.map((a) => (
                  <tr key={a.id} className="border-b border-l-border/50 dark:border-border/50 hover:bg-l-panel/50 dark:hover:bg-panel/50">
                    <td className="py-3 text-l-text dark:text-gray-200 font-medium">{a.display_name}</td>
                    <td className="py-3 font-mono text-[11px] text-l-sub dark:text-gray-500 hidden sm:table-cell">{a.cpe_string}</td>
                    <td className="py-3 text-center"><span className={cn("badge text-[10px] py-0.5", critColors[a.criticality])}>{a.criticality}</span></td>
                    <td className="py-3 text-right"><button onClick={() => handleDelete(a.id)} className="text-l-sub dark:text-gray-500 hover:text-red-400"><Trash2 className="h-3.5 w-3.5" /></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8">
            <Server className="h-8 w-8 mx-auto mb-2 text-l-muted dark:text-muted" />
            <p className="text-sm text-l-sub dark:text-gray-500">No assets for this client yet.</p>
          </div>
        )}
      </div>
      <Footer />
    </>
  );
}
