"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { Server, Plus, Trash2, ExternalLink, X, Eye } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import { listAssets, addAsset, deleteAsset, getAssetCVEs } from "@/lib/api";
import type { Asset, ProcessedCVE } from "@/types/cve";
import Footer from "@/components/layout/Footer";
import Link from "next/link";

function CriticalityBadge({ criticality }: { criticality: string }) {
  const colors: Record<string, string> = {
    CRITICAL: "bg-red-500/15 border-red-500/30 text-red-400",
    HIGH: "bg-amber-500/15 border-amber-500/30 text-amber-400",
    MEDIUM: "bg-yellow-500/15 border-yellow-500/30 text-yellow-300",
    LOW: "bg-blue-500/15 border-blue-500/30 text-blue-400",
  };
  return (
    <span className={cn("badge text-[10px] py-0.5", colors[criticality] || colors.MEDIUM)}>
      {criticality}
    </span>
  );
}

export default function AssetsPage() {
  const { user } = useAuth();
  const params = useParams();
  const orgId = params.orgId as string;

  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetCount, setAssetCount] = useState(0);
  const [assetLimit, setAssetLimit] = useState(50);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [viewCVEsFor, setViewCVEsFor] = useState<string | null>(null);
  const [matchedCVEs, setMatchedCVEs] = useState<ProcessedCVE[]>([]);
  const [loadingCVEs, setLoadingCVEs] = useState(false);

  // Add form
  const [name, setName] = useState("");
  const [cpe, setCpe] = useState("");
  const [criticality, setCriticality] = useState("MEDIUM");
  const [owner, setOwner] = useState("");
  const [notes, setNotes] = useState("");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");

  const fetchData = useCallback(async () => {
    if (!user?.id) return;
    setLoading(true);
    try {
      const result = await listAssets(orgId, user.id);
      setAssets(result.data || []);
      setAssetCount(result.asset_count || 0);
      setAssetLimit(result.asset_limit || 50);
    } catch { /* fail */ }
    setLoading(false);
  }, [user?.id, orgId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleAdd = async () => {
    if (!user || !name.trim()) return;
    setAdding(true);
    setAddError("");
    try {
      await addAsset(orgId, user.id, {
        display_name: name.trim(),
        cpe_string: cpe.trim() || name.trim().toLowerCase().replace(/\s+/g, ":"),
        criticality,
        owner_name: owner.trim(),
        notes: notes.trim(),
      });
      setName(""); setCpe(""); setCriticality("MEDIUM"); setOwner(""); setNotes("");
      setShowForm(false);
      await fetchData();
    } catch (e: unknown) {
      setAddError(e instanceof Error ? e.message : "Failed to add asset");
    }
    setAdding(false);
  };

  const handleDelete = async (assetId: string) => {
    if (!user?.id) return;
    try {
      await deleteAsset(orgId, assetId, user.id);
      await fetchData();
    } catch { /* fail */ }
  };

  const handleViewCVEs = async (assetId: string) => {
    if (!user?.id) return;
    if (viewCVEsFor === assetId) { setViewCVEsFor(null); return; }
    setViewCVEsFor(assetId);
    setLoadingCVEs(true);
    try {
      const result = await getAssetCVEs(orgId, user.id, { page_size: 50 });
      setMatchedCVEs(result.cves || []);
    } catch { setMatchedCVEs([]); }
    setLoadingCVEs(false);
  };

  const atLimit = assetCount >= assetLimit;

  if (loading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-10 w-48 skeleton" />
        <div className="h-64 skeleton rounded-xl" />
      </div>
    );
  }

  return (
    <>
      <div className="card p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5 text-purple-400" />
            <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
              Asset Register
            </h2>
            <span className="text-xs font-mono text-l-sub dark:text-gray-500">
              {assetCount} / {assetLimit === 999999 ? "∞" : assetLimit} assets
            </span>
          </div>
          <button
            onClick={() => setShowForm(!showForm)}
            disabled={atLimit}
            className={cn("btn-primary text-xs flex items-center gap-1.5", atLimit && "opacity-50 cursor-not-allowed")}
          >
            <Plus className="h-3.5 w-3.5" />
            Add Asset
          </button>
        </div>

        {/* Add form */}
        {showForm && (
          <div className="mb-4 p-4 rounded-lg border border-acid/20 bg-acid/5 animate-fade-in">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">Display Name *</label>
                <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Apache Tomcat" className="input-base w-full" />
              </div>
              <div>
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">
                  CPE String{" "}
                  <a href="https://nvd.nist.gov/products/cpe" target="_blank" rel="noopener noreferrer" className="text-acid hover:underline inline-flex items-center gap-0.5">
                    What is this? <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                </label>
                <input type="text" value={cpe} onChange={(e) => setCpe(e.target.value)} placeholder="e.g. cpe:2.3:a:apache:tomcat" className="input-base w-full font-mono text-xs" />
              </div>
              <div>
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">Owner</label>
                <input type="text" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Team/person responsible" className="input-base w-full" />
              </div>
              <div>
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">Criticality</label>
                <select value={criticality} onChange={(e) => setCriticality(e.target.value)} className="input-base text-xs w-full">
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
            </div>
            <div className="mt-3">
              <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">Notes</label>
              <input type="text" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Optional notes" className="input-base w-full" />
            </div>
            <div className="flex gap-2 mt-3">
              <button onClick={handleAdd} disabled={adding || !name.trim()} className="btn-primary text-xs">{adding ? "Adding…" : "Add Asset"}</button>
              <button onClick={() => { setShowForm(false); setAddError(""); }} className="btn-ghost text-xs">Cancel</button>
            </div>
            {addError && <p className="text-xs text-red-400 mt-2">{addError}</p>}
          </div>
        )}

        {/* Asset table */}
        {assets.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-l-border dark:border-border">
                  <th className="text-left py-2 text-xs font-mono text-l-sub dark:text-gray-500">Name</th>
                  <th className="text-left py-2 text-xs font-mono text-l-sub dark:text-gray-500 hidden sm:table-cell">CPE</th>
                  <th className="text-center py-2 text-xs font-mono text-l-sub dark:text-gray-500">Criticality</th>
                  <th className="text-left py-2 text-xs font-mono text-l-sub dark:text-gray-500 hidden md:table-cell">Owner</th>
                  <th className="text-right py-2 text-xs font-mono text-l-sub dark:text-gray-500">Actions</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => (
                  <tr key={asset.id} className="border-b border-l-border/50 dark:border-border/50 hover:bg-l-panel/50 dark:hover:bg-panel/50">
                    <td className="py-3 text-l-text dark:text-gray-200 font-medium">{asset.display_name}</td>
                    <td className="py-3 font-mono text-[11px] text-l-sub dark:text-gray-500 hidden sm:table-cell">{asset.cpe_string}</td>
                    <td className="py-3 text-center"><CriticalityBadge criticality={asset.criticality} /></td>
                    <td className="py-3 text-xs text-l-sub dark:text-gray-400 hidden md:table-cell">{asset.owner_name || "—"}</td>
                    <td className="py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => handleViewCVEs(asset.id)} className="text-l-sub dark:text-gray-500 hover:text-acid transition-colors p-1" title="View matching CVEs">
                          <Eye className="h-3.5 w-3.5" />
                        </button>
                        <button onClick={() => handleDelete(asset.id)} className="text-l-sub dark:text-gray-500 hover:text-red-400 transition-colors p-1">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8">
            <Server className="h-8 w-8 mx-auto mb-2 text-l-muted dark:text-muted" />
            <p className="text-sm text-l-sub dark:text-gray-500">No assets added yet. Add your tech stack to start monitoring.</p>
          </div>
        )}
      </div>

      {/* Matched CVEs panel */}
      {viewCVEsFor && (
        <div className="card p-6 mb-6 animate-fade-in">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-semibold text-sm text-l-text dark:text-gray-200">
              Matching CVEs
            </h3>
            <button onClick={() => setViewCVEsFor(null)} className="text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300">
              <X className="h-4 w-4" />
            </button>
          </div>
          {loadingCVEs ? (
            <div className="h-24 skeleton rounded-lg" />
          ) : matchedCVEs.length > 0 ? (
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {matchedCVEs.map((cve) => (
                <Link key={cve.cve_id} href={`/cve/${cve.cve_id}`} className="card card-hover p-2 flex items-center gap-2 block text-xs">
                  <span className="font-mono text-acid font-medium">{cve.cve_id}</span>
                  <span className="font-mono text-l-sub dark:text-gray-500">KRS {cve.priority_score}</span>
                  <span className="text-l-sub dark:text-gray-500 truncate hidden sm:inline">{cve.description?.slice(0, 60)}…</span>
                </Link>
              ))}
            </div>
          ) : (
            <p className="text-xs text-l-sub dark:text-gray-500">No CVEs match this asset register.</p>
          )}
        </div>
      )}

      <Footer />
    </>
  );
}
