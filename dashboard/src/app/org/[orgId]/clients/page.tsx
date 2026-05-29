"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  Users,
  Plus,
  Trash2,
  ArrowRight,
  Building2,
  Mail,
  X,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import {
  listClients,
  createClient,
  deleteClient,
  getClientSummary,
} from "@/lib/api";
import type { OrgClient, ClientSummary } from "@/types/cve";
import Footer from "@/components/layout/Footer";

function scoreColor(score: number) {
  if (score < 30) return "text-emerald-400";
  if (score <= 70) return "text-amber-400";
  return "text-red-400";
}

export default function ClientsPage() {
  const { user } = useAuth();
  const params = useParams();
  const orgId = params.orgId as string;

  const [clients, setClients] = useState<OrgClient[]>([]);
  const [summaries, setSummaries] = useState<Record<string, ClientSummary>>({});
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  // Form
  const [name, setName] = useState("");
  const [contactName, setContactName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");

  const fetchData = useCallback(async () => {
    if (!user?.id) return;
    setLoading(true);
    try {
      const result = await listClients(orgId, user.id);
      const cls = result.data || [];
      setClients(cls);

      // Fetch summaries in parallel
      const sums: Record<string, ClientSummary> = {};
      await Promise.all(
        cls.map(async (c) => {
          try {
            sums[c.id] = await getClientSummary(orgId, c.id, user.id);
          } catch { /* skip */ }
        })
      );
      setSummaries(sums);
    } catch { /* fail */ }
    setLoading(false);
  }, [user?.id, orgId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleAdd = async () => {
    if (!user || !name.trim()) return;
    setAdding(true);
    setAddError("");
    try {
      await createClient(orgId, user.id, {
        name: name.trim(),
        contact_name: contactName.trim(),
        contact_email: contactEmail.trim(),
      });
      setName("");
      setContactName("");
      setContactEmail("");
      setShowForm(false);
      await fetchData();
    } catch (e: unknown) {
      setAddError(e instanceof Error ? e.message : "Failed to add client");
    }
    setAdding(false);
  };

  const handleDelete = async (clientId: string) => {
    if (!user || !confirm("Delete this client? This will also delete all its assets and triage items.")) return;
    try {
      await deleteClient(orgId, clientId, user.id);
      await fetchData();
    } catch { /* fail */ }
  };

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
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-2">
          <Users className="h-5 w-5 text-purple-400" />
          <h1 className="font-display font-bold text-xl text-l-text dark:text-gray-100">
            Client Management
          </h1>
          <span className="text-xs font-mono text-l-sub dark:text-gray-500">
            {clients.length} clients
          </span>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="btn-primary text-xs flex items-center gap-1.5"
        >
          <Plus className="h-3.5 w-3.5" />
          Add Client
        </button>
      </div>

      {/* Add form */}
      {showForm && (
        <div className="card p-4 mb-6 border border-acid/20 bg-acid/5 animate-fade-in">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium text-l-text dark:text-gray-200">New Client</h3>
            <button onClick={() => setShowForm(false)} className="text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div>
              <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">
                Client Name *
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Acme Corp"
                className="input-base w-full"
                autoFocus
              />
            </div>
            <div>
              <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">
                Contact Name
              </label>
              <input
                type="text"
                value={contactName}
                onChange={(e) => setContactName(e.target.value)}
                placeholder="John Doe"
                className="input-base w-full"
              />
            </div>
            <div>
              <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">
                Contact Email
              </label>
              <input
                type="email"
                value={contactEmail}
                onChange={(e) => setContactEmail(e.target.value)}
                placeholder="john@acme.com"
                className="input-base w-full"
              />
            </div>
          </div>
          <div className="flex gap-2 mt-3">
            <button
              onClick={handleAdd}
              disabled={adding || !name.trim()}
              className={cn("btn-primary text-xs", (adding || !name.trim()) && "opacity-50")}
            >
              {adding ? "Adding…" : "Add Client"}
            </button>
            <button onClick={() => setShowForm(false)} className="btn-ghost text-xs">
              Cancel
            </button>
          </div>
          {addError && <p className="text-xs text-red-400 mt-2">{addError}</p>}
        </div>
      )}

      {/* Client cards */}
      {clients.length > 0 ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 mb-6">
          {clients.map((client) => {
            const summary = summaries[client.id];
            const score = summary?.exposure_score ?? 0;
            return (
              <div key={client.id} className="card card-hover p-5 group relative">
                {/* Delete button */}
                <button
                  onClick={(e) => {
                    e.preventDefault();
                    handleDelete(client.id);
                  }}
                  className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity text-l-sub dark:text-gray-600 hover:text-red-400"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>

                {/* Header */}
                <div className="flex items-center gap-2.5 mb-3">
                  <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
                    <Building2 className="h-5 w-5 text-purple-400" />
                  </div>
                  <div>
                    <h3 className="font-medium text-l-text dark:text-gray-200">
                      {client.name}
                    </h3>
                    {client.contact_email && (
                      <p className="text-[10px] text-l-sub dark:text-gray-500 flex items-center gap-1">
                        <Mail className="h-2.5 w-2.5" />
                        {client.contact_email}
                      </p>
                    )}
                  </div>
                </div>

                {/* Metrics */}
                <div className="grid grid-cols-3 gap-2 mb-3">
                  <div className="text-center p-2 rounded-lg bg-l-panel dark:bg-panel">
                    <div className={cn("text-lg font-display font-bold", scoreColor(score))}>
                      {score}
                    </div>
                    <p className="text-[9px] font-mono text-l-sub dark:text-gray-500">
                      Exposure
                    </p>
                  </div>
                  <div className="text-center p-2 rounded-lg bg-l-panel dark:bg-panel">
                    <div className="text-lg font-display font-bold text-amber-400">
                      {summary?.open_triage ?? 0}
                    </div>
                    <p className="text-[9px] font-mono text-l-sub dark:text-gray-500">
                      Open
                    </p>
                  </div>
                  <div className="text-center p-2 rounded-lg bg-l-panel dark:bg-panel">
                    <div className={cn(
                      "text-lg font-display font-bold",
                      (summary?.overdue_count ?? 0) > 0 ? "text-red-400" : "text-emerald-400"
                    )}>
                      {summary?.overdue_count ?? 0}
                    </div>
                    <p className="text-[9px] font-mono text-l-sub dark:text-gray-500">
                      Overdue
                    </p>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex gap-2">
                  <Link
                    href={`/org/${orgId}/clients/${client.id}/dashboard`}
                    className="btn-primary text-xs flex-1 flex items-center justify-center gap-1.5"
                  >
                    Dashboard
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                  <Link
                    href={`/org/${orgId}/clients/${client.id}/assets`}
                    className="btn-ghost text-xs flex-1 text-center border border-l-border dark:border-border"
                  >
                    Assets
                  </Link>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="card p-12 text-center mb-6">
          <Users className="h-10 w-10 mx-auto mb-3 text-l-muted dark:text-muted" />
          <h3 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-2">
            No clients yet
          </h3>
          <p className="text-sm text-l-sub dark:text-gray-500 mb-4 max-w-sm mx-auto">
            Add your first client to start managing their vulnerability exposure,
            asset register, and triage board separately.
          </p>
          <button
            onClick={() => setShowForm(true)}
            className="btn-primary text-xs"
          >
            Add Your First Client
          </button>
        </div>
      )}

      <Footer />
    </>
  );
}
