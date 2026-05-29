"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  LayoutDashboard,
  Bookmark,
  Cpu,
  Shield,
  Mail,
  ArrowRight,
  Plus,
  Trash2,
  RefreshCw,
  Send,
  X,
  ExternalLink,
  AlertTriangle,
  Zap,
  Info,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn, priorityColor, formatDateRelative } from "@/lib/utils";
import Footer from "@/components/layout/Footer";
import CreateOrgModal from "@/components/CreateOrgModal";
import { OrgProvider } from "@/lib/org-context";
import type { WatchlistItem, ExposureScore, ProcessedCVE } from "@/types/cve";
import {
  getWatchlist,
  addWatchlistItem,
  removeWatchlistItem,
  getExposureScore,
  recalculateExposure,
  getWatchlistCVEs,
  setDigestEnabled as setDigestEnabledApi,
  sendTestDigest,
} from "@/lib/api";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/* ── Score color helper ──────────────────────── */
function scoreColor(score: number) {
  if (score < 30) return { text: "text-emerald-400", bg: "bg-emerald-500/15", border: "border-emerald-500/30", glow: "shadow-emerald-500/20" };
  if (score <= 70) return { text: "text-amber-400", bg: "bg-amber-500/15", border: "border-amber-500/30", glow: "shadow-amber-500/20" };
  return { text: "text-red-400", bg: "bg-red-500/15", border: "border-red-500/30", glow: "shadow-red-500/20" };
}

/* ── Criticality badge ──────────────────────── */
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

export default function WorkspacePage() {
  const { user, profile } = useAuth();

  /* ── State ─────────────────────────────── */
  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);
  const [exposure, setExposure] = useState<ExposureScore | null>(null);
  const [matchedCVEs, setMatchedCVEs] = useState<ProcessedCVE[]>([]);
  const [matchTotal, setMatchTotal] = useState(0);
  const [cvePage, setCvePage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [recalculating, setRecalculating] = useState(false);
  const [digestEnabled, setDigestEnabled] = useState(true);
  const [sendingTest, setSendingTest] = useState(false);
  const [testSent, setTestSent] = useState(false);

  /* ── Add form state ────────────────────── */
  const [showAddForm, setShowAddForm] = useState(false);
  const [newDisplayName, setNewDisplayName] = useState("");
  const [newCpeString, setNewCpeString] = useState("");
  const [newCriticality, setNewCriticality] = useState("MEDIUM");
  const [addError, setAddError] = useState("");
  const [adding, setAdding] = useState(false);
  const [showCreateOrg, setShowCreateOrg] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      if (params.get("create_org") === "1") {
        setShowCreateOrg(true);
      }
    }
  }, []);

  /* ── Tech context suggestion ───────────── */
  const [showSuggestions, setShowSuggestions] = useState(true);
  const suggestedTechs = profile?.tech_context
    ? profile.tech_context.split(",").map((t: string) => t.trim()).filter(Boolean)
    : [];

  /* ── Data fetching ─────────────────────── */
  const fetchData = useCallback(async () => {
    if (!user) return;
    setLoading(true);
    try {
      const [wl, exp] = await Promise.all([
        getWatchlist(user.id),
        getExposureScore(user.id).catch(() => null),
      ]);
      setWatchlist(wl);
      setExposure(exp);

      if (wl.length > 0) {
        const cveResult = await getWatchlistCVEs(user.id, 1, 10).catch(() => ({ cves: [], total: 0, page: 1 }));
        setMatchedCVEs(cveResult.cves || []);
        setMatchTotal(cveResult.total || 0);
      }

      // Check digest preference from profile
      try {
        const profileRes = await fetch(`${API_BASE}/api/auth/profile/${user.id}`);
        if (profileRes.ok) {
          const profileData = await profileRes.json();
          setDigestEnabled(profileData.digest_enabled !== false);
        }
      } catch { /* use default */ }
    } catch (e) {
      console.error("Failed to load workspace data:", e);
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => { fetchData(); }, [fetchData]);

  /* ── Handlers ──────────────────────────── */

  const handleAdd = async () => {
    if (!user || !newDisplayName.trim()) return;
    setAdding(true);
    setAddError("");
    try {
      await addWatchlistItem({
        user_id: user.id,
        cpe_string: newCpeString.trim() || newDisplayName.trim().toLowerCase().replace(/\s+/g, ":"),
        display_name: newDisplayName.trim(),
        criticality: newCriticality,
      });
      setNewDisplayName("");
      setNewCpeString("");
      setNewCriticality("MEDIUM");
      setShowAddForm(false);
      await fetchData();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to add";
      setAddError(msg);
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (itemId: string) => {
    if (!user) return;
    try {
      await removeWatchlistItem(user.id, itemId);
      await fetchData();
    } catch { /* silently fail */ }
  };

  const handleRecalculate = async () => {
    if (!user) return;
    setRecalculating(true);
    try {
      const result = await recalculateExposure(user.id);
      setExposure(result);
    } catch { /* silently fail */ }
    setRecalculating(false);
  };

  const handleDigestToggle = async () => {
    if (!user) return;
    const newVal = !digestEnabled;
    setDigestEnabled(newVal);
    try {
      await setDigestEnabledApi(user.id, newVal);
    } catch {
      setDigestEnabled(!newVal); // revert
    }
  };

  const handleTestDigest = async () => {
    if (!user) return;
    setSendingTest(true);
    setTestSent(false);
    try {
      const result = await sendTestDigest(user.id);
      setTestSent(result.sent);
    } catch { /* fail */ }
    setSendingTest(false);
  };

  const handleLoadMoreCVEs = async () => {
    if (!user) return;
    const nextPage = cvePage + 1;
    try {
      const result = await getWatchlistCVEs(user.id, nextPage, 10);
      setMatchedCVEs((prev) => [...prev, ...(result.cves || [])]);
      setCvePage(nextPage);
    } catch { /* fail */ }
  };

  const handleSuggestionClick = (tech: string) => {
    setNewDisplayName(tech);
    setShowAddForm(true);
  };

  /* ── Render ────────────────────────────── */

  const sc = exposure ? scoreColor(exposure.score) : null;
  const hasWatchlist = watchlist.length > 0;
  const atLimit = watchlist.length >= 20;

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6 py-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <div className="p-2 rounded-xl bg-acid/10 border border-acid/20">
          <LayoutDashboard className="h-6 w-6 text-acid" />
        </div>
        <div>
          <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
            My Workspace
          </h1>
          <p className="text-sm text-l-sub dark:text-gray-400">
            {profile?.display_name
              ? `Welcome back, ${profile.display_name}`
              : "Your personal vulnerability dashboard"}
          </p>
        </div>
      </div>

      {/* Phase 8: Org Upgrade CTA */}
      <div className="card p-4 mb-6 border-purple-500/20 bg-gradient-to-r from-purple-500/5 to-acid/5 animate-fade-in">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
              <Shield className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-l-text dark:text-gray-200">
                Upgrade to Team or MSSP workspace
              </p>
              <p className="text-xs text-l-sub dark:text-gray-500">
                Shared asset registers, CVE triage boards, SLA tracking, and compliance reports.
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowCreateOrg(true)}
            className="btn-primary text-xs flex items-center gap-1.5 shrink-0"
          >
            <Plus className="h-3.5 w-3.5" />
            Create Org Workspace
          </button>
        </div>
      </div>

      {/* Onboarding banner */}
      {profile && !profile.onboarding_complete && (
        <div className="card p-4 mb-6 border-acid/20 bg-acid/5 animate-fade-in">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-medium text-l-text dark:text-gray-200">
                Complete your profile setup
              </p>
              <p className="text-xs text-l-sub dark:text-gray-400 mt-0.5">
                Tell us about your role and tech stack to personalize your experience
              </p>
            </div>
            <Link href="/onboarding" className="btn-primary text-xs shrink-0">
              Set Up
            </Link>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════ */}
      {/* 1. EXPOSURE SCORE CARD                                       */}
      {/* ══════════════════════════════════════════════════════════════ */}
      <div className={cn(
        "card p-6 mb-6 border transition-all duration-500",
        sc ? `${sc.border} shadow-lg ${sc.glow}` : "border-l-border dark:border-border"
      )}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-acid" />
            <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
              Your Personal Exposure Score
            </h2>
          </div>
          {hasWatchlist && (
            <button
              onClick={handleRecalculate}
              disabled={recalculating}
              className="btn-ghost text-xs flex items-center gap-1.5"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", recalculating && "animate-spin")} />
              Recalculate
            </button>
          )}
        </div>

        {hasWatchlist && exposure ? (
          <div className="text-center">
            <div className={cn("text-6xl font-display font-extrabold leading-none mb-3", sc?.text)}>
              {exposure.score}
            </div>
            <div className="flex items-center justify-center gap-4 text-xs font-mono">
              <span className="text-red-400">{exposure.critical_count} Critical CVEs</span>
              <span className="text-l-muted dark:text-muted">|</span>
              <span className="text-amber-400">{exposure.high_count} High CVEs</span>
              <span className="text-l-muted dark:text-muted">|</span>
              <span className="text-red-400">{exposure.actively_exploited_count} Actively Exploited</span>
            </div>
            {exposure.calculated_at && (
              <p className="text-[10px] font-mono text-l-sub dark:text-gray-600 mt-3">
                Last calculated {formatDateRelative(exposure.calculated_at)}
              </p>
            )}
          </div>
        ) : (
          <div className="text-center py-4">
            <div className="text-5xl font-display font-extrabold text-l-muted dark:text-muted leading-none mb-2">
              —
            </div>
            <p className="text-sm text-l-sub dark:text-gray-500">
              Add technologies to your watchlist to calculate your exposure
            </p>
          </div>
        )}
      </div>

      {/* ══════════════════════════════════════════════════════════════ */}
      {/* 2. TECH STACK WATCHLIST CARD                                  */}
      {/* ══════════════════════════════════════════════════════════════ */}
      <div className="card p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Cpu className="h-5 w-5 text-purple-400" />
            <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
              Tech Stack Watchlist
            </h2>
            <span className="text-xs font-mono text-l-sub dark:text-gray-500 ml-2">
              {watchlist.length} / 20 technologies
            </span>
          </div>
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            disabled={atLimit}
            className={cn(
              "btn-primary text-xs flex items-center gap-1.5",
              atLimit && "opacity-50 cursor-not-allowed"
            )}
            title={atLimit ? "Upgrade to Pro for unlimited watchlist items" : ""}
          >
            <Plus className="h-3.5 w-3.5" />
            Add Technology
          </button>
        </div>

        {/* Tech context suggestions */}
        {showSuggestions && suggestedTechs.length > 0 && watchlist.length === 0 && (
          <div className="mb-4 p-3 rounded-lg border border-purple-500/20 bg-purple-500/5 animate-fade-in">
            <div className="flex items-start justify-between gap-2 mb-2">
              <p className="text-xs text-purple-400">
                <Zap className="h-3.5 w-3.5 inline mr-1" />
                We noticed you mentioned these technologies. Add them to your watchlist?
              </p>
              <button onClick={() => setShowSuggestions(false)} className="text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {suggestedTechs.map((tech: string) => (
                <button
                  key={tech}
                  onClick={() => handleSuggestionClick(tech)}
                  className="text-xs font-mono px-2.5 py-1 rounded-md bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 transition-colors"
                >
                  + {tech}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Add form */}
        {showAddForm && (
          <div className="mb-4 p-4 rounded-lg border border-acid/20 bg-acid/5 animate-fade-in">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">
                  Display Name
                </label>
                <input
                  type="text"
                  value={newDisplayName}
                  onChange={(e) => setNewDisplayName(e.target.value)}
                  placeholder="e.g. Apache Tomcat"
                  className="input-base w-full"
                />
              </div>
              <div>
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">
                  CPE String{" "}
                  <a
                    href="https://nvd.nist.gov/products/cpe"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-acid hover:underline inline-flex items-center gap-0.5"
                  >
                    What is this? <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                </label>
                <input
                  type="text"
                  value={newCpeString}
                  onChange={(e) => setNewCpeString(e.target.value)}
                  placeholder="e.g. cpe:2.3:a:apache:tomcat"
                  className="input-base w-full font-mono text-xs"
                />
              </div>
            </div>
            <div className="flex items-center gap-3 mt-3">
              <div>
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">
                  Criticality
                </label>
                <select
                  value={newCriticality}
                  onChange={(e) => setNewCriticality(e.target.value)}
                  className="input-base text-xs"
                >
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
              <div className="flex gap-2 mt-5">
                <button
                  onClick={handleAdd}
                  disabled={adding || !newDisplayName.trim()}
                  className="btn-primary text-xs"
                >
                  {adding ? "Adding..." : "Add"}
                </button>
                <button
                  onClick={() => { setShowAddForm(false); setAddError(""); }}
                  className="btn-ghost text-xs"
                >
                  Cancel
                </button>
              </div>
            </div>
            {addError && (
              <p className="text-xs text-red-400 mt-2">{addError}</p>
            )}
          </div>
        )}

        {/* Watchlist items */}
        {watchlist.length > 0 ? (
          <div className="space-y-2">
            {watchlist.map((item) => (
              <div
                key={item.id}
                className="flex items-center justify-between gap-3 p-3 rounded-lg border border-l-border dark:border-border hover:border-l-muted dark:hover:border-muted transition-colors"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className="text-sm font-medium text-l-text dark:text-gray-200">
                    {item.display_name}
                  </span>
                  <span className="text-[11px] font-mono text-l-sub dark:text-gray-500 truncate hidden sm:inline">
                    {item.cpe_string}
                  </span>
                  <CriticalityBadge criticality={item.criticality} />
                </div>
                <button
                  onClick={() => handleRemove(item.id)}
                  className="text-l-sub dark:text-gray-600 hover:text-red-400 transition-colors shrink-0"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-6 text-sm text-l-sub dark:text-gray-500">
            <Cpu className="h-8 w-8 mx-auto mb-2 text-l-muted dark:text-muted" />
            No technologies in your watchlist yet. Add your stack to start monitoring.
          </div>
        )}
      </div>

      {/* ══════════════════════════════════════════════════════════════ */}
      {/* 3. YOUR CVEs CARD                                            */}
      {/* ══════════════════════════════════════════════════════════════ */}
      <div className="card p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="h-5 w-5 text-amber-400" />
          <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
            Your CVEs
          </h2>
          {matchTotal > 0 && (
            <span className="text-xs font-mono text-l-sub dark:text-gray-500">
              ({matchTotal} matching)
            </span>
          )}
        </div>

        {matchedCVEs.length > 0 ? (
          <>
            <div className="space-y-2">
              {matchedCVEs.map((cve) => {
                const colors = priorityColor(cve.priority_label);
                return (
                  <Link
                    key={cve.cve_id}
                    href={`/cve/${cve.cve_id}`}
                    className="card card-hover p-3 flex items-center justify-between gap-3 block"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-mono text-sm text-acid font-medium shrink-0">
                        {cve.cve_id}
                      </span>
                      <span
                        className={cn(
                          "badge text-[10px] py-0.5 shrink-0",
                          colors.bg,
                          colors.border,
                          colors.text
                        )}
                      >
                        {cve.priority_label}
                      </span>
                      <span className="text-xs font-mono text-l-sub dark:text-gray-500">
                        KRS {cve.priority_score}
                      </span>
                      <span className="text-xs text-l-sub dark:text-gray-500 truncate hidden sm:inline">
                        {cve.description?.slice(0, 80)}…
                      </span>
                    </div>
                    <ArrowRight className="h-3.5 w-3.5 text-l-sub dark:text-gray-600 shrink-0" />
                  </Link>
                );
              })}
            </div>
            {matchedCVEs.length < matchTotal && (
              <button onClick={handleLoadMoreCVEs} className="btn-ghost text-xs mx-auto block mt-3">
                Load more →
              </button>
            )}
          </>
        ) : hasWatchlist ? (
          <div className="text-center py-6 text-sm text-l-sub dark:text-gray-500">
            No CVEs match your stack right now. Add more technologies to your watchlist.
          </div>
        ) : (
          <div className="text-center py-6 text-sm text-l-sub dark:text-gray-500">
            Add technologies to your watchlist to see matching CVEs.
          </div>
        )}
      </div>

      {/* ══════════════════════════════════════════════════════════════ */}
      {/* 4. RECENT BOOKMARKS                                          */}
      {/* ══════════════════════════════════════════════════════════════ */}
      <BookmarksSection userId={user?.id} />

      {/* ══════════════════════════════════════════════════════════════ */}
      {/* 5. DIGEST SETTINGS CARD                                      */}
      {/* ══════════════════════════════════════════════════════════════ */}
      <div className="card p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Mail className="h-5 w-5 text-blue-400" />
          <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
            Daily Digest
          </h2>
        </div>

        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="text-sm text-l-text dark:text-gray-200">Daily digest email</span>
              <button
                onClick={handleDigestToggle}
                className={cn(
                  "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                  digestEnabled ? "bg-acid" : "bg-l-muted dark:bg-muted"
                )}
              >
                <span
                  className={cn(
                    "inline-block h-4 w-4 rounded-full bg-white transition-transform",
                    digestEnabled ? "translate-x-6" : "translate-x-1"
                  )}
                />
              </button>
            </div>
            <p className="text-xs text-l-sub dark:text-gray-500 mt-1 flex items-center gap-1">
              <Info className="h-3 w-3" />
              Sent daily at 8:00 AM UTC
            </p>
          </div>
          <button
            onClick={handleTestDigest}
            disabled={sendingTest}
            className="btn-ghost text-xs flex items-center gap-1.5 border border-l-border dark:border-border"
          >
            <Send className={cn("h-3.5 w-3.5", sendingTest && "animate-pulse")} />
            {sendingTest ? "Sending..." : testSent ? "Sent ✓" : "Send Test Digest"}
          </button>
        </div>
      </div>

      <div className="mt-12" />
      <Footer />
      <CreateOrgModal open={showCreateOrg} onClose={() => setShowCreateOrg(false)} />
    </div>
  );
}

/* ── Bookmarks sub-component (kept from original) ── */
function BookmarksSection({ userId }: { userId?: string }) {
  const [bookmarks, setBookmarks] = useState<Array<{
    cve_id: string;
    note: string | null;
    created_at: string;
    cve_data?: { priority_score: number; priority_label: string; description: string } | null;
  }>>([]);

  useEffect(() => {
    if (!userId) return;
    const fetchBookmarks = async () => {
      try {
        const res = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/bookmarks/${userId}`
        );
        if (res.ok) {
          const data = await res.json();
          setBookmarks(data.slice(0, 5));
        }
      } catch { /* silent */ }
    };
    fetchBookmarks();
  }, [userId]);

  return (
    <div className="card p-6 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Bookmark className="h-5 w-5 text-acid" />
          <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
            Recent Bookmarks
          </h2>
        </div>
        {bookmarks.length > 0 && (
          <Link href="/bookmarks" className="text-xs font-mono text-acid hover:text-acid-dim transition-colors">
            View all →
          </Link>
        )}
      </div>

      {bookmarks.length > 0 ? (
        <div className="space-y-2">
          {bookmarks.map((bm) => {
            const colors = bm.cve_data ? priorityColor(bm.cve_data.priority_label) : null;
            return (
              <Link
                key={bm.cve_id}
                href={`/cve/${bm.cve_id}`}
                className="card card-hover p-3 flex items-center justify-between gap-3 block"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className="font-mono text-sm text-acid font-medium shrink-0">{bm.cve_id}</span>
                  {colors && (
                    <span className={cn("badge text-[10px] py-0.5 shrink-0", colors.bg, colors.border, colors.text)}>
                      {bm.cve_data!.priority_label}
                    </span>
                  )}
                  {bm.note && (
                    <span className="text-xs text-l-sub dark:text-gray-500 truncate">— {bm.note}</span>
                  )}
                </div>
                <ArrowRight className="h-3.5 w-3.5 text-l-sub dark:text-gray-600 shrink-0" />
              </Link>
            );
          })}
        </div>
      ) : (
        <div className="text-center py-4 text-sm text-l-sub dark:text-gray-500">
          No bookmarks yet.{" "}
          <Link href="/" className="text-acid hover:underline">Browse the feed</Link>{" "}
          to start tracking CVEs.
        </div>
      )}
    </div>
  );
}
