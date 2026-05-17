"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import {
  Bookmark,
  Trash2,
  Download,
  ArrowUpDown,
  Search,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn, priorityColor, formatDate } from "@/lib/utils";
import Footer from "@/components/layout/Footer";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface BookmarkItem {
  id: string;
  user_id: string;
  cve_id: string;
  note: string | null;
  created_at: string;
  updated_at: string;
  cve_data?: {
    cve_id: string;
    description: string;
    priority_score: number;
    priority_label: string;
    cvss_score: number;
    published_date: string | null;
  } | null;
}

type SortMode = "newest" | "priority";

export default function BookmarksPage() {
  const { user } = useAuth();
  const [bookmarks, setBookmarks] = useState<BookmarkItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [sort, setSort] = useState<SortMode>("newest");
  const [editingNote, setEditingNote] = useState<string | null>(null);
  const [noteValue, setNoteValue] = useState("");

  const fetchBookmarks = useCallback(async () => {
    if (!user) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/bookmarks/${user.id}`);
      if (res.ok) {
        const data = await res.json();
        setBookmarks(data);
      }
    } catch (err) {
      console.error("Failed to fetch bookmarks:", err);
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    fetchBookmarks();
  }, [fetchBookmarks]);

  const sortedBookmarks = [...bookmarks].sort((a, b) => {
    if (sort === "priority") {
      return (
        (b.cve_data?.priority_score ?? 0) -
        (a.cve_data?.priority_score ?? 0)
      );
    }
    return (
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
  });

  const handleDelete = async (cveId: string) => {
    if (!user) return;
    // Optimistic remove
    setBookmarks((prev) => prev.filter((b) => b.cve_id !== cveId));
    try {
      await fetch(`${API_BASE}/api/bookmarks/${user.id}/${cveId}`, {
        method: "DELETE",
      });
    } catch {
      fetchBookmarks(); // Revert
    }
  };

  const handleNoteBlur = async (cveId: string) => {
    if (!user) return;
    setEditingNote(null);
    try {
      await fetch(`${API_BASE}/api/bookmarks/${user.id}/${cveId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note: noteValue || null }),
      });
      setBookmarks((prev) =>
        prev.map((b) =>
          b.cve_id === cveId ? { ...b, note: noteValue || null } : b
        )
      );
    } catch {
      // Silently fail
    }
  };

  const exportCSV = () => {
    const headers = [
      "CVE ID",
      "Priority",
      "Score",
      "CVSS",
      "Note",
      "Bookmarked At",
    ];
    const rows = bookmarks.map((b) => [
      b.cve_id,
      b.cve_data?.priority_label || "N/A",
      String(b.cve_data?.priority_score ?? "N/A"),
      String(b.cve_data?.cvss_score ?? "N/A"),
      (b.note || "").replace(/"/g, '""'),
      new Date(b.created_at).toISOString(),
    ]);

    const csv =
      [headers.join(","), ...rows.map((r) => r.map((c) => `"${c}"`).join(","))].join(
        "\n"
      );

    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `knowcve-bookmarks-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 py-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-acid/10 border border-acid/20">
            <Bookmark className="h-6 w-6 text-acid" />
          </div>
          <div>
            <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
              Bookmarks
            </h1>
            <p className="text-sm text-l-sub dark:text-gray-400">
              {bookmarks.length} saved CVE{bookmarks.length !== 1 ? "s" : ""}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Sort toggle */}
          <button
            onClick={() =>
              setSort((s) => (s === "newest" ? "priority" : "newest"))
            }
            className="btn-ghost flex items-center gap-1.5 text-xs font-mono border border-l-border dark:border-border rounded-lg px-3 py-1.5"
          >
            <ArrowUpDown className="h-3.5 w-3.5" />
            {sort === "newest" ? "Newest" : "Priority"}
          </button>

          {/* CSV Export */}
          {bookmarks.length > 0 && (
            <button
              onClick={exportCSV}
              className="btn-ghost flex items-center gap-1.5 text-xs font-mono border border-l-border dark:border-border rounded-lg px-3 py-1.5"
            >
              <Download className="h-3.5 w-3.5" />
              CSV
            </button>
          )}
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="card p-4">
              <div className="skeleton h-4 w-32 mb-2" />
              <div className="skeleton h-3 w-full mb-2" />
              <div className="skeleton h-3 w-2/3" />
            </div>
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && bookmarks.length === 0 && (
        <div className="card p-12 text-center">
          <Bookmark className="h-12 w-12 mx-auto text-l-muted dark:text-muted mb-4" />
          <h2 className="font-display font-bold text-lg text-l-text dark:text-gray-200 mb-2">
            No bookmarks yet
          </h2>
          <p className="text-sm text-l-sub dark:text-gray-500 max-w-sm mx-auto mb-6">
            Browse the CVE feed and click the bookmark icon on any vulnerability
            to track it here. Add notes for your team.
          </p>
          <Link href="/" className="btn-primary text-xs inline-flex">
            Browse Feed
          </Link>
        </div>
      )}

      {/* Bookmark list */}
      {!loading && sortedBookmarks.length > 0 && (
        <div className="space-y-2">
          {sortedBookmarks.map((bm) => {
            const colors = bm.cve_data
              ? priorityColor(bm.cve_data.priority_label)
              : null;

            return (
              <div
                key={bm.id}
                className="card p-4 hover:border-l-muted dark:hover:border-muted transition-colors"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <Link
                        href={`/cve/${bm.cve_id}`}
                        className="font-mono font-medium text-acid text-sm hover:underline"
                      >
                        {bm.cve_id}
                      </Link>
                      {colors && (
                        <span
                          className={cn(
                            "badge text-[10px] py-0.5",
                            colors.bg,
                            colors.border,
                            colors.text
                          )}
                        >
                          KRS {bm.cve_data!.priority_score} ·{" "}
                          {bm.cve_data!.priority_label}
                        </span>
                      )}
                    </div>

                    {bm.cve_data?.description && (
                      <p className="text-xs text-l-sub dark:text-gray-400 line-clamp-1 mb-2">
                        {bm.cve_data.description}
                      </p>
                    )}

                    {/* Inline-editable note */}
                    {editingNote === bm.cve_id ? (
                      <input
                        type="text"
                        value={noteValue}
                        onChange={(e) => setNoteValue(e.target.value)}
                        onBlur={() => handleNoteBlur(bm.cve_id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") handleNoteBlur(bm.cve_id);
                          if (e.key === "Escape") setEditingNote(null);
                        }}
                        autoFocus
                        placeholder="Add a note..."
                        className="input-base text-xs w-full max-w-md"
                        maxLength={500}
                      />
                    ) : (
                      <button
                        onClick={() => {
                          setEditingNote(bm.cve_id);
                          setNoteValue(bm.note || "");
                        }}
                        className="text-xs text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300 transition-colors"
                      >
                        {bm.note || (
                          <span className="italic opacity-50">
                            Click to add note...
                          </span>
                        )}
                      </button>
                    )}

                    <div className="text-[10px] font-mono text-l-sub dark:text-gray-600 mt-1">
                      Bookmarked {formatDate(bm.created_at)}
                    </div>
                  </div>

                  {/* Delete button */}
                  <button
                    onClick={() => handleDelete(bm.cve_id)}
                    className="p-1.5 rounded-lg text-l-sub dark:text-gray-600 hover:text-red-400 hover:bg-red-500/10 transition-colors shrink-0"
                    aria-label="Remove bookmark"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="mt-12" />
      <Footer />
    </div>
  );
}
