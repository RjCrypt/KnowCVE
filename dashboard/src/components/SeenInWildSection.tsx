"use client";

import { useEffect, useState } from "react";
import { Eye, Send, CheckCircle2 } from "lucide-react";
import { getWildReports, reportSeenInWild } from "@/lib/api";
import type { WildReportSummary } from "@/types/cve";
import { cn, formatDateRelative } from "@/lib/utils";

interface Props {
  cveId: string;
}

export default function SeenInWildSection({ cveId }: Props) {
  const [wildData, setWildData] = useState<WildReportSummary | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const [context, setContext] = useState("");
  const [loading, setLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    getWildReports(cveId)
      .then(setWildData)
      .catch(() => {});
  }, [cveId]);

  const handleSubmit = async () => {
    setLoading(true);
    setMessage(null);
    try {
      const res = await reportSeenInWild(cveId, context || undefined);
      setMessage(res.message);
      setSubmitted(true);
      setShowForm(false);
      // Refresh count
      if (!res.duplicate && wildData) {
        setWildData({
          ...wildData,
          report_count: wildData.report_count + 1,
          last_reported_at: new Date().toISOString(),
        });
      }
    } catch {
      setMessage("Failed to submit report. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const count = wildData?.report_count ?? 0;

  return (
    <div className="mt-4 p-4 rounded-lg border border-orange-500/20 bg-orange-500/5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-mono text-sm font-medium text-orange-400 flex items-center gap-2 uppercase tracking-widest">
          <Eye className="w-4 h-4" />
          Seen in Wild
        </h3>
        {count > 0 && (
          <span className="text-xs font-mono text-orange-400">
            {formatDateRelative(wildData?.last_reported_at ?? null)}
          </span>
        )}
      </div>

      {/* Report count */}
      {count > 0 ? (
        <p className="text-sm text-l-sub dark:text-gray-300 mb-3">
          <span className="font-bold text-orange-400">👁 {count}</span>{" "}
          researcher{count > 1 ? "s" : ""} reported seeing this exploited in
          the wild
        </p>
      ) : (
        <p className="text-sm text-l-sub dark:text-gray-400 mb-3">
          No wild exploitation reports yet
        </p>
      )}

      {/* Success/duplicate message */}
      {message && (
        <div className="flex items-center gap-2 mb-3 text-sm">
          <CheckCircle2 className="h-4 w-4 text-acid shrink-0" />
          <span className="text-l-sub dark:text-gray-400">{message}</span>
        </div>
      )}

      {/* Report button */}
      {!submitted && !showForm && (
        <button
          onClick={() => setShowForm(true)}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono
                     bg-orange-500/10 text-orange-400 border border-orange-500/30
                     hover:bg-orange-500/20 transition-colors"
        >
          <Eye className="w-3.5 h-3.5" />
          Report Seen in Wild
        </button>
      )}

      {/* Report form */}
      {showForm && (
        <div className="space-y-3 animate-fade-in">
          <div>
            <label className="block text-xs font-mono text-l-sub dark:text-gray-500 mb-1">
              Where did you see this? (optional, public)
            </label>
            <textarea
              value={context}
              onChange={(e) => setContext(e.target.value.slice(0, 200))}
              placeholder="e.g. during web app pentest, ransomware dropper, bug bounty engagement"
              className="input-base w-full h-20 resize-none text-xs"
              maxLength={200}
            />
            <div className="text-right text-[10px] font-mono text-l-sub dark:text-gray-600 mt-1">
              {context.length}/200
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleSubmit}
              disabled={loading}
              className={cn(
                "inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono",
                "bg-orange-500/15 text-orange-400 border border-orange-500/30",
                "hover:bg-orange-500/25 transition-colors",
                loading && "opacity-60"
              )}
            >
              <Send className="w-3.5 h-3.5" />
              {loading ? "Submitting…" : "Submit Report"}
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="text-xs font-mono text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Disclaimer */}
      <p className="text-[10px] font-mono text-l-sub dark:text-gray-600 mt-3">
        Reports are anonymous and public. One per CVE per day.
      </p>
    </div>
  );
}
