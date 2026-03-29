"use client";

import { useEffect, useState } from "react";
import { ShieldAlert, AlertTriangle, Flame } from "lucide-react";
import { getThreats } from "@/lib/api";
import type { ProcessedCVE } from "@/types/cve";
import { cn, priorityColor, cvssColor, epssPercent, formatDateRelative } from "@/lib/utils";
import Link from "next/link";

export default function ThreatsPage() {
  const [threats, setThreats] = useState<ProcessedCVE[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchThreats = async () => {
    try {
      const data = await getThreats(20);
      setThreats(data);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to fetch threats");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
    const id = setInterval(fetchThreats, 120_000); // 2 minutes
    return () => clearInterval(id);
  }, []);

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 space-y-6">
      {/* Header */}
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-red-500/10 border border-red-500/20">
            <ShieldAlert className="h-6 w-6 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
              🚨 Breaking Threats
            </h1>
            <p className="text-sm text-l-sub dark:text-gray-400">
              Actively exploited or critical severity — updated every 2 minutes
            </p>
          </div>
          {/* Live indicator */}
          <div className="ml-auto flex items-center gap-1.5 text-xs font-mono text-red-400">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
            </span>
            LIVE
          </div>
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="card p-5">
              <div className="skeleton h-4 w-32 mb-3" />
              <div className="skeleton h-3 w-full mb-2" />
              <div className="skeleton h-3 w-2/3" />
            </div>
          ))}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="card p-5 border-red-500/30 bg-red-500/5">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && threats.length === 0 && (
        <div className="card p-12 text-center">
          <p className="text-4xl mb-3">🛡️</p>
          <p className="text-lg font-medium text-l-text dark:text-gray-200">
            No breaking threats in the last 7 days
          </p>
          <p className="text-sm text-l-sub dark:text-gray-500 mt-1">
            That&apos;s good news — stay vigilant!
          </p>
        </div>
      )}

      {/* Threat cards */}
      {!loading && threats.length > 0 && (
        <div className="space-y-3">
          {threats.map((cve, i) => (
            <ThreatCard key={cve.cve_id} cve={cve} index={i} />
          ))}
        </div>
      )}
    </div>
  );
}

function ThreatCard({ cve, index }: { cve: ProcessedCVE; index: number }) {
  const summary = cve.ai_explanation?.summary || cve.description || "No description available.";

  return (
    <Link
      href={`/cve/${cve.cve_id}`}
      className="card card-hover block overflow-hidden animate-slide-up border-red-500/20 hover:border-red-500/40"
      style={{ animationDelay: `${index * 60}ms` }}
    >
      {/* Red top bar */}
      <div className="h-1 bg-gradient-to-r from-red-500 via-orange-500 to-red-600" />

      <div className="p-5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono font-bold text-red-400 text-sm">
              {cve.cve_id}
            </span>

            {/* CRITICAL badge */}
            <span className="badge bg-red-500/15 border-red-500/30 text-red-400 text-[10px] py-0.5">
              {cve.priority_score} {cve.priority_label}
            </span>

            {/* KEV badge */}
            {cve.enrichment.in_kev && (
              <span className="badge bg-red-500/15 border-red-500/30 text-red-400 text-[10px] py-0.5">
                <ShieldAlert className="h-3 w-3" />
                KEV
              </span>
            )}

            {/* GreyNoise badge */}
            {cve.enrichment.greynoise_scanner_count > 0 && (
              <span className="badge bg-orange-500/15 border-orange-500/30 text-orange-400 text-[10px] py-0.5">
                <Flame className="h-3 w-3" />
                {cve.enrichment.greynoise_scanner_count} IPs scanning
              </span>
            )}
          </div>

          {/* CVSS */}
          <span className={cn("font-mono text-sm font-bold", cvssColor(cve.cvss_score))}>
            CVSS {cve.cvss_score.toFixed(1)}
          </span>
        </div>

        {/* Summary */}
        <p className="text-sm text-l-sub dark:text-gray-300 line-clamp-3 leading-relaxed mb-3">
          {summary}
        </p>

        {/* Footer */}
        <div className="flex items-center gap-4 text-[11px] font-mono text-l-sub dark:text-gray-500">
          {cve.enrichment.epss_score > 0 && (
            <span>EPSS {epssPercent(cve.enrichment.epss_score)}</span>
          )}
          <span className="ml-auto">
            {formatDateRelative(cve.published_date)}
          </span>
        </div>
      </div>
    </Link>
  );
}
