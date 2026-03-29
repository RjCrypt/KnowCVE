"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Shield } from "lucide-react";
import { getCVEs } from "@/lib/api";
import type { ProcessedCVE } from "@/types/cve";
import { cn, cvssColor, epssPercent, formatDateRelative } from "@/lib/utils";
import Link from "next/link";

export default function ZeroDayPage() {
  const [cves, setCves] = useState<ProcessedCVE[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      try {
        const data = await getCVEs({ page_size: 100 });
        // Filter: empty weaknesses (CWEs), priority >= 60, published < 48h
        const cutoff = new Date(Date.now() - 48 * 60 * 60 * 1000);
        const filtered = data.filter((c) => {
          const hasNoCWE = !c.weaknesses || c.weaknesses.length === 0 ||
            (c.weaknesses.length === 1 && c.weaknesses[0] === "NVD-CWE-noinfo");
          const isHighPriority = c.priority_score >= 60;
          const isRecent = c.published_date ? new Date(c.published_date) >= cutoff : false;
          return hasNoCWE && isHighPriority && isRecent;
        });
        setCves(filtered);
      } catch (e) {
        console.error("Failed to fetch zero-day candidates:", e);
      } finally {
        setLoading(false);
      }
    };
    fetch();
    const id = setInterval(fetch, 300_000); // 5 minutes
    return () => clearInterval(id);
  }, []);

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 space-y-6">
      {/* Header */}
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20">
            <AlertTriangle className="h-6 w-6 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
              Zero-Day Radar
            </h1>
            <p className="text-sm text-l-sub dark:text-gray-400">
              High-priority CVEs with no assigned CWE — potential zero-days or newly discovered
            </p>
          </div>
        </div>
      </div>

      {/* Disclaimer banner */}
      <div className="card p-4 border-amber-500/30 bg-amber-500/5">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm font-medium text-amber-400">
              ⚠️ Unconfirmed — Intelligence gathered before or during official CVE assignment
            </p>
            <p className="text-xs text-l-sub dark:text-gray-400 mt-1">
              These CVEs lack CWE classification and were published within the last 48 hours with high priority scores.
              Verify independently before taking action.
            </p>
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

      {/* Empty state */}
      {!loading && cves.length === 0 && (
        <div className="card p-12 text-center">
          <p className="text-4xl mb-3">🔍</p>
          <p className="text-lg font-medium text-l-text dark:text-gray-200">
            No zero-day candidates detected
          </p>
          <p className="text-sm text-l-sub dark:text-gray-500 mt-1">
            No high-priority CVEs without CWE classification in the last 48 hours.
          </p>
        </div>
      )}

      {/* CVE cards */}
      {!loading && cves.length > 0 && (
        <div className="space-y-3">
          {cves.map((cve, i) => (
            <ZeroDayCard key={cve.cve_id} cve={cve} index={i} />
          ))}
        </div>
      )}

      {/* Educational section */}
      <div className="card p-6 mt-8">
        <h2 className="text-lg font-display font-bold text-l-text dark:text-gray-100 mb-3 flex items-center gap-2">
          <Shield className="h-5 w-5 text-amber-400" />
          What is a Zero-Day?
        </h2>
        <div className="space-y-2 text-sm text-l-sub dark:text-gray-400 leading-relaxed">
          <p>
            A <strong className="text-l-text dark:text-gray-200">zero-day vulnerability</strong> is
            a security flaw discovered by attackers before the software vendor is aware of it.
            The term &ldquo;zero-day&rdquo; refers to the fact that developers have had zero days
            to create a patch.
          </p>
          <p>
            This radar identifies CVEs that are <strong className="text-l-text dark:text-gray-200">recently published</strong>,
            have <strong className="text-l-text dark:text-gray-200">high priority scores</strong>,
            and lack <strong className="text-l-text dark:text-gray-200">CWE classification</strong> —
            indicators that the vulnerability is still being analyzed and may represent a previously
            unknown attack vector.
          </p>
          <p className="text-amber-400">
            Always verify findings against official sources (NVD, vendor advisories) before taking action.
          </p>
        </div>
      </div>
    </div>
  );
}

function ZeroDayCard({ cve, index }: { cve: ProcessedCVE; index: number }) {
  const summary = cve.ai_explanation?.summary || cve.description || "No description available.";

  return (
    <Link
      href={`/cve/${cve.cve_id}`}
      className="card card-hover block overflow-hidden animate-slide-up border-amber-500/20 hover:border-amber-500/40"
      style={{ animationDelay: `${index * 60}ms` }}
    >
      {/* Amber top bar */}
      <div className="h-1 bg-gradient-to-r from-amber-500 via-yellow-500 to-amber-600" />

      <div className="p-5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono font-bold text-amber-400 text-sm">
              {cve.cve_id}
            </span>

            {/* UNCONFIRMED badge */}
            <span className="badge bg-amber-500/15 border-amber-500/30 text-amber-400 text-[10px] py-0.5">
              <AlertTriangle className="h-3 w-3" />
              UNCONFIRMED
            </span>

            {/* Priority badge */}
            <span className={cn(
              "badge text-[10px] py-0.5",
              cve.priority_label === "CRITICAL" ? "bg-red-500/15 border-red-500/30 text-red-400" :
              cve.priority_label === "HIGH" ? "bg-orange-500/15 border-orange-500/30 text-orange-400" :
              "bg-amber-500/15 border-amber-500/30 text-amber-400"
            )}>
              {cve.priority_score} {cve.priority_label}
            </span>

            {/* KEV badge */}
            {cve.enrichment.in_kev && (
              <span className="badge bg-red-500/15 border-red-500/30 text-red-400 text-[10px] py-0.5">
                KEV
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
          {cve.enrichment.greynoise_scanner_count > 0 && (
            <span className="text-orange-400">
              🔥 {cve.enrichment.greynoise_scanner_count} scanning
            </span>
          )}
          <span className="ml-auto">
            {formatDateRelative(cve.published_date)}
          </span>
        </div>
      </div>
    </Link>
  );
}
