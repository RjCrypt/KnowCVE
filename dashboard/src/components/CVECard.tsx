"use client";

import Link from "next/link";
import { ShieldAlert, GitBranch, TrendingUp, Terminal } from "lucide-react";
import type { ProcessedCVE } from "@/types/cve";
import {
  cn,
  priorityColor,
  cvssColor,
  epssPercent,
  formatDateRelative,
} from "@/lib/utils";

/* ── Category chip config ──────────────────────────── */

const CATEGORY_CHIP: Record<string, { label: string; icon: string; cls: string }> = {
  ACTIVELY_EXPLOITED: {
    label: "Active",
    icon: "🔴",
    cls: "bg-red-500/15 border-red-500/30 text-red-400",
  },
  TRENDING: {
    label: "Trending",
    icon: "🔥",
    cls: "bg-orange-500/15 border-orange-500/30 text-orange-400",
  },
  JUST_DROPPED: {
    label: "New",
    icon: "⚡",
    cls: "bg-emerald-500/15 border-emerald-500/30 text-emerald-400",
  },
  HIGH_EXPLOITABILITY: {
    label: "Exploitable",
    icon: "🎯",
    cls: "bg-purple-500/15 border-purple-500/30 text-purple-400",
  },
  NO_AUTH_REQUIRED: {
    label: "No Auth",
    icon: "🔓",
    cls: "bg-amber-500/15 border-amber-500/30 text-amber-400",
  },
};

interface CVECardProps {
  cve: ProcessedCVE;
  index?: number;
}

export default function CVECard({ cve, index = 0 }: CVECardProps) {
  const colors = priorityColor(cve.priority_label);

  const summary =
    cve.ai_explanation?.summary || cve.description || "No description available.";

  const tags = cve.ai_explanation?.tags ?? [];
  const affectedTech = cve.ai_explanation?.affected_tech ?? [];
  const firstTech = affectedTech[0] || null;
  const categories = cve.categories || [];

  // Trend indicators
  const enrichment = cve.enrichment;
  const epssRising = enrichment?.epss_trend === "rising";
  const scannerRising = enrichment?.scanner_trend === "rising" || enrichment?.scanner_trend === "new";
  const hasTrend = epssRising || scannerRising;

  // EPSS change display
  const epssDelta = enrichment?.previous_epss_score
    ? enrichment.epss_score - enrichment.previous_epss_score
    : 0;

  return (
    <Link
      href={`/cve/${cve.cve_id}`}
      className={cn(
        "card card-hover block overflow-hidden animate-slide-up",
      )}
      style={{ animationDelay: `${index * 50}ms` }}
    >
      {/* Top priority bar */}
      <div className="h-0.5 relative bg-l-border dark:bg-border">
        <div
          className={cn("h-full transition-all duration-700", colors.bar)}
          style={{ width: `${cve.priority_score}%` }}
        />
      </div>

      <div className="p-4">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3 mb-2">
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            <span className="font-mono font-medium text-acid text-sm shrink-0">
              {cve.cve_id}
            </span>
            {cve.cve_id.toUpperCase().startsWith("GHSA-") && (
              <span className="badge bg-purple-500/10 border-purple-500/30 text-purple-400 text-[10px] py-0 px-1.5 flex items-center gap-1">
                <ShieldAlert className="h-2.5 w-2.5" /> GHSA
              </span>
            )}


            {/* KEV badge */}
            {cve.enrichment.in_kev && (
              <span className="badge bg-red-500/15 border-red-500/30 text-red-400 text-[10px] py-0.5">
                <ShieldAlert className="h-3 w-3" />
                KEV
              </span>
            )}

            {/* PoC badge */}
            {cve.enrichment.has_poc && (
              <span className="badge bg-amber-500/15 border-amber-500/30 text-amber-400 text-[10px] py-0.5">
                <GitBranch className="h-3 w-3" />
                PoC
              </span>
            )}

            {/* GreyNoise scanning badge */}
            {cve.enrichment.greynoise_scanner_count > 0 && (
              <span className="badge bg-orange-500/15 border-orange-500/30 text-orange-400 text-[10px] py-0.5">
                🔥 {cve.enrichment.greynoise_scanner_count} scanning
              </span>
            )}

            {/* Nuclei badge */}
            {cve.enrichment.has_nuclei_template && (
              <a
                href={cve.enrichment.nuclei_template_url || "#"}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono
                           bg-purple-500/15 text-purple-400 border border-purple-500/30
                           hover:bg-purple-500/25 transition-colors"
              >
                <Terminal className="w-3 h-3" />
                Nuclei
              </a>
            )}
          </div>

          {/* Priority badge */}
          <span
            className={cn(
              "badge shrink-0 text-[11px] py-0.5",
              colors.bg,
              colors.border,
              colors.text
            )}
          >
            KRS {cve.priority_score} ·{" "}
            <span className="hidden sm:inline">{cve.priority_label}</span>
          </span>
        </div>

        {/* Category chips */}
        {categories.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-2">
            {categories.map((cat) => {
              const chip = CATEGORY_CHIP[cat];
              if (!chip) return null;
              return (
                <span
                  key={cat}
                  className={cn("badge text-[10px] py-0.5", chip.cls)}
                >
                  {chip.icon} {chip.label}
                </span>
              );
            })}
          </div>
        )}

        {/* Summary */}
        <p className="text-sm text-l-sub dark:text-gray-400 line-clamp-2 mb-3 leading-relaxed">
          {summary}
        </p>

        {/* Tags */}
        {tags.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-3">
            {tags.slice(0, 5).map((tag) => (
              <span
                key={tag}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-l-panel dark:bg-panel text-l-sub dark:text-gray-500 border border-l-border dark:border-border"
              >
                {tag}
              </span>
            ))}
          </div>
        )}

        {/* Trend indicators */}
        {hasTrend && (
          <div className="flex flex-wrap items-center gap-3 mb-3 text-[11px] font-mono">
            {epssRising && epssDelta > 0 && (
              <span className="flex items-center gap-1 text-orange-400">
                <TrendingUp className="h-3 w-3" />
                ↑ EPSS +{(epssDelta * 100).toFixed(1)}%
              </span>
            )}
            {scannerRising && enrichment.greynoise_scanner_count > 0 && (
              <span className="flex items-center gap-1 text-orange-400">
                <TrendingUp className="h-3 w-3" />
                ↑ {enrichment.greynoise_scanner_count} IPs scanning
              </span>
            )}
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center gap-3 text-[11px] font-mono text-l-sub dark:text-gray-500">
          <span className={cvssColor(cve.cvss_score)}>
            CVSS {cve.cvss_score.toFixed(1)}
          </span>
          {cve.enrichment.epss_score > 0 && (
            <span>EPSS {epssPercent(cve.enrichment.epss_score)}</span>
          )}
          {firstTech && <span className="hidden sm:inline">{firstTech}</span>}
          <span className="ml-auto">
            {formatDateRelative(cve.published_date)}
          </span>
        </div>
      </div>
    </Link>
  );
}
