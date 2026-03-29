"use client";

import Link from "next/link";
import { ShieldAlert, GitBranch } from "lucide-react";
import type { ProcessedCVE } from "@/types/cve";
import {
  cn,
  priorityColor,
  cvssColor,
  epssPercent,
  formatDateRelative,
} from "@/lib/utils";

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
          <div className="flex items-center gap-2 min-w-0">
            <span className="font-mono font-medium text-acid text-sm shrink-0">
              {cve.cve_id}
            </span>

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
            {cve.priority_score}{" "}
            <span className="hidden sm:inline">{cve.priority_label}</span>
          </span>
        </div>

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
