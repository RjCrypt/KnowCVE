"use client";

import { Search, X } from "lucide-react";
import type { FilterState, PriorityLabel } from "@/types/cve";
import { cn, priorityColor } from "@/lib/utils";

const PRIORITIES: PriorityLabel[] = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

interface FilterBarProps {
  filters: FilterState;
  onChange: (filters: FilterState) => void;
  resultCount: number;
}

export default function FilterBar({ filters, onChange, resultCount }: FilterBarProps) {
  const update = (partial: Partial<FilterState>) =>
    onChange({ ...filters, ...partial });

  return (
    <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
      {/* Search */}
      <div className="relative w-full sm:w-64">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-l-sub dark:text-gray-500" />
        <input
          type="text"
          placeholder="Search CVE ID, description…"
          value={filters.search}
          onChange={(e) => update({ search: e.target.value })}
          className="input-base w-full pl-9 pr-8"
        />
        {filters.search && (
          <button
            onClick={() => update({ search: "" })}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Priority pills */}
      <div className="flex flex-wrap items-center gap-1.5">
        {PRIORITIES.map((p) => {
          const active = filters.priority === p;
          const colors = p !== "ALL" ? priorityColor(p) : null;
          return (
            <button
              key={p}
              onClick={() => update({ priority: p })}
              className={cn(
                "badge cursor-pointer",
                active && p === "ALL" && "bg-acid/15 border-acid/30 text-acid",
                active && colors && `${colors.bg} ${colors.border} ${colors.text}`,
                !active &&
                  "bg-transparent border-l-border dark:border-border text-l-sub dark:text-gray-500 hover:border-l-muted dark:hover:border-muted"
              )}
            >
              {p}
            </button>
          );
        })}
      </div>

      {/* Toggle chips */}
      <div className="flex items-center gap-1.5">
        <button
          onClick={() => update({ kev_only: !filters.kev_only })}
          className={cn(
            "badge cursor-pointer",
            filters.kev_only
              ? "bg-red-500/15 border-red-500/30 text-red-400"
              : "bg-transparent border-l-border dark:border-border text-l-sub dark:text-gray-500 hover:border-l-muted dark:hover:border-muted"
          )}
        >
          KEV
        </button>
        <button
          onClick={() => update({ has_poc: !filters.has_poc })}
          className={cn(
            "badge cursor-pointer",
            filters.has_poc
              ? "bg-amber-500/15 border-amber-500/30 text-amber-400"
              : "bg-transparent border-l-border dark:border-border text-l-sub dark:text-gray-500 hover:border-l-muted dark:hover:border-muted"
          )}
        >
          PoC
        </button>

        {/* Result count */}
        <span className="text-xs font-mono text-l-sub dark:text-gray-500 ml-2">
          {resultCount} result{resultCount !== 1 ? "s" : ""}
        </span>
      </div>
    </div>
  );
}
