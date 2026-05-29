"use client";

import Link from "next/link";
import { GripVertical, User } from "lucide-react";
import { cn } from "@/lib/utils";
import SLATimer from "./SLATimer";
import type { TriageItem } from "@/types/cve";

interface TriageCardProps {
  item: TriageItem;
  isDragging?: boolean;
  onSelect?: (item: TriageItem) => void;
  dragHandleProps?: Record<string, unknown>;
}

function priorityBadge(label: string) {
  const colors: Record<string, string> = {
    CRITICAL: "bg-red-500/15 border-red-500/30 text-red-400",
    HIGH: "bg-amber-500/15 border-amber-500/30 text-amber-400",
    MEDIUM: "bg-yellow-500/15 border-yellow-500/30 text-yellow-300",
    LOW: "bg-blue-500/15 border-blue-500/30 text-blue-400",
  };
  return colors[label] || colors.MEDIUM;
}

export default function TriageCard({ item, isDragging, onSelect, dragHandleProps }: TriageCardProps) {
  const cve = item.cve_data;
  const priorityLabel = cve?.priority_label || "LOW";

  return (
    <div
      {...(dragHandleProps || {})}
      className={cn(
        "card p-3 cursor-grab active:cursor-grabbing transition-all duration-150 group touch-none",
        isDragging
          ? "opacity-60 rotate-1 shadow-lg shadow-acid/10 scale-[1.02]"
          : "hover:border-l-muted dark:hover:border-muted",
        item.is_overdue && "border-red-500/30"
      )}
      onClick={() => onSelect?.(item)}
    >
      <div className="flex items-start gap-2">
        {/* Drag handle visual indicator */}
        <div
          className="hidden md:flex items-center pt-0.5 text-l-muted dark:text-muted opacity-0 group-hover:opacity-100 transition-opacity"
        >
          <GripVertical className="h-3.5 w-3.5" />
        </div>

        <div className="flex-1 min-w-0">
          {/* CVE ID + Priority Badge */}
          <div className="flex items-center gap-1.5 mb-1">
            <Link
              href={`/cve/${item.cve_id}`}
              onClick={(e) => e.stopPropagation()}
              className="font-mono text-xs text-acid font-medium hover:underline shrink-0"
            >
              {item.cve_id}
            </Link>
            <span
              className={cn(
                "inline-flex items-center rounded-md px-1.5 py-0.5 text-[9px] font-mono font-medium border",
                priorityBadge(priorityLabel)
              )}
            >
              {priorityLabel}
            </span>
            {cve?.in_kev && (
              <span className="inline-flex items-center rounded-md px-1.5 py-0.5 text-[9px] font-mono font-medium bg-red-500/10 border border-red-500/30 text-red-400">
                KEV
              </span>
            )}
          </div>

          {/* AI Summary */}
          {cve?.ai_summary && (
            <p className="text-[11px] text-l-sub dark:text-gray-500 leading-snug line-clamp-2 mb-1.5">
              {cve.ai_summary}
            </p>
          )}

          {/* Bottom row: Assignee + SLA */}
          <div className="flex items-center justify-between gap-2">
            {/* Assignee */}
            <div className="flex items-center gap-1">
              {item.assignee_avatar ? (
                <img
                  src={item.assignee_avatar}
                  alt=""
                  className="h-4 w-4 rounded-full border border-l-border dark:border-border"
                />
              ) : (
                <div className="h-4 w-4 rounded-full bg-l-panel dark:bg-panel border border-l-border dark:border-border flex items-center justify-center">
                  <User className="h-2.5 w-2.5 text-l-muted dark:text-gray-600" />
                </div>
              )}
              <span className="text-[10px] text-l-sub dark:text-gray-600 truncate max-w-[60px]">
                {item.assignee_name || "Unassigned"}
              </span>
            </div>

            {/* SLA Timer */}
            <SLATimer
              slaDueAt={item.sla_due_at}
              status={item.status}
              compact
            />
          </div>
        </div>
      </div>
    </div>
  );
}
