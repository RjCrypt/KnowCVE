"use client";

import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

interface SLATimerProps {
  slaDueAt: string | null;
  status: string;
  className?: string;
  compact?: boolean;
}

function formatDuration(ms: number): string {
  const abs = Math.abs(ms);
  const days = Math.floor(abs / (1000 * 60 * 60 * 24));
  const hours = Math.floor((abs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((abs % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((abs % (1000 * 60)) / 1000);

  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
  return `${minutes}m ${seconds}s`;
}

export default function SLATimer({ slaDueAt, status, className, compact = false }: SLATimerProps) {
  const [remaining, setRemaining] = useState<number | null>(null);

  useEffect(() => {
    if (!slaDueAt || status === "mitigated" || status === "wont_fix") {
      setRemaining(null);
      return;
    }

    const compute = () => {
      const due = new Date(slaDueAt).getTime();
      const now = Date.now();
      setRemaining(due - now);
    };

    compute();
    const id = setInterval(compute, 1000); // 1-second updates
    return () => clearInterval(id);
  }, [slaDueAt, status]);

  // No SLA set
  if (remaining === null) {
    if (status === "mitigated") {
      return (
        <span className={cn("text-[10px] font-mono text-emerald-400", className)}>
          ✓ Resolved
        </span>
      );
    }
    if (status === "wont_fix") {
      return (
        <span className={cn("text-[10px] font-mono text-l-sub dark:text-gray-600", className)}>
          Won&apos;t Fix
        </span>
      );
    }
    return (
      <span className={cn("text-[10px] font-mono text-l-sub dark:text-gray-500", className)}>
        No SLA
      </span>
    );
  }

  const isOverdue = remaining < 0;
  const totalMs = slaDueAt
    ? new Date(slaDueAt).getTime() - (new Date(slaDueAt).getTime() - (remaining < 0 ? 0 : remaining))
    : 0;
  const percentage = totalMs > 0 ? Math.max(0, remaining) / totalMs : 0;

  // Color states
  let colorClass: string;
  let pulseClass = "";
  let label = "";

  if (isOverdue) {
    colorClass = "text-red-500";
    pulseClass = "animate-pulse";
    label = `OVERDUE +${formatDuration(remaining)}`;
  } else if (percentage < 0.25) {
    colorClass = "text-red-400";
    pulseClass = "animate-sla-pulse";
    label = formatDuration(remaining);
  } else if (percentage < 0.5) {
    colorClass = "text-amber-400";
    label = formatDuration(remaining);
  } else {
    colorClass = "text-emerald-400";
    label = formatDuration(remaining);
  }

  if (compact) {
    return (
      <span
        className={cn(
          "font-mono text-[10px] font-medium transition-colors",
          colorClass,
          pulseClass,
          className
        )}
      >
        {label}
      </span>
    );
  }

  return (
    <div
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 border text-[10px] font-mono font-medium transition-all",
        isOverdue
          ? "bg-red-500/10 border-red-500/30 shadow-sm shadow-red-500/10"
          : percentage < 0.25
          ? "bg-red-500/5 border-red-500/20"
          : percentage < 0.5
          ? "bg-amber-500/5 border-amber-500/20"
          : "bg-emerald-500/5 border-emerald-500/20",
        colorClass,
        pulseClass,
        className
      )}
    >
      {/* Tiny clock icon */}
      <svg
        className={cn("h-2.5 w-2.5 shrink-0", isOverdue && "animate-spin")}
        style={isOverdue ? { animationDuration: "3s" } : undefined}
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
      >
        <circle cx="8" cy="8" r="6.5" />
        <path d="M8 4v4l2.5 1.5" strokeLinecap="round" />
      </svg>
      {label}
    </div>
  );
}
