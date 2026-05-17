"use client";

import { useEffect, useState } from "react";
import {
  Database,
  Eye,
  ShieldAlert,
  Hash,
  Clock,
  Timer,
} from "lucide-react";
import { getStats } from "@/lib/api";
import type { StatsResponse } from "@/types/cve";
import { formatDateRelative, formatTimeUntil } from "@/lib/utils";

interface MetricCardProps {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  subtitle?: string;
  accent?: string;
  onClick?: () => void;
  clickable?: boolean;
}

function MetricCard({ icon, label, value, subtitle, accent, onClick, clickable }: MetricCardProps) {
  const Wrapper = clickable ? "button" : "div";
  return (
    <Wrapper
      className={`card px-4 py-3 animate-fade-in text-left transition-all ${
        clickable
          ? "cursor-pointer hover:ring-1 hover:ring-acid/30 hover:shadow-lg hover:shadow-acid/5 active:scale-[0.98]"
          : ""
      }`}
      onClick={onClick}
      title={clickable ? `Click to filter by ${label}` : undefined}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className={accent || "text-l-sub dark:text-gray-500"}>
          {icon}
        </span>
        <span className="text-[10px] font-mono uppercase tracking-widest text-l-sub dark:text-gray-500">
          {label}
        </span>
      </div>
      <div className="font-display font-bold text-2xl text-l-text dark:text-gray-100">
        {value}
      </div>
      {subtitle && (
        <div className="text-xs text-l-sub dark:text-gray-500 font-mono mt-0.5">
          {subtitle}
        </div>
      )}
      {clickable && (
        <div className="text-[9px] font-mono text-acid/60 mt-1">
          ▸ click to filter
        </div>
      )}
    </Wrapper>
  );
}

function SkeletonCard() {
  return (
    <div className="card px-4 py-3">
      <div className="skeleton h-3 w-20 mb-2" />
      <div className="skeleton h-8 w-16 mb-1" />
      <div className="skeleton h-3 w-24" />
    </div>
  );
}

/** Dispatches a custom event that CVEFeed listens for to set the priority filter */
function scrollToFeedWithPriority(priority: string) {
  window.dispatchEvent(
    new CustomEvent("knowcve:set-priority", { detail: priority })
  );
}

export default function StatsBar() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [error, setError] = useState(false);

  const fetchStats = async () => {
    try {
      const data = await getStats();
      setStats(data);
      setError(false);
    } catch {
      setError(true);
    }
  };

  useEffect(() => {
    fetchStats();
    const id = setInterval(fetchStats, 60_000);
    return () => clearInterval(id);
  }, []);

  if (error) {
    return (
      <div className="card border-danger/30 bg-red-500/5 px-4 py-3 text-sm text-red-400 font-mono">
        ⚠ Backend unreachable — stats unavailable
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <SkeletonCard key={i} />
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      <MetricCard
        icon={<Database className="h-3.5 w-3.5" />}
        label="CVEs Cached"
        value={stats.total_cves_processed}
        accent="text-acid"
      />
      <MetricCard
        icon={<ShieldAlert className="h-3.5 w-3.5" />}
        label="CISA KEV"
        value={stats.kev_catalog_size}
        accent="text-danger"
      />
      <MetricCard
        icon={<Eye className="h-3.5 w-3.5" />}
        label="Critical"
        value={stats.critical_count}
        subtitle={`${stats.high_count} high`}
        accent="text-red-400"
        clickable
        onClick={() => scrollToFeedWithPriority("CRITICAL")}
      />
      <MetricCard
        icon={<Hash className="h-3.5 w-3.5" />}
        label="Medium"
        value={stats.medium_count}
        subtitle={`${stats.low_count} low`}
        accent="text-yellow-300"
        clickable
        onClick={() => scrollToFeedWithPriority("MEDIUM")}
      />
      <MetricCard
        icon={<Clock className="h-3.5 w-3.5" />}
        label="Last Poll"
        value={formatDateRelative(stats.last_poll_time)}
        accent="text-info"
      />
      <MetricCard
        icon={<Timer className="h-3.5 w-3.5" />}
        label="Next Poll"
        value={formatTimeUntil(stats.next_poll_time)}
        accent="text-amber"
      />
    </div>
  );
}
