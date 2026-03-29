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
}

function MetricCard({ icon, label, value, subtitle, accent }: MetricCardProps) {
  return (
    <div className="card px-4 py-3 animate-fade-in">
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
    </div>
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
      />
      <MetricCard
        icon={<Hash className="h-3.5 w-3.5" />}
        label="Medium"
        value={stats.medium_count}
        subtitle={`${stats.low_count} low`}
        accent="text-yellow-300"
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
