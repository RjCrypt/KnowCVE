"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Database,
  ShieldAlert,
  Hash,
  Clock,
  Timer,
  Bot,
  Zap,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from "lucide-react";
import { getStats, getCVEs, triggerPoll, getHealth } from "@/lib/api";
import type { StatsResponse, ProcessedCVE, PollResponse, HealthResponse } from "@/types/cve";
import { cn, formatDateRelative, formatTimeUntil, priorityColor } from "@/lib/utils";
import Footer from "@/components/layout/Footer";

/* ── Metric tile ───────────────────────────────── */

function Metric({
  icon,
  label,
  value,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  accent?: string;
}) {
  return (
    <div className="card px-4 py-4 animate-fade-in">
      <div className="flex items-center gap-2 mb-1.5">
        <span className={accent || "text-l-sub dark:text-gray-500"}>{icon}</span>
        <span className="text-[10px] font-mono uppercase tracking-widest text-l-sub dark:text-gray-500">
          {label}
        </span>
      </div>
      <div className="font-display font-bold text-3xl text-l-text dark:text-gray-100">
        {value}
      </div>
    </div>
  );
}

/* ── Status row ────────────────────────────────── */

function StatusRow({
  label,
  active,
}: {
  label: string;
  active: boolean | undefined;
}) {
  return (
    <div className="flex items-center justify-between px-4 py-2.5 border-b border-l-border dark:border-border last:border-b-0">
      <span className="text-sm text-l-sub dark:text-gray-400">{label}</span>
      <div className="flex items-center gap-2">
        <span
          className={cn(
            "h-2.5 w-2.5 rounded-full",
            active ? "bg-acid animate-pulse-slow" : "bg-danger"
          )}
        />
        <span
          className={cn(
            "text-xs font-mono",
            active ? "text-acid" : "text-danger"
          )}
        >
          {active ? "Online" : "Offline"}
        </span>
      </div>
    </div>
  );
}

/* ── Priority card ─────────────────────────────── */

function PriorityCard({
  label,
  count,
}: {
  label: string;
  count: number;
}) {
  const colors = priorityColor(label);
  return (
    <div
      className={cn(
        "card px-4 py-4 border animate-fade-in",
        colors.border,
        colors.bg
      )}
    >
      <span
        className={cn(
          "text-[10px] font-mono uppercase tracking-widest",
          colors.text
        )}
      >
        {label}
      </span>
      <div className={cn("font-display font-bold text-3xl mt-1", colors.text)}>
        {count}
      </div>
    </div>
  );
}

/* ── Main page ─────────────────────────────────── */

/* ── Volume Chart (pure CSS) ──────────────────── */

function VolumeChart({ cves }: { cves: ProcessedCVE[] }) {
  // Group CVEs by date (last 14 days)
  const days: { date: string; count: number; dominant: string }[] = [];
  const now = new Date();

  for (let i = 13; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    const dayCves = cves.filter((c) => {
      if (!c.published_date) return false;
      return c.published_date.slice(0, 10) === dateStr;
    });
    const count = dayCves.length;

    // Determine dominant severity
    let dominant = "LOW";
    if (dayCves.some((c) => c.priority_label === "CRITICAL")) dominant = "CRITICAL";
    else if (dayCves.some((c) => c.priority_label === "HIGH")) dominant = "HIGH";
    else if (dayCves.some((c) => c.priority_label === "MEDIUM")) dominant = "MEDIUM";

    days.push({ date: dateStr, count, dominant });
  }

  const maxCount = Math.max(...days.map((d) => d.count), 1);

  const barColor = (dom: string) => {
    switch (dom) {
      case "CRITICAL": return "bg-red-500";
      case "HIGH": return "bg-amber-500";
      case "MEDIUM": return "bg-yellow-400";
      default: return "bg-green-500";
    }
  };

  return (
    <div>
      <div className="flex items-end gap-1.5 h-32">
        {days.map((day) => (
          <div key={day.date} className="flex-1 flex flex-col items-center justify-end h-full group relative">
            {/* Tooltip */}
            <div className="absolute -top-8 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10">
              <div className="bg-l-text dark:bg-gray-100 text-l-bg dark:text-void text-[9px] font-mono px-2 py-1 rounded whitespace-nowrap">
                {day.date.slice(5)}: {day.count} CVEs
              </div>
            </div>
            <div
              className={cn(
                "w-full rounded-sm transition-all duration-300 min-h-[2px]",
                day.count > 0 ? barColor(day.dominant) : "bg-l-border dark:bg-border",
                "group-hover:opacity-80"
              )}
              style={{ height: `${Math.max((day.count / maxCount) * 100, 3)}%` }}
            />
          </div>
        ))}
      </div>
      {/* Date labels */}
      <div className="flex gap-1.5 mt-1.5">
        {days.map((day, i) => (
          <div key={day.date} className="flex-1 text-center">
            {(i === 0 || i === 6 || i === 13) && (
              <span className="text-[8px] font-mono text-l-sub dark:text-gray-600">
                {day.date.slice(5)}
              </span>
            )}
          </div>
        ))}
      </div>
      {/* Legend */}
      <div className="flex items-center gap-4 mt-3 text-[9px] font-mono text-l-sub dark:text-gray-500">
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-red-500" /> Critical</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-amber-500" /> High</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-yellow-400" /> Medium</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-green-500" /> Low</span>
      </div>
    </div>
  );
}


export default function StatsPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [cves, setCves] = useState<ProcessedCVE[]>([]);
  const [loading, setLoading] = useState(true);
  const [pollLoading, setPollLoading] = useState(false);
  const [pollResult, setPollResult] = useState<{status: string; message?: string} | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [adminKey, setAdminKey] = useState("");

  const fetchData = useCallback(async () => {
    try {
      const [s, c, h] = await Promise.all([getStats(), getCVEs({ page_size: 100 }), getHealth()]);
      setStats(s);
      setCves(c);
      setHealth(h);
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 30_000);
    return () => clearInterval(id);
  }, [fetchData]);

  const handlePoll = async () => {
    if (!adminKey.trim()) {
      setPollError("Enter your admin key to trigger a poll.");
      return;
    }
    setPollLoading(true);
    setPollResult(null);
    setPollError(null);
    try {
      const res = await triggerPoll(adminKey.trim());
      setPollResult(res);
      setTimeout(fetchData, 2000);
    } catch (e: unknown) {
      setPollError(e instanceof Error ? e.message : "Poll failed — check your admin key.");
    } finally {
      setPollLoading(false);
    }
  };

  // Priority breakdown from CVEs
  const breakdown = {
    CRITICAL: cves.filter((c) => c.priority_label === "CRITICAL").length,
    HIGH: cves.filter((c) => c.priority_label === "HIGH").length,
    MEDIUM: cves.filter((c) => c.priority_label === "MEDIUM").length,
    LOW: cves.filter((c) => c.priority_label === "LOW").length,
  };

  if (loading) {
    return (
      <div className="mx-auto max-w-5xl px-4 sm:px-6 py-8">
        <div className="skeleton h-10 w-48 mb-8" />
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="card px-4 py-4">
              <div className="skeleton h-3 w-20 mb-2" />
              <div className="skeleton h-10 w-16" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6 py-8 animate-fade-in">
      <h1 className="font-display font-bold text-3xl tracking-tight text-l-text dark:text-gray-100 mb-2">
        System <span className="text-acid">Status</span>
      </h1>
      <p className="text-sm font-mono text-l-sub dark:text-gray-500 mb-8">
        Backend health · Polling statistics · Priority breakdown
      </p>

      {/* Metric cards */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 mb-8">
          <Metric
            icon={<Database className="h-4 w-4" />}
            label="CVEs Processed"
            value={stats.total_cves_processed}
            accent="text-acid"
          />
          <Metric
            icon={<ShieldAlert className="h-4 w-4" />}
            label="CISA KEV Size"
            value={stats.kev_catalog_size}
            accent="text-danger"
          />
          <Metric
            icon={<Hash className="h-4 w-4" />}
            label="Subscribers"
            value={stats.subscribers_count}
            accent="text-info"
          />
          <Metric
            icon={<Clock className="h-4 w-4" />}
            label="Last Poll"
            value={formatDateRelative(stats.last_poll_time)}
            accent="text-amber"
          />
          <Metric
            icon={<Timer className="h-4 w-4" />}
            label="Next Poll"
            value={formatTimeUntil(stats.next_poll_time)}
            accent="text-info"
          />
          <Metric
            icon={<Activity className="h-4 w-4" />}
            label="Critical"
            value={stats.critical_count}
            accent="text-red-400"
          />
          <Metric
            icon={<AlertTriangle className="h-4 w-4" />}
            label="High"
            value={stats.high_count}
            accent="text-amber-400"
          />
          <Metric
            icon={<Hash className="h-4 w-4" />}
            label="Medium + Low"
            value={stats.medium_count + stats.low_count}
            accent="text-yellow-300"
          />
        </div>
      )}

      {/* Priority breakdown */}
      <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-3">
        Priority Breakdown
      </h2>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        <PriorityCard label="CRITICAL" count={breakdown.CRITICAL} />
        <PriorityCard label="HIGH" count={breakdown.HIGH} />
        <PriorityCard label="MEDIUM" count={breakdown.MEDIUM} />
        <PriorityCard label="LOW" count={breakdown.LOW} />
      </div>

      {/* Service status */}
      <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-3">
        Service Status
      </h2>
      <div className="card mb-8 overflow-hidden">
        <StatusRow label="APScheduler Poller" active={health?.poller_active ?? false} />
        <StatusRow label="Telegram Bot" active={health?.telegram_active ?? false} />
      </div>

      {/* Manual poll trigger */}
      <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-3">
        Manual Poll
      </h2>
      <div className="card p-4">
        <p className="text-sm text-l-sub dark:text-gray-400 mb-4">
          Trigger a manual CVE poll cycle. Requires your admin key (APP_SECRET_KEY).
        </p>
        <div className="flex items-center gap-3 flex-wrap">
          <input
            type="password"
            value={adminKey}
            onChange={(e) => setAdminKey(e.target.value)}
            placeholder="Admin key"
            className="input-base w-48 text-xs font-mono"
          />
          <button
            onClick={handlePoll}
            disabled={pollLoading}
            className={cn(
              "btn-primary flex items-center gap-2 text-xs",
              pollLoading && "opacity-60"
            )}
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", pollLoading && "animate-spin")}
            />
            {pollLoading ? "Polling…" : "Trigger Poll"}
          </button>
        </div>

        {/* Result */}
        {pollResult && (
          <div className="mt-4 card bg-acid/5 border-acid/20 p-3 flex items-start gap-2">
            <CheckCircle2 className="h-4 w-4 text-acid shrink-0 mt-0.5" />
            <div className="text-xs font-mono text-acid">
              <p>Status: {pollResult.status}</p>
              {pollResult.message && <p>{pollResult.message}</p>}
            </div>
          </div>
        )}

        {pollError && (
          <div className="mt-4 card bg-red-500/5 border-danger/20 p-3 flex items-center gap-2">
            <XCircle className="h-4 w-4 text-danger shrink-0" />
            <span className="text-xs font-mono text-danger">{pollError}</span>
          </div>
        )}
      </div>

      {/* 30-Day CVE Volume Chart */}
      <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-3 mt-8">
        14-Day CVE Volume
      </h2>
      <div className="card p-4 mb-8">
        <VolumeChart cves={cves} />
      </div>

      <div className="mt-12" />
      <Footer />
    </div>
  );
}
