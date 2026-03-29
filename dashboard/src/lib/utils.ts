/* ── Utility helpers ─── */

import clsx, { type ClassValue } from "clsx";

/** Merge Tailwind classes via clsx */
export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

/* ── Priority badge classes (dark mode) ─────────────── */

export function priorityColor(label: string) {
  switch (label) {
    case "CRITICAL":
      return {
        text: "text-red-400",
        bg: "bg-red-500/15",
        border: "border-red-500/30",
        bar: "bg-red-500",
        dot: "bg-red-400",
      };
    case "HIGH":
      return {
        text: "text-amber-400",
        bg: "bg-amber-500/15",
        border: "border-amber-500/30",
        bar: "bg-amber-500",
        dot: "bg-amber-400",
      };
    case "MEDIUM":
      return {
        text: "text-yellow-300",
        bg: "bg-yellow-500/15",
        border: "border-yellow-500/30",
        bar: "bg-yellow-500",
        dot: "bg-yellow-400",
      };
    case "LOW":
      return {
        text: "text-blue-400",
        bg: "bg-blue-500/15",
        border: "border-blue-500/30",
        bar: "bg-blue-500",
        dot: "bg-blue-400",
      };
    default:
      return {
        text: "text-gray-400",
        bg: "bg-gray-500/15",
        border: "border-gray-500/30",
        bar: "bg-gray-500",
        dot: "bg-gray-400",
      };
  }
}

/* ── CVSS color ─────────────────────────────────────── */

export function cvssColor(score: number): string {
  if (score >= 9.0) return "text-red-400";
  if (score >= 7.0) return "text-amber-400";
  if (score >= 4.0) return "text-yellow-300";
  return "text-blue-400";
}

/* ── Date formatting ───────────────────────────────── */

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export function formatDateRelative(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(iso);
}

export function formatTimeUntil(iso: string | null): string {
  if (!iso) return "—";
  const diff = new Date(iso).getTime() - Date.now();
  if (diff <= 0) return "now";
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `in ${mins}m`;
  const hrs = Math.floor(mins / 60);
  return `in ${hrs}h ${mins % 60}m`;
}

/* ── EPSS formatting ───────────────────────────────── */

export function epssPercent(score: number): string {
  return `${(score * 100).toFixed(1)}%`;
}
