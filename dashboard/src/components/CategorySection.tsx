"use client";

import { useCallback, useEffect, useState } from "react";
import type { ProcessedCVE } from "@/types/cve";
import CVECard from "./CVECard";

interface CategorySectionProps {
  title: string;
  subtitle: string;
  accent: string;       // e.g. "text-red-400"
  accentBorder: string;  // e.g. "border-red-500/20"
  icon: string;          // emoji
  fetchFn: () => Promise<ProcessedCVE[]>;
  refreshMs: number;     // auto-refresh interval in ms
  maxCards: number;
}

export default function CategorySection({
  title,
  subtitle,
  accent,
  accentBorder,
  icon,
  fetchFn,
  refreshMs,
  maxCards,
}: CategorySectionProps) {
  const [cves, setCves] = useState<ProcessedCVE[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const data = await fetchFn();
      setCves(data.slice(0, maxCards));
    } catch {
      // silent — section hides if no data
    } finally {
      setLoading(false);
    }
  }, [fetchFn, maxCards]);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, refreshMs);
    return () => clearInterval(id);
  }, [fetchData, refreshMs]);

  // Hide entirely when empty (not loading)
  if (!loading && cves.length === 0) return null;

  // Skeleton while loading
  if (loading) {
    return (
      <section className="mb-8 animate-fade-in">
        <div className="skeleton h-6 w-48 mb-2" />
        <div className="skeleton h-4 w-72 mb-4" />
        <div className="grid gap-3">
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} className="card p-4">
              <div className="skeleton h-4 w-full mb-2" />
              <div className="skeleton h-3 w-3/4" />
            </div>
          ))}
        </div>
      </section>
    );
  }

  return (
    <section className={`mb-8 animate-fade-in`}>
      {/* Section header */}
      <div className={`flex items-center gap-2 mb-1`}>
        <span className="text-lg">{icon}</span>
        <h2 className={`font-display font-bold text-lg ${accent}`}>
          {title}
        </h2>
      </div>
      <p className="text-xs font-mono text-l-sub dark:text-gray-500 mb-4">
        {subtitle}
      </p>

      {/* Accent divider */}
      <div className={`h-px mb-4 border-t ${accentBorder}`} />

      {/* Cards */}
      <div className="grid gap-3">
        {cves.map((cve, i) => (
          <CVECard key={cve.cve_id} cve={cve} index={i} />
        ))}
      </div>
    </section>
  );
}
