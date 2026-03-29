"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { RefreshCw, Inbox } from "lucide-react";
import { getCVEs } from "@/lib/api";
import type { FilterState, ProcessedCVE } from "@/types/cve";
import { cn } from "@/lib/utils";
import FilterBar from "./FilterBar";
import CVECard from "./CVECard";
import TechStackFilter from "./TechStackFilter";

function SkeletonCards() {
  return (
    <div className="grid gap-3">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="card p-4" style={{ animationDelay: `${i * 80}ms` }}>
          <div className="h-0.5 skeleton w-full mb-4" />
          <div className="flex justify-between mb-2">
            <div className="skeleton h-5 w-36" />
            <div className="skeleton h-5 w-20" />
          </div>
          <div className="skeleton h-4 w-full mb-1" />
          <div className="skeleton h-4 w-3/4 mb-3" />
          <div className="flex gap-2">
            <div className="skeleton h-4 w-12" />
            <div className="skeleton h-4 w-16" />
            <div className="skeleton h-4 w-14 ml-auto" />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function CVEFeed() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [cves, setCves] = useState<ProcessedCVE[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(false);
  const [stackFilter, setStackFilter] = useState<string[]>([]);

  // Read filters from URL
  const [filters, setFilters] = useState<FilterState>(() => ({
    priority: (searchParams.get("priority") as FilterState["priority"]) || "ALL",
    kev_only: searchParams.get("kev") === "true",
    has_poc: searchParams.get("poc") === "true",
    search: searchParams.get("q") || "",
  }));

  // Sync filters → URL
  const updateFilters = useCallback(
    (f: FilterState) => {
      setFilters(f);
      const sp = new URLSearchParams();
      if (f.priority !== "ALL") sp.set("priority", f.priority);
      if (f.kev_only) sp.set("kev", "true");
      if (f.has_poc) sp.set("poc", "true");
      if (f.search) sp.set("q", f.search);
      const qs = sp.toString();
      router.replace(qs ? `?${qs}` : "/", { scroll: false });
    },
    [router]
  );

  // Fetch CVEs
  const fetchCVEs = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    try {
      const data = await getCVEs({ page_size: 100 });
      setCves(data);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchCVEs();
    const id = setInterval(() => fetchCVEs(), 300_000); // 5 min
    return () => clearInterval(id);
  }, [fetchCVEs]);

  // Client-side filtering
  const filtered = useMemo(() => {
    let result = cves;

    if (filters.priority !== "ALL") {
      result = result.filter((c) => c.priority_label === filters.priority);
    }
    if (filters.kev_only) {
      result = result.filter((c) => c.enrichment.in_kev);
    }
    if (filters.has_poc) {
      result = result.filter((c) => c.enrichment.has_poc);
    }
    if (filters.search) {
      const q = filters.search.toLowerCase();
      result = result.filter(
        (c) =>
          c.cve_id.toLowerCase().includes(q) ||
          c.description.toLowerCase().includes(q) ||
          (c.ai_explanation?.summary || "").toLowerCase().includes(q) ||
          (c.ai_explanation?.tags || []).some((t) => t.toLowerCase().includes(q)) ||
          (c.ai_explanation?.affected_tech || []).some((t) =>
            t.toLowerCase().includes(q)
          )
      );
    }

    // Tech stack filter
    if (stackFilter.length > 0) {
      result = result.filter((c) => {
        const techs = [
          ...(c.ai_explanation?.affected_tech || []),
          c.description,
        ].join(" ").toLowerCase();
        return stackFilter.some((t) => techs.includes(t.toLowerCase()));
      });
    }

    return result;
  }, [cves, filters, stackFilter]);

  return (
    <section>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-display font-bold text-lg text-l-text dark:text-gray-100">
          CVE Feed
        </h2>
        <button
          onClick={() => fetchCVEs(true)}
          disabled={refreshing}
          className="btn-ghost flex items-center gap-1.5 text-xs font-mono"
        >
          <RefreshCw
            className={cn(
              "h-3.5 w-3.5",
              refreshing && "animate-spin"
            )}
          />
          Refresh
        </button>
      </div>

      <FilterBar
        filters={filters}
        onChange={updateFilters}
        resultCount={filtered.length}
      />

      <div className="mt-3">
        <TechStackFilter onFilterChange={setStackFilter} />
      </div>

      <div className="mt-4">
        {loading ? (
          <SkeletonCards />
        ) : error ? (
          <div className="card border-danger/30 bg-red-500/5 p-8 text-center">
            <p className="text-red-400 font-mono text-sm">
              Failed to load CVEs — is the backend running?
            </p>
            <button
              onClick={() => fetchCVEs()}
              className="btn-primary mt-4 text-xs"
            >
              Retry
            </button>
          </div>
        ) : filtered.length === 0 ? (
          <div className="card p-12 text-center">
            <Inbox className="h-12 w-12 mx-auto text-l-muted dark:text-muted mb-3" />
            <p className="text-l-sub dark:text-gray-500 font-mono text-sm">
              {cves.length === 0
                ? "No CVEs processed yet — wait for the poller or trigger a manual poll."
                : "No CVEs match your filters."}
            </p>
          </div>
        ) : (
          <div className="grid gap-3">
            {filtered.map((cve, i) => (
              <CVECard key={cve.cve_id} cve={cve} index={i} />
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
