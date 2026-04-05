"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { RefreshCw, Inbox, Shield, Flame, Zap, Target, Unlock } from "lucide-react";
import { getCVEs } from "@/lib/api";
import type { FilterState, ProcessedCVE, CategoryLabel } from "@/types/cve";
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

/* ── Category tab config ───────────────────────────── */

const CATEGORY_TABS: { value: CategoryLabel; label: string; icon: React.ReactNode; accent: string }[] = [
  { value: "ALL",                 label: "All",           icon: <Shield className="h-3.5 w-3.5" />,  accent: "text-acid border-acid/30 bg-acid/10"             },
  { value: "ACTIVELY_EXPLOITED",  label: "Exploited",     icon: <Shield className="h-3.5 w-3.5" />,  accent: "text-red-400 border-red-400/30 bg-red-400/10"     },
  { value: "TRENDING",            label: "Trending",      icon: <Flame className="h-3.5 w-3.5" />,   accent: "text-orange-400 border-orange-400/30 bg-orange-400/10" },
  { value: "JUST_DROPPED",        label: "Just Dropped",  icon: <Zap className="h-3.5 w-3.5" />,     accent: "text-emerald-400 border-emerald-400/30 bg-emerald-400/10" },
  { value: "HIGH_EXPLOITABILITY", label: "Exploitable",   icon: <Target className="h-3.5 w-3.5" />,  accent: "text-purple-400 border-purple-400/30 bg-purple-400/10" },
  { value: "NO_AUTH_REQUIRED",    label: "No Auth",       icon: <Unlock className="h-3.5 w-3.5" />,  accent: "text-amber-400 border-amber-400/30 bg-amber-400/10"   },
];

export default function CVEFeed() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [cves, setCves] = useState<ProcessedCVE[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(false);
  const [stackFilter, setStackFilter] = useState<string[]>([]);

  // Debounced search — only re-fetch 600ms after user stops typing
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const searchTimer = useRef<ReturnType<typeof setTimeout>>();


  // Read filters from URL
  const [filters, setFilters] = useState<FilterState>(() => ({
    priority: (searchParams.get("priority") as FilterState["priority"]) || "ALL",
    category: (searchParams.get("cat") as FilterState["category"]) || "ALL",
    kev_only: searchParams.get("kev") === "true",
    has_poc: searchParams.get("poc") === "true",
    search: searchParams.get("q") || "",
  }));

  // Sync filters → URL
  const updateFilters = useCallback(
    (f: FilterState) => {
      setFilters(f);
      const sp = new URLSearchParams();
      if (f.category !== "ALL") sp.set("cat", f.category);
      if (f.priority !== "ALL") sp.set("priority", f.priority);
      if (f.kev_only) sp.set("kev", "true");
      if (f.has_poc) sp.set("poc", "true");
      if (f.search) sp.set("q", f.search);
      const qs = sp.toString();
      router.replace(qs ? `?${qs}` : "/", { scroll: false });
    },
    [router]
  );

  // Debounce the search input — wait 600ms after last keystroke
  useEffect(() => {
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => {
      setDebouncedSearch(filters.search);
    }, 600);
    return () => clearTimeout(searchTimer.current);
  }, [filters.search]);

  // Fetch CVEs — uses server-side category + search filtering
  const fetchCVEs = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    try {
      const params: Record<string, string | number> = { page_size: 200 };
      if (filters.category !== "ALL") {
        params.category = filters.category;
      }
      // Send debounced search to backend for server-side CVE ID lookup
      if (debouncedSearch) {
        params.search = debouncedSearch;
      }
      const data = await getCVEs(params);
      setCves(data);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [filters.category, debouncedSearch]);

  useEffect(() => {
    setLoading(true);
    fetchCVEs();
    const id = setInterval(() => fetchCVEs(), 300_000);
    return () => clearInterval(id);
  }, [fetchCVEs]);

  // Client-side filtering: priority → toggles → search → stack
  const filtered = useMemo(() => {
    let result = [...cves];

    // Priority subfilter
    if (filters.priority !== "ALL") {
      result = result.filter((c) => c.priority_label === filters.priority);
    }

    // Toggle filters
    if (filters.kev_only) {
      result = result.filter((c) => c.enrichment.in_kev);
    }
    if (filters.has_poc) {
      result = result.filter((c) => c.enrichment.has_poc);
    }

    // Text search
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
          All CVEs
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

      {/* Category tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 mb-3 scrollbar-hide">
        {CATEGORY_TABS.map((tab) => {
          const active = filters.category === tab.value;
          return (
            <button
              key={tab.value}
              onClick={() => updateFilters({ ...filters, category: tab.value })}
              className={cn(
                "category-tab flex items-center gap-1.5 text-xs font-medium px-3.5 py-2 rounded-lg border transition-all whitespace-nowrap",
                active
                  ? tab.accent
                  : "text-l-sub dark:text-gray-500 border-l-border dark:border-border bg-transparent hover:border-l-muted dark:hover:border-muted"
              )}
            >
              {tab.icon}
              {tab.label}
            </button>
          );
        })}
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
              No CVEs match your current filters.
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
