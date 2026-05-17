"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Search, Building2, Shield, Users, ExternalLink, ChevronDown, ChevronUp, FileText } from "lucide-react";
import { getBreaches, searchBreaches, getBreachStats } from "@/lib/api";
import type { BreachRecord } from "@/types/cve";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";

function formatNumber(n: number | null | undefined): string {
  if (!n) return "N/A";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

export default function BreachesPage() {
  const [breaches, setBreaches] = useState<BreachRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [stats, setStats] = useState<Record<string, unknown>>({});
  const [category, setCategory] = useState<"latest" | "major" | "active">("latest");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Fetch breaches and stats dynamically based on category or query
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        if (query.trim()) {
          const [data, s] = await Promise.all([
            searchBreaches(query.trim()),
            getBreachStats({ query: query.trim() })
          ]);
          setBreaches(data);
          setStats(s);
        } else {
          const [data, s] = await Promise.all([
            getBreaches({ limit: 50, category }),
            getBreachStats({ category })
          ]);
          setBreaches(data);
          setStats(s);
        }
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [category, query]);

  const handleSearch = () => {
    // Search is handled by the useEffect watching the `query` state,
    // but we can manually trigger if needed or just rely on debounce/submit.
    // For now, it updates automatically.
  };

  const totalBreaches = (stats.total_breaches as number) || 0;
  const totalRecords = (stats.total_records as number) || 0;
  const topSectors = (stats.top_sectors as Array<{ sector: string; count: number }>) || [];

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-xl bg-orange-500/10 border border-orange-500/20">
          <AlertTriangle className="h-6 w-6 text-orange-400" />
        </div>
        <div>
          <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
            Breach Intelligence Monitor
          </h1>
          <p className="text-sm text-l-sub dark:text-gray-400">
            Tracking publicly disclosed data breaches linked to CVEs and threat actors
          </p>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold font-mono text-orange-400">{totalBreaches}</p>
          <p className="text-[10px] text-l-sub dark:text-gray-500 uppercase tracking-wider">Tracked Breaches</p>
        </div>
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold font-mono text-red-400">{formatNumber(totalRecords)}</p>
          <p className="text-[10px] text-l-sub dark:text-gray-500 uppercase tracking-wider">Records Exposed</p>
        </div>
        {topSectors.slice(0, 2).map((s) => (
          <div key={s.sector} className="card p-4 text-center">
            <p className="text-2xl font-bold font-mono text-amber-400">{s.count}</p>
            <p className="text-[10px] text-l-sub dark:text-gray-500 uppercase tracking-wider">{s.sector}</p>
          </div>
        ))}
      </div>

      {/* Search & Tabs */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-l-card dark:bg-card p-3 rounded-xl border border-l-border dark:border-border">
        <div className="flex gap-2 w-full md:w-auto overflow-x-auto pb-1 md:pb-0 hide-scrollbar">
          {(["latest", "major", "active"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => { setCategory(tab); setQuery(""); setExpandedId(null); }}
              className={cn(
                "px-4 py-2 rounded-lg text-sm font-medium transition-all whitespace-nowrap",
                category === tab && !query
                  ? "bg-orange-500 text-white shadow-md shadow-orange-500/20"
                  : "bg-transparent text-l-sub dark:text-gray-400 hover:bg-l-panel dark:hover:bg-panel hover:text-l-text dark:hover:text-gray-200"
              )}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)} Breaches
            </button>
          ))}
        </div>
        
        <div className="relative w-full md:max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-l-sub dark:text-gray-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search breaches..."
            className="w-full pl-9 pr-3 py-2 text-sm rounded-lg bg-l-panel dark:bg-panel border border-l-border dark:border-border focus:outline-none focus:ring-2 focus:ring-orange-500/30 text-l-text dark:text-gray-200 placeholder:text-l-sub/50 dark:placeholder:text-gray-600"
          />
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="card p-5">
              <div className="skeleton h-5 w-48 mb-3" />
              <div className="skeleton h-3 w-full mb-2" />
              <div className="skeleton h-3 w-2/3" />
            </div>
          ))}
        </div>
      )}

      {/* Breach cards */}
      {!loading && (
        <div className="space-y-4">
          {breaches.map((breach, i) => {
            const breachIdentifier = String(breach.id || breach.company_name);
            const isExpanded = expandedId === breachIdentifier;
            return (
              <motion.div
                layout
                key={breachIdentifier + "-" + i}
                onClick={() => setExpandedId(isExpanded ? null : breachIdentifier)}
                className={cn(
                  "card p-5 cursor-pointer transition-all duration-300",
                  isExpanded ? "ring-2 ring-orange-500/50 shadow-lg" : "card-hover hover:border-orange-500/30"
                )}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <h3 className="text-base font-semibold text-l-text dark:text-gray-100 flex items-center gap-1.5">
                        <Building2 className="h-4 w-4 text-orange-400" />
                        {breach.company_name}
                      </h3>
                      {!breach.verified && (
                        <span className="badge text-[10px] py-0.5 bg-yellow-500/10 border-yellow-500/20 text-yellow-500">
                          UNVERIFIED
                        </span>
                      )}
                      {breach.actor_slug && breach.actor_name && (
                        <Link
                          href={`/threat-actors/${breach.actor_slug}`}
                          onClick={(e) => e.stopPropagation()}
                          className="badge text-[10px] py-0.5 bg-blue-500/10 border-blue-500/20 text-blue-400 hover:bg-blue-500/20 transition-colors"
                        >
                          <Users className="h-3 w-3" /> {breach.actor_name}
                        </Link>
                      )}
                    </div>
                    {breach.breach_date && (
                      <p className="text-xs text-l-sub dark:text-gray-500 font-mono mt-1 flex items-center gap-2">
                        <span className="text-orange-400/90 font-semibold bg-orange-500/10 px-1.5 py-0.5 rounded">Occurred: {breach.breach_date.split('T')[0]}</span> 
                        {breach.disclosed_date && <span>· Disclosed: {breach.disclosed_date.split('T')[0]}</span>}
                      </p>
                    )}
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    {breach.records_count ? (
                      <div className="text-right">
                        <p className="text-xl font-bold font-mono text-red-400">{formatNumber(breach.records_count)}</p>
                        <p className="text-[10px] text-l-sub dark:text-gray-500 uppercase tracking-wider">records</p>
                      </div>
                    ) : (
                      <div className="h-10" />
                    )}
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4 text-l-sub" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-l-sub" />
                    )}
                  </div>
                </div>

                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className="mt-4 pt-4 border-t border-l-border dark:border-border/50"
                    >
                      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        <div className="lg:col-span-2 space-y-4">
                          <div>
                            <h4 className="text-xs font-semibold text-l-sub dark:text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                              <FileText className="h-3.5 w-3.5" />
                              Technical Synopsis
                            </h4>
                            <p className="text-sm text-l-text dark:text-gray-300 leading-relaxed">
                              {breach.description}
                            </p>
                          </div>
                          
                          {(breach.cve_ids?.length ?? 0) > 0 && (
                            <div className="bg-orange-500/5 dark:bg-orange-500/10 p-3.5 rounded-xl border border-orange-500/20">
                              <h4 className="text-xs font-semibold text-orange-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                <Shield className="h-4 w-4" />
                                KnowCVE Intelligence Context
                              </h4>
                              <p className="text-[11px] text-l-sub dark:text-gray-400 mb-3 leading-relaxed">
                                This breach was facilitated by specific vulnerabilities. KnowCVE actively tracks these to calculate dynamic Exploit Maturity Scores (EMS), uncover threat actor playbooks, and provide actionable mitigation strategies.
                              </p>
                              <div className="flex flex-wrap gap-2">
                                {breach.cve_ids?.map((cve) => (
                                  <Link
                                    key={cve}
                                    href={`/cve/${cve}`}
                                    onClick={(e) => e.stopPropagation()}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500/15 border border-orange-500/30 text-orange-400 hover:bg-orange-500/25 hover:scale-105 transition-all text-xs font-bold shadow-sm"
                                  >
                                    <Shield className="h-3.5 w-3.5" /> Analyze {cve}
                                  </Link>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>

                        <div className="space-y-4 bg-l-panel/50 dark:bg-panel/30 p-4 rounded-xl border border-l-border dark:border-border/50">
                          <div>
                            <h4 className="text-[10px] font-semibold text-l-sub dark:text-gray-500 uppercase tracking-wider mb-1.5">
                              Data Exposed
                            </h4>
                            <div className="flex flex-wrap gap-1.5">
                              {breach.data_exposed?.map((d) => (
                                <span key={d} className="text-[10px] text-l-text dark:text-gray-300 bg-l-panel dark:bg-panel px-2 py-1 rounded border border-l-border dark:border-border">
                                  {d}
                                </span>
                              ))}
                            </div>
                          </div>

                          <div>
                            <h4 className="text-[10px] font-semibold text-l-sub dark:text-gray-500 uppercase tracking-wider mb-1.5">
                              Target Sectors
                            </h4>
                            <div className="flex flex-wrap gap-1.5">
                              {breach.sectors?.map((s) => (
                                <span key={s} className="text-[10px] text-orange-400 bg-orange-500/10 px-2 py-1 rounded border border-orange-500/20">
                                  {s}
                                </span>
                              ))}
                            </div>
                          </div>

                          {breach.source_urls && breach.source_urls.length > 0 && (
                            <div>
                              <h4 className="text-[10px] font-semibold text-l-sub dark:text-gray-500 uppercase tracking-wider mb-1.5">
                                External References
                              </h4>
                              <div className="flex flex-col gap-1.5">
                                {breach.source_urls.map((url, idx) => (
                                  <a
                                    key={idx}
                                    href={url}
                                    target="_blank"
                                    rel="noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    className="flex items-center gap-1.5 text-xs text-blue-500 hover:text-blue-400 transition-colors truncate"
                                  >
                                    <ExternalLink className="h-3 w-3 shrink-0" />
                                    <span className="truncate">{new URL(url).hostname.replace('www.', '')}</span>
                                  </a>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
                
                {!isExpanded && (
                  <>
                    <p className="text-xs text-l-sub dark:text-gray-400 line-clamp-2 leading-relaxed">
                      {breach.description}
                    </p>
                    {/* Compact preview of CVEs when collapsed */}
                    {(breach.cve_ids?.length ?? 0) > 0 && (
                      <div className="mt-3 flex gap-1.5">
                        {breach.cve_ids?.map((cve) => (
                          <span key={cve} className="badge text-[9px] py-0.5 bg-red-500/10 border-red-500/20 text-red-400">
                            <Shield className="h-2.5 w-2.5" /> {cve}
                          </span>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </motion.div>
            );
          })}
        </div>
      )}

      {/* Empty */}
      {!loading && breaches.length === 0 && (
        <div className="card p-12 text-center">
          <p className="text-4xl mb-3">🔒</p>
          <p className="text-lg font-medium text-l-text dark:text-gray-200">No breaches found</p>
          <p className="text-sm text-l-sub dark:text-gray-500 mt-1">
            {query ? "Try a different search term" : "No breaches in this category"}
          </p>
        </div>
      )}

      {/* Disclaimer */}
      <div className="text-[11px] text-l-sub dark:text-gray-600 text-center px-4">
        <p>⚠️ All data sourced from public breach disclosure reports. This is NOT a personal data lookup tool.</p>
        <p>KnowCVE does not store, process, or facilitate access to any breached personal data.</p>
      </div>
    </div>
  );
}
