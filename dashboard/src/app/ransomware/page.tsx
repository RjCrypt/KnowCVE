"use client";

import { useEffect, useState } from "react";
import { Skull, AlertTriangle, Shield } from "lucide-react";
import { getRansomwareMatrix } from "@/lib/api";
import type { RansomwareCampaign } from "@/types/cve";
import { cn } from "@/lib/utils";
import Link from "next/link";

const STATUS_TABS = ["all", "active", "historical"];

export default function RansomwarePage() {
  const [campaigns, setCampaigns] = useState<RansomwareCampaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("all");

  const fetchData = async () => {
    try {
      const data = await getRansomwareMatrix();
      setCampaigns(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 300_000); // 5 min
    return () => clearInterval(id);
  }, []);

  const activeCount = campaigns.filter((c) => c.status === "active").length;
  const filtered = campaigns.filter((c) => tab === "all" || c.status === tab);

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20">
          <Skull className="h-6 w-6 text-rose-400" />
        </div>
        <div>
          <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
            Ransomware Campaign Tracker
          </h1>
          <p className="text-sm text-l-sub dark:text-gray-400">
            Tracking active and historical ransomware campaigns and their CVE exploitation
          </p>
        </div>
      </div>

      {/* Active alert bar */}
      {activeCount > 0 && (
        <div className="card p-4 border-rose-500/30 bg-rose-500/5 flex items-center gap-3">
          <div className="relative flex h-3 w-3 flex-shrink-0">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-3 w-3 bg-rose-500" />
          </div>
          <span className="text-sm text-rose-400 font-medium">
            {activeCount} active ransomware campaign{activeCount !== 1 ? "s" : ""} tracked
          </span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 bg-l-panel dark:bg-panel rounded-lg p-1 w-fit">
        {STATUS_TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={cn(
              "text-xs font-medium px-4 py-1.5 rounded-md transition-colors capitalize",
              tab === t
                ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
            )}
          >
            {t}
          </button>
        ))}
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

      {/* Campaign cards */}
      {!loading && (
        <div className="space-y-3">
          {filtered.map((c, i) => (
            <div
              key={`${c.actor_slug}-${c.campaign_name}`}
              className={cn(
                "card overflow-hidden animate-slide-up",
                c.status === "active" ? "border-rose-500/20" : "border-l-border dark:border-border"
              )}
              style={{ animationDelay: `${i * 40}ms` }}
            >
              {c.status === "active" && (
                <div className="h-0.5 bg-gradient-to-r from-rose-500 via-orange-500 to-rose-600" />
              )}
              <div className="p-5">
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Link
                        href={`/threat-actors/${c.actor_slug}`}
                        className="text-sm font-semibold text-rose-400 hover:underline"
                      >
                        {c.actor_name || c.actor_slug}
                      </Link>
                      <span
                        className={cn(
                          "text-[10px] font-medium px-2 py-0.5 rounded-full border",
                          c.status === "active"
                            ? "bg-rose-500/10 border-rose-500/30 text-rose-400"
                            : "bg-gray-500/10 border-gray-500/30 text-gray-400"
                        )}
                      >
                        {c.status}
                      </span>
                    </div>
                    <h3 className="text-sm font-medium text-l-text dark:text-gray-200 mt-1">{c.campaign_name}</h3>
                  </div>
                </div>

                <p className="text-xs text-l-sub dark:text-gray-400 line-clamp-2 mb-3 leading-relaxed">
                  {c.description}
                </p>

                {/* CVEs */}
                {((c.cves || c.cve_ids) ?? []).length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mb-3">
                    {((c.cves || c.cve_ids) ?? []).map((cve) => (
                      <Link
                        key={cve}
                        href={`/cve/${cve}`}
                        className="badge text-[10px] py-0.5 bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors"
                      >
                        <Shield className="h-3 w-3" /> {cve}
                      </Link>
                    ))}
                  </div>
                )}

                {/* Tags */}
                <div className="flex flex-wrap gap-1.5">
                  {c.sectors?.map((s) => (
                    <span key={s} className="text-[10px] text-l-sub dark:text-gray-500 bg-l-panel dark:bg-panel px-2 py-0.5 rounded">
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Empty */}
      {!loading && filtered.length === 0 && (
        <div className="card p-12 text-center">
          <p className="text-4xl mb-3">🔒</p>
          <p className="text-lg font-medium text-l-text dark:text-gray-200">No campaigns found</p>
          <p className="text-sm text-l-sub dark:text-gray-500 mt-1">Try a different filter</p>
        </div>
      )}
    </div>
  );
}
