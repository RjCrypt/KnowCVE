"use client";

import { useEffect, useState } from "react";
import { Users, Globe, Crosshair, Search } from "lucide-react";
import { getThreatActors } from "@/lib/api";
import type { ThreatActor } from "@/types/cve";
import { cn } from "@/lib/utils";
import Link from "next/link";

const FILTERS = ["All", "Nation-State", "Organized Crime"];

const countryFlag: Record<string, string> = {
  "North Korea": "🇰🇵",
  China: "🇨🇳",
  Russia: "🇷🇺",
  Iran: "🇮🇷",
  "United States/United Kingdom": "🇺🇸🇬🇧",
  Unknown: "🏴",
};

export default function ThreatActorsPage() {
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("All");
  const [search, setSearch] = useState("");
  const [activeOnly, setActiveOnly] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const data = await getThreatActors({ active_only: activeOnly });
        setActors(data);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    })();
  }, [activeOnly]);

  const filtered = actors.filter((a) => {
    if (filter !== "All" && (!a.sophistication || !a.sophistication.includes(filter))) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        a.name.toLowerCase().includes(q) ||
        a.aliases.some((al) => al.toLowerCase().includes(q)) ||
        (a.origin_country || "").toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-start gap-3 flex-wrap">
        <div className="p-2 rounded-xl bg-blue-500/10 border border-blue-500/20">
          <Users className="h-6 w-6 text-blue-400" />
        </div>
        <div className="flex-1 min-w-0">
          <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
            Threat Actor Hub
          </h1>
          <p className="text-sm text-l-sub dark:text-gray-400">
            {actors.length} tracked actor groups · CVE exploitation intelligence
          </p>
        </div>
      </div>

      {/* Filters + Search */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="flex gap-1 bg-l-panel dark:bg-panel rounded-lg p-1">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                "text-xs font-medium px-3 py-1.5 rounded-md transition-colors",
                filter === f
                  ? "bg-blue-500/15 text-blue-400 border border-blue-500/30"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
              )}
            >
              {f}
            </button>
          ))}
        </div>
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-l-sub dark:text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search actors, aliases..."
            className="w-full pl-9 pr-3 py-2 text-sm rounded-lg bg-l-panel dark:bg-panel border border-l-border dark:border-border focus:outline-none focus:ring-2 focus:ring-blue-500/30 text-l-text dark:text-gray-200 placeholder:text-l-sub/50 dark:placeholder:text-gray-600"
          />
        </div>
        <label className="flex items-center gap-2 text-xs text-l-sub dark:text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(e) => setActiveOnly(e.target.checked)}
            className="rounded accent-blue-500"
          />
          Active only
        </label>
      </div>

      {/* Loading */}
      {loading && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="card p-5">
              <div className="skeleton h-5 w-32 mb-3" />
              <div className="skeleton h-3 w-full mb-2" />
              <div className="skeleton h-3 w-2/3" />
            </div>
          ))}
        </div>
      )}

      {/* Actor grid */}
      {!loading && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map((actor, i) => (
            <Link
              key={actor.slug}
              href={`/threat-actors/${actor.slug}`}
              className="card card-hover p-5 animate-slide-up"
              style={{ animationDelay: `${i * 40}ms` }}
            >
              {/* Name + Country */}
              <div className="flex items-start justify-between mb-2">
                <div>
                  <h3 className="font-semibold text-l-text dark:text-gray-100 text-sm flex items-center gap-2">
                    <span className="text-lg">{countryFlag[actor.origin_country || "Unknown"] || "🏴"}</span>
                    {actor.name}
                  </h3>
                  {actor.aliases.length > 0 && (
                    <p className="text-[11px] text-l-sub dark:text-gray-500 mt-0.5 line-clamp-1">
                      aka {actor.aliases.join(", ")}
                    </p>
                  )}
                </div>
                <span
                  className={cn(
                    "text-[10px] font-medium px-2 py-0.5 rounded-full border",
                    actor.is_active
                      ? "bg-acid/10 border-acid/30 text-acid"
                      : "bg-gray-500/10 border-gray-500/30 text-gray-400"
                  )}
                >
                  {actor.is_active ? "Active" : "Inactive"}
                </span>
              </div>

              {/* Description */}
              <p className="text-xs text-l-sub dark:text-gray-400 line-clamp-3 mb-3 leading-relaxed">
                {actor.description}
              </p>

              {/* Tags */}
              <div className="flex flex-wrap gap-1.5 mb-2">
                <span className="badge text-[10px] py-0.5 bg-blue-500/10 border-blue-500/20 text-blue-400">
                  {actor.sophistication}
                </span>
                <span className="badge text-[10px] py-0.5 bg-purple-500/10 border-purple-500/20 text-purple-400">
                  {actor.motivation}
                </span>
              </div>

              {/* Footer */}
              <div className="flex items-center justify-between text-[10px] text-l-sub dark:text-gray-500 font-mono mt-auto pt-2 border-t border-l-border dark:border-border">
                <span>{actor.first_seen}–{actor.last_active || "present"}</span>
                <span className="flex items-center gap-1">
                  <Globe className="h-3 w-3" />
                  {actor.targeted_sectors.slice(0, 2).join(", ")}
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}

      {/* Empty */}
      {!loading && filtered.length === 0 && (
        <div className="card p-12 text-center">
          <p className="text-4xl mb-3">🕵️</p>
          <p className="text-lg font-medium text-l-text dark:text-gray-200">No actors found</p>
          <p className="text-sm text-l-sub dark:text-gray-500 mt-1">Try a different filter or search term</p>
        </div>
      )}
    </div>
  );
}
