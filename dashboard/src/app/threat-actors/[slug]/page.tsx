"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ArrowLeft, ExternalLink, Globe, Crosshair } from "lucide-react";
import { getThreatActor } from "@/lib/api";
import type { ThreatActorDetail } from "@/types/cve";
import { cn } from "@/lib/utils";
import Link from "next/link";

export default function ThreatActorDetailPage() {
  const params = useParams();
  const slug = params.slug as string;
  const [actor, setActor] = useState<ThreatActorDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const data = await getThreatActor(slug);
        setActor(data);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    })();
  }, [slug]);

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl px-4 sm:px-6 py-8 space-y-4">
        <div className="skeleton h-8 w-48" />
        <div className="skeleton h-4 w-full" />
        <div className="skeleton h-4 w-2/3" />
        <div className="card p-6"><div className="skeleton h-32 w-full" /></div>
      </div>
    );
  }

  if (!actor) {
    return (
      <div className="mx-auto max-w-4xl px-4 sm:px-6 py-12 text-center">
        <p className="text-4xl mb-3">🕵️</p>
        <p className="text-lg font-medium text-l-text dark:text-gray-200">Actor not found</p>
        <Link href="/threat-actors" className="text-blue-400 text-sm mt-2 inline-block hover:underline">
          ← Back to Threat Actors
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 py-8 space-y-6">
      {/* Back link */}
      <Link
        href="/threat-actors"
        className="inline-flex items-center gap-1.5 text-sm text-l-sub dark:text-gray-400 hover:text-blue-400 transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        All Threat Actors
      </Link>

      {/* Header */}
      <div className="card p-6 border-blue-500/20">
        <div className="h-1 bg-gradient-to-r from-blue-500 via-cyan-500 to-blue-600 -mt-6 -mx-6 mb-5 rounded-t-xl" />
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
              {actor.name}
            </h1>
            {actor.aliases.length > 0 && (
              <p className="text-sm text-l-sub dark:text-gray-400 mt-1">
                Also known as: {actor.aliases.join(" · ")}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "text-xs font-medium px-3 py-1 rounded-full border",
                actor.is_active
                  ? "bg-acid/10 border-acid/30 text-acid"
                  : "bg-gray-500/10 border-gray-500/30 text-gray-400"
              )}
            >
              {actor.is_active ? "Active" : "Inactive"}
            </span>
            {actor.mitre_url && (
              <a
                href={actor.mitre_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-xs text-blue-400 hover:underline"
              >
                MITRE <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>
        </div>

        <p className="text-sm text-l-sub dark:text-gray-300 mt-4 leading-relaxed">
          {actor.description}
        </p>

        {/* Metadata grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6">
          <div>
            <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500">Origin</p>
            <p className="text-sm font-medium text-l-text dark:text-gray-200">{actor.origin_country || "Unknown"}</p>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500">Sophistication</p>
            <p className="text-sm font-medium text-blue-400">{actor.sophistication}</p>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500">Motivation</p>
            <p className="text-sm font-medium text-purple-400">{actor.motivation}</p>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500">Active Period</p>
            <p className="text-sm font-medium text-l-text dark:text-gray-200">{actor.first_seen}–{actor.last_active || "present"}</p>
          </div>
        </div>

        {/* Sectors & Countries */}
        <div className="mt-4 flex flex-wrap gap-4">
          <div>
            <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500 mb-1.5">Targeted Sectors</p>
            <div className="flex flex-wrap gap-1.5">
              {actor.targeted_sectors.map((s) => (
                <span key={s} className="badge text-[10px] py-0.5 bg-amber-500/10 border-amber-500/20 text-amber-400">
                  {s}
                </span>
              ))}
            </div>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500 mb-1.5">Targeted Countries</p>
            <div className="flex flex-wrap gap-1.5">
              {actor.targeted_countries.map((c) => (
                <span key={c} className="badge text-[10px] py-0.5 bg-cyan-500/10 border-cyan-500/20 text-cyan-400">
                  <Globe className="h-3 w-3" /> {c}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Exploited CVEs */}
      <div className="card p-6">
        <h2 className="text-lg font-semibold text-l-text dark:text-gray-100 mb-4 flex items-center gap-2">
          <Crosshair className="h-5 w-5 text-red-400" />
          Exploited CVEs ({actor.exploited_cves?.length || 0})
        </h2>

        {(!actor.exploited_cves || actor.exploited_cves.length === 0) ? (
          <p className="text-sm text-l-sub dark:text-gray-500">No CVE mappings recorded yet.</p>
        ) : (
          <div className="space-y-2">
            {actor.exploited_cves.map((cve) => (
              <Link
                key={cve.cve_id}
                href={`/cve/${cve.cve_id}`}
                className="flex items-center justify-between p-3 rounded-lg bg-l-panel dark:bg-panel hover:bg-l-panel/80 dark:hover:bg-panel/80 transition-colors border border-l-border dark:border-border"
              >
                <div>
                  <span className="font-mono text-sm font-medium text-red-400">{cve.cve_id}</span>
                  {cve.notes && (
                    <p className="text-xs text-l-sub dark:text-gray-400 mt-0.5 line-clamp-1">{cve.notes}</p>
                  )}
                </div>
                <span
                  className={cn(
                    "text-[10px] font-medium px-2 py-0.5 rounded-full border",
                    cve.confirmed
                      ? "bg-red-500/10 border-red-500/30 text-red-400"
                      : "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
                  )}
                >
                  {cve.confirmed ? "Confirmed" : "Suspected"}
                </span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
