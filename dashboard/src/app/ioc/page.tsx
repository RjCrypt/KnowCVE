"use client";

import { useState, useEffect } from "react";
import { Search, AlertTriangle, Shield, CheckCircle, HelpCircle, Activity } from "lucide-react";
import { lookupIOC, getIOCFeed } from "@/lib/api";
import type { IOCResult, IOCFeedEntry } from "@/types/cve";
import { cn } from "@/lib/utils";

const verdictConfig: Record<string, { color: string; bg: string; icon: typeof Shield; label: string }> = {
  malicious: { color: "text-red-400", bg: "bg-red-500/10 border-red-500/30", icon: AlertTriangle, label: "MALICIOUS" },
  suspicious: { color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/30", icon: HelpCircle, label: "SUSPICIOUS" },
  clean: { color: "text-acid", bg: "bg-acid/10 border-acid/30", icon: CheckCircle, label: "CLEAN" },
  unknown: { color: "text-gray-400", bg: "bg-gray-500/10 border-gray-500/30", icon: HelpCircle, label: "UNKNOWN" },
};

export default function IOCPage() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<IOCResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [feed, setFeed] = useState<IOCFeedEntry[]>([]);
  const [feedLoading, setFeedLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const data = await getIOCFeed();
        setFeed(data);
      } catch (e) {
        console.error(e);
      } finally {
        setFeedLoading(false);
      }
    })();
  }, []);

  const handleLookup = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await lookupIOC(query.trim());
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const verdict = result ? verdictConfig[result.verdict] || verdictConfig.unknown : null;

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 space-y-8">
      {/* Header */}
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20">
          <Search className="h-6 w-6 text-cyan-400" />
        </div>
        <div>
          <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
            IOC Pulse
          </h1>
          <p className="text-sm text-l-sub dark:text-gray-400">
            Indicator of Compromise lookup — ThreatFox · URLhaus · AbuseIPDB · GreyNoise
          </p>
        </div>
      </div>

      {/* Search hero */}
      <div className="card p-8 text-center border-cyan-500/20">
        <h2 className="text-lg font-semibold text-l-text dark:text-gray-100 mb-1">
          Look up any indicator
        </h2>
        <p className="text-sm text-l-sub dark:text-gray-400 mb-6">
          IP address, domain, URL, or file hash (MD5/SHA1/SHA256)
        </p>
        <div className="flex gap-3 max-w-xl mx-auto">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-l-sub dark:text-gray-500" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleLookup()}
              placeholder="8.8.8.8 · evil.com · https://... · d41d8cd98f..."
              className="w-full pl-10 pr-4 py-3 text-sm rounded-lg bg-l-panel dark:bg-panel border border-l-border dark:border-border focus:outline-none focus:ring-2 focus:ring-cyan-500/30 text-l-text dark:text-gray-200 placeholder:text-l-sub/50 dark:placeholder:text-gray-600"
            />
          </div>
          <button
            onClick={handleLookup}
            disabled={loading || !query.trim()}
            className={cn(
              "px-6 py-3 rounded-lg text-sm font-medium transition-all",
              loading
                ? "bg-cyan-500/20 text-cyan-400 cursor-wait"
                : "bg-cyan-500 text-white hover:bg-cyan-400"
            )}
          >
            {loading ? "Scanning..." : "Lookup"}
          </button>
        </div>

        {/* Privacy notice */}
        <p className="text-[10px] text-l-sub dark:text-gray-600 mt-4">
          🔒 Stateless lookup — we do not log or store queried indicators
        </p>
      </div>

      {/* Error */}
      {error && (
        <div className="card p-4 border-red-500/30 bg-red-500/5">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Result */}
      {result && verdict && (
        <div className="card p-6 animate-slide-up">
          {/* Verdict header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className={cn("p-2 rounded-xl border", verdict.bg)}>
                <verdict.icon className={cn("h-6 w-6", verdict.color)} />
              </div>
              <div>
                <p className={cn("text-lg font-bold", verdict.color)}>{verdict.label}</p>
                <p className="text-xs text-l-sub dark:text-gray-400 font-mono">{result.indicator}</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold font-mono text-l-text dark:text-gray-100">{result.risk_score}</p>
              <p className="text-[10px] text-l-sub dark:text-gray-500">Risk Score</p>
            </div>
          </div>

          {/* Source breakdown */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {/* ThreatFox */}
            {result.sources.threatfox && (
              <div className="p-3 rounded-lg bg-l-panel dark:bg-panel border border-l-border dark:border-border">
                <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500 mb-2">ThreatFox</p>
                {result.sources.threatfox.hit ? (
                  <>
                    <p className="text-sm text-red-400 font-medium">⚠️ HIT</p>
                    {result.sources.threatfox.malware_family && (
                      <p className="text-xs text-l-sub dark:text-gray-400 mt-1">Family: {result.sources.threatfox.malware_family}</p>
                    )}
                    <div className="flex flex-wrap gap-1 mt-1">
                      {result.sources.threatfox.tags?.map((t) => (
                        <span key={t} className="text-[9px] bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded">{t}</span>
                      ))}
                    </div>
                  </>
                ) : (
                  <p className="text-sm text-acid">✓ Clean</p>
                )}
              </div>
            )}

            {/* AbuseIPDB */}
            {result.sources.abuseipdb && (
              <div className="p-3 rounded-lg bg-l-panel dark:bg-panel border border-l-border dark:border-border">
                <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500 mb-2">AbuseIPDB</p>
                <p className={cn("text-sm font-medium", result.sources.abuseipdb.confidence > 50 ? "text-red-400" : result.sources.abuseipdb.confidence > 10 ? "text-yellow-400" : "text-acid")}>
                  {result.sources.abuseipdb.confidence}% confidence
                </p>
                <p className="text-xs text-l-sub dark:text-gray-400 mt-1">{result.sources.abuseipdb.reports} reports</p>
                {result.sources.abuseipdb.isp && (
                  <p className="text-xs text-l-sub dark:text-gray-400">ISP: {result.sources.abuseipdb.isp}</p>
                )}
              </div>
            )}

            {/* URLhaus */}
            {result.sources.urlhaus && (
              <div className="p-3 rounded-lg bg-l-panel dark:bg-panel border border-l-border dark:border-border">
                <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500 mb-2">URLhaus</p>
                <p className={cn("text-sm font-medium", result.sources.urlhaus.status === "online" ? "text-red-400" : result.sources.urlhaus.status === "offline" ? "text-yellow-400" : "text-acid")}>
                  {result.sources.urlhaus.status || "clean"}
                </p>
                {result.sources.urlhaus.urls_count !== undefined && (
                  <p className="text-xs text-l-sub dark:text-gray-400 mt-1">{result.sources.urlhaus.urls_count} URLs tracked</p>
                )}
              </div>
            )}

            {/* GreyNoise */}
            {result.sources.greynoise && (
              <div className="p-3 rounded-lg bg-l-panel dark:bg-panel border border-l-border dark:border-border">
                <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500 mb-2">GreyNoise</p>
                {result.sources.greynoise.riot ? (
                  <p className="text-sm text-acid font-medium">✓ Known benign: {result.sources.greynoise.name}</p>
                ) : result.sources.greynoise.noise ? (
                  <p className="text-sm text-yellow-400 font-medium">⚡ Internet noise ({result.sources.greynoise.classification})</p>
                ) : (
                  <p className="text-sm text-l-sub dark:text-gray-400">No activity</p>
                )}
              </div>
            )}
          </div>

          {result.cached && (
            <p className="text-[10px] text-l-sub dark:text-gray-600 mt-4">📦 Result served from cache (6h TTL)</p>
          )}
        </div>
      )}

      {/* Live IOC Feed */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-l-text dark:text-gray-100 flex items-center gap-2">
            <Activity className="h-5 w-5 text-cyan-400" />
            Live IOC Feed
          </h2>
          <span className="text-[10px] text-l-sub dark:text-gray-500">Source: ThreatFox (24h)</span>
        </div>

        {feedLoading ? (
          <div className="space-y-2">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="skeleton h-8 w-full" />
            ))}
          </div>
        ) : feed.length === 0 ? (
          <p className="text-sm text-l-sub dark:text-gray-500 text-center py-8">No recent IOCs available</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-l-sub dark:text-gray-500 border-b border-l-border dark:border-border">
                  <th className="pb-2 pr-4">Indicator</th>
                  <th className="pb-2 pr-4">Type</th>
                  <th className="pb-2 pr-4">Malware</th>
                  <th className="pb-2">Tags</th>
                </tr>
              </thead>
              <tbody>
                {feed.slice(0, 25).map((ioc, i) => (
                  <tr key={i} className="border-b border-l-border/50 dark:border-border/50 hover:bg-l-panel dark:hover:bg-panel">
                    <td className="py-2 pr-4 font-mono text-l-text dark:text-gray-300 truncate max-w-[240px]">{ioc.indicator}</td>
                    <td className="py-2 pr-4 text-l-sub dark:text-gray-400">{ioc.ioc_type}</td>
                    <td className="py-2 pr-4 text-red-400">{ioc.malware_family || "—"}</td>
                    <td className="py-2">
                      <div className="flex gap-1 flex-wrap">
                        {ioc.tags?.slice(0, 3).map((t) => (
                          <span key={t} className="text-[9px] bg-cyan-500/10 text-cyan-400 px-1.5 py-0.5 rounded">{t}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Disclaimer */}
      <div className="text-[11px] text-l-sub dark:text-gray-600 text-center px-4">
        <p>⚠️ IOC Pulse performs real-time lookups against third-party APIs. Results are for informational purposes only.</p>
        <p>This tool does NOT log, store, or share your queried indicators. All data from public threat intelligence feeds.</p>
      </div>
    </div>
  );
}
