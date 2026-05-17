"use client";

import { useEffect, useState } from "react";
import { Newspaper, RefreshCcw, ExternalLink, Flame, Zap, TrendingUp, ShieldAlert, ArrowRight } from "lucide-react";
import { getSecurityNews, getNewsBriefing } from "@/lib/api";
import type { SecurityNewsItem } from "@/types/cve";
import { cn } from "@/lib/utils";
import Link from "next/link";

export default function NewsPage() {
  const [articles, setArticles] = useState<SecurityNewsItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [briefing, setBriefing] = useState<string | null>(null);
  const [briefingLoading, setBriefingLoading] = useState(true);
  const [filter, setFilter] = useState<"all" | "with-cves">("all");

  const fetchData = async () => {
    try {
      const [news, brief] = await Promise.allSettled([
        getSecurityNews({ limit: 50, has_cves: filter === "with-cves" }),
        getNewsBriefing(),
      ]);
      if (news.status === "fulfilled") setArticles(news.value);
      if (brief.status === "fulfilled") setBriefing(brief.value.briefing);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      setBriefingLoading(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    fetchData();
    const id = setInterval(fetchData, 600_000); // 10 min
    return () => clearInterval(id);
  }, [filter]);

  // Derived sections
  const breakingNews = articles.slice(0, 5);
  const quickReads = articles.slice(5, 11);
  const standardNews = articles.slice(11);

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-2xl bg-gradient-to-br from-amber-500/20 to-orange-600/10 border border-amber-500/30 shadow-[0_0_15px_rgba(245,158,11,0.15)] flex-shrink-0">
            <Newspaper className="h-8 w-8 text-amber-400" />
          </div>
          <div>
            <h1 className="text-3xl font-display font-bold text-transparent bg-clip-text bg-gradient-to-r from-amber-400 to-orange-400">
              Security News & Intelligence
            </h1>
            <p className="text-sm text-l-sub dark:text-gray-400 mt-1">
              Aggregated from 15+ sources · AI-summarized · Contextualized
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="flex gap-1 bg-l-panel dark:bg-panel/50 backdrop-blur-sm border border-border/50 rounded-lg p-1">
            <button
              onClick={() => setFilter("all")}
              className={cn(
                "text-sm font-medium px-4 py-2 rounded-md transition-all duration-300",
                filter === "all"
                  ? "bg-amber-500/15 text-amber-400 border border-amber-500/30 shadow-sm"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
              )}
            >
              All News
            </button>
            <button
              onClick={() => setFilter("with-cves")}
              className={cn(
                "text-sm font-medium px-4 py-2 rounded-md transition-all duration-300",
                filter === "with-cves"
                  ? "bg-amber-500/15 text-amber-400 border border-amber-500/30 shadow-sm"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
              )}
            >
              CVE Mentions
            </button>
          </div>
          <button
            onClick={() => { setLoading(true); fetchData(); }}
            className="flex items-center justify-center h-10 w-10 rounded-lg bg-l-panel dark:bg-panel border border-border/50 text-l-sub hover:text-amber-400 hover:border-amber-500/30 transition-all shadow-sm flex-shrink-0"
            title="Refresh News"
          >
            <RefreshCcw className={cn("h-4 w-4", loading && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* Breaking Bulletin Marquee */}
      {!loading && breakingNews.length > 0 && (
        <div className="relative flex items-center overflow-hidden rounded-xl bg-gradient-to-r from-red-500/10 via-orange-500/5 to-transparent border border-red-500/20 py-3 px-4 shadow-sm">
          <div className="flex items-center gap-2 pr-4 border-r border-red-500/20 shrink-0 z-10 bg-[#f4f5f7] dark:bg-[#080a0f]">
            <Flame className="h-5 w-5 text-red-500 animate-pulse" />
            <span className="text-sm font-semibold text-red-500 tracking-wider uppercase">Breaking</span>
          </div>
          <div className="flex flex-1 overflow-hidden ml-4 [mask-image:linear-gradient(to_right,transparent,black_5%,black_95%,transparent)]">
             <div className="flex w-max animate-marquee gap-8 py-1 px-4 hover:[animation-play-state:paused]">
                {[...breakingNews, ...breakingNews].map((article, idx) => (
                  <Link key={`marquee-${idx}`} href={article.url} target="_blank" className="text-sm text-l-text dark:text-gray-200 hover:text-amber-500 transition-colors flex items-center gap-2 min-w-max">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                    {article.title}
                  </Link>
                ))}
             </div>
          </div>
        </div>
      )}

      {/* Daily Briefing */}
      {!briefingLoading && briefing && (
        <div className="relative group overflow-hidden rounded-2xl border border-amber-500/30 bg-gradient-to-br from-amber-500/10 via-background to-background p-[1px] isolate shadow-sm">
            <div className="absolute inset-0 bg-gradient-to-r from-amber-500/10 to-orange-500/5 opacity-50 group-hover:opacity-100 transition-opacity duration-700" />
            <div className="relative bg-l-surface dark:bg-[#0a0a0b] rounded-2xl p-6 md:p-8 backdrop-blur-xl">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-display font-semibold text-amber-500 flex items-center gap-2">
                  <TrendingUp className="h-5 w-5" />
                  AI Intelligence Briefing
                </h2>
                <span className="text-xs px-2 py-1 bg-amber-500/10 text-amber-600 dark:text-amber-500 rounded border border-amber-500/20 tracking-wider font-medium">
                  AUTO-GENERATED
                </span>
              </div>
              <p className="text-sm md:text-base text-l-text dark:text-gray-300 whitespace-pre-wrap font-sans leading-relaxed">
                {briefing}
              </p>
            </div>
        </div>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Quick Reads */}
        {!loading && quickReads.length > 0 && (
          <div className="lg:col-span-1 space-y-4">
            <div className="flex items-center gap-2 mb-4 border-b border-border/50 pb-2">
              <Zap className="h-5 w-5 text-yellow-500" />
              <h3 className="text-lg font-semibold text-l-text dark:text-gray-100">Quick Reads</h3>
            </div>
            <div className="grid grid-cols-1 gap-3">
              {quickReads.map((article, i) => (
                <div
                  key={article.id || `quick-${i}`}
                  className="group relative overflow-hidden rounded-xl border border-l-border dark:border-border/50 bg-l-surface dark:bg-panel/30 hover:bg-l-panel dark:hover:bg-panel/80 p-4 transition-all duration-300 hover:shadow-md hover:border-amber-500/30 cursor-pointer"
                  onClick={() => window.open(article.url, '_blank')}
                  style={{ animationDelay: `${i * 20}ms` }}
                >
                  <div className="flex justify-between items-start gap-2 mb-2">
                     <span className="text-[10px] text-gray-500 dark:text-gray-400 font-mono uppercase tracking-wider">{article.source}</span>
                     <p className="text-[10px] text-gray-400 dark:text-gray-500">
                      {article.published_at ? new Date(article.published_at).toLocaleDateString() : ""}
                     </p>
                  </div>
                  <h4 className="text-sm font-medium text-l-text dark:text-gray-200 group-hover:text-amber-600 dark:group-hover:text-amber-400 transition-colors line-clamp-2 leading-snug">
                    {article.title}
                  </h4>
                  <div className="flex flex-wrap gap-1 mt-3">
                    {article.mentioned_cves?.slice(0, 2).map((cve) => (
                      <span key={cve} className="text-[9px] bg-red-500/10 text-red-600 dark:text-red-400 px-1.5 py-0.5 rounded border border-red-500/20">
                        {cve}
                      </span>
                    ))}
                  </div>
                  <div className="absolute top-4 right-4 opacity-0 transform -translate-x-2 translate-y-2 group-hover:opacity-100 group-hover:translate-x-0 group-hover:translate-y-0 transition-all duration-300">
                    <ArrowRight className="h-4 w-4 text-amber-500" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Right Columns: Standard News Feed */}
        <div className="lg:col-span-2 space-y-4">
           <div className="flex items-center gap-2 mb-4 border-b border-border/50 pb-2">
              <ShieldAlert className="h-5 w-5 text-blue-500" />
              <h3 className="text-lg font-semibold text-l-text dark:text-gray-100">Latest Intelligence Reports</h3>
            </div>

            {loading && (
              <div className="space-y-4">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="card p-5 rounded-xl border border-border/50">
                    <div className="skeleton h-5 w-3/4 mb-4 rounded" />
                    <div className="skeleton h-3 w-full mb-2 rounded" />
                    <div className="skeleton h-3 w-5/6 mb-4 rounded" />
                    <div className="skeleton h-8 w-24 rounded-lg" />
                  </div>
                ))}
              </div>
            )}

            {!loading && standardNews.length > 0 && (
              <div className="space-y-4">
                {standardNews.map((article, i) => (
                  <div
                    key={article.id || `std-${i}`}
                    className="group card p-5 hover:border-amber-500/30 transition-all duration-300 hover:shadow-lg animate-slide-up rounded-xl bg-l-surface dark:bg-panel/40 backdrop-blur-sm relative overflow-hidden"
                    style={{ animationDelay: `${i * 30}ms` }}
                  >
                    {/* Hover Gradient Effect */}
                    <div className="absolute inset-0 bg-gradient-to-r from-amber-500/0 via-amber-500/0 to-amber-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none" />
                    
                    <div className="relative flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-black/5 border border-black/10 dark:bg-white/5 dark:border-white/10 text-l-sub dark:text-gray-400 transition-colors">
                            {article.source}
                          </span>
                          <span className="text-[10px] text-gray-400 dark:text-gray-500">
                            • {article.published_at ? new Date(article.published_at).toLocaleString() : ""}
                          </span>
                        </div>

                        <a
                          href={article.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-base font-semibold text-l-text dark:text-gray-100 group-hover:text-amber-600 dark:group-hover:text-amber-400 transition-colors inline-flex items-start gap-2"
                        >
                          <span className="line-clamp-2 leading-snug">{article.title}</span>
                          <ExternalLink className="h-4 w-4 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-all transform group-hover:translate-x-1 group-hover:-translate-y-1 mt-0.5 text-amber-500" />
                        </a>

                        {article.summary && (
                          <p className="text-sm text-l-sub dark:text-gray-400 mt-2 line-clamp-3 leading-relaxed">
                            {article.summary}
                          </p>
                        )}

                        {/* Tags: CVEs + Actors */}
                        <div className="flex flex-wrap gap-2 mt-4">
                          {article.mentioned_cves?.map((cve) => (
                            <Link
                              key={cve}
                              href={`/cve/${cve}`}
                              className="text-xs bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 hover:bg-red-500/20 hover:text-red-500 px-2 py-1 rounded-md transition-colors flex items-center gap-1"
                            >
                              <Flame className="w-3 h-3 flex-shrink-0" />
                              {cve}
                            </Link>
                          ))}
                          {article.mentioned_actors?.map((actor) => (
                            <span
                              key={actor}
                              className="text-xs bg-blue-500/10 border border-blue-500/20 text-blue-600 dark:text-blue-400 px-2 py-1 rounded-md flex items-center gap-1"
                            >
                              <ShieldAlert className="w-3 h-3 flex-shrink-0" />
                              {actor}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Empty State */}
            {!loading && articles.length === 0 && (
              <div className="card p-12 text-center rounded-2xl border-dashed border-2 border-border/50 shadow-sm bg-l-surface dark:bg-panel/40">
                <div className="mx-auto w-16 h-16 rounded-full bg-l-panel dark:bg-gray-800 flex items-center justify-center mb-4">
                  <Newspaper className="h-8 w-8 text-l-sub dark:text-gray-500" />
                </div>
                <p className="text-lg font-medium text-l-text dark:text-gray-200">No signals detected</p>
                <p className="text-sm text-l-sub dark:text-gray-500 mt-2 max-w-md mx-auto">
                  Our intelligence feeds are currently quiet. New articles and breach reports will appear here automatically when detected.
                </p>
              </div>
            )}
        </div>
      </div>
    </div>
  );
}
