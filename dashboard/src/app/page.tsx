"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, X } from "lucide-react";
import StatsBar from "@/components/StatsBar";
import CVEFeed from "@/components/CVEFeed";
import CategorySection from "@/components/CategorySection";
import Footer from "@/components/layout/Footer";
import { getCVEsByCategory, getTrendingCVEs, getFreshCVEs, getWatchlistCVEs } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";

export default function DashboardPage() {
  const { user } = useAuth();
  const [matchCount, setMatchCount] = useState(0);
  const [bannerDismissed, setBannerDismissed] = useState(true);

  useEffect(() => {
    // Check localStorage for dismissal
    const dismissed = localStorage.getItem("knowcve_feed_banner_dismissed");
    if (!dismissed) setBannerDismissed(false);
  }, []);

  useEffect(() => {
    if (!user) return;
    getWatchlistCVEs(user.id, 1, 1)
      .then((res) => setMatchCount(res.total || 0))
      .catch(() => {});
  }, [user]);

  const dismissBanner = () => {
    setBannerDismissed(true);
    localStorage.setItem("knowcve_feed_banner_dismissed", "1");
  };

  const showBanner = user && matchCount > 0 && !bannerDismissed;

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 animate-fade-in">
      {/* Heading */}
      <div className="mb-6">
        <h1 className="font-display font-bold text-3xl sm:text-4xl tracking-tight text-l-text dark:text-gray-100">
          Real-time vulnerability{" "}
          <span className="text-acid">intelligence</span>{" "}
          <span className="text-l-text dark:text-gray-100">for security teams</span>
        </h1>
        <p className="mt-1 font-mono text-sm text-l-sub dark:text-gray-500">
          Monitor CVEs that matter to your stack · Triage faster · Stay ahead of active exploits
        </p>
      </div>

      {/* Personalization banner */}
      {showBanner && (
        <div className="mb-4 p-3 rounded-xl border border-acid/20 bg-acid/5 flex items-center justify-between gap-3 animate-fade-in">
          <p className="text-sm text-l-text dark:text-gray-200">
            Showing all CVEs.{" "}
            <span className="text-acid font-medium">{matchCount} CVEs match your stack today.</span>{" "}
            <Link href="/workspace" className="text-acid hover:underline inline-flex items-center gap-1">
              View your personalized feed <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </p>
          <button onClick={dismissBanner} className="text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300 shrink-0">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Stats row */}
      <StatsBar />

      {/* Divider */}
      <div className="my-6 h-px bg-l-border dark:bg-border" />

      {/* ── Categorised sections ──────────────────── */}

      {/* 🔴 Actively Exploited */}
      <CategorySection
        title="Actively Exploited"
        subtitle="Confirmed in-the-wild attacks or mass scanning activity"
        accent="text-red-400"
        accentBorder="border-red-500/20"
        icon="🔴"
        fetchFn={() => getCVEsByCategory("ACTIVELY_EXPLOITED", 5)}
        refreshMs={120_000}
        maxCards={5}
      />

      {/* 🔥 Trending */}
      <CategorySection
        title="Trending"
        subtitle="Gaining momentum — rising EPSS scores or scanning activity"
        accent="text-orange-400"
        accentBorder="border-orange-500/20"
        icon="🔥"
        fetchFn={() => getTrendingCVEs()}
        refreshMs={300_000}
        maxCards={5}
      />

      {/* ⚡ Just Dropped */}
      <CategorySection
        title="Just Dropped"
        subtitle="High-severity CVEs published in the last 48 hours"
        accent="text-emerald-400"
        accentBorder="border-emerald-500/20"
        icon="⚡"
        fetchFn={() => getFreshCVEs(5)}
        refreshMs={300_000}
        maxCards={5}
      />

      {/* ── Full Feed ── */}
      <div className="my-6 h-px bg-l-border dark:bg-border" />

      <Suspense fallback={null}>
        <CVEFeed />
      </Suspense>

      <div className="mt-12" />
      <Footer />
    </div>
  );
}

