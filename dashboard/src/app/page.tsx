"use client";

import { Suspense } from "react";
import StatsBar from "@/components/StatsBar";
import CVEFeed from "@/components/CVEFeed";
import CategorySection from "@/components/CategorySection";
import Footer from "@/components/layout/Footer";
import { getCVEsByCategory, getTrendingCVEs, getFreshCVEs } from "@/lib/api";

export default function DashboardPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 animate-fade-in">
      {/* Heading */}
      <div className="mb-6">
        <h1 className="font-display font-bold text-3xl sm:text-4xl tracking-tight text-l-text dark:text-gray-100">
          Vulnerability{" "}
          <span className="text-acid">Intelligence</span>
        </h1>
        <p className="mt-1 font-mono text-sm text-l-sub dark:text-gray-500">
          Real-time CVE monitoring · AI-enriched analysis · Priority scoring
        </p>
      </div>

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
