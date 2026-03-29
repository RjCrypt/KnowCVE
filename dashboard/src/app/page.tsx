import { Suspense } from "react";
import StatsBar from "@/components/StatsBar";
import CVEFeed from "@/components/CVEFeed";
import Footer from "@/components/layout/Footer";

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

      {/* CVE feed */}
      <Suspense fallback={null}>
        <CVEFeed />
      </Suspense>

      <div className="mt-12" />
      <Footer />
    </div>
  );
}
