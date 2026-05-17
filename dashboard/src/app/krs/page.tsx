"use client";

import { useEffect, useState } from "react";
import { Shield, Zap, ExternalLink } from "lucide-react";
import { getKRSFormula } from "@/lib/api";
import { cn } from "@/lib/utils";
import Footer from "@/components/layout/Footer";

/* ── Score label cards ─────────────────────────── */

const LABELS = [
  { label: "CRITICAL", range: "75–100", color: "text-red-400", bg: "bg-red-500/15", border: "border-red-500/30", bar: "bg-red-500" },
  { label: "HIGH",     range: "50–74",  color: "text-amber-400", bg: "bg-amber-500/15", border: "border-amber-500/30", bar: "bg-amber-500" },
  { label: "MEDIUM",   range: "25–49",  color: "text-yellow-300", bg: "bg-yellow-500/15", border: "border-yellow-500/30", bar: "bg-yellow-500" },
  { label: "LOW",      range: "0–24",   color: "text-blue-400", bg: "bg-blue-500/15", border: "border-blue-500/30", bar: "bg-blue-500" },
];

const COMPONENTS = [
  {
    name: "CVSS Severity",
    weight: "35%",
    calc: "(cvss_score / 10) × 35",
    description: "Base vulnerability severity from NVD. A CVSS 9.8 contributes 34.3 points.",
    accent: "text-red-400",
    bg: "bg-red-500/5",
    border: "border-red-500/20",
  },
  {
    name: "EPSS Probability",
    weight: "25%",
    calc: "epss_score × 25",
    description: "FIRST.org exploit prediction score. Higher EPSS = higher chance of real-world exploitation.",
    accent: "text-orange-400",
    bg: "bg-orange-500/5",
    border: "border-orange-500/20",
  },
  {
    name: "CISA KEV",
    weight: "20%",
    calc: "20 if confirmed, else 0",
    description: "Is this CVE in CISA's Known Exploited Vulnerabilities catalog? If yes, it's confirmed in-the-wild.",
    accent: "text-red-400",
    bg: "bg-red-500/5",
    border: "border-red-500/20",
  },
  {
    name: "PoC Available",
    weight: "15%",
    calc: "15 if public PoC exists, else 0",
    description: "Public proof-of-concept exploit code found on GitHub. Lowers the barrier for attackers.",
    accent: "text-amber-400",
    bg: "bg-amber-500/5",
    border: "border-amber-500/20",
  },
  {
    name: "Recency Bonus",
    weight: "±15",
    calc: "+15 (<24h), +8 (<72h), +3 (<7d), −10 (>30d)",
    description: "New vulnerabilities get a boost. Ancient ones get penalized. Fresh threats demand faster action.",
    accent: "text-emerald-400",
    bg: "bg-emerald-500/5",
    border: "border-emerald-500/20",
  },
  {
    name: "GreyNoise Scanning",
    weight: "+20 max",
    calc: "Tiered: +6 (>10 IPs), +12 (>100), +20 (>500)",
    description: "Live internet scanning activity from GreyNoise. More scanners = actively being probed in the wild.",
    accent: "text-purple-400",
    bg: "bg-purple-500/5",
    border: "border-purple-500/20",
  },
];

export default function KRSPage() {
  const [formula, setFormula] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    getKRSFormula()
      .then(setFormula)
      .catch(() => {});
  }, []);

  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 py-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-3 mb-2">
        <div className="p-2 rounded-xl bg-acid/10 border border-acid/20">
          <Shield className="h-6 w-6 text-acid" />
        </div>
        <div>
          <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
            KnowCVE Risk Score{" "}
            <span className="text-acid">— How We Prioritize What Matters</span>
          </h1>
          <p className="text-sm text-l-sub dark:text-gray-400">
            An open, transparent composite score that helps defenders prioritize real-world exploitation risk
          </p>
        </div>
      </div>

      {/* Live formula badge */}
      {formula && (
        <div className="flex items-center gap-2 mt-2 mb-8">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-acid/10 text-acid border border-acid/20">
            v{(formula as Record<string, string>).version || "1.0"} · LIVE FROM API
          </span>
        </div>
      )}

      {/* Section 1 — Why KRS? */}
      <div className="card p-5 mb-6">
        <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-100 mb-3 flex items-center gap-2">
          <Zap className="h-5 w-5 text-acid" />
          Why KRS?
        </h2>
        <div className="space-y-3 text-sm text-l-sub dark:text-gray-400 leading-relaxed">
          <p>
            As a defender, you don&apos;t have time to patch everything. CVSS alone doesn&apos;t tell you{" "}
            <em>what attackers are actually using right now</em>. A{" "}
            <strong className="text-l-text dark:text-gray-200">
              CVSS 9.8
            </strong>{" "}
            with no public exploit poses{" "}
            <em>less immediate risk to your environment</em> than a{" "}
            <strong className="text-l-text dark:text-gray-200">
              CVSS 7.5
            </strong>{" "}
            that has a working PoC, active scanning campaigns, and
            CISA KEV confirmation.
          </p>
          <p>
            KRS helps your team{" "}
            <strong className="text-acid">
              focus patching effort where it matters most
            </strong>{" "}
            — by weighing real-world exploitation signals more heavily than theoretical severity.
            When your SLA clock is ticking, KRS tells you which CVEs to patch first.
          </p>
        </div>
      </div>

      {/* Section 2 — Formula breakdown */}
      <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-4">
        Formula Breakdown
      </h2>
      <div className="grid gap-3 mb-8">
        {COMPONENTS.map((c) => (
          <div
            key={c.name}
            className={cn(
              "card p-4 border",
              c.border,
              c.bg
            )}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className={cn("font-display font-semibold text-sm", c.accent)}>
                    {c.name}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-l-panel dark:bg-panel text-l-sub dark:text-gray-500 border border-l-border dark:border-border">
                    {c.weight}
                  </span>
                </div>
                <p className="text-xs text-l-sub dark:text-gray-400 mb-2">
                  {c.description}
                </p>
                <code className="text-[11px] font-mono text-l-text dark:text-gray-300 bg-l-panel dark:bg-panel px-2 py-1 rounded border border-l-border dark:border-border">
                  {c.calc}
                </code>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Section 3 — Score labels */}
      <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-4">
        Score Labels
      </h2>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        {LABELS.map((l) => (
          <div
            key={l.label}
            className={cn(
              "card px-4 py-4 text-center border",
              l.border,
              l.bg
            )}
          >
            <div className={cn("font-display font-bold text-2xl", l.color)}>
              {l.label}
            </div>
            <div className="text-sm font-mono text-l-sub dark:text-gray-500 mt-1">
              {l.range}
            </div>
            <div className={cn("h-1 rounded-full mt-3", l.bar)} />
          </div>
        ))}
      </div>

      {/* Section 4 — Compare to CVSS */}
      <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-4">
        Compare to CVSS
      </h2>
      <div className="card p-5 mb-8">
        <div className="space-y-4">
          {/* CVE-A */}
          <div className="flex items-start gap-4 p-3 rounded-lg bg-l-panel dark:bg-panel border border-l-border dark:border-border">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-sm text-l-text dark:text-gray-200 font-medium">
                  CVE-A
                </span>
                <span className="badge bg-red-500/15 border-red-500/30 text-red-400 text-[10px] py-0.5">
                  CVSS 9.8
                </span>
              </div>
              <p className="text-xs text-l-sub dark:text-gray-400">
                No PoC · Not in KEV · EPSS 0.02 · No scanning
              </p>
            </div>
            <div className="text-right">
              <span className="badge bg-yellow-500/15 border-yellow-500/30 text-yellow-300 text-sm py-1 px-3">
                KRS 42
              </span>
              <div className="text-[10px] font-mono text-yellow-300 mt-1">
                MEDIUM
              </div>
            </div>
          </div>

          {/* CVE-B */}
          <div className="flex items-start gap-4 p-3 rounded-lg bg-l-panel dark:bg-panel border border-acid/20">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-sm text-l-text dark:text-gray-200 font-medium">
                  CVE-B
                </span>
                <span className="badge bg-amber-500/15 border-amber-500/30 text-amber-400 text-[10px] py-0.5">
                  CVSS 7.5
                </span>
              </div>
              <p className="text-xs text-l-sub dark:text-gray-400">
                PoC available · In CISA KEV · EPSS 0.78 · 200+ IPs scanning
              </p>
            </div>
            <div className="text-right">
              <span className="badge bg-red-500/15 border-red-500/30 text-red-400 text-sm py-1 px-3">
                KRS 85
              </span>
              <div className="text-[10px] font-mono text-red-400 mt-1">
                CRITICAL
              </div>
            </div>
          </div>

          <p className="text-sm text-l-sub dark:text-gray-400 text-center mt-2">
            <strong className="text-acid">CVE-B demands your attention first</strong>{" "}
            — despite having a lower CVSS score.
          </p>
        </div>
      </div>

      {/* Footer link */}
      <div className="text-center mb-8">
        <a
          href="https://github.com/RjCrypt/KnowCVE"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 text-sm font-mono text-acid hover:text-acid-dim transition-colors"
        >
          KRS formula is open source — view on GitHub{" "}
          <ExternalLink className="h-3.5 w-3.5" />
        </a>
      </div>

      <Footer />
    </div>
  );
}
