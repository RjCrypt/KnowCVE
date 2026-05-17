"use client";

import { useState } from "react";
import Link from "next/link";
import { Check, Star, Zap, Building2, Globe, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import WaitlistModal from "@/components/WaitlistModal";
import Footer from "@/components/layout/Footer";

/* ── Tier data ─────────────────────────────────── */

interface Tier {
  name: string;
  price: string;
  annualPrice?: string;
  period: string;
  badge?: string;
  badgeColor?: string;
  description: string;
  features: string[];
  cta: string;
  ctaAction: "login" | "waitlist" | "mailto";
  tier?: string;
  accent: string;
  border: string;
  bg: string;
  popular?: boolean;
}

const TIERS: Tier[] = [
  {
    name: "Free",
    price: "$0",
    period: "forever",
    description: "Full intelligence access for individual researchers",
    features: [
      "Real-time CVE feed with AI analysis",
      "Full AI explanations & attack chains",
      "Exploit intelligence & EMS scores",
      "IOC Pulse lookups",
      "KnowCVE Risk Score (KRS)",
      "Threat actor & ransomware intel",
      "25 CVE bookmarks",
      "Telegram alerts",
    ],
    cta: "Get Started Free",
    ctaAction: "login",
    accent: "text-acid",
    border: "border-acid/20",
    bg: "bg-acid/5",
  },
  {
    name: "Pro",
    price: "$29",
    annualPrice: "$23",
    period: "/mo",
    badge: "Coming Soon",
    badgeColor: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    description: "Advanced tools for security professionals",
    features: [
      "Everything in Free",
      "Unlimited bookmarks",
      "Tech stack watchlist (20 CPEs)",
      "Personal exposure score",
      "Daily digest email",
      "Priority support",
    ],
    cta: "Join Waitlist",
    ctaAction: "waitlist",
    tier: "pro",
    accent: "text-purple-400",
    border: "border-purple-500/20",
    bg: "bg-purple-500/5",
  },
  {
    name: "Team",
    price: "$99",
    annualPrice: "$79",
    period: "/mo",
    badge: "Most Popular",
    badgeColor: "bg-acid/15 text-acid border-acid/30",
    description: "Collaborative vulnerability management for teams",
    features: [
      "Everything in Pro",
      "Asset register (50 assets)",
      "CVE triage board with SLA timers",
      "Compliance PDF snapshots",
      "5 team members",
      "Team Telegram channel",
    ],
    cta: "Join Waitlist",
    ctaAction: "waitlist",
    tier: "team",
    accent: "text-acid",
    border: "border-acid/20",
    bg: "bg-acid/5",
    popular: true,
  },
  {
    name: "MSSP",
    price: "$299",
    annualPrice: "$239",
    period: "/mo",
    badge: "Coming Soon",
    badgeColor: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    description: "Multi-client intelligence for managed security providers",
    features: [
      "Everything in Team",
      "Multi-client workspaces (20 clients)",
      "Per-client dashboards",
      "API access",
      "White-label reports",
      "Dedicated account manager",
    ],
    cta: "Contact Us",
    ctaAction: "mailto",
    tier: "mssp",
    accent: "text-blue-400",
    border: "border-blue-500/20",
    bg: "bg-blue-500/5",
  },
];

/* ── Main ──────────────────────────────────────── */

export default function PricingPage() {
  const [annual, setAnnual] = useState(false);
  const [waitlistTier, setWaitlistTier] = useState<{
    tier: string;
    label: string;
  } | null>(null);

  const handleCTA = (tier: Tier) => {
    if (tier.ctaAction === "mailto") {
      window.location.href = "mailto:contact@knowcve.com?subject=MSSP%20Plan%20Inquiry";
    } else if (tier.ctaAction === "waitlist" && tier.tier) {
      setWaitlistTier({ tier: tier.tier, label: tier.name });
    }
    // login action handled by Link component
  };

  return (
    <div className="mx-auto max-w-6xl px-4 sm:px-6 py-12 animate-fade-in">
      {/* Header */}
      <div className="text-center mb-12">
        <h1 className="font-display font-bold text-3xl sm:text-4xl text-l-text dark:text-gray-100 mb-3">
          Intelligence for every{" "}
          <span className="text-acid">security team</span>
        </h1>
        <p className="text-base text-l-sub dark:text-gray-400 max-w-xl mx-auto mb-8">
          Start free with full CVE feed access. Scale up when you need advanced
          tooling, team collaboration, or multi-client management.
        </p>

        {/* Annual toggle */}
        <div className="inline-flex items-center gap-3 p-1 rounded-lg border border-l-border dark:border-border bg-l-panel dark:bg-panel">
          <button
            onClick={() => setAnnual(false)}
            className={cn(
              "px-4 py-1.5 rounded-md text-sm font-medium transition-all",
              !annual
                ? "bg-l-surface dark:bg-surface text-l-text dark:text-gray-200 shadow-sm"
                : "text-l-sub dark:text-gray-500"
            )}
          >
            Monthly
          </button>
          <button
            onClick={() => setAnnual(true)}
            className={cn(
              "px-4 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-1.5",
              annual
                ? "bg-l-surface dark:bg-surface text-l-text dark:text-gray-200 shadow-sm"
                : "text-l-sub dark:text-gray-500"
            )}
          >
            Annual
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-acid/10 text-acid border border-acid/20">
              -20%
            </span>
          </button>
        </div>
      </div>

      {/* Tier grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-12">
        {TIERS.map((tier) => (
          <div
            key={tier.name}
            className={cn(
              "card p-6 flex flex-col relative",
              tier.popular &&
                "ring-2 ring-acid/30 border-acid/30 shadow-lg shadow-acid/5"
            )}
          >
            {/* Badge */}
            {tier.badge && (
              <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                <span
                  className={cn(
                    "badge text-[10px] py-0.5 px-3",
                    tier.badgeColor
                  )}
                >
                  {tier.popular && (
                    <Star className="h-3 w-3 fill-current mr-1" />
                  )}
                  {tier.badge}
                </span>
              </div>
            )}

            {/* Tier name */}
            <h3
              className={cn(
                "font-display font-bold text-lg mb-1",
                tier.accent
              )}
            >
              {tier.name}
            </h3>

            {/* Price */}
            <div className="flex items-baseline gap-1 mb-1">
              <span className="font-display font-bold text-3xl text-l-text dark:text-gray-100">
                {annual && tier.annualPrice
                  ? tier.annualPrice
                  : tier.price}
              </span>
              {tier.period !== "forever" && (
                <span className="text-sm text-l-sub dark:text-gray-500">
                  {tier.period}
                </span>
              )}
            </div>

            {annual && tier.annualPrice && (
              <p className="text-[10px] font-mono text-l-sub dark:text-gray-600 mb-3">
                billed annually
              </p>
            )}
            {tier.period === "forever" && (
              <p className="text-[10px] font-mono text-acid mb-3">
                available now
              </p>
            )}

            <p className="text-xs text-l-sub dark:text-gray-400 mb-5 leading-relaxed">
              {tier.description}
            </p>

            {/* Features */}
            <ul className="space-y-2 mb-6 flex-1">
              {tier.features.map((feature) => (
                <li
                  key={feature}
                  className="flex items-start gap-2 text-xs text-l-sub dark:text-gray-400"
                >
                  <Check
                    className={cn("h-3.5 w-3.5 mt-0.5 shrink-0", tier.accent)}
                  />
                  {feature}
                </li>
              ))}
            </ul>

            {/* CTA */}
            {tier.ctaAction === "login" ? (
              <Link
                href="/auth/login"
                className={cn(
                  "w-full text-center py-2.5 rounded-lg text-sm font-medium transition-all",
                  "bg-acid text-void hover:bg-acid-dim active:scale-[0.98]"
                )}
              >
                {tier.cta}
              </Link>
            ) : (
              <button
                onClick={() => handleCTA(tier)}
                className={cn(
                  "w-full py-2.5 rounded-lg text-sm font-medium border transition-all active:scale-[0.98]",
                  tier.popular
                    ? "bg-acid/10 text-acid border-acid/20 hover:bg-acid/20"
                    : "bg-l-panel dark:bg-panel text-l-sub dark:text-gray-400 border-l-border dark:border-border hover:text-l-text dark:hover:text-gray-200"
                )}
              >
                {tier.cta}
              </button>
            )}
          </div>
        ))}
      </div>

      {/* Trust bar */}
      <div className="text-center">
        <div className="inline-flex items-center gap-6 text-xs font-mono text-l-sub dark:text-gray-500">
          <span className="flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5 text-acid" />
            Open-source KRS formula
          </span>
          <span className="flex items-center gap-1.5">
            <Globe className="h-3.5 w-3.5 text-acid" />
            4,400+ CVEs tracked
          </span>
          <span className="flex items-center gap-1.5">
            <Zap className="h-3.5 w-3.5 text-acid" />
            Real-time updates
          </span>
        </div>
      </div>

      {/* Waitlist Modal */}
      {waitlistTier && (
        <WaitlistModal
          tier={waitlistTier.tier}
          tierLabel={waitlistTier.label}
          onClose={() => setWaitlistTier(null)}
        />
      )}

      <div className="mt-12" />
      <Footer />
    </div>
  );
}
