"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  LayoutDashboard,
  Bookmark,
  Cpu,
  Shield,
  Mail,
  Lock,
  ArrowRight,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn, priorityColor } from "@/lib/utils";
import Footer from "@/components/layout/Footer";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface BookmarkPreview {
  cve_id: string;
  note: string | null;
  created_at: string;
  cve_data?: {
    priority_score: number;
    priority_label: string;
    description: string;
  } | null;
}

const COMING_SOON_FEATURES = [
  {
    title: "Tech Stack Watchlist",
    desc: "Monitor CVEs targeting your specific technologies. Get notified when a new vulnerability affects your stack.",
    icon: Cpu,
    color: "text-purple-400",
    border: "border-purple-500/20",
    bg: "bg-purple-500/5",
  },
  {
    title: "Personal Exposure Score",
    desc: "AI-calculated risk score based on your declared tech stack, factoring in active exploits and EPSS trends.",
    icon: Shield,
    color: "text-amber-400",
    border: "border-amber-500/20",
    bg: "bg-amber-500/5",
  },
  {
    title: "Daily Digest",
    desc: "Morning email with the highest-priority CVEs from the last 24 hours, filtered to your tech context.",
    icon: Mail,
    color: "text-blue-400",
    border: "border-blue-500/20",
    bg: "bg-blue-500/5",
  },
];

export default function WorkspacePage() {
  const { user, profile } = useAuth();
  const [recentBookmarks, setRecentBookmarks] = useState<BookmarkPreview[]>([]);

  useEffect(() => {
    if (!user) return;

    const fetchBookmarks = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/bookmarks/${user.id}`);
        if (res.ok) {
          const data = await res.json();
          setRecentBookmarks(data.slice(0, 5));
        }
      } catch {
        // Silently fail
      }
    };

    fetchBookmarks();
  }, [user]);

  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 py-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <div className="p-2 rounded-xl bg-acid/10 border border-acid/20">
          <LayoutDashboard className="h-6 w-6 text-acid" />
        </div>
        <div>
          <h1 className="text-2xl font-display font-bold text-l-text dark:text-gray-100">
            My Workspace
          </h1>
          <p className="text-sm text-l-sub dark:text-gray-400">
            {profile?.display_name
              ? `Welcome back, ${profile.display_name}`
              : "Your personal vulnerability dashboard"}
          </p>
        </div>
      </div>

      {/* Onboarding banner (if not completed) */}
      {profile && !profile.onboarding_complete && (
        <div className="card p-4 mb-6 border-acid/20 bg-acid/5 animate-fade-in">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-medium text-l-text dark:text-gray-200">
                Complete your profile setup
              </p>
              <p className="text-xs text-l-sub dark:text-gray-400 mt-0.5">
                Tell us about your role and tech stack to personalize your
                experience
              </p>
            </div>
            <Link
              href="/onboarding"
              className="btn-primary text-xs shrink-0"
            >
              Set Up
            </Link>
          </div>
        </div>
      )}

      {/* Recent Bookmarks */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 flex items-center gap-2">
            <Bookmark className="h-5 w-5 text-acid" />
            Recent Bookmarks
          </h2>
          {recentBookmarks.length > 0 && (
            <Link
              href="/bookmarks"
              className="text-xs font-mono text-acid hover:text-acid-dim transition-colors"
            >
              View all →
            </Link>
          )}
        </div>

        {recentBookmarks.length > 0 ? (
          <div className="space-y-2">
            {recentBookmarks.map((bm) => {
              const colors = bm.cve_data
                ? priorityColor(bm.cve_data.priority_label)
                : null;
              return (
                <Link
                  key={bm.cve_id}
                  href={`/cve/${bm.cve_id}`}
                  className="card card-hover p-3 flex items-center justify-between gap-3 block"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="font-mono text-sm text-acid font-medium shrink-0">
                      {bm.cve_id}
                    </span>
                    {colors && (
                      <span
                        className={cn(
                          "badge text-[10px] py-0.5 shrink-0",
                          colors.bg,
                          colors.border,
                          colors.text
                        )}
                      >
                        {bm.cve_data!.priority_label}
                      </span>
                    )}
                    {bm.note && (
                      <span className="text-xs text-l-sub dark:text-gray-500 truncate">
                        — {bm.note}
                      </span>
                    )}
                  </div>
                  <ArrowRight className="h-3.5 w-3.5 text-l-sub dark:text-gray-600 shrink-0" />
                </Link>
              );
            })}
          </div>
        ) : (
          <div className="card p-6 text-center">
            <p className="text-sm text-l-sub dark:text-gray-500">
              No bookmarks yet.{" "}
              <Link href="/" className="text-acid hover:underline">
                Browse the feed
              </Link>{" "}
              to start tracking CVEs.
            </p>
          </div>
        )}
      </div>

      {/* Coming Soon Features */}
      <div className="mb-8">
        <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-4">
          Coming in Pro
        </h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {COMING_SOON_FEATURES.map((feature) => {
            const Icon = feature.icon;
            return (
              <div
                key={feature.title}
                className={cn(
                  "card p-4 border opacity-60",
                  feature.border,
                  feature.bg
                )}
              >
                <div className="flex items-center gap-2 mb-2">
                  <Icon className={cn("h-5 w-5", feature.color)} />
                  <span
                    className={cn(
                      "font-display font-semibold text-sm",
                      feature.color
                    )}
                  >
                    {feature.title}
                  </span>
                </div>
                <p className="text-xs text-l-sub dark:text-gray-500 leading-relaxed mb-3">
                  {feature.desc}
                </p>
                <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-l-panel dark:bg-panel border border-l-border dark:border-border text-l-sub dark:text-gray-500">
                  <Lock className="h-3 w-3" />
                  Coming in Pro
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Pro CTA */}
      <div className="card p-6 border-acid/20 bg-gradient-to-r from-acid/5 to-transparent text-center">
        <h3 className="font-display font-bold text-lg text-l-text dark:text-gray-100 mb-2">
          Unlock the full workspace
        </h3>
        <p className="text-sm text-l-sub dark:text-gray-400 mb-4 max-w-md mx-auto">
          Tech stack watchlists, personal exposure scores, and daily digests —
          join the Pro waitlist to be first in line.
        </p>
        <Link
          href="/pricing"
          className="btn-primary inline-flex items-center gap-2 text-xs"
        >
          View Pricing <ArrowRight className="h-4 w-4" />
        </Link>
      </div>

      <div className="mt-12" />
      <Footer />
    </div>
  );
}
