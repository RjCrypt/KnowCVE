"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Shield,
  ShieldCheck,
  Search,
  Building2,
  User,
  ArrowRight,
  Check,
  SkipForward,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/* ── Role cards ────────────────────────────────── */

const ROLES = [
  {
    id: "security_analyst",
    label: "Security Analyst",
    desc: "SOC, blue team, vulnerability management",
    icon: ShieldCheck,
    color: "text-acid",
    border: "border-acid/30",
    bg: "bg-acid/10",
  },
  {
    id: "pentest_consultant",
    label: "Pentest Consultant",
    desc: "Offensive security, red team, assessments",
    icon: Search,
    color: "text-purple-400",
    border: "border-purple-500/30",
    bg: "bg-purple-500/10",
  },
  {
    id: "mssp",
    label: "MSSP / MSP",
    desc: "Managed security services, multi-client",
    icon: Building2,
    color: "text-blue-400",
    border: "border-blue-500/30",
    bg: "bg-blue-500/10",
  },
  {
    id: "solo_researcher",
    label: "Solo Researcher",
    desc: "Independent researcher, bug bounty, hobbyist",
    icon: User,
    color: "text-amber-400",
    border: "border-amber-500/30",
    bg: "bg-amber-500/10",
  },
];

/* ── Main ──────────────────────────────────────── */

export default function OnboardingPage() {
  const router = useRouter();
  const { user, refreshProfile } = useAuth();
  const [step, setStep] = useState(1);
  const [role, setRole] = useState<string | null>(null);
  const [techContext, setTechContext] = useState("");
  const [saving, setSaving] = useState(false);

  const completeOnboarding = async () => {
    if (!user) return;
    setSaving(true);

    try {
      await fetch(`${API_BASE}/api/auth/profile/${user.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          role: role || "security_analyst",
          tech_context: techContext || null,
          onboarding_complete: true,
        }),
      });
      await refreshProfile();
      router.push("/");
    } catch (err) {
      console.error("Onboarding save failed:", err);
      router.push("/");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex min-h-[calc(100vh-3.5rem)] items-center justify-center px-4 py-12">
      <div className="w-full max-w-lg animate-fade-in">
        {/* Progress dots */}
        <div className="flex items-center justify-center gap-2 mb-8">
          {[1, 2, 3].map((s) => (
            <div
              key={s}
              className={cn(
                "h-2 rounded-full transition-all duration-300",
                s === step
                  ? "w-8 bg-acid"
                  : s < step
                  ? "w-2 bg-acid/50"
                  : "w-2 bg-l-border dark:bg-border"
              )}
            />
          ))}
        </div>

        {/* Step 1: Role */}
        {step === 1 && (
          <div className="space-y-6 animate-fade-in">
            <div className="text-center">
              <h1 className="font-display font-bold text-2xl text-l-text dark:text-gray-100 mb-2">
                What describes you best?
              </h1>
              <p className="text-sm text-l-sub dark:text-gray-400">
                We'll tailor your dashboard experience
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {ROLES.map((r) => {
                const Icon = r.icon;
                return (
                  <button
                    key={r.id}
                    onClick={() => setRole(r.id)}
                    className={cn(
                      "card p-4 text-left transition-all duration-200",
                      role === r.id
                        ? `${r.border} ${r.bg} ring-1 ring-inset ring-current ${r.color}`
                        : "border-l-border dark:border-border hover:border-l-muted dark:hover:border-muted"
                    )}
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className={cn(
                          "p-2 rounded-lg",
                          role === r.id ? r.bg : "bg-l-panel dark:bg-panel"
                        )}
                      >
                        <Icon
                          className={cn(
                            "h-5 w-5",
                            role === r.id
                              ? r.color
                              : "text-l-sub dark:text-gray-500"
                          )}
                        />
                      </div>
                      <div>
                        <div className="font-medium text-sm text-l-text dark:text-gray-200">
                          {r.label}
                        </div>
                        <div className="text-xs text-l-sub dark:text-gray-500 mt-0.5">
                          {r.desc}
                        </div>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>

            <button
              onClick={() => setStep(2)}
              disabled={!role}
              className="w-full btn-primary flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Continue <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Step 2: Tech Context */}
        {step === 2 && (
          <div className="space-y-6 animate-fade-in">
            <div className="text-center">
              <h1 className="font-display font-bold text-2xl text-l-text dark:text-gray-100 mb-2">
                What tech do you monitor?
              </h1>
              <p className="text-sm text-l-sub dark:text-gray-400">
                Optional — helps us surface relevant CVEs
              </p>
            </div>

            <div className="card p-5">
              <textarea
                value={techContext}
                onChange={(e) => setTechContext(e.target.value)}
                placeholder="e.g. nginx, Apache, Windows Server, Kubernetes, AWS, PostgreSQL..."
                rows={4}
                maxLength={500}
                className="input-base w-full resize-none"
              />
              <p className="text-[10px] font-mono text-l-sub dark:text-gray-600 mt-2">
                Comma-separated technologies. Used for future watchlist features.
              </p>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => setStep(3)}
                className="flex-1 btn-ghost flex items-center justify-center gap-2 border border-l-border dark:border-border"
              >
                <SkipForward className="h-4 w-4" /> Skip
              </button>
              <button
                onClick={() => setStep(3)}
                className="flex-1 btn-primary flex items-center justify-center gap-2"
              >
                Continue <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Confirmation */}
        {step === 3 && (
          <div className="space-y-6 animate-fade-in text-center">
            <div className="inline-flex p-4 rounded-2xl bg-acid/10 border border-acid/20 mx-auto">
              <Check className="h-10 w-10 text-acid" />
            </div>

            <div>
              <h1 className="font-display font-bold text-2xl text-l-text dark:text-gray-100 mb-2">
                You're all set
              </h1>
              <p className="text-sm text-l-sub dark:text-gray-400">
                Your workspace is ready. Start monitoring vulnerabilities.
              </p>
            </div>

            <div className="card p-4 text-left space-y-2">
              <div className="flex items-center gap-2 text-sm text-l-sub dark:text-gray-400">
                <Check className="h-4 w-4 text-acid shrink-0" />
                Full CVE feed with AI analysis
              </div>
              <div className="flex items-center gap-2 text-sm text-l-sub dark:text-gray-400">
                <Check className="h-4 w-4 text-acid shrink-0" />
                Exploit intelligence & IOC data
              </div>
              <div className="flex items-center gap-2 text-sm text-l-sub dark:text-gray-400">
                <Check className="h-4 w-4 text-acid shrink-0" />
                25 CVE bookmarks with notes
              </div>
              <div className="flex items-center gap-2 text-sm text-l-sub dark:text-gray-400">
                <Check className="h-4 w-4 text-acid shrink-0" />
                KnowCVE Risk Score (KRS)
              </div>
            </div>

            <button
              onClick={completeOnboarding}
              disabled={saving}
              className="w-full btn-primary flex items-center justify-center gap-2 disabled:opacity-60"
            >
              {saving ? (
                "Setting up..."
              ) : (
                <>
                  Go to Dashboard <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
