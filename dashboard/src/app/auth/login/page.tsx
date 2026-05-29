"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Shield, Github } from "lucide-react";
import { createClient } from "@/lib/supabase/client";
import Footer from "@/components/layout/Footer";

export default function LoginPage() {
  const searchParams = useSearchParams();
  const hasError = searchParams.get("error") === "true";
  const [loading, setLoading] = useState<"github" | "google" | null>(null);
  const supabase = createClient();

  const handleOAuth = async (provider: "github" | "google") => {
    setLoading(provider);
    try {
      // Dynamically get the current domain (works flawlessly on Vercel previews and production)
      const appUrl = typeof window !== "undefined" ? window.location.origin : (process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000");
      
      // Preserve invite token through the OAuth redirect cycle
      const invite = searchParams.get("invite");
      const callbackUrl = `${appUrl}/auth/callback${invite ? `?invite=${invite}` : ""}`;

      await supabase.auth.signInWithOAuth({
        provider,
        options: {
          redirectTo: callbackUrl,
        },
      });
    } catch (err) {
      console.error("OAuth error:", err);
      setLoading(null);
    }
  };

  return (
    <div className="flex min-h-[calc(100vh-3.5rem)] items-center justify-center px-4">
      <div className="w-full max-w-md animate-fade-in">
        {/* Card */}
        <div className="card p-8 sm:p-10 border-l-border dark:border-border">
          {/* Logo */}
          <div className="flex items-center justify-center gap-2.5 mb-6">
            <Shield className="h-7 w-7 text-acid" />
            <span className="font-display font-bold text-2xl tracking-tight">
              Know<span className="text-acid">CVE</span>
            </span>
          </div>

          {/* Headline */}
          <h1 className="font-display font-bold text-xl text-center text-l-text dark:text-gray-100 mb-2">
            Sign in to KnowCVE
          </h1>
          <p className="text-sm text-center text-l-sub dark:text-gray-400 mb-8">
            Real-time vulnerability intelligence for security teams
          </p>

          {/* Error banner */}
          {hasError && (
            <div className="mb-6 p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-sm text-red-400 text-center animate-fade-in">
              Authentication failed. Please try again.
            </div>
          )}

          {/* OAuth buttons */}
          <div className="space-y-3">
            <button
              onClick={() => handleOAuth("github")}
              disabled={loading !== null}
              className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-lg
                         bg-l-text dark:bg-white text-white dark:text-gray-900
                         font-medium text-sm
                         hover:opacity-90 transition-all active:scale-[0.98]
                         disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Github className="h-5 w-5" />
              {loading === "github" ? "Redirecting..." : "Continue with GitHub"}
            </button>

            <button
              onClick={() => handleOAuth("google")}
              disabled={loading !== null}
              className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-lg
                         border border-l-border dark:border-border
                         bg-l-surface dark:bg-surface
                         text-l-text dark:text-gray-200
                         font-medium text-sm
                         hover:bg-l-panel dark:hover:bg-panel transition-all active:scale-[0.98]
                         disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {/* Google icon */}
              <svg className="h-5 w-5" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                />
              </svg>
              {loading === "google"
                ? "Redirecting..."
                : "Continue with Google"}
            </button>
          </div>

          {/* Divider */}
          <div className="mt-8 flex items-center gap-3">
            <div className="flex-1 h-px bg-l-border dark:bg-border" />
            <span className="text-[10px] font-mono uppercase tracking-wider text-l-sub dark:text-gray-600">
              Free forever
            </span>
            <div className="flex-1 h-px bg-l-border dark:bg-border" />
          </div>

          {/* Note */}
          <p className="mt-4 text-xs text-center text-l-sub dark:text-gray-500">
            No credit card required · Full CVE feed access ·{" "}
            <span className="text-acid">25 bookmarks</span>
          </p>
        </div>

        {/* Footer link */}
        <p className="text-center text-xs text-l-sub dark:text-gray-600 mt-6">
          By signing in, you agree to our terms of service.
        </p>
      </div>
    </div>
  );
}
