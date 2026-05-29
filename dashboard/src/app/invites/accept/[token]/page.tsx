"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  Building2,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Clock,
  Shield,
  Github,
} from "lucide-react";
import { acceptInvite } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { createClient } from "@/lib/supabase/client";

export default function AcceptInvitePage() {
  const { user } = useAuth();
  const params = useParams();
  const router = useRouter();
  const token = params.token as string;

  const [status, setStatus] = useState<
    "loading" | "success" | "signup_required" | "error"
  >("loading");
  const [orgName, setOrgName] = useState("");
  const [orgId, setOrgId] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [error, setError] = useState("");
  const [oauthLoading, setOauthLoading] = useState<"github" | "google" | null>(
    null
  );

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setError("Invalid invite link.");
      return;
    }

    const doAccept = async () => {
      try {
        const result = await acceptInvite(token, user?.id);

        if (result.requires_signup) {
          setOrgName(result.org_name || "Organization");
          setInviteEmail(result.email || "");
          setStatus("signup_required");
          return;
        }

        if (result.org_id) {
          setOrgId(result.org_id);
          setOrgName(result.org_name || "Organization");
          setStatus("success");
          setTimeout(() => {
            router.push(`/org/${result.org_id}/dashboard`);
          }, 2000);
        } else {
          setStatus("error");
          setError("Failed to accept invite.");
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Failed to accept invite.";
        setStatus("error");

        // Map backend errors to user-friendly messages
        if (msg.includes("expired")) {
          setError("This invite has expired.");
        } else if (msg.includes("already been used")) {
          setError("This invite has already been used.");
        } else if (msg.includes("already a member")) {
          setError("You are already a member of this organization.");
        } else if (msg.includes("Invalid")) {
          setError("Invalid invite link.");
        } else {
          setError(msg);
        }
      }
    };

    doAccept();
  }, [token, user, router]);

  const handleOAuth = async (provider: "github" | "google") => {
    setOauthLoading(provider);
    try {
      const supabase = createClient();
      const appUrl =
        typeof window !== "undefined"
          ? window.location.origin
          : process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

      await supabase.auth.signInWithOAuth({
        provider,
        options: {
          redirectTo: `${appUrl}/auth/callback?invite=${token}`,
        },
      });
    } catch (err) {
      console.error("OAuth error:", err);
      setOauthLoading(null);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-l-bg dark:bg-void">
      <div className="card p-8 max-w-md w-full text-center animate-fade-in">
        {/* Loading */}
        {status === "loading" && (
          <>
            <Loader2 className="h-10 w-10 mx-auto mb-4 text-acid animate-spin" />
            <h1 className="font-display font-bold text-xl text-l-text dark:text-gray-100 mb-2">
              {user ? "Joining Organization…" : "Checking Invitation…"}
            </h1>
            <p className="text-sm text-l-sub dark:text-gray-500">
              Please wait while we process your invite.
            </p>
          </>
        )}

        {/* Success */}
        {status === "success" && (
          <>
            <div className="p-3 rounded-full bg-emerald-500/10 border border-emerald-500/20 w-fit mx-auto mb-4">
              <CheckCircle2 className="h-10 w-10 text-emerald-400" />
            </div>
            <h1 className="font-display font-bold text-xl text-l-text dark:text-gray-100 mb-2">
              Welcome to {orgName}!
            </h1>
            <p className="text-sm text-l-sub dark:text-gray-500 mb-4">
              You&apos;ve successfully joined the organization. Redirecting to
              your new workspace…
            </p>
            <Link
              href={`/org/${orgId}/dashboard`}
              className="btn-primary text-sm inline-flex items-center gap-2"
            >
              <Building2 className="h-4 w-4" />
              Go to {orgName}
            </Link>
          </>
        )}

        {/* Signup Required */}
        {status === "signup_required" && (
          <>
            <div className="p-3 rounded-full bg-acid/10 border border-acid/20 w-fit mx-auto mb-4">
              <Building2 className="h-10 w-10 text-acid" />
            </div>
            <h1 className="font-display font-bold text-xl text-l-text dark:text-gray-100 mb-2">
              You&apos;re invited to join{" "}
              <span className="text-acid">{orgName}</span>
            </h1>
            <p className="text-sm text-l-sub dark:text-gray-500 mb-6">
              Create your KnowCVE account to accept this invitation
              {inviteEmail && (
                <span className="block mt-1 font-mono text-xs text-l-muted dark:text-gray-600">
                  Invited as {inviteEmail}
                </span>
              )}
            </p>

            <div className="space-y-3">
              <button
                onClick={() => handleOAuth("github")}
                disabled={oauthLoading !== null}
                className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-lg
                           bg-l-text dark:bg-white text-white dark:text-gray-900
                           font-medium text-sm
                           hover:opacity-90 transition-all active:scale-[0.98]
                           disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Github className="h-5 w-5" />
                {oauthLoading === "github"
                  ? "Redirecting..."
                  : "Sign Up with GitHub"}
              </button>

              <button
                onClick={() => handleOAuth("google")}
                disabled={oauthLoading !== null}
                className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-lg
                           border border-l-border dark:border-border
                           bg-l-surface dark:bg-surface
                           text-l-text dark:text-gray-200
                           font-medium text-sm
                           hover:bg-l-panel dark:hover:bg-panel transition-all active:scale-[0.98]
                           disabled:opacity-50 disabled:cursor-not-allowed"
              >
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
                {oauthLoading === "google"
                  ? "Redirecting..."
                  : "Sign Up with Google"}
              </button>
            </div>

            <div className="mt-6 flex items-center gap-3">
              <div className="flex-1 h-px bg-l-border dark:bg-border" />
              <span className="text-[10px] font-mono uppercase tracking-wider text-l-sub dark:text-gray-600">
                Already have an account?
              </span>
              <div className="flex-1 h-px bg-l-border dark:bg-border" />
            </div>

            <Link
              href={`/auth/login?invite=${token}`}
              className="mt-3 text-sm text-acid hover:text-acid/80 transition-colors inline-block"
            >
              Sign in instead →
            </Link>
          </>
        )}

        {/* Error */}
        {status === "error" && (
          <>
            <div className="p-3 rounded-full bg-red-500/10 border border-red-500/20 w-fit mx-auto mb-4">
              {error.includes("expired") ? (
                <Clock className="h-10 w-10 text-red-400" />
              ) : error.includes("already") ? (
                <Shield className="h-10 w-10 text-amber-400" />
              ) : (
                <AlertTriangle className="h-10 w-10 text-red-400" />
              )}
            </div>
            <h1 className="font-display font-bold text-xl text-l-text dark:text-gray-100 mb-2">
              {error.includes("expired")
                ? "Invitation Expired"
                : error.includes("already been used")
                  ? "Already Used"
                  : error.includes("already a member")
                    ? "Already a Member"
                    : "Invitation Error"}
            </h1>
            <p className="text-sm text-red-400 mb-4">{error}</p>
            <div className="flex items-center justify-center gap-3">
              <Link
                href="/"
                className="btn-ghost text-sm border border-l-border dark:border-border"
              >
                Go to Homepage
              </Link>
              {error.includes("already a member") && (
                <Link
                  href="/workspace"
                  className="btn-primary text-sm"
                >
                  Go to Workspace
                </Link>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
