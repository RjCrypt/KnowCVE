"use client";

import { useState } from "react";
import {
  X,
  Check,
  Loader2,
  Mail,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface WaitlistModalProps {
  tier: string;
  tierLabel: string;
  onClose: () => void;
}

export default function WaitlistModal({
  tier,
  tierLabel,
  onClose,
}: WaitlistModalProps) {
  const { user, profile } = useAuth();
  const [email, setEmail] = useState(profile?.email || user?.email || "");
  const [status, setStatus] = useState<
    "idle" | "loading" | "success" | "already" | "error"
  >("idle");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;

    setStatus("loading");
    try {
      const res = await fetch(`${API_BASE}/api/waitlist`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), tier }),
      });

      if (res.ok) {
        const data = await res.json();
        setStatus(data.already_registered ? "already" : "success");
      } else if (res.status === 429) {
        setStatus("error");
      } else {
        setStatus("error");
      }
    } catch {
      setStatus("error");
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-md card p-6 border-l-border dark:border-border shadow-2xl animate-slide-up z-10">
        {/* Close */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1 rounded-lg text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-200 transition-colors"
        >
          <X className="h-5 w-5" />
        </button>

        {status === "success" || status === "already" ? (
          /* Success state */
          <div className="text-center py-4 animate-fade-in">
            <div className="inline-flex p-3 rounded-2xl bg-acid/10 border border-acid/20 mb-4">
              <Check className="h-8 w-8 text-acid" />
            </div>
            <h3 className="font-display font-bold text-lg text-l-text dark:text-gray-100 mb-2">
              {status === "already"
                ? "You're already on the list!"
                : "You're on the waitlist!"}
            </h3>
            <p className="text-sm text-l-sub dark:text-gray-400">
              {status === "already"
                ? `We already have ${email} registered for ${tierLabel}. We'll reach out when it's ready.`
                : `We'll notify ${email} when ${tierLabel} launches. Thanks for your interest!`}
            </p>
            <button onClick={onClose} className="btn-primary text-xs mt-6">
              Done
            </button>
          </div>
        ) : (
          /* Form state */
          <>
            <div className="flex items-center gap-2 mb-1">
              <Mail className="h-5 w-5 text-acid" />
              <h3 className="font-display font-bold text-lg text-l-text dark:text-gray-100">
                Join the {tierLabel} Waitlist
              </h3>
            </div>
            <p className="text-sm text-l-sub dark:text-gray-400 mb-6">
              Be the first to know when {tierLabel} launches. No commitment.
            </p>

            <form onSubmit={handleSubmit}>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                required
                className="input-base w-full mb-3"
                autoFocus
              />

              {status === "error" && (
                <p className="text-xs text-red-400 mb-3">
                  Something went wrong. Please try again.
                </p>
              )}

              <button
                type="submit"
                disabled={status === "loading" || !email.trim()}
                className="w-full btn-primary flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {status === "loading" ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Joining...
                  </>
                ) : (
                  "Join Waitlist"
                )}
              </button>
            </form>

            <p className="text-[10px] text-center text-l-sub dark:text-gray-600 mt-4 font-mono">
              No spam · Unsubscribe anytime
            </p>
          </>
        )}
      </div>
    </div>
  );
}
