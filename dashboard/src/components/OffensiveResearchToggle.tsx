"use client";

import { useState, useEffect } from "react";
import { Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth-context";

const LS_KEY = "knowcve_offensive_research_mode";

interface OffensiveResearchToggleProps {
  onToggle?: (enabled: boolean) => void;
}

export default function OffensiveResearchToggle({
  onToggle,
}: OffensiveResearchToggleProps) {
  const { user } = useAuth();
  const [enabled, setEnabled] = useState(false);
  const [tooltip, setTooltip] = useState<string | null>(null);

  // Load from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem(LS_KEY);
    if (stored === "true") {
      // Only enable if user is logged in
      if (user) {
        setEnabled(true);
        onToggle?.(true);
      } else {
        // Auto-reset if logged out
        localStorage.setItem(LS_KEY, "false");
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  const handleToggle = () => {
    if (!user) {
      setTooltip("Sign in to enable Offensive Research Mode");
      setTimeout(() => setTooltip(null), 2500);
      return;
    }

    const newValue = !enabled;
    setEnabled(newValue);
    localStorage.setItem(LS_KEY, String(newValue));
    onToggle?.(newValue);
  };

  return (
    <div className="relative inline-flex items-center">
      <button
        onClick={handleToggle}
        className={cn(
          "flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all duration-200",
          enabled
            ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
            : "bg-l-panel dark:bg-panel text-l-sub dark:text-gray-500 border-l-border dark:border-border hover:border-amber-500/30 hover:text-amber-400",
          !user && "opacity-70"
        )}
      >
        <Terminal className="h-3.5 w-3.5" />
        <span>Offensive Research Mode</span>
        <div
          className={cn(
            "relative w-7 h-4 rounded-full transition-colors duration-200",
            enabled ? "bg-amber-500" : "bg-l-muted dark:bg-muted"
          )}
        >
          <div
            className={cn(
              "absolute top-0.5 h-3 w-3 rounded-full bg-white transition-transform duration-200",
              enabled ? "translate-x-3.5" : "translate-x-0.5"
            )}
          />
        </div>
      </button>

      {/* Tooltip */}
      {tooltip && (
        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2.5 py-1.5 rounded-md text-[11px] font-mono
                        bg-l-text dark:bg-white text-white dark:text-gray-900 whitespace-nowrap shadow-lg animate-fade-in z-50">
          {tooltip}
          <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-px border-4 border-transparent border-t-l-text dark:border-t-white" />
        </div>
      )}
    </div>
  );
}

/* ── Hook for consuming components ─────────────── */

export function useOffensiveMode() {
  const { user } = useAuth();
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem(LS_KEY);
    if (stored === "true" && user) {
      setEnabled(true);
    } else {
      setEnabled(false);
    }
  }, [user]);

  return enabled;
}
