"use client";

import { useState, useEffect, useCallback } from "react";
import { Bookmark } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth-context";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface BookmarkButtonProps {
  cveId: string;
  className?: string;
  size?: "sm" | "md";
}

export default function BookmarkButton({
  cveId,
  className,
  size = "md",
}: BookmarkButtonProps) {
  const { user } = useAuth();
  const [bookmarked, setBookmarked] = useState(false);
  const [loading, setLoading] = useState(false);
  const [tooltip, setTooltip] = useState<string | null>(null);

  // Check if already bookmarked
  useEffect(() => {
    if (!user) return;

    const checkBookmark = async () => {
      try {
        const res = await fetch(
          `${API_BASE}/api/bookmarks/${user.id}`
        );
        if (res.ok) {
          const bookmarks = await res.json();
          const found = bookmarks.some(
            (b: { cve_id: string }) =>
              b.cve_id.toUpperCase() === cveId.toUpperCase()
          );
          setBookmarked(found);
        }
      } catch {
        // Silently fail
      }
    };

    checkBookmark();
  }, [user, cveId]);

  const toggleBookmark = useCallback(
    async (e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();

      if (!user) {
        setTooltip("Sign in to bookmark");
        setTimeout(() => setTooltip(null), 2000);
        return;
      }

      setLoading(true);
      const wasBookmarked = bookmarked;
      setBookmarked(!bookmarked); // Optimistic

      try {
        if (wasBookmarked) {
          await fetch(
            `${API_BASE}/api/bookmarks/${user.id}/${cveId}`,
            { method: "DELETE" }
          );
        } else {
          const res = await fetch(`${API_BASE}/api/bookmarks`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user_id: user.id, cve_id: cveId }),
          });
          if (!res.ok) {
            const data = await res.json();
            if (res.status === 403) {
              setTooltip(data.detail || "Bookmark limit reached");
              setTimeout(() => setTooltip(null), 3000);
              setBookmarked(wasBookmarked); // Revert
            }
          }
        }
      } catch {
        setBookmarked(wasBookmarked); // Revert on error
      } finally {
        setLoading(false);
      }
    },
    [user, bookmarked, cveId]
  );

  const iconSize = size === "sm" ? "h-3.5 w-3.5" : "h-4 w-4";
  const btnSize = size === "sm" ? "p-1.5" : "p-2";

  return (
    <div className={cn("relative inline-flex", className)}>
      <button
        onClick={toggleBookmark}
        disabled={loading}
        className={cn(
          "rounded-lg transition-all duration-200",
          btnSize,
          bookmarked
            ? "text-acid bg-acid/10 hover:bg-acid/20"
            : "text-l-sub dark:text-gray-500 hover:text-acid hover:bg-acid/5",
          loading && "opacity-50"
        )}
        aria-label={bookmarked ? "Remove bookmark" : "Bookmark CVE"}
      >
        <Bookmark
          className={cn(iconSize, bookmarked && "fill-current")}
        />
      </button>

      {/* Tooltip */}
      {tooltip && (
        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2.5 py-1 rounded-md text-[11px] font-mono
                        bg-l-text dark:bg-white text-white dark:text-gray-900 whitespace-nowrap shadow-lg animate-fade-in z-50">
          {tooltip}
          <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-px border-4 border-transparent border-t-l-text dark:border-t-white" />
        </div>
      )}
    </div>
  );
}
