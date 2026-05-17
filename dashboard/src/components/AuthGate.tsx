"use client";

import { Lock, LogIn } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import type { User } from "@supabase/supabase-js";

interface AuthGateProps {
  user: User | null;
  blur?: "light" | "heavy";
  message?: string;
  children: React.ReactNode;
}

export default function AuthGate({
  user,
  blur = "heavy",
  message = "Sign in to unlock this content",
  children,
}: AuthGateProps) {
  if (user) {
    return <>{children}</>;
  }

  return (
    <div className="relative rounded-xl overflow-hidden">
      {/* Blurred content */}
      <div
        className={cn(
          "pointer-events-none select-none",
          blur === "heavy" ? "blur-md opacity-40" : "blur-sm opacity-50"
        )}
        aria-hidden="true"
      >
        {children}
      </div>

      {/* Overlay with CTA */}
      <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-l-bg/40 dark:bg-void/50 backdrop-blur-[2px] rounded-xl">
        <div className="p-3 rounded-xl bg-l-panel/80 dark:bg-panel/80 border border-l-border dark:border-border">
          <Lock className="h-5 w-5 text-l-sub dark:text-gray-500" />
        </div>
        <p className="text-sm font-medium text-l-text dark:text-gray-200 text-center px-4">
          {message}
        </p>
        <Link
          href="/auth/login"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
                     bg-acid/10 text-acid border border-acid/20
                     hover:bg-acid/20 transition-all"
        >
          <LogIn className="h-4 w-4" />
          Sign In — it's free
        </Link>
      </div>
    </div>
  );
}
