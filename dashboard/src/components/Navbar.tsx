"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Sun, Moon, Activity } from "lucide-react";
import { useEffect, useState } from "react";
import { useTheme } from "./ThemeProvider";
import { getHealth } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function Navbar() {
  const { theme, toggle } = useTheme();
  const pathname = usePathname();
  const [alive, setAlive] = useState<boolean | null>(null);

  useEffect(() => {
    let mounted = true;
    const check = async () => {
      try {
        await getHealth();
        if (mounted) setAlive(true);
      } catch {
        if (mounted) setAlive(false);
      }
    };
    check();
    const id = setInterval(check, 30_000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  const navLink = (href: string, label: string, accent?: string) => (
    <Link
      href={href}
      className={cn(
        "text-sm font-medium transition-colors px-3 py-1.5 rounded-md",
        pathname === href
          ? accent
            ? `${accent}`
            : "text-acid bg-acid/10"
          : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
      )}
    >
      {label}
    </Link>
  );

  return (
    <header className="sticky top-0 z-50 w-full border-b glass">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
        {/* Left — Logo + Nav */}
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-2 group">
            <Shield className="h-5 w-5 text-acid transition-transform group-hover:scale-110" />
            <span className="font-display font-bold text-lg tracking-tight">
              Know<span className="text-acid">CVE</span>
            </span>
          </Link>

          <nav className="hidden sm:flex items-center gap-1">
            {navLink("/", "Dashboard")}

            {/* Threats link — red accent with pulsing dot */}
            <Link
              href="/threats"
              className={cn(
                "text-sm font-medium transition-colors px-3 py-1.5 rounded-md flex items-center gap-1.5",
                pathname === "/threats"
                  ? "text-red-400 bg-red-500/10"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
              )}
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
              </span>
              Threats
            </Link>

            {/* Zero-Day link — amber accent */}
            {navLink("/zeroday", "Zero-Day", "text-amber-400 bg-amber-500/10")}

            {navLink("/stats", "Stats")}
          </nav>
        </div>

        {/* Right — Status + Theme */}
        <div className="flex items-center gap-3">
          {/* Backend status */}
          <div className="flex items-center gap-1.5 text-xs font-mono text-l-sub dark:text-gray-500">
            <Activity className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">API</span>
            <span
              className={cn(
                "h-2 w-2 rounded-full",
                alive === true && "bg-acid animate-pulse-slow",
                alive === false && "bg-danger",
                alive === null && "bg-muted"
              )}
            />
          </div>

          {/* Mobile nav */}
          <nav className="flex sm:hidden items-center gap-1">
            {navLink("/", "Home")}
            <Link
              href="/threats"
              className={cn(
                "text-sm font-medium transition-colors px-2 py-1.5 rounded-md flex items-center gap-1",
                pathname === "/threats"
                  ? "text-red-400 bg-red-500/10"
                  : "text-l-sub dark:text-gray-400"
              )}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
              Threats
            </Link>
            {navLink("/zeroday", "0-Day", "text-amber-400 bg-amber-500/10")}
            {navLink("/stats", "Stats")}
          </nav>

          {/* Theme toggle */}
          <button
            onClick={toggle}
            className="btn-ghost rounded-lg p-2"
            aria-label="Toggle theme"
          >
            {theme === "dark" ? (
              <Sun className="h-4 w-4" />
            ) : (
              <Moon className="h-4 w-4" />
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
