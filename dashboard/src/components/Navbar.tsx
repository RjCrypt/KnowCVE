"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Sun, Moon, Activity, Menu, X, Crosshair } from "lucide-react";
import { useEffect, useState } from "react";
import { useTheme } from "./ThemeProvider";
import { getHealth } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function Navbar() {
  const { theme, toggle } = useTheme();
  const pathname = usePathname();
  const [alive, setAlive] = useState<boolean | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);

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

  // Close mobile menu on route change
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

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

  const mobileLink = (href: string, label: string, accent?: string) => (
    <Link
      href={href}
      className={cn(
        "block text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
        pathname === href
          ? accent
            ? `${accent}`
            : "text-acid bg-acid/10"
          : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel"
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

          <nav className="hidden md:flex items-center gap-1">
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

            {/* Exploit Intel link — purple accent with crosshair */}
            <Link
              href="/exploit-intel"
              className={cn(
                "text-sm font-medium transition-colors px-3 py-1.5 rounded-md flex items-center gap-1.5",
                pathname === "/exploit-intel" || pathname.startsWith("/exploit-intel/")
                  ? "text-purple-400 bg-purple-500/10"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
              )}
            >
              <Crosshair className="h-3.5 w-3.5" />
              Exploit Intel
            </Link>

            {/* KRS link — acid accent */}
            {navLink("/krs", "KRS", "text-acid bg-acid/10")}

            {navLink("/stats", "Stats")}
          </nav>
        </div>

        {/* Right — Status + Theme + Mobile toggle */}
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

          {/* Mobile hamburger */}
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="md:hidden btn-ghost rounded-lg p-2"
            aria-label="Toggle menu"
          >
            {mobileOpen ? (
              <X className="h-4 w-4" />
            ) : (
              <Menu className="h-4 w-4" />
            )}
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="md:hidden border-t border-l-border dark:border-border glass animate-fade-in">
          <nav className="mx-auto max-w-7xl px-4 py-3 space-y-1">
            {mobileLink("/", "Dashboard")}
            <Link
              href="/threats"
              className={cn(
                "flex items-center gap-2 text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
                pathname === "/threats"
                  ? "text-red-400 bg-red-500/10"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              <span className="h-2 w-2 rounded-full bg-red-500" />
              Threats
            </Link>
            <Link
              href="/exploit-intel"
              className={cn(
                "flex items-center gap-2 text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
                pathname === "/exploit-intel" || pathname.startsWith("/exploit-intel/")
                  ? "text-purple-400 bg-purple-500/10"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              <Crosshair className="h-3.5 w-3.5" />
              Exploit Intel
            </Link>
            {mobileLink("/krs", "KRS", "text-acid bg-acid/10")}
            {mobileLink("/stats", "Stats")}
          </nav>
        </div>
      )}
    </header>
  );
}
