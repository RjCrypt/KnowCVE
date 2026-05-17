"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  Sun,
  Moon,
  Activity,
  Menu,
  X,
  Crosshair,
  ChevronDown,
  User,
  Bookmark,
  Settings,
  LogOut,
  LayoutDashboard,
  DollarSign,
  LogIn,
} from "lucide-react";
import { useEffect, useState, useRef } from "react";
import { useTheme } from "./ThemeProvider";
import { useAuth } from "@/lib/auth-context";
import { getHealth } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function Navbar() {
  const { theme, toggle } = useTheme();
  const { user, profile, signOut } = useAuth();
  const pathname = usePathname();
  const [alive, setAlive] = useState<boolean | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [intelOpen, setIntelOpen] = useState(false);
  const [avatarOpen, setAvatarOpen] = useState(false);

  const intelRef = useRef<HTMLDivElement>(null);
  const avatarRef = useRef<HTMLDivElement>(null);

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

  // Close menus on route change
  useEffect(() => {
    setMobileOpen(false);
    setIntelOpen(false);
    setAvatarOpen(false);
  }, [pathname]);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (intelRef.current && !intelRef.current.contains(e.target as Node)) {
        setIntelOpen(false);
      }
      if (avatarRef.current && !avatarRef.current.contains(e.target as Node)) {
        setAvatarOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  /* ── Helpers ─────────────────────────────── */

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

  const iconLink = (
    href: string,
    label: string,
    Icon: React.ComponentType<{ className?: string }>,
    activeColor: string,
    activeBg: string
  ) => (
    <Link
      href={href}
      className={cn(
        "text-sm font-medium transition-colors px-3 py-1.5 rounded-md flex items-center gap-1.5",
        pathname === href || pathname.startsWith(href + "/")
          ? `${activeColor} ${activeBg}`
          : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
      )}
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
    </Link>
  );

  /* ── Intel Hub items ─────────────────────── */

  const intelItems = [
    { href: "/threat-actors", label: "Threat Actors", emoji: "👥" },
    { href: "/ransomware", label: "Ransomware", emoji: "💀" },
    { href: "/ioc", label: "IOC Pulse", emoji: "🔍" },
    { href: "/news", label: "News", emoji: "📰" },
    { href: "/breaches", label: "Breach Intel", emoji: "⚠️" },
  ];

  const isIntelActive = intelItems.some(
    (item) =>
      pathname === item.href || pathname.startsWith(item.href + "/")
  );

  /* ── Avatar display ──────────────────────── */

  const avatarDisplay = profile?.avatar_url ? (
    <img
      src={profile.avatar_url}
      alt=""
      className="h-7 w-7 rounded-full border border-l-border dark:border-border"
    />
  ) : (
    <div className="h-7 w-7 rounded-full bg-acid/20 border border-acid/30 flex items-center justify-center">
      <span className="text-xs font-mono font-bold text-acid">
        {(profile?.display_name || profile?.email || "U")[0].toUpperCase()}
      </span>
    </div>
  );

  return (
    <header className="sticky top-0 z-50 w-full border-b glass">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
        {/* ── Left — Logo ──────────────────── */}
        <Link href="/" className="flex items-center gap-2 group shrink-0">
          <Shield className="h-5 w-5 text-acid transition-transform group-hover:scale-110" />
          <span className="font-display font-bold text-lg tracking-tight">
            Know<span className="text-acid">CVE</span>
          </span>
        </Link>

        {/* ── Center — Nav Links ──────────── */}
        <nav className="hidden lg:flex items-center gap-0.5 mx-6">
          {navLink("/", "Feed")}

          {/* Active Threats with ping */}
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
            Active Threats
          </Link>

          {iconLink(
            "/exploit-intel",
            "Exploit Intel",
            Crosshair,
            "text-purple-400",
            "bg-purple-500/10"
          )}

          {navLink("/krs", "KRS", "text-acid bg-acid/10")}

          {/* Intel Hub Dropdown */}
          <div className="relative" ref={intelRef}>
            <button
              onClick={() => setIntelOpen(!intelOpen)}
              className={cn(
                "text-sm font-medium transition-colors px-3 py-1.5 rounded-md flex items-center gap-1",
                isIntelActive
                  ? "text-cyan-400 bg-cyan-500/10"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
              )}
            >
              Intel Hub
              <ChevronDown
                className={cn(
                  "h-3.5 w-3.5 transition-transform duration-200",
                  intelOpen && "rotate-180"
                )}
              />
            </button>

            {intelOpen && (
              <div className="absolute top-full left-0 mt-1 w-48 py-1 rounded-lg border card shadow-xl animate-fade-in z-50">
                {intelItems.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-2.5 px-3 py-2 text-sm transition-colors",
                      pathname === item.href ||
                        pathname.startsWith(item.href + "/")
                        ? "text-acid bg-acid/5"
                        : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel"
                    )}
                  >
                    <span>{item.emoji}</span>
                    {item.label}
                  </Link>
                ))}
              </div>
            )}
          </div>

          {/* Divider */}
          <span className="mx-1.5 h-4 w-px bg-l-border dark:bg-border" />

          {navLink("/stats", "Stats")}
        </nav>

        {/* ── Right — Actions ────────────── */}
        <div className="flex items-center gap-2">
          {/* Pricing link */}
          <Link
            href="/pricing"
            className={cn(
              "hidden sm:flex items-center gap-1 text-sm font-medium transition-colors px-3 py-1.5 rounded-md",
              pathname === "/pricing"
                ? "text-acid bg-acid/10"
                : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
            )}
          >
            Pricing
          </Link>

          {/* Backend status */}
          <div className="hidden sm:flex items-center gap-1.5 text-xs font-mono text-l-sub dark:text-gray-500">
            <Activity className="h-3.5 w-3.5" />
            <span className="hidden md:inline">API</span>
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

          {/* Auth section */}
          {user ? (
            /* Avatar dropdown */
            <div className="relative" ref={avatarRef}>
              <button
                onClick={() => setAvatarOpen(!avatarOpen)}
                className="flex items-center gap-1.5 rounded-lg px-1.5 py-1 hover:bg-l-panel dark:hover:bg-panel transition-colors"
              >
                {avatarDisplay}
                <ChevronDown
                  className={cn(
                    "h-3 w-3 text-l-sub dark:text-gray-500 transition-transform duration-200",
                    avatarOpen && "rotate-180"
                  )}
                />
              </button>

              {avatarOpen && (
                <div className="absolute right-0 top-full mt-1 w-56 py-1 rounded-lg border card shadow-xl animate-fade-in z-50">
                  {/* User info */}
                  <div className="px-3 py-2 border-b border-l-border dark:border-border mb-1">
                    <div className="text-sm font-medium text-l-text dark:text-gray-200 truncate">
                      {profile?.display_name || "User"}
                    </div>
                    <div className="text-[11px] font-mono text-l-sub dark:text-gray-500 truncate">
                      {profile?.email || user.email}
                    </div>
                  </div>

                  <Link
                    href="/workspace"
                    className="flex items-center gap-2.5 px-3 py-2 text-sm text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel transition-colors"
                  >
                    <LayoutDashboard className="h-4 w-4" />
                    My Workspace
                  </Link>
                  <Link
                    href="/bookmarks"
                    className="flex items-center gap-2.5 px-3 py-2 text-sm text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel transition-colors"
                  >
                    <Bookmark className="h-4 w-4" />
                    Bookmarks
                  </Link>
                  <Link
                    href="/settings"
                    className="flex items-center gap-2.5 px-3 py-2 text-sm text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel transition-colors"
                  >
                    <Settings className="h-4 w-4" />
                    Settings
                  </Link>

                  <div className="my-1 h-px bg-l-border dark:bg-border" />

                  <button
                    onClick={async () => {
                      await signOut();
                      setAvatarOpen(false);
                    }}
                    className="flex items-center gap-2.5 px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 transition-colors w-full text-left"
                  >
                    <LogOut className="h-4 w-4" />
                    Sign Out
                  </button>
                </div>
              )}
            </div>
          ) : (
            /* Sign In button */
            <Link
              href="/auth/login"
              className="hidden sm:flex items-center gap-1.5 text-sm font-medium px-3 py-1.5 rounded-lg
                         bg-acid/10 text-acid border border-acid/20
                         hover:bg-acid/20 transition-all"
            >
              <LogIn className="h-3.5 w-3.5" />
              Sign In
            </Link>
          )}

          {/* Mobile hamburger */}
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="lg:hidden btn-ghost rounded-lg p-2"
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

      {/* ── Mobile menu ──────────────────── */}
      {mobileOpen && (
        <div className="lg:hidden border-t border-l-border dark:border-border glass animate-fade-in">
          <nav className="mx-auto max-w-7xl px-4 py-3 space-y-1">
            <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500 font-semibold px-3 pt-1">
              CVE Intelligence
            </p>
            <Link
              href="/"
              className={cn(
                "block text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
                pathname === "/"
                  ? "text-acid bg-acid/10"
                  : "text-l-sub dark:text-gray-400 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              Feed
            </Link>
            <Link
              href="/threats"
              className={cn(
                "flex items-center gap-2 text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
                pathname === "/threats"
                  ? "text-red-400 bg-red-500/10"
                  : "text-l-sub dark:text-gray-400 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              <span className="h-2 w-2 rounded-full bg-red-500" />
              Active Threats
            </Link>
            <Link
              href="/exploit-intel"
              className={cn(
                "flex items-center gap-2 text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
                pathname === "/exploit-intel" ||
                  pathname.startsWith("/exploit-intel/")
                  ? "text-purple-400 bg-purple-500/10"
                  : "text-l-sub dark:text-gray-400 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              <Crosshair className="h-3.5 w-3.5" />
              Exploit Intel
            </Link>

            <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500 font-semibold px-3 pt-3">
              Intel Hub
            </p>
            {intelItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-2 text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
                  pathname === item.href ||
                    pathname.startsWith(item.href + "/")
                    ? "text-cyan-400 bg-cyan-500/10"
                    : "text-l-sub dark:text-gray-400 hover:bg-l-panel dark:hover:bg-panel"
                )}
              >
                <span>{item.emoji}</span>
                {item.label}
              </Link>
            ))}

            <p className="text-[10px] uppercase tracking-wider text-l-sub dark:text-gray-500 font-semibold px-3 pt-3">
              System
            </p>
            <Link
              href="/krs"
              className={cn(
                "block text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
                pathname === "/krs"
                  ? "text-acid bg-acid/10"
                  : "text-l-sub dark:text-gray-400 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              KRS
            </Link>
            <Link
              href="/stats"
              className={cn(
                "block text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
                pathname === "/stats"
                  ? "text-acid bg-acid/10"
                  : "text-l-sub dark:text-gray-400 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              Stats
            </Link>
            <Link
              href="/pricing"
              className={cn(
                "block text-sm font-medium transition-colors px-3 py-2.5 rounded-md",
                pathname === "/pricing"
                  ? "text-acid bg-acid/10"
                  : "text-l-sub dark:text-gray-400 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              Pricing
            </Link>

            {/* Mobile auth section */}
            <div className="mt-2 pt-3 border-t border-l-border dark:border-border">
              {user ? (
                <>
                  <div className="px-3 py-2 mb-1">
                    <div className="text-sm font-medium text-l-text dark:text-gray-200">
                      {profile?.display_name || "User"}
                    </div>
                    <div className="text-[11px] font-mono text-l-sub dark:text-gray-500">
                      {profile?.email || user.email}
                    </div>
                  </div>
                  <Link
                    href="/workspace"
                    className="block text-sm font-medium text-l-sub dark:text-gray-400 px-3 py-2.5 rounded-md hover:bg-l-panel dark:hover:bg-panel"
                  >
                    My Workspace
                  </Link>
                  <Link
                    href="/bookmarks"
                    className="block text-sm font-medium text-l-sub dark:text-gray-400 px-3 py-2.5 rounded-md hover:bg-l-panel dark:hover:bg-panel"
                  >
                    Bookmarks
                  </Link>
                  <button
                    onClick={signOut}
                    className="block w-full text-left text-sm font-medium text-red-400 px-3 py-2.5 rounded-md hover:bg-red-500/10"
                  >
                    Sign Out
                  </button>
                </>
              ) : (
                <Link
                  href="/auth/login"
                  className="flex items-center justify-center gap-2 text-sm font-medium px-3 py-2.5 rounded-lg
                             bg-acid/10 text-acid border border-acid/20"
                >
                  <LogIn className="h-4 w-4" />
                  Sign In
                </Link>
              )}
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}
