"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Building2, ChevronDown, Plus, User } from "lucide-react";
import { useOrg } from "@/lib/org-context";
import { cn } from "@/lib/utils";

export default function OrgSwitcher() {
  const { orgs, currentOrg, setCurrentOrg } = useOrg();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const pathname = usePathname();

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  // Auto-detect current org from URL
  useEffect(() => {
    const match = pathname.match(/^\/org\/([^/]+)/);
    if (match) {
      const orgId = match[1];
      const org = orgs.find((o) => o.id === orgId);
      if (org && (!currentOrg || currentOrg.id !== orgId)) {
        setCurrentOrg(org);
      }
    }
  }, [pathname, orgs, currentOrg, setCurrentOrg]);

  if (orgs.length === 0) return null;

  const isOrgRoute = pathname.startsWith("/org/");

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className={cn(
          "flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg transition-all border",
          isOrgRoute
            ? "bg-acid/10 text-acid border-acid/20"
            : "bg-l-panel dark:bg-panel text-l-sub dark:text-gray-400 border-l-border dark:border-border hover:border-acid/30 hover:text-acid"
        )}
      >
        <Building2 className="h-3.5 w-3.5" />
        <span className="max-w-[100px] truncate">
          {currentOrg ? currentOrg.name : "Org"}
        </span>
        <ChevronDown
          className={cn(
            "h-3 w-3 transition-transform duration-200",
            open && "rotate-180"
          )}
        />
      </button>

      {open && (
        <div className="absolute top-full right-0 mt-1 w-56 py-1 rounded-lg border card shadow-xl animate-fade-in z-50">
          {/* Personal workspace */}
          <Link
            href="/workspace"
            className={cn(
              "flex items-center gap-2.5 px-3 py-2 text-sm transition-colors",
              pathname === "/workspace"
                ? "text-acid bg-acid/5"
                : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel"
            )}
          >
            <User className="h-3.5 w-3.5" />
            Personal Workspace
          </Link>

          {orgs.length > 0 && (
            <div className="my-1 h-px bg-l-border dark:bg-border" />
          )}

          {/* Org list */}
          {orgs.map((org) => (
            <Link
              key={org.id}
              href={`/org/${org.id}/dashboard`}
              onClick={() => setCurrentOrg(org)}
              className={cn(
                "flex items-center gap-2.5 px-3 py-2 text-sm transition-colors",
                currentOrg?.id === org.id && isOrgRoute
                  ? "text-acid bg-acid/5"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              <Building2 className="h-3.5 w-3.5" />
              <span className="truncate">{org.name}</span>
              <span className="ml-auto text-[10px] font-mono text-l-muted dark:text-gray-600 uppercase">
                {org.org_type}
              </span>
            </Link>
          ))}

          <div className="my-1 h-px bg-l-border dark:bg-border" />

          <Link
            href="/workspace?create_org=1"
            className="flex items-center gap-2.5 px-3 py-2 text-sm text-acid hover:bg-acid/5 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Create New Org
          </Link>
        </div>
      )}
    </div>
  );
}
