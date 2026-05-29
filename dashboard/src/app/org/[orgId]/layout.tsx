"use client";

import { useEffect, useState, type ReactNode } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  LayoutDashboard,
  Server,
  Columns3,
  Settings,
  FileCheck,
  Users,
  ChevronRight,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { getOrg } from "@/lib/api";
import { cn } from "@/lib/utils";
import { usePathname } from "next/navigation";
import type { Organization } from "@/types/cve";

export default function OrgLayout({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const params = useParams();
  const router = useRouter();
  const pathname = usePathname();
  const orgId = params.orgId as string;
  const [org, setOrg] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user || !orgId) return;
    setLoading(true);
    getOrg(orgId, user.id)
      .then(setOrg)
      .catch(() => {
        router.push("/workspace");
      })
      .finally(() => setLoading(false));
  }, [user?.id, orgId, router]);

  if (loading) {
    return (
      <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8">
        <div className="space-y-4 animate-pulse">
          <div className="h-8 w-48 skeleton" />
          <div className="h-4 w-64 skeleton" />
          <div className="h-64 skeleton rounded-xl" />
        </div>
      </div>
    );
  }

  if (!org) {
    return (
      <div className="mx-auto max-w-7xl px-4 sm:px-6 py-8 text-center">
        <p className="text-l-sub dark:text-gray-500">Organization not found or access denied.</p>
      </div>
    );
  }

  const navItems = [
    { href: `/org/${orgId}/dashboard`, label: "Dashboard", icon: LayoutDashboard },
    { href: `/org/${orgId}/assets`, label: "Assets", icon: Server },
    { href: `/org/${orgId}/triage`, label: "Triage", icon: Columns3 },
    { href: `/org/${orgId}/compliance`, label: "Compliance", icon: FileCheck },
    ...(org.org_type === "mssp"
      ? [{ href: `/org/${orgId}/clients`, label: "Clients", icon: Users }]
      : []),
    { href: `/org/${orgId}/settings`, label: "Settings", icon: Settings },
  ];

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-6 animate-fade-in">
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-xs text-l-sub dark:text-gray-500 mb-4">
        <Link href="/workspace" className="hover:text-acid transition-colors">
          Workspace
        </Link>
        <ChevronRight className="h-3 w-3" />
        <span className="text-l-text dark:text-gray-300 font-medium">{org.name}</span>
        <span className="badge text-[9px] py-0 ml-1 bg-acid/10 border-acid/20 text-acid uppercase">
          {org.org_type}
        </span>
      </div>

      {/* Sub-nav */}
      <nav className="flex items-center gap-1 mb-6 overflow-x-auto scrollbar-hide pb-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + "/");
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-colors",
                isActive
                  ? "bg-acid/10 text-acid"
                  : "text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200 hover:bg-l-panel dark:hover:bg-panel"
              )}
            >
              <item.icon className="h-3.5 w-3.5" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {children}
    </div>
  );
}
