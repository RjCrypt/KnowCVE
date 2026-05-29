"use client";

import { useEffect, useState, type ReactNode } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  LayoutDashboard,
  Server,
  Columns3,
  FileCheck,
  ChevronRight,
  Building2,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import { usePathname } from "next/navigation";
import type { OrgClient } from "@/types/cve";

export default function ClientLayout({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const params = useParams();
  const router = useRouter();
  const pathname = usePathname();
  const orgId = params.orgId as string;
  const clientId = params.clientId as string;
  const [client, setClient] = useState<OrgClient | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user || !clientId) return;
    setLoading(true);
    import("@/lib/api")
      .then(({ listClients }) => listClients(orgId, user.id))
      .then((result) => {
        const found = (result.data || []).find((c: OrgClient) => c.id === clientId);
        if (found) {
          setClient(found);
        } else {
          router.push(`/org/${orgId}/clients`);
        }
      })
      .catch(() => router.push(`/org/${orgId}/clients`))
      .finally(() => setLoading(false));
  }, [user?.id, orgId, clientId, router]);

  if (loading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-6 w-48 skeleton" />
        <div className="h-64 skeleton rounded-xl" />
      </div>
    );
  }

  if (!client) return null;

  const navItems = [
    { href: `/org/${orgId}/clients/${clientId}/dashboard`, label: "Dashboard", icon: LayoutDashboard },
    { href: `/org/${orgId}/clients/${clientId}/assets`, label: "Assets", icon: Server },
    { href: `/org/${orgId}/clients/${clientId}/triage`, label: "Triage", icon: Columns3 },
    { href: `/org/${orgId}/clients/${clientId}/compliance`, label: "Compliance", icon: FileCheck },
  ];

  return (
    <div className="animate-fade-in">
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-xs text-l-sub dark:text-gray-500 mb-4">
        <Link href={`/org/${orgId}/clients`} className="hover:text-acid transition-colors">
          Clients
        </Link>
        <ChevronRight className="h-3 w-3" />
        <span className="text-l-text dark:text-gray-300 font-medium flex items-center gap-1">
          <Building2 className="h-3 w-3" />
          {client.name}
        </span>
      </div>

      {/* Sub-nav */}
      <nav className="flex items-center gap-1 mb-5 overflow-x-auto scrollbar-hide pb-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors",
                isActive
                  ? "bg-purple-500/10 text-purple-400"
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
