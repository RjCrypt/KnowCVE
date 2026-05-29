"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from "react";
import { useAuth } from "@/lib/auth-context";
import { getUserOrgs } from "@/lib/api";
import type { Organization } from "@/types/cve";

interface OrgContextType {
  orgs: Organization[];
  currentOrg: Organization | null;
  setCurrentOrg: (org: Organization | null) => void;
  refreshOrgs: () => Promise<void>;
  loading: boolean;
}

const OrgContext = createContext<OrgContextType>({
  orgs: [],
  currentOrg: null,
  setCurrentOrg: () => {},
  refreshOrgs: async () => {},
  loading: false,
});

export function useOrg() {
  return useContext(OrgContext);
}

export function OrgProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [currentOrg, setCurrentOrg] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(false);

  const refreshOrgs = useCallback(async () => {
    if (!user) {
      setOrgs([]);
      setCurrentOrg(null);
      return;
    }
    setLoading(true);
    try {
      const result = await getUserOrgs(user.id);
      setOrgs(result.data || []);
    } catch {
      setOrgs([]);
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    refreshOrgs();
  }, [refreshOrgs]);

  return (
    <OrgContext.Provider value={{ orgs, currentOrg, setCurrentOrg, refreshOrgs, loading }}>
      {children}
    </OrgContext.Provider>
  );
}
