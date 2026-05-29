"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Building2, Shield, Users } from "lucide-react";
import { createOrg } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { useOrg } from "@/lib/org-context";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";

interface CreateOrgModalProps {
  open: boolean;
  onClose: () => void;
}

export default function CreateOrgModal({ open, onClose }: CreateOrgModalProps) {
  const { user } = useAuth();
  const { refreshOrgs } = useOrg();
  const router = useRouter();
  const [name, setName] = useState("");
  const [orgType, setOrgType] = useState<"team" | "mssp">("team");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");

  const handleCreate = async () => {
    if (!user || !name.trim()) return;
    setCreating(true);
    setError("");
    try {
      const result = await createOrg({
        name: name.trim(),
        org_type: orgType,
        owner_id: user.id,
      });
      await refreshOrgs();
      onClose();
      setName("");
      setOrgType("team");
      router.push(`/org/${result.id}/dashboard`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create organization";
      setError(msg);
    } finally {
      setCreating(false);
    }
  };

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-void/60 backdrop-blur-sm z-50"
            onClick={onClose}
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ type: "spring", duration: 0.4, bounce: 0.15 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card p-6 w-full max-w-md shadow-2xl">
              {/* Header */}
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-acid/10 border border-acid/20">
                    <Building2 className="h-5 w-5 text-acid" />
                  </div>
                  <h2 className="font-display font-bold text-lg text-l-text dark:text-gray-100">
                    Create Organization
                  </h2>
                </div>
                <button
                  onClick={onClose}
                  className="text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300 transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Name input */}
              <div className="mb-4">
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1.5 block">
                  Organization Name
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Acme Security Team"
                  className="input-base w-full"
                  autoFocus
                />
              </div>

              {/* Type selector */}
              <div className="mb-6">
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1.5 block">
                  Workspace Type
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => setOrgType("team")}
                    className={cn(
                      "p-3 rounded-lg border text-left transition-all",
                      orgType === "team"
                        ? "border-acid/40 bg-acid/5"
                        : "border-l-border dark:border-border hover:border-l-muted dark:hover:border-muted"
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      <Shield className="h-4 w-4 text-acid" />
                      <span className="text-sm font-medium text-l-text dark:text-gray-200">Team</span>
                    </div>
                    <p className="text-[11px] text-l-sub dark:text-gray-500 leading-snug">
                      Internal security team. Up to 50 assets and 10 members.
                    </p>
                  </button>

                  <button
                    onClick={() => setOrgType("mssp")}
                    className={cn(
                      "p-3 rounded-lg border text-left transition-all",
                      orgType === "mssp"
                        ? "border-acid/40 bg-acid/5"
                        : "border-l-border dark:border-border hover:border-l-muted dark:hover:border-muted"
                    )}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      <Users className="h-4 w-4 text-purple-400" />
                      <span className="text-sm font-medium text-l-text dark:text-gray-200">MSSP</span>
                    </div>
                    <p className="text-[11px] text-l-sub dark:text-gray-500 leading-snug">
                      Manage multiple clients. Unlimited assets and members.
                    </p>
                  </button>
                </div>
              </div>

              {/* Error */}
              {error && (
                <p className="text-xs text-red-400 mb-4">{error}</p>
              )}

              {/* Actions */}
              <div className="flex items-center justify-end gap-3">
                <button onClick={onClose} className="btn-ghost text-xs">
                  Cancel
                </button>
                <button
                  onClick={handleCreate}
                  disabled={creating || !name.trim()}
                  className={cn(
                    "btn-primary text-xs",
                    (creating || !name.trim()) && "opacity-50 cursor-not-allowed"
                  )}
                >
                  {creating ? "Creating…" : "Create Workspace"}
                </button>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
