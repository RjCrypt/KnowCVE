"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import {
  Settings,
  Users,
  Clock,
  Building2,
  Trash2,
  Send,
  Mail,
  Shield,
  Info,
  CheckCircle2,
  X,
  AlertTriangle,
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import {
  getOrg,
  getSLAConfig,
  upsertSLAConfig,
  listMembers,
  inviteMember,
  updateMemberRole,
  removeMember,
  listInvites,
  revokeInvite,
  updateOrg,
} from "@/lib/api";
import type { Organization, OrgMember, OrgInvite } from "@/types/cve";
import Footer from "@/components/layout/Footer";

type Tab = "sla" | "members" | "details";

/* ── Role descriptions ─────────────────── */
const ROLE_INFO: Record<string, string> = {
  admin: "Manage assets, triage, and members",
  member: "Manage assets and triage, cannot manage members",
  viewer: "Read-only access to all data",
};

export default function OrgSettingsPage() {
  const { user, profile } = useAuth();
  const params = useParams();
  const orgId = params.orgId as string;

  const [tab, setTab] = useState<Tab>("sla");
  const [org, setOrg] = useState<Organization | null>(null);
  const [slaConfig, setSlaConfig] = useState({ CRITICAL: 24, HIGH: 72, MEDIUM: 168, LOW: 336 });
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [invites, setInvites] = useState<OrgInvite[]>([]);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("member");
  const [inviting, setInviting] = useState(false);
  const [inviteError, setInviteError] = useState("");
  const [inviteSuccess, setInviteSuccess] = useState("");
  const [orgName, setOrgName] = useState("");
  const [updatingName, setUpdatingName] = useState(false);
  const [removingMember, setRemovingMember] = useState<OrgMember | null>(null);
  const [roleToast, setRoleToast] = useState("");

  const fetchData = useCallback(async () => {
    if (!user?.id) return;
    try {
      const [orgData, sla, memberData, inviteData] = await Promise.all([
        getOrg(orgId, user.id),
        getSLAConfig(orgId, user.id),
        listMembers(orgId, user.id),
        listInvites(orgId, user.id).catch(() => ({ data: [] })),
      ]);
      setOrg(orgData);
      setOrgName(orgData?.name || "");
      setMembers(memberData.data || []);
      setInvites(inviteData.data || []);

      // Parse SLA config
      const slaMap: Record<string, number> = {};
      for (const s of (sla.data || [])) {
        slaMap[s.priority] = s.sla_hours;
      }
      setSlaConfig({
        CRITICAL: slaMap.CRITICAL || 24,
        HIGH: slaMap.HIGH || 72,
        MEDIUM: slaMap.MEDIUM || 168,
        LOW: slaMap.LOW || 336,
      });
    } catch { /* fail */ }
  }, [user?.id, orgId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleSaveSLA = async () => {
    if (!user?.id) return;
    setSaving(true);
    try {
      await upsertSLAConfig(orgId, user.id, slaConfig);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch { /* fail */ }
    setSaving(false);
  };

  const handleInvite = async () => {
    if (!user || !inviteEmail.trim()) return;
    setInviting(true);
    setInviteError("");
    setInviteSuccess("");
    try {
      await inviteMember(orgId, user.id, {
        email: inviteEmail.trim(),
        role: inviteRole,
        inviter_name: profile?.display_name || "A team member",
      });
      const sentTo = inviteEmail.trim();
      setInviteEmail("");
      setInviteSuccess(`Invite sent to ${sentTo}`);
      setTimeout(() => setInviteSuccess(""), 5000);
      await fetchData();
    } catch (e: unknown) {
      setInviteError(e instanceof Error ? e.message : "Failed to send invite");
    }
    setInviting(false);
  };

  const handleRoleChange = async (targetUserId: string, newRole: string) => {
    if (!user?.id) return;
    try {
      await updateMemberRole(orgId, targetUserId, user.id, newRole);
      setRoleToast("Role updated");
      setTimeout(() => setRoleToast(""), 2500);
      await fetchData();
    } catch { /* fail */ }
  };

  const handleConfirmRemove = async () => {
    if (!user?.id || !removingMember) return;
    try {
      await removeMember(orgId, removingMember.user_id, user.id);
      setRemovingMember(null);
      await fetchData();
    } catch { /* fail */ }
  };

  const handleRevokeInvite = async (inviteId: string) => {
    if (!user?.id) return;
    try {
      await revokeInvite(orgId, inviteId, user.id);
      await fetchData();
    } catch { /* fail */ }
  };

  const handleUpdateName = async () => {
    if (!user || !orgName.trim()) return;
    setUpdatingName(true);
    try {
      await updateOrg(orgId, user.id, orgName.trim());
      await fetchData();
    } catch { /* fail */ }
    setUpdatingName(false);
  };

  const userRole = org?.user_role;
  const isOwnerOrAdmin = userRole === "owner" || userRole === "admin";
  const memberLimit = org?.plan_limits?.members || 5;
  const memberCount = members.length;
  const atMemberLimit = memberCount >= memberLimit;

  const tabs: { id: Tab; label: string; icon: typeof Clock }[] = [
    { id: "sla", label: "SLA Thresholds", icon: Clock },
    { id: "members", label: "Team Members", icon: Users },
    { id: "details", label: "Org Details", icon: Building2 },
  ];

  /* ── Check if invite is expired ─────── */
  const isInviteExpired = (expiresAt: string) => {
    try {
      return new Date() > new Date(expiresAt);
    } catch {
      return false;
    }
  };

  return (
    <>
      <div className="flex items-center gap-2 mb-6">
        <Settings className="h-5 w-5 text-l-sub dark:text-gray-400" />
        <h1 className="font-display font-bold text-xl text-l-text dark:text-gray-100">Settings</h1>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 border-b border-l-border dark:border-border pb-0.5">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              "flex items-center gap-1.5 px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-[1.5px]",
              tab === t.id
                ? "border-acid text-acid"
                : "border-transparent text-l-sub dark:text-gray-400 hover:text-l-text dark:hover:text-gray-200"
            )}
          >
            <t.icon className="h-3.5 w-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {/* Role update toast */}
      {roleToast && (
        <div className="fixed top-4 right-4 z-50 animate-fade-in">
          <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-sm">
            <CheckCircle2 className="h-4 w-4" />
            {roleToast}
          </div>
        </div>
      )}

      {/* SLA Tab */}
      {tab === "sla" && (
        <div className="card p-6 mb-6">
          <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-4">
            SLA Thresholds
          </h2>
          <p className="text-xs text-l-sub dark:text-gray-500 mb-4">
            Configure how many hours your team has to respond to CVEs by priority level.
          </p>
          <div className="space-y-3">
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((p) => (
              <div key={p} className="flex items-center gap-4">
                <span className={cn(
                  "badge text-[10px] py-0.5 w-20 justify-center",
                  p === "CRITICAL" && "bg-red-500/15 border-red-500/30 text-red-400",
                  p === "HIGH" && "bg-amber-500/15 border-amber-500/30 text-amber-400",
                  p === "MEDIUM" && "bg-yellow-500/15 border-yellow-500/30 text-yellow-300",
                  p === "LOW" && "bg-blue-500/15 border-blue-500/30 text-blue-400",
                )}>
                  {p}
                </span>
                <input
                  type="number"
                  min={1}
                  value={slaConfig[p]}
                  onChange={(e) => setSlaConfig((prev) => ({ ...prev, [p]: parseInt(e.target.value) || 0 }))}
                  className="input-base w-24 text-center font-mono text-xs"
                  disabled={!isOwnerOrAdmin}
                />
                <span className="text-xs text-l-sub dark:text-gray-500">hours</span>
              </div>
            ))}
          </div>
          {isOwnerOrAdmin && (
            <button onClick={handleSaveSLA} disabled={saving} className="btn-primary text-xs mt-4">
              {saving ? "Saving…" : saved ? "Saved ✓" : "Save All"}
            </button>
          )}
        </div>
      )}

      {/* Members Tab */}
      {tab === "members" && (
        <div className="card p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200">
              Team Members
            </h2>
            <span className={cn(
              "text-xs font-mono px-2.5 py-1 rounded-md border",
              atMemberLimit
                ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
                : "text-l-sub dark:text-gray-500 bg-l-surface dark:bg-surface border-l-border dark:border-border"
            )}>
              {memberCount} / {memberLimit === 999999 ? "∞" : memberLimit} members
            </span>
          </div>

          {/* Invite form */}
          {isOwnerOrAdmin && (
            <div className="mb-4 p-4 rounded-lg border border-acid/20 bg-acid/5">
              {atMemberLimit ? (
                <div className="flex items-center gap-2 text-amber-400">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  <p className="text-xs">
                    You&apos;ve reached your plan&apos;s member limit ({memberLimit}).
                    Upgrade to add more members.
                  </p>
                </div>
              ) : (
                <>
                  <div className="flex gap-2 items-end flex-wrap">
                    <div className="flex-1 min-w-[200px]">
                      <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">
                        Invite by email
                      </label>
                      <input
                        type="email"
                        value={inviteEmail}
                        onChange={(e) => { setInviteEmail(e.target.value); setInviteError(""); }}
                        placeholder="teammate@company.com"
                        className="input-base w-full text-xs"
                        onKeyDown={(e) => { if (e.key === "Enter") handleInvite(); }}
                      />
                    </div>
                    <div className="min-w-[140px]">
                      <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">
                        Role
                      </label>
                      <select
                        value={inviteRole}
                        onChange={(e) => setInviteRole(e.target.value)}
                        className="input-base text-xs w-full"
                      >
                        <option value="admin">Admin</option>
                        <option value="member">Member</option>
                        <option value="viewer">Viewer</option>
                      </select>
                    </div>
                    <button
                      onClick={handleInvite}
                      disabled={inviting || !inviteEmail.trim()}
                      className="btn-primary text-xs flex items-center gap-1.5"
                    >
                      <Send className="h-3.5 w-3.5" />
                      {inviting ? "Sending…" : "Send Invite"}
                    </button>
                  </div>
                  {/* Role tooltip */}
                  <div className="mt-2 flex items-start gap-1.5">
                    <Info className="h-3 w-3 text-l-muted dark:text-gray-600 mt-0.5 shrink-0" />
                    <span className="text-[10px] text-l-muted dark:text-gray-600">
                      {ROLE_INFO[inviteRole] || "Select a role"}
                    </span>
                  </div>
                </>
              )}
              {inviteError && <p className="text-xs text-red-400 mt-2">{inviteError}</p>}
              {inviteSuccess && (
                <div className="flex items-center gap-1.5 mt-2 text-xs text-emerald-400 animate-fade-in">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  {inviteSuccess}
                </div>
              )}
            </div>
          )}

          {/* Member list */}
          <div className="space-y-2">
            {members.map((m) => {
              const mRole = m.member_role || "member";
              const isOwner = mRole === "owner";
              const isSelf = m.user_id === user?.id;

              return (
                <div
                  key={m.user_id}
                  className="flex items-center justify-between gap-3 p-3 rounded-lg border border-l-border dark:border-border hover:border-l-muted dark:hover:border-muted transition-colors"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {m.avatar_url ? (
                      <img
                        src={m.avatar_url}
                        alt=""
                        className="h-7 w-7 rounded-full border border-l-border dark:border-border"
                      />
                    ) : (
                      <div className="h-7 w-7 rounded-full bg-acid/20 border border-acid/30 flex items-center justify-center">
                        <span className="text-xs font-mono font-bold text-acid">
                          {(m.display_name || m.email || "U")[0].toUpperCase()}
                        </span>
                      </div>
                    )}
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-l-text dark:text-gray-200 truncate">
                        {m.display_name || "User"}
                        {isSelf && (
                          <span className="text-[10px] font-mono text-l-muted dark:text-gray-600 ml-1.5">
                            (you)
                          </span>
                        )}
                      </p>
                      <p className="text-[10px] font-mono text-l-sub dark:text-gray-500 truncate">
                        {m.email}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {isOwnerOrAdmin && !isOwner ? (
                      <select
                        value={mRole}
                        onChange={(e) => handleRoleChange(m.user_id, e.target.value)}
                        className="input-base text-[10px] py-1 px-2"
                      >
                        <option value="admin">Admin</option>
                        <option value="member">Member</option>
                        <option value="viewer">Viewer</option>
                      </select>
                    ) : (
                      <span
                        className={cn(
                          "badge text-[10px] py-0.5 uppercase",
                          isOwner
                            ? "bg-acid/10 border-acid/20 text-acid"
                            : "bg-l-surface dark:bg-surface border-l-border dark:border-border text-l-sub dark:text-gray-400"
                        )}
                      >
                        {mRole}
                      </span>
                    )}
                    {isOwnerOrAdmin && !isOwner && !isSelf && (
                      <button
                        onClick={() => setRemovingMember(m)}
                        className="text-l-sub dark:text-gray-600 hover:text-red-400 transition-colors"
                        title="Remove member"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Pending invites */}
          {invites.length > 0 && (
            <div className="mt-6">
              <h3 className="text-xs font-mono text-l-sub dark:text-gray-500 mb-2 uppercase tracking-wider">
                Pending Invites
              </h3>
              <div className="space-y-2">
                {invites.map((inv) => {
                  const expired = isInviteExpired(inv.expires_at);
                  return (
                    <div
                      key={inv.id}
                      className={cn(
                        "flex items-center justify-between gap-3 p-3 rounded-lg border border-dashed",
                        expired
                          ? "border-l-muted/30 dark:border-muted/30 opacity-60"
                          : "border-l-border dark:border-border"
                      )}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <Mail className="h-3.5 w-3.5 text-l-sub dark:text-gray-500 shrink-0" />
                        <div className="min-w-0">
                          <span className="text-xs text-l-text dark:text-gray-300 truncate block">
                            {inv.email}
                          </span>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[10px] font-mono text-l-muted dark:text-gray-600 uppercase">
                              {inv.role}
                            </span>
                            <span className="text-[10px] text-l-muted dark:text-gray-600">·</span>
                            <span className="text-[10px] text-l-muted dark:text-gray-600">
                              Expires {new Date(inv.expires_at).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                      </div>
                      {expired ? (
                        <span className="badge text-[10px] py-0.5 bg-l-muted/10 dark:bg-muted/10 border-l-muted/20 dark:border-muted/20 text-l-muted dark:text-gray-600">
                          Expired
                        </span>
                      ) : (
                        <button
                          onClick={() => handleRevokeInvite(inv.id)}
                          className="text-xs text-red-400 hover:text-red-300 transition-colors font-medium"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Details Tab */}
      {tab === "details" && (
        <div className="card p-6 mb-6">
          <h2 className="font-display font-semibold text-lg text-l-text dark:text-gray-200 mb-4">
            Organization Details
          </h2>
          <div className="space-y-4">
            <div>
              <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">Name</label>
              <div className="flex gap-2">
                <input type="text" value={orgName} onChange={(e) => setOrgName(e.target.value)} className="input-base flex-1" disabled={!isOwnerOrAdmin} />
                {isOwnerOrAdmin && (
                  <button onClick={handleUpdateName} disabled={updatingName} className="btn-ghost text-xs border border-l-border dark:border-border">
                    {updatingName ? "Saving…" : "Save"}
                  </button>
                )}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-xs font-mono text-l-sub dark:text-gray-500">Plan</span>
                <p className="flex items-center gap-1.5 mt-0.5">
                  <Shield className="h-3.5 w-3.5 text-acid" />
                  <span className="font-medium text-l-text dark:text-gray-200 uppercase">{org?.org_type}</span>
                </p>
              </div>
              <div>
                <span className="text-xs font-mono text-l-sub dark:text-gray-500">Members</span>
                <p className="font-medium text-l-text dark:text-gray-200 mt-0.5">{org?.member_count ?? 0}</p>
              </div>
              <div>
                <span className="text-xs font-mono text-l-sub dark:text-gray-500">Assets</span>
                <p className="font-medium text-l-text dark:text-gray-200 mt-0.5">{org?.asset_count ?? 0} / {org?.plan_limits?.assets === 999999 ? "∞" : org?.plan_limits?.assets}</p>
              </div>
              <div>
                <span className="text-xs font-mono text-l-sub dark:text-gray-500">Created</span>
                <p className="font-medium text-l-text dark:text-gray-200 mt-0.5">{org?.created_at ? new Date(org.created_at).toLocaleDateString() : "—"}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Remove member confirmation modal */}
      {removingMember && (
        <>
          <div className="fixed inset-0 bg-void/60 backdrop-blur-sm z-50" onClick={() => setRemovingMember(null)} />
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="card p-6 w-full max-w-sm shadow-2xl animate-fade-in" onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                  </div>
                  <h2 className="font-display font-bold text-lg text-l-text dark:text-gray-100">
                    Remove Member
                  </h2>
                </div>
                <button
                  onClick={() => setRemovingMember(null)}
                  className="text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300 transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
              <p className="text-sm text-l-sub dark:text-gray-400 mb-6">
                Remove <strong className="text-l-text dark:text-gray-200">{removingMember.display_name || removingMember.email}</strong> from{" "}
                <strong className="text-l-text dark:text-gray-200">{org?.name}</strong>?
                They will lose access immediately.
              </p>
              <div className="flex items-center justify-end gap-3">
                <button onClick={() => setRemovingMember(null)} className="btn-ghost text-xs">
                  Cancel
                </button>
                <button
                  onClick={handleConfirmRemove}
                  className="px-4 py-2 text-xs font-medium rounded-lg bg-red-500/15 border border-red-500/30 text-red-400 hover:bg-red-500/25 transition-colors"
                >
                  Remove
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      <Footer />
    </>
  );
}
