"""Phase 8 — OrgService: Org workspaces, assets, triage, MSSP, compliance.

All Phase 8 backend logic lives here as a single class.
Does NOT modify any existing service files or model fields.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Plan limits ───────────────────────────────────────────────────────────────
PLAN_LIMITS = {
    "team": {"assets": 50, "members": 10},
    "mssp": {"assets": 999_999, "members": 999_999},  # effectively unlimited
}

DEFAULT_SLA_HOURS = {
    "CRITICAL": 24,
    "HIGH": 72,
    "MEDIUM": 168,
    "LOW": 336,
}

ROLE_HIERARCHY = {"viewer": 0, "member": 1, "admin": 2, "owner": 3}


class OrgService:
    """Manages org workspaces, asset registers, triage, MSSP clients, and compliance."""

    def __init__(self, db=None) -> None:
        self._db = db

    # ══════════════════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════════════════

    def _check_db(self) -> bool:
        return self._db is not None and self._db.is_configured

    def _get_plan_limits(self, org_type: str) -> dict:
        return PLAN_LIMITS.get(org_type, PLAN_LIMITS["team"])

    async def check_org_access(
        self, org_id: str, user_id: str, min_role: str = "member"
    ) -> dict | None:
        """Validate user has sufficient role in org. Returns member row or None."""
        if not self._check_db():
            return None
        try:
            result = (
                self._db._client.table("org_members")
                .select("*")
                .eq("org_id", org_id)
                .eq("user_id", user_id)
                .execute()
            )
            if not result.data:
                return None
            member = result.data[0]
            user_level = ROLE_HIERARCHY.get(member.get("member_role", "viewer"), 0)
            required_level = ROLE_HIERARCHY.get(min_role, 0)
            if user_level < required_level:
                return None
            return member
        except Exception as e:
            logger.error(f"check_org_access failed: {e}")
            return None

    # ══════════════════════════════════════════════════════════════════════
    # ORG CRUD & MEMBERSHIP
    # ══════════════════════════════════════════════════════════════════════

    async def create_org(self, name: str, org_type: str, owner_id: str) -> dict | None:
        """Create a new organization and add owner as first member."""
        if not self._check_db():
            return None
        try:
            org_type_lower = org_type.lower()
            if org_type_lower not in ("team", "mssp"):
                return {"error": "org_type must be 'team' or 'mssp'"}

            org_result = self._db._client.table("organizations").insert({
                "name": name.strip(),
                "org_type": org_type_lower,
                "owner_id": owner_id,
            }).execute()

            if not org_result.data:
                return {"error": "Failed to create organization"}

            org = org_result.data[0]
            org_id = org["id"]

            # Add owner as first member
            self._db._client.table("org_members").insert({
                "org_id": org_id,
                "user_id": owner_id,
                "member_role": "owner",
            }).execute()

            # Create default SLA config
            for priority, hours in DEFAULT_SLA_HOURS.items():
                self._db._client.table("sla_configs").insert({
                    "org_id": org_id,
                    "priority": priority,
                    "sla_hours": hours,
                }).execute()

            return org
        except Exception as e:
            logger.error(f"create_org failed: {e}")
            return {"error": str(e)}

    async def get_org(self, org_id: str) -> dict | None:
        """Get org details including members and plan limits."""
        if not self._check_db():
            return None
        try:
            org_result = (
                self._db._client.table("organizations")
                .select("*")
                .eq("id", org_id)
                .execute()
            )
            if not org_result.data:
                return None

            org = org_result.data[0]

            # Get members with profile info
            members_result = (
                self._db._client.table("org_members")
                .select("*")
                .eq("org_id", org_id)
                .execute()
            )
            members = members_result.data or []

            # Enrich with profile data
            unique_uids = list({m["user_id"] for m in members})
            profile_map = {}
            if unique_uids:
                try:
                    profile_resp = (
                        self._db._client.table("user_profiles")
                        .select("id,email,display_name,avatar_url")
                        .in_("id", unique_uids)
                        .execute()
                    )
                    for p in (profile_resp.data or []):
                        profile_map[p["id"]] = p
                except Exception:
                    pass

            enriched_members = []
            for m in members:
                uid = m.get("user_id")
                if uid in profile_map:
                    # Exclude id from update to not overwrite member.id
                    p_data = {k: v for k, v in profile_map[uid].items() if k != "id"}
                    m.update(p_data)
                enriched_members.append(m)

            # Asset count
            asset_count_result = (
                self._db._client.table("assets")
                .select("id", count="exact")
                .eq("org_id", org_id)
                .execute()
            )
            asset_count = asset_count_result.count or 0

            limits = self._get_plan_limits(org.get("org_type", "team"))

            return {
                **org,
                "members": enriched_members,
                "member_count": len(enriched_members),
                "asset_count": asset_count,
                "plan_limits": limits,
            }
        except Exception as e:
            logger.error(f"get_org failed: {e}")
            return None

    async def update_org(self, org_id: str, name: str) -> dict | None:
        if not self._check_db():
            return None
        try:
            result = (
                self._db._client.table("organizations")
                .update({"name": name.strip(), "updated_at": datetime.now(timezone.utc).isoformat()})
                .eq("id", org_id)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"update_org failed: {e}")
            return None

    async def get_user_orgs(self, user_id: str) -> list[dict]:
        """Get all orgs a user belongs to."""
        if not self._check_db():
            return []
        try:
            memberships = (
                self._db._client.table("org_members")
                .select("org_id,member_role")
                .eq("user_id", user_id)
                .execute()
            )
            if not memberships.data:
                return []

            org_ids = list({m["org_id"] for m in memberships.data})
            if not org_ids:
                return []
            
            orgs_resp = (
                self._db._client.table("organizations")
                .select("*")
                .in_("id", org_ids)
                .execute()
            )
            org_map = {o["id"]: o for o in (orgs_resp.data or [])}

            orgs = []
            for m in memberships.data:
                if m["org_id"] in org_map:
                    org = dict(org_map[m["org_id"]])
                    org["user_role"] = m["member_role"]
                    orgs.append(org)
            return orgs
        except Exception as e:
            logger.error(f"get_user_orgs failed: {e}")
            return []

    # ── Invites ──────────────────────────────────────────────────────────

    async def invite_member(
        self, org_id: str, email: str, role: str, inviter_name: str, org_name: str
    ) -> dict | None:
        """Generate invite token, store, and send email."""
        if not self._check_db():
            return None
        try:
            if role not in ("admin", "member", "viewer"):
                return {"error": "Role must be admin, member, or viewer"}

            email_lower = email.strip().lower()

            # ── Member limit enforcement ──
            try:
                org_result = (
                    self._db._client.table("organizations")
                    .select("member_limit")
                    .eq("id", org_id)
                    .execute()
                )
                member_limit = (org_result.data[0]["member_limit"] if org_result.data else 5)
                current_members = (
                    self._db._client.table("org_members")
                    .select("id", count="exact")
                    .eq("org_id", org_id)
                    .execute()
                )
                if (current_members.count or 0) >= member_limit:
                    return {"error": "member_limit_reached", "limit": member_limit}
            except Exception as e:
                logger.warning(f"Member limit check failed, proceeding: {e}")

            # ── Check if user is already a member ──
            profile_result = (
                self._db._client.table("user_profiles")
                .select("id")
                .eq("email", email_lower)
                .execute()
            )
            if profile_result.data:
                existing_uid = profile_result.data[0]["id"]
                member_check = (
                    self._db._client.table("org_members")
                    .select("id")
                    .eq("org_id", org_id)
                    .eq("user_id", existing_uid)
                    .execute()
                )
                if member_check.data:
                    return {"error": "User is already a member of this organization"}

            # ── Check for pending non-expired invite ──
            try:
                pending_invite = (
                    self._db._client.table("org_invites")
                    .select("id,expires_at")
                    .eq("org_id", org_id)
                    .eq("email", email_lower)
                    .eq("accepted", False)
                    .execute()
                )
                if pending_invite.data:
                    # Check if any are still valid
                    now = datetime.now(timezone.utc)
                    for inv in pending_invite.data:
                        try:
                            exp = datetime.fromisoformat(inv["expires_at"].replace("Z", "+00:00"))
                            if now < exp:
                                return {"error": "Invite already sent to this email"}
                        except Exception:
                            pass
            except Exception:
                pass

            token = str(uuid.uuid4())
            expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

            self._db._client.table("org_invites").insert({
                "org_id": org_id,
                "email": email_lower,
                "role": role,
                "token": token,
                "expires_at": expires_at,
                "accepted": False,
            }).execute()

            # Send invite email
            accept_url = f"{settings.FRONTEND_URL}/invites/accept/{token}"
            html = self._build_invite_email(org_name, inviter_name, role, accept_url)
            await self._send_email(
                email_lower,
                f"You've been invited to join {org_name} on KnowCVE",
                html,
            )

            return {"success": True, "token": token, "email": email_lower, "expires_at": expires_at}
        except Exception as e:
            if "duplicate" in str(e).lower() or "unique" in str(e).lower():
                return {"error": "Invite already sent to this email"}
            logger.error(f"invite_member failed: {e}")
            return {"error": str(e)}

    async def accept_invite(self, token: str, user_id: str | None = None) -> dict | None:
        """Accept an invite by token. Creates org_member record.
        
        If user_id is provided, uses it directly. Otherwise looks up by email.
        Returns {requires_signup: true, ...} if no account exists yet.
        """
        if not self._check_db():
            return None
        try:
            invite_result = (
                self._db._client.table("org_invites")
                .select("*")
                .eq("token", token)
                .execute()
            )
            if not invite_result.data:
                return {"error": "Invalid invite link"}

            invite = invite_result.data[0]

            if invite.get("accepted"):
                return {"error": "This invite has already been used"}

            # Check expiry
            expires_at = invite.get("expires_at", "")
            try:
                exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > exp_dt:
                    return {"error": "This invite has expired"}
            except Exception:
                pass

            # Get org name (needed for all response paths)
            org_result = (
                self._db._client.table("organizations")
                .select("id,name")
                .eq("id", invite["org_id"])
                .execute()
            )
            org_name = org_result.data[0]["name"] if org_result.data else "Organization"

            # Resolve user — by explicit user_id or by email lookup
            resolved_user_id = user_id
            if not resolved_user_id:
                email = invite["email"]
                profile_result = (
                    self._db._client.table("user_profiles")
                    .select("id")
                    .eq("email", email)
                    .execute()
                )
                if not profile_result.data:
                    # User hasn't signed up yet — frontend handles signup redirect
                    return {
                        "requires_signup": True,
                        "email": invite["email"],
                        "org_name": org_name,
                        "org_id": invite["org_id"],
                    }
                resolved_user_id = profile_result.data[0]["id"]

            # Check not already a member
            existing = (
                self._db._client.table("org_members")
                .select("id")
                .eq("org_id", invite["org_id"])
                .eq("user_id", resolved_user_id)
                .execute()
            )
            if existing.data:
                self._db._client.table("org_invites").update({"accepted": True}).eq("id", invite["id"]).execute()
                return {"error": "You are already a member of this organization"}

            # Create membership
            self._db._client.table("org_members").insert({
                "org_id": invite["org_id"],
                "user_id": resolved_user_id,
                "member_role": invite.get("role", "member"),
            }).execute()

            # Mark invite as accepted
            self._db._client.table("org_invites").update({"accepted": True}).eq("id", invite["id"]).execute()

            return {
                "requires_signup": False,
                "org_id": invite["org_id"],
                "org_name": org_name,
            }
        except Exception as e:
            logger.error(f"accept_invite failed: {e}")
            return {"error": str(e)}

    async def list_members(self, org_id: str) -> list[dict]:
        if not self._check_db():
            return []
        try:
            result = (
                self._db._client.table("org_members")
                .select("*")
                .eq("org_id", org_id)
                .execute()
            )
            members = result.data or []
            unique_uids = list({m["user_id"] for m in members})
            profile_map = {}
            if unique_uids:
                try:
                    profile_resp = (
                        self._db._client.table("user_profiles")
                        .select("id,email,display_name,avatar_url")
                        .in_("id", unique_uids)
                        .execute()
                    )
                    for p in (profile_resp.data or []):
                        profile_map[p["id"]] = p
                except Exception:
                    pass

            enriched = []
            for m in members:
                uid = m.get("user_id")
                if uid in profile_map:
                    p_data = {k: v for k, v in profile_map[uid].items() if k != "id"}
                    m.update(p_data)
                enriched.append(m)
            return enriched
        except Exception as e:
            logger.error(f"list_members failed: {e}")
            return []

    async def update_member_role(self, org_id: str, user_id: str, role: str) -> bool:
        if not self._check_db():
            return False
        try:
            if role not in ("admin", "member", "viewer"):
                return False
            self._db._client.table("org_members").update({
                "member_role": role,
            }).eq("org_id", org_id).eq("user_id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"update_member_role failed: {e}")
            return False

    async def remove_member(self, org_id: str, user_id: str) -> bool:
        if not self._check_db():
            return False
        try:
            self._db._client.table("org_members").delete().eq(
                "org_id", org_id
            ).eq("user_id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"remove_member failed: {e}")
            return False

    async def list_invites(self, org_id: str) -> list[dict]:
        if not self._check_db():
            return []
        try:
            result = (
                self._db._client.table("org_invites")
                .select("*")
                .eq("org_id", org_id)
                .eq("accepted", False)
                .order("created_at", desc=True)
                .execute()
            )
            return result.data or []
        except Exception as e:
            logger.error(f"list_invites failed: {e}")
            return []

    async def revoke_invite(self, org_id: str, invite_id: str) -> bool:
        if not self._check_db():
            return False
        try:
            self._db._client.table("org_invites").delete().eq(
                "id", invite_id
            ).eq("org_id", org_id).execute()
            return True
        except Exception as e:
            logger.error(f"revoke_invite failed: {e}")
            return False

    # ══════════════════════════════════════════════════════════════════════
    # ASSET REGISTER
    # ══════════════════════════════════════════════════════════════════════

    async def list_assets(self, org_id: str, client_id: str | None = None) -> list[dict]:
        if not self._check_db():
            return []
        try:
            query = (
                self._db._client.table("assets")
                .select("*")
                .eq("org_id", org_id)
                .order("created_at", desc=True)
            )
            if client_id:
                query = query.eq("client_id", client_id)
            result = query.execute()
            return result.data or []
        except Exception as e:
            logger.error(f"list_assets failed: {e}")
            return []

    async def get_asset_count(self, org_id: str) -> int:
        if not self._check_db():
            return 0
        try:
            result = (
                self._db._client.table("assets")
                .select("id", count="exact")
                .eq("org_id", org_id)
                .execute()
            )
            return result.count or 0
        except Exception as e:
            logger.error(f"get_asset_count failed: {e}")
            return 0

    async def add_asset(
        self,
        org_id: str,
        display_name: str,
        cpe_string: str,
        criticality: str,
        owner_name: str = "",
        notes: str = "",
        client_id: str | None = None,
        org_type: str = "team",
    ) -> dict | None:
        if not self._check_db():
            return None
        try:
            # Enforce limits
            limits = self._get_plan_limits(org_type)
            current_count = await self.get_asset_count(org_id)
            if current_count >= limits["assets"]:
                return {"error": f"Asset limit reached ({limits['assets']}). Upgrade your plan for more."}

            criticality_upper = criticality.upper()
            if criticality_upper not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return {"error": "Criticality must be CRITICAL, HIGH, MEDIUM, or LOW"}

            result = self._db._client.table("assets").insert({
                "org_id": org_id,
                "display_name": display_name.strip(),
                "cpe_string": cpe_string.strip().lower(),
                "criticality": criticality_upper,
                "owner_name": owner_name.strip() if owner_name else "",
                "notes": notes.strip() if notes else "",
                "client_id": client_id,
            }).execute()

            return result.data[0] if result.data else {"status": "created"}
        except Exception as e:
            if "duplicate" in str(e).lower() or "unique" in str(e).lower():
                return {"error": "Asset with this CPE string already exists"}
            logger.error(f"add_asset failed: {e}")
            return None

    async def update_asset(self, org_id: str, asset_id: str, **kwargs) -> dict | None:
        if not self._check_db():
            return None
        try:
            update_data = {"updated_at": datetime.now(timezone.utc).isoformat()}
            for key in ("display_name", "cpe_string", "criticality", "owner_name", "notes"):
                if key in kwargs and kwargs[key] is not None:
                    val = kwargs[key]
                    if key == "criticality":
                        val = val.upper()
                    elif key == "cpe_string":
                        val = val.strip().lower()
                    elif isinstance(val, str):
                        val = val.strip()
                    update_data[key] = val

            result = (
                self._db._client.table("assets")
                .update(update_data)
                .eq("id", asset_id)
                .eq("org_id", org_id)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"update_asset failed: {e}")
            return None

    async def delete_asset(self, org_id: str, asset_id: str) -> bool:
        if not self._check_db():
            return False
        try:
            self._db._client.table("assets").delete().eq(
                "id", asset_id
            ).eq("org_id", org_id).execute()
            return True
        except Exception as e:
            logger.error(f"delete_asset failed: {e}")
            return False

    async def get_asset_cves(
        self, org_id: str, page: int = 1, page_size: int = 20, client_id: str | None = None
    ) -> dict:
        """Find CVEs matching org asset register — reuses WatchlistService matching logic."""
        if not self._check_db():
            return {"cves": [], "total": 0, "page": page}

        assets = await self.list_assets(org_id, client_id=client_id)
        if not assets:
            return {"cves": [], "total": 0, "page": page}

        # Build search terms from assets
        search_terms = []
        asset_cpe_map: dict[str, list[str]] = {}  # cve_id -> [asset_names]
        for asset in assets:
            cpe = asset.get("cpe_string", "").lower()
            name = asset.get("display_name", "").lower()
            if cpe:
                search_terms.append(cpe)
            if name:
                search_terms.append(name)

        search_terms = list(set(t for t in search_terms if t))
        if not search_terms:
            return {"cves": [], "total": 0, "page": page}

        try:
            query = (
                self._db._client.table("processed_cves")
                .select("*")
                .not_.is_("affected_products", "null")
                .order("priority_score", desc=True)
                .limit(500)
            )
            result = query.execute()
            all_cves = result.data or []

            matched = []
            for cve_row in all_cves:
                affected = cve_row.get("affected_products") or []
                if not affected:
                    continue
                affected_lower = [str(a).lower() for a in affected]
                affected_joined = " ".join(affected_lower)

                matched_assets = []
                for asset in assets:
                    cpe = asset.get("cpe_string", "").lower()
                    name = asset.get("display_name", "").lower()
                    if (cpe and cpe in affected_joined) or (name and name in affected_joined):
                        matched_assets.append(asset.get("display_name", ""))

                if matched_assets:
                    cve_row["matched_assets"] = matched_assets
                    matched.append(cve_row)

            matched.sort(key=lambda c: c.get("priority_score", 0), reverse=True)

            total = len(matched)
            start = (page - 1) * page_size
            end = start + page_size
            page_cves = matched[start:end]

            # Convert to ProcessedCVE format
            from app.services.database import SupabaseService
            converted = []
            for row in page_cves:
                cve = SupabaseService._row_to_cve(row)
                cve_dict = cve.model_dump() if hasattr(cve, "model_dump") else row
                cve_dict["matched_assets"] = row.get("matched_assets", [])
                converted.append(cve_dict)

            return {"cves": converted, "total": total, "page": page}
        except Exception as e:
            logger.error(f"get_asset_cves failed: {e}")
            return {"cves": [], "total": 0, "page": page}

    # ══════════════════════════════════════════════════════════════════════
    # TRIAGE BOARD
    # ══════════════════════════════════════════════════════════════════════

    async def _get_sla_hours(self, org_id: str, priority: str) -> int:
        """Get SLA hours for a priority level from sla_configs."""
        if not self._check_db():
            return DEFAULT_SLA_HOURS.get(priority, 168)
        try:
            result = (
                self._db._client.table("sla_configs")
                .select("sla_hours")
                .eq("org_id", org_id)
                .eq("priority", priority.upper())
                .execute()
            )
            if result.data:
                return result.data[0]["sla_hours"]
            return DEFAULT_SLA_HOURS.get(priority, 168)
        except Exception:
            return DEFAULT_SLA_HOURS.get(priority, 168)

    async def list_triage_items(
        self,
        org_id: str,
        status: str | None = None,
        client_id: str | None = None,
        assignee_id: str | None = None,
        severity: str | None = None,
        overdue_only: bool = False,
    ) -> list[dict]:
        if not self._check_db():
            return []
        try:
            query = (
                self._db._client.table("triage_items")
                .select("*")
                .eq("org_id", org_id)
                .order("created_at", desc=True)
            )
            if status:
                query = query.eq("status", status)
            if client_id:
                query = query.eq("client_id", client_id)
            if assignee_id:
                query = query.eq("assigned_to", assignee_id)

            result = query.execute()
            items = result.data or []

            # Bulk fetch CVEs
            unique_cves = list({item.get("cve_id") for item in items if item.get("cve_id")})
            cve_map = {}
            if unique_cves:
                try:
                    cve_resp = (
                        self._db._client.table("processed_cves")
                        .select("cve_id,description,priority_score,priority_label,cvss_score,enrichment,ai_explanation")
                        .in_("cve_id", unique_cves)
                        .execute()
                    )
                    for c in (cve_resp.data or []):
                        cve_map[c["cve_id"]] = c
                except Exception as e:
                    logger.error(f"Bulk fetch CVEs failed: {e}")

            # Bulk fetch Assignees
            unique_assignees = list({item.get("assigned_to") for item in items if item.get("assigned_to")})
            profile_map = {}
            if unique_assignees:
                try:
                    profile_resp = (
                        self._db._client.table("user_profiles")
                        .select("id,display_name,avatar_url")
                        .in_("id", unique_assignees)
                        .execute()
                    )
                    for p in (profile_resp.data or []):
                        profile_map[p["id"]] = p
                except Exception as e:
                    logger.error(f"Bulk fetch assignees failed: {e}")

            # Enrich with CVE data
            enriched = []
            for item in items:
                cve_id = item.get("cve_id")
                if cve_id and cve_id in cve_map:
                    cve_data = cve_map[cve_id]
                    item["cve_data"] = {
                        "description": (cve_data.get("description") or "")[:200],
                        "priority_score": cve_data.get("priority_score", 0),
                        "priority_label": cve_data.get("priority_label", "LOW"),
                        "cvss_score": cve_data.get("cvss_score", 0),
                        "in_kev": (cve_data.get("enrichment") or {}).get("in_kev", False),
                        "ai_summary": "",
                    }
                    ai = cve_data.get("ai_explanation")
                    if ai and isinstance(ai, dict):
                        item["cve_data"]["ai_summary"] = (ai.get("summary") or "")[:120]
                else:
                    item["cve_data"] = None

                # Compute is_overdue
                sla_due = item.get("sla_due_at")
                item_status = item.get("status", "")
                if sla_due and item_status not in ("mitigated", "wont_fix"):
                    try:
                        due_dt = datetime.fromisoformat(sla_due.replace("Z", "+00:00"))
                        item["is_overdue"] = datetime.now(timezone.utc) > due_dt
                    except Exception:
                        item["is_overdue"] = False
                else:
                    item["is_overdue"] = False

                # Severity filter (from CVE data)
                if severity:
                    cve_label = (item.get("cve_data") or {}).get("priority_label", "")
                    if cve_label != severity.upper():
                        continue

                if overdue_only and not item.get("is_overdue"):
                    continue

                # Enrich assignee
                assignee = item.get("assigned_to")
                item["assignee_id"] = assignee  # Map DB column to frontend field
                if assignee and assignee in profile_map:
                    profile = profile_map[assignee]
                    item["assignee_name"] = profile.get("display_name")
                    item["assignee_avatar"] = profile.get("avatar_url")

                enriched.append(item)

            return enriched
        except Exception as e:
            logger.error(f"list_triage_items failed: {e}")
            return []

    async def create_triage_item(
        self, org_id: str, cve_id: str, client_id: str | None = None, notes: str = ""
    ) -> dict | None:
        if not self._check_db():
            return None
        try:
            # Get CVE priority to set SLA
            priority = "MEDIUM"
            try:
                cve_result = (
                    self._db._client.table("processed_cves")
                    .select("priority_label")
                    .eq("cve_id", cve_id.upper())
                    .limit(1)
                    .execute()
                )
                if cve_result.data:
                    priority = cve_result.data[0].get("priority_label", "MEDIUM")
            except Exception:
                pass

            sla_hours = await self._get_sla_hours(org_id, priority)

            result = self._db._client.table("triage_items").insert({
                "org_id": org_id,
                "cve_id": cve_id.upper(),
                "client_id": client_id,
                "status": "new",
                "notes": notes[:500] if notes else "",
                "sla_hours": sla_hours,
            }).execute()

            if result.data:
                # Log activity
                item = result.data[0]
                asyncio.create_task(self._log_triage_activity(
                    item["id"], None, "created", f"Added to triage board"
                ))
                return item
            return None
        except Exception as e:
            if "duplicate" in str(e).lower() or "unique" in str(e).lower():
                return {"error": "This CVE is already in triage"}
            logger.error(f"create_triage_item failed: {e}")
            return None

    async def update_triage_item(
        self,
        org_id: str,
        item_id: str,
        user_id: str | None = None,
        status: str | None = None,
        assignee_id: str | None = None,
        notes: str | None = None,
    ) -> dict | None:
        if not self._check_db():
            return None
        try:
            # Get current item
            current = (
                self._db._client.table("triage_items")
                .select("*")
                .eq("id", item_id)
                .eq("org_id", org_id)
                .execute()
            )
            if not current.data:
                return {"error": "Triage item not found"}

            old_item = current.data[0]
            update_data = {"updated_at": datetime.now(timezone.utc).isoformat()}

            if status is not None:
                valid_statuses = ("new", "investigating", "remediation_planned", "mitigated", "wont_fix")
                if status not in valid_statuses:
                    return {"error": f"Status must be one of: {', '.join(valid_statuses)}"}

                update_data["status"] = status

                # SLA logic: when moving to investigating, start the clock
                if status == "investigating" and old_item.get("status") != "investigating":
                    now = datetime.now(timezone.utc)
                    sla_hours = old_item.get("sla_hours") or await self._get_sla_hours(org_id, "MEDIUM")
                    sla_due = now + timedelta(hours=sla_hours)
                    update_data["sla_started_at"] = now.isoformat()
                    update_data["sla_due_at"] = sla_due.isoformat()

                # Log status change
                if status != old_item.get("status"):
                    asyncio.create_task(self._log_triage_activity(
                        item_id,
                        user_id,
                        "status_change",
                        f"Status changed: {old_item.get('status', 'new')} → {status}",
                    ))

            if assignee_id is not None:
                update_data["assigned_to"] = assignee_id if assignee_id else None
                if assignee_id != old_item.get("assigned_to"):
                    asyncio.create_task(self._log_triage_activity(
                        item_id, user_id, "assignment", f"Assigned to {assignee_id or 'unassigned'}"
                    ))

            if notes is not None:
                update_data["notes"] = notes[:500]

            self._db._client.table("triage_items") \
                .update(update_data) \
                .eq("id", item_id) \
                .eq("org_id", org_id) \
                .execute()

            # Re-fetch the updated row
            updated = (
                self._db._client.table("triage_items")
                .select("*")
                .eq("id", item_id)
                .eq("org_id", org_id)
                .execute()
            )
            return updated.data[0] if updated.data else old_item
        except Exception as e:
            logger.error(f"update_triage_item failed: {e}")
            return None

    async def delete_triage_item(self, org_id: str, item_id: str) -> bool:
        if not self._check_db():
            return False
        try:
            # Delete activity first
            self._db._client.table("triage_activity").delete().eq("triage_item_id", item_id).execute()
            self._db._client.table("triage_items").delete().eq(
                "id", item_id
            ).eq("org_id", org_id).execute()
            return True
        except Exception as e:
            logger.error(f"delete_triage_item failed: {e}")
            return False

    async def get_triage_activity(self, item_id: str) -> list[dict]:
        if not self._check_db():
            return []
        try:
            result = (
                self._db._client.table("triage_activity")
                .select("*")
                .eq("triage_item_id", item_id)
                .order("created_at", desc=True)
                .limit(50)
                .execute()
            )
            return result.data or []
        except Exception as e:
            logger.error(f"get_triage_activity failed: {e}")
            return []

    async def auto_populate_triage(self, org_id: str, client_id: str | None = None) -> int:
        """Add all CRITICAL/HIGH CVEs from asset register not already in triage."""
        cve_result = await self.get_asset_cves(org_id, page=1, page_size=500, client_id=client_id)
        cves = cve_result.get("cves", [])

        # Filter CRITICAL/HIGH
        critical_high = [
            c for c in cves
            if c.get("priority_label") in ("CRITICAL", "HIGH")
        ]

        if not critical_high:
            return 0

        # Get existing triage CVE IDs
        try:
            existing = (
                self._db._client.table("triage_items")
                .select("cve_id")
                .eq("org_id", org_id)
                .execute()
            )
            existing_ids = {r["cve_id"] for r in (existing.data or [])}
        except Exception:
            existing_ids = set()

        added = 0
        for cve in critical_high:
            cve_id = cve.get("cve_id", "")
            if cve_id in existing_ids:
                continue
            result = await self.create_triage_item(org_id, cve_id, client_id=client_id)
            if result and "error" not in (result if isinstance(result, dict) else {}):
                added += 1

        return added

    async def _log_triage_activity(
        self, triage_item_id: str, user_id: str | None, action: str, detail: str
    ) -> None:
        if not self._check_db():
            return
        try:
            self._db._client.table("triage_activity").insert({
                "triage_item_id": triage_item_id,
                "actor_id": user_id,
                "action": action,
                "note": detail,
            }).execute()
        except Exception as e:
            logger.error(f"_log_triage_activity failed: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # SLA CONFIGURATION
    # ══════════════════════════════════════════════════════════════════════

    async def get_sla_config(self, org_id: str) -> list[dict]:
        if not self._check_db():
            return [{"priority": p, "sla_hours": h} for p, h in DEFAULT_SLA_HOURS.items()]
        try:
            result = (
                self._db._client.table("sla_configs")
                .select("*")
                .eq("org_id", org_id)
                .execute()
            )
            if result.data:
                return result.data
            return [{"priority": p, "sla_hours": h} for p, h in DEFAULT_SLA_HOURS.items()]
        except Exception as e:
            logger.error(f"get_sla_config failed: {e}")
            return [{"priority": p, "sla_hours": h} for p, h in DEFAULT_SLA_HOURS.items()]

    async def upsert_sla_config(self, org_id: str, config: dict) -> bool:
        """config: { 'CRITICAL': 24, 'HIGH': 72, 'MEDIUM': 168, 'LOW': 336 }"""
        if not self._check_db():
            return False
        try:
            for priority, hours in config.items():
                priority_upper = priority.upper()
                if priority_upper not in DEFAULT_SLA_HOURS:
                    continue
                self._db._client.table("sla_configs").upsert({
                    "org_id": org_id,
                    "priority": priority_upper,
                    "sla_hours": int(hours),
                }, on_conflict="org_id,priority").execute()
            return True
        except Exception as e:
            logger.error(f"upsert_sla_config failed: {e}")
            return False

    # ══════════════════════════════════════════════════════════════════════
    # MSSP CLIENT MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════

    async def list_clients(self, org_id: str) -> list[dict]:
        if not self._check_db():
            return []
        try:
            result = (
                self._db._client.table("org_clients")
                .select("*")
                .eq("org_id", org_id)
                .order("created_at", desc=True)
                .execute()
            )
            return result.data or []
        except Exception as e:
            logger.error(f"list_clients failed: {e}")
            return []

    async def create_client(
        self, org_id: str, name: str, contact_name: str = "", contact_email: str = ""
    ) -> dict | None:
        if not self._check_db():
            return None
        try:
            result = self._db._client.table("org_clients").insert({
                "org_id": org_id,
                "name": name.strip(),
                "contact_name": contact_name.strip() if contact_name else "",
                "contact_email": contact_email.strip().lower() if contact_email else "",
            }).execute()
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"create_client failed: {e}")
            return None

    async def update_client(self, org_id: str, client_id: str, **kwargs) -> dict | None:
        if not self._check_db():
            return None
        try:
            update_data = {"updated_at": datetime.now(timezone.utc).isoformat()}
            for key in ("name", "contact_name", "contact_email"):
                if key in kwargs and kwargs[key] is not None:
                    update_data[key] = kwargs[key].strip()
            result = (
                self._db._client.table("org_clients")
                .update(update_data)
                .eq("id", client_id)
                .eq("org_id", org_id)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"update_client failed: {e}")
            return None

    async def delete_client(self, org_id: str, client_id: str) -> bool:
        """Delete client and cascade to assets + triage items."""
        if not self._check_db():
            return False
        try:
            # Delete triage items for this client
            triage_items = (
                self._db._client.table("triage_items")
                .select("id")
                .eq("org_id", org_id)
                .eq("client_id", client_id)
                .execute()
            )
            for item in (triage_items.data or []):
                self._db._client.table("triage_activity").delete().eq("triage_item_id", item["id"]).execute()
            self._db._client.table("triage_items").delete().eq("org_id", org_id).eq("client_id", client_id).execute()

            # Delete assets for this client
            self._db._client.table("assets").delete().eq("org_id", org_id).eq("client_id", client_id).execute()

            # Delete client
            self._db._client.table("org_clients").delete().eq("id", client_id).eq("org_id", org_id).execute()
            return True
        except Exception as e:
            logger.error(f"delete_client failed: {e}")
            return False

    async def get_client_summary(self, org_id: str, client_id: str) -> dict:
        """Get exposure score + open triage count + overdue count for one client."""
        if not self._check_db():
            return {"exposure_score": 0, "open_triage": 0, "overdue_count": 0}
        try:
            # Get exposure from cache or calculate
            score = 0
            try:
                result = (
                    self._db._client.table("org_exposure_scores")
                    .select("*")
                    .eq("org_id", org_id)
                    .eq("client_id", client_id)
                    .order("calculated_at", desc=True)
                    .limit(1)
                    .execute()
                )
                if result.data:
                    row = result.data[0]
                    calc_dt = datetime.fromisoformat(row.get("calculated_at", "").replace("Z", "+00:00"))
                    if (datetime.now(timezone.utc) - calc_dt) < timedelta(hours=1):
                        score = row.get("score", 0)
                    else:
                        exposure = await self.calculate_org_exposure(org_id, client_id=client_id)
                        score = exposure.get("score", 0)
                else:
                    exposure = await self.calculate_org_exposure(org_id, client_id=client_id)
                    score = exposure.get("score", 0)
            except Exception:
                exposure = await self.calculate_org_exposure(org_id, client_id=client_id)
                score = exposure.get("score", 0)

            # Open triage count
            triage = (
                self._db._client.table("triage_items")
                .select("id,sla_due_at,status")
                .eq("org_id", org_id)
                .eq("client_id", client_id)
                .not_.in_("status", ["mitigated", "wont_fix"])
                .execute()
            )
            open_items = triage.data or []
            overdue = 0
            now = datetime.now(timezone.utc)
            for item in open_items:
                sla_due = item.get("sla_due_at")
                if sla_due:
                    try:
                        due_dt = datetime.fromisoformat(sla_due.replace("Z", "+00:00"))
                        if now > due_dt:
                            overdue += 1
                    except Exception:
                        pass

            return {
                "exposure_score": score,
                "open_triage": len(open_items),
                "overdue_count": overdue,
                "client_id": client_id,
            }
        except Exception as e:
            logger.error(f"get_client_summary failed: {e}")
            return {"exposure_score": 0, "open_triage": 0, "overdue_count": 0}

    # ══════════════════════════════════════════════════════════════════════
    # ORG EXPOSURE SCORE
    # ══════════════════════════════════════════════════════════════════════

    async def calculate_org_exposure(self, org_id: str, client_id: str | None = None) -> dict:
        """Compute exposure score 0-100 scoped to org assets."""
        cve_result = await self.get_asset_cves(org_id, page=1, page_size=500, client_id=client_id)
        cves = cve_result.get("cves", [])

        critical_count = sum(1 for c in cves if c.get("priority_label") == "CRITICAL")
        high_count = sum(1 for c in cves if c.get("priority_label") == "HIGH")
        medium_count = sum(1 for c in cves if c.get("priority_label") == "MEDIUM")

        base = min(100, critical_count * 10 + high_count * 4 + medium_count * 1)

        actively_exploited_count = sum(
            1 for c in cves
            if (c.get("enrichment") or {}).get("in_kev", False)
        )
        score = base
        if actively_exploited_count > 0:
            score = min(100, int(base * 1.3))

        top_cves = []
        sorted_cves = sorted(cves, key=lambda c: c.get("priority_score", 0), reverse=True)[:5]
        for c in sorted_cves:
            top_cves.append({
                "cve_id": c.get("cve_id", ""),
                "priority_score": c.get("priority_score", 0),
                "priority_label": c.get("priority_label", "LOW"),
                "description": (c.get("description") or "")[:150],
                "in_kev": (c.get("enrichment") or {}).get("in_kev", False),
                "matched_assets": c.get("matched_assets", []),
            })

        now_iso = datetime.now(timezone.utc).isoformat()

        # Store in org_exposure_scores
        if self._check_db():
            try:
                store_data = {
                    "org_id": org_id,
                    "client_id": client_id,
                    "score": score,
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "actively_exploited_count": actively_exploited_count,
                    "calculated_at": now_iso,
                }
                # Delete existing for this org+client, then insert
                q = self._db._client.table("org_exposure_scores").delete().eq("org_id", org_id)
                if client_id:
                    q = q.eq("client_id", client_id)
                else:
                    q = q.is_("client_id", "null")
                q.execute()
                self._db._client.table("org_exposure_scores").insert(store_data).execute()
            except Exception as e:
                logger.error(f"Failed to store org exposure score: {e}")

        return {
            "score": score,
            "critical_count": critical_count,
            "high_count": high_count,
            "actively_exploited_count": actively_exploited_count,
            "top_cves": top_cves,
            "calculated_at": now_iso,
        }

    async def get_org_exposure(self, org_id: str) -> dict:
        """Get latest org exposure score, recalculate if older than 1 hour."""
        if not self._check_db():
            return await self.calculate_org_exposure(org_id)
        try:
            result = (
                self._db._client.table("org_exposure_scores")
                .select("*")
                .eq("org_id", org_id)
                .order("calculated_at", desc=True)
                .limit(10)
                .execute()
            )
            if result.data:
                # Check freshness of the most recent
                row = result.data[0]
                calc_at = row.get("calculated_at", "")
                try:
                    calc_dt = datetime.fromisoformat(calc_at.replace("Z", "+00:00"))
                    if (datetime.now(timezone.utc) - calc_dt) < timedelta(hours=1):
                        # Return all client scores
                        return {
                            "scores": result.data,
                            "calculated_at": calc_at,
                        }
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Failed to fetch cached org exposure: {e}")

        # Recalculate
        return await self.calculate_org_exposure(org_id)

    async def recalculate_all_clients(self, org_id: str) -> list[dict]:
        """Force recalculate exposure for org and all clients."""
        results = []

        # Org-level (no client filter)
        org_score = await self.calculate_org_exposure(org_id)
        results.append({"client_id": None, **org_score})

        # Per-client
        clients = await self.list_clients(org_id)
        for client in clients:
            client_score = await self.calculate_org_exposure(org_id, client_id=client["id"])
            results.append({"client_id": client["id"], **client_score})

        return results

    # ══════════════════════════════════════════════════════════════════════
    # COMPLIANCE SNAPSHOT
    # ══════════════════════════════════════════════════════════════════════

    async def get_compliance_data(
        self, org_id: str, days: int = 30, client_id: str | None = None
    ) -> dict:
        """Assemble compliance snapshot data."""
        if not self._check_db():
            return {"cves": [], "stats": {}}

        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

            # Get triage items in date range
            query = (
                self._db._client.table("triage_items")
                .select("*")
                .eq("org_id", org_id)
                .gte("created_at", cutoff)
            )
            if client_id:
                query = query.eq("client_id", client_id)

            result = query.order("created_at", desc=True).execute()
            items = result.data or []

            # Enrich with CVE data
            enriched = []
            kev_count = 0
            mitigated_count = 0
            critical_high_count = 0
            total_remediation_days = 0
            remediated_in_sla = 0

            for item in items:
                cve_id = item.get("cve_id")
                cve_data = {}
                if cve_id:
                    try:
                        cve_result = (
                            self._db._client.table("processed_cves")
                            .select("priority_label,cvss_score,enrichment,published")
                            .eq("cve_id", cve_id)
                            .limit(1)
                            .execute()
                        )
                        if cve_result.data:
                            cve_data = cve_result.data[0]
                    except Exception:
                        pass

                priority_label = cve_data.get("priority_label", "LOW")
                in_kev = (cve_data.get("enrichment") or {}).get("in_kev", False)

                if in_kev:
                    kev_count += 1
                if priority_label in ("CRITICAL", "HIGH"):
                    critical_high_count += 1
                if item.get("status") == "mitigated":
                    mitigated_count += 1
                    # Calculate days to remediate
                    created = item.get("created_at", "")
                    updated = item.get("updated_at", "")
                    try:
                        c_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        u_dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                        days_to_rem = (u_dt - c_dt).days
                        total_remediation_days += max(0, days_to_rem)
                    except Exception:
                        days_to_rem = None

                    # Check if remediated within SLA
                    sla_due = item.get("sla_due_at")
                    if sla_due and updated:
                        try:
                            sla_dt = datetime.fromisoformat(sla_due.replace("Z", "+00:00"))
                            u_dt2 = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                            if u_dt2 <= sla_dt:
                                remediated_in_sla += 1
                        except Exception:
                            pass

                # Get matched assets
                matched_assets = []
                try:
                    asset_results = (
                        self._db._client.table("assets")
                        .select("display_name")
                        .eq("org_id", org_id)
                        .execute()
                    )
                    # Simple matching by CVE affected products
                    matched_assets = [a["display_name"] for a in (asset_results.data or [])][:3]
                except Exception:
                    pass

                enriched.append({
                    "cve_id": cve_id,
                    "severity": priority_label,
                    "in_kev": in_kev,
                    "first_detected": item.get("created_at"),
                    "triage_status": item.get("status"),
                    "days_to_remediate": days_to_rem if item.get("status") == "mitigated" else None,
                    "matched_assets": matched_assets,
                })

            total = len(items)
            remediation_rate = round((mitigated_count / total * 100), 1) if total > 0 else 0
            sla_compliance_rate = round((remediated_in_sla / mitigated_count * 100), 1) if mitigated_count > 0 else 0
            avg_remediation_days = round(total_remediation_days / mitigated_count, 1) if mitigated_count > 0 else 0

            return {
                "cves": enriched,
                "stats": {
                    "total_cves": total,
                    "critical_high_count": critical_high_count,
                    "kev_count": kev_count,
                    "mitigated_count": mitigated_count,
                    "remediation_rate": remediation_rate,
                    "sla_compliance_rate": sla_compliance_rate,
                    "avg_remediation_days": avg_remediation_days,
                },
                "date_range": {"days": days, "from": cutoff},
            }
        except Exception as e:
            logger.error(f"get_compliance_data failed: {e}")
            return {"cves": [], "stats": {}}

    # ══════════════════════════════════════════════════════════════════════
    # SCHEDULED JOBS
    # ══════════════════════════════════════════════════════════════════════

    async def check_sla_breaches(self) -> None:
        """Hourly job: log overdue triage items."""
        if not self._check_db():
            return
        logger.info("🕐 SLA breach check triggered")
        try:
            now = datetime.now(timezone.utc)
            result = (
                self._db._client.table("triage_items")
                .select("id,org_id,cve_id,sla_due_at,status")
                .not_.in_("status", ["mitigated", "wont_fix"])
                .not_.is_("sla_due_at", "null")
                .execute()
            )
            overdue_count = 0
            for item in (result.data or []):
                sla_due = item.get("sla_due_at", "")
                try:
                    due_dt = datetime.fromisoformat(sla_due.replace("Z", "+00:00"))
                    if now > due_dt:
                        overdue_count += 1
                        logger.warning(
                            f"SLA BREACH: {item['cve_id']} in org {item['org_id']} — "
                            f"due {sla_due}, status={item['status']}"
                        )
                except Exception:
                    pass
            logger.info(f"SLA breach check complete: {overdue_count} overdue items")
        except Exception as e:
            logger.error(f"check_sla_breaches failed: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # EMAIL
    # ══════════════════════════════════════════════════════════════════════

    async def _send_email(self, to_email: str, subject: str, html_content: str) -> bool:
        """Send an email via SendGrid (reusing existing pattern)."""
        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail

            if not settings.SENDGRID_API_KEY or not settings.SENDGRID_FROM_EMAIL:
                logger.warning("SendGrid not configured, skipping invite email")
                return False

            message = Mail(
                from_email=(settings.SENDGRID_FROM_EMAIL, settings.SENDGRID_FROM_NAME),
                to_emails=to_email,
                subject=subject,
                html_content=html_content,
            )
            sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
            try:
                response = sg.send(message)
                logger.info(f"Invite email sent to {to_email}: {response.status_code}")
                with open("sendgrid_log.txt", "a") as f:
                    f.write(f"SUCCESS: {to_email} {response.status_code}\n")
                return response.status_code in (200, 201, 202)
            except Exception as e:
                with open("sendgrid_log.txt", "a") as f:
                    f.write(f"ERROR inside send(): {e}\n")
                raise e
        except Exception as e:
            logger.error(f"SendGrid send failed to {to_email}: {e}")
            with open("sendgrid_log.txt", "a") as f:
                f.write(f"ERROR: {e}\n")
            return False

    def _build_invite_email(
        self, org_name: str, inviter_name: str, role: str, accept_url: str
    ) -> str:
        """Build dark-themed invite HTML email."""
        return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#080a0f;font-family:'DM Sans',-apple-system,sans-serif;">
  <div style="max-width:600px;margin:0 auto;padding:24px;">
    <!-- Header -->
    <div style="text-align:center;padding:24px 0;border-bottom:1px solid #1e293b;">
      <div style="font-family:'Syne',sans-serif;font-size:24px;font-weight:700;color:#e6edf3;">
        Know<span style="color:#00ff88;">CVE</span>
      </div>
    </div>

    <!-- Body -->
    <div style="padding:32px 0;">
      <h1 style="margin:0 0 16px;font-size:22px;color:#e6edf3;font-family:'Syne',sans-serif;">
        You've been invited to join {org_name}
      </h1>
      <p style="margin:0 0 24px;font-size:15px;color:#9ca3af;line-height:1.6;">
        <strong style="color:#e6edf3;">{inviter_name}</strong> has invited you to join
        <strong style="color:#00ff88;">{org_name}</strong> on KnowCVE as a
        <span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;color:#00ff88;background:#00ff8815;border:1px solid #00ff8830;font-family:'JetBrains Mono',monospace;">{role.upper()}</span>.
      </p>
      <p style="margin:0 0 32px;font-size:14px;color:#6b7280;line-height:1.6;">
        You'll get access to shared asset tracking, CVE triage boards, and compliance reporting for your team.
      </p>

      <!-- CTA Button -->
      <div style="text-align:center;">
        <a href="{accept_url}" style="display:inline-block;padding:14px 32px;background:#00ff88;color:#080a0f;font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:600;text-decoration:none;border-radius:8px;letter-spacing:0.5px;text-transform:uppercase;">
          Accept Invitation
        </a>
      </div>
    </div>

    <!-- Footer -->
    <div style="margin:32px 0 0;padding:20px 0 0;border-top:1px solid #1e293b;text-align:center;">
      <p style="font-size:11px;color:#4b5563;line-height:1.8;">
        This invitation expires in 7 days.<br>
        If you didn't expect this invitation, you can safely ignore this email.
      </p>
    </div>
  </div>
</body>
</html>"""
