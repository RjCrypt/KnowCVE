"""Phase 8 — Org workspace endpoints.

Completely separate from the existing routes.py and auth_routes.py.
Uses the same SupabaseService (_db) pattern.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

org_router = APIRouter()

# Injected by main.py at startup
_db = None
_org_svc = None


def init_org_routes(db=None, org=None) -> None:
    global _db, _org_svc
    _db = db
    _org_svc = org


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class OrgCreateRequest(BaseModel):
    name: str
    org_type: str  # "team" or "mssp"
    owner_id: str

class OrgUpdateRequest(BaseModel):
    name: str

class InviteMemberRequest(BaseModel):
    email: str
    role: str  # "admin", "member", "viewer"
    inviter_name: str = "A team member"

class MemberRoleUpdateRequest(BaseModel):
    role: str

class AssetCreateRequest(BaseModel):
    display_name: str
    cpe_string: str
    criticality: str = "MEDIUM"
    owner_name: str = ""
    notes: str = ""
    client_id: Optional[str] = None

class AssetUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    cpe_string: Optional[str] = None
    criticality: Optional[str] = None
    owner_name: Optional[str] = None
    notes: Optional[str] = None

class TriageCreateRequest(BaseModel):
    cve_id: str
    client_id: Optional[str] = None
    notes: str = ""

class TriageUpdateRequest(BaseModel):
    status: Optional[str] = None
    assignee_id: Optional[str] = None
    notes: Optional[str] = None
    user_id: Optional[str] = None  # who is making the change

class SLAConfigRequest(BaseModel):
    CRITICAL: int = 24
    HIGH: int = 72
    MEDIUM: int = 168
    LOW: int = 336

class ClientCreateRequest(BaseModel):
    name: str
    contact_name: str = ""
    contact_email: str = ""

class ClientUpdateRequest(BaseModel):
    name: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ensure_svc():
    if not _org_svc:
        raise HTTPException(status_code=503, detail="Org service not configured")

def _ensure_db():
    if not _db or not _db.is_configured:
        raise HTTPException(status_code=503, detail="Database not configured")


async def _require_access(org_id: str, user_id: str, min_role: str = "member"):
    """Validate user has sufficient role in org. Raises 403 if not."""
    member = await _org_svc.check_org_access(org_id, user_id, min_role)
    if not member:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied. Requires '{min_role}' role or higher.",
        )
    return member

async def _require_mssp(org_id: str):
    """Validate org is an MSSP."""
    org = await _org_svc.get_org(org_id)
    if not org or org.get("org_type") != "mssp":
        raise HTTPException(
            status_code=403,
            detail="Access denied. This feature requires an MSSP plan.",
        )
    return org


# ══════════════════════════════════════════════════════════════════════════════
# Org CRUD
# ══════════════════════════════════════════════════════════════════════════════

@org_router.post("/api/orgs", tags=["Organizations"])
async def create_org(req: OrgCreateRequest):
    """Create a new organization."""
    _ensure_svc()
    _ensure_db()
    result = await _org_svc.create_org(req.name, req.org_type, req.owner_id)
    if result is None:
        raise HTTPException(status_code=500, detail="Failed to create organization")
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@org_router.get("/api/orgs/user/{user_id}", tags=["Organizations"])
async def get_user_orgs(user_id: str):
    """Get all orgs a user belongs to."""
    _ensure_svc()
    orgs = await _org_svc.get_user_orgs(user_id)
    return {"data": orgs, "total": len(orgs)}


@org_router.get("/api/orgs/{org_id}", tags=["Organizations"])
async def get_org(org_id: str, user_id: str = Query(...)):
    """Get org details + members + plan limits."""
    _ensure_svc()
    _ensure_db()
    member = await _require_access(org_id, user_id, "viewer")
    org = await _org_svc.get_org(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org["user_role"] = member.get("member_role") or member.get("role")
    return org


@org_router.patch("/api/orgs/{org_id}", tags=["Organizations"])
async def update_org(org_id: str, req: OrgUpdateRequest, user_id: str = Query(...)):
    """Update org name."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")
    result = await _org_svc.update_org(org_id, req.name)
    if not result:
        raise HTTPException(status_code=500, detail="Failed to update organization")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Members & Invites
# ══════════════════════════════════════════════════════════════════════════════

@org_router.post("/api/orgs/{org_id}/members/invite", tags=["Org Members"])
async def invite_member(org_id: str, req: InviteMemberRequest, user_id: str = Query(...)):
    """Send an invite to join the org."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")

    # Get org name for email
    org = await _org_svc.get_org(org_id)
    org_name = org.get("name", "Organization") if org else "Organization"

    result = await _org_svc.invite_member(org_id, req.email, req.role, req.inviter_name, org_name)
    if result is None:
        raise HTTPException(status_code=500, detail="Failed to send invite")
    if isinstance(result, dict) and "error" in result:
        status_code = 400
        if result["error"] == "member_limit_reached":
            status_code = 403
            result["error"] = f"Member limit reached ({result.get('limit', '?')}). Upgrade your plan to add more members."
        raise HTTPException(status_code=status_code, detail=result["error"])
    return result


@org_router.get("/api/orgs/{org_id}/members", tags=["Org Members"])
async def list_members(org_id: str, user_id: str = Query(...)):
    """List all members with roles."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    members = await _org_svc.list_members(org_id)
    return {"data": members, "total": len(members)}


@org_router.patch("/api/orgs/{org_id}/members/{target_user_id}", tags=["Org Members"])
async def update_member_role(
    org_id: str, target_user_id: str, req: MemberRoleUpdateRequest, user_id: str = Query(...)
):
    """Update a member's role."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")
    ok = await _org_svc.update_member_role(org_id, target_user_id, req.role)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to update role")
    return {"status": "updated"}


@org_router.delete("/api/orgs/{org_id}/members/{target_user_id}", tags=["Org Members"])
async def remove_member(org_id: str, target_user_id: str, user_id: str = Query(...)):
    """Remove a member from the org."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")
    ok = await _org_svc.remove_member(org_id, target_user_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to remove member")
    return {"status": "removed"}


@org_router.get("/api/invites/accept/{token}", tags=["Org Members"])
async def accept_invite(token: str, user_id: Optional[str] = Query(None)):
    """Accept an org invite by token. Pass user_id if the user is logged in."""
    _ensure_svc()
    _ensure_db()
    result = await _org_svc.accept_invite(token, user_id=user_id)
    if result is None:
        raise HTTPException(status_code=500, detail="Failed to accept invite")
    # requires_signup is not an error — return 200 so frontend handles it
    if isinstance(result, dict) and result.get("requires_signup"):
        return result
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@org_router.get("/api/orgs/{org_id}/invites", tags=["Org Members"])
async def list_invites(org_id: str, user_id: str = Query(...)):
    """List pending invites."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")
    invites = await _org_svc.list_invites(org_id)
    return {"data": invites, "total": len(invites)}


@org_router.delete("/api/orgs/{org_id}/invites/{invite_id}", tags=["Org Members"])
async def revoke_invite(org_id: str, invite_id: str, user_id: str = Query(...)):
    """Revoke a pending invite."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")
    ok = await _org_svc.revoke_invite(org_id, invite_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to revoke invite")
    return {"status": "revoked"}


# ══════════════════════════════════════════════════════════════════════════════
# Asset Register
# ══════════════════════════════════════════════════════════════════════════════

@org_router.get("/api/orgs/{org_id}/assets", tags=["Assets"])
async def list_assets(
    org_id: str,
    user_id: str = Query(...),
    client_id: Optional[str] = Query(None),
):
    """List org assets, optionally filtered by client."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    assets = await _org_svc.list_assets(org_id, client_id=client_id)
    count = await _org_svc.get_asset_count(org_id)

    # Get org type for limits
    org = await _org_svc.get_org(org_id)
    org_type = org.get("org_type", "team") if org else "team"
    from app.services.org_service import PLAN_LIMITS
    limits = PLAN_LIMITS.get(org_type, PLAN_LIMITS["team"])

    return {
        "data": assets,
        "total": len(assets),
        "asset_count": count,
        "asset_limit": limits["assets"],
    }


@org_router.post("/api/orgs/{org_id}/assets", tags=["Assets"])
async def add_asset(org_id: str, req: AssetCreateRequest, user_id: str = Query(...)):
    """Add an asset to the org register."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "member")

    # Get org type for limit enforcement
    org = await _org_svc.get_org(org_id)
    org_type = org.get("org_type", "team") if org else "team"

    result = await _org_svc.add_asset(
        org_id=org_id,
        display_name=req.display_name,
        cpe_string=req.cpe_string,
        criticality=req.criticality,
        owner_name=req.owner_name,
        notes=req.notes,
        client_id=req.client_id,
        org_type=org_type,
    )
    if result is None:
        raise HTTPException(status_code=500, detail="Failed to add asset")
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@org_router.patch("/api/orgs/{org_id}/assets/{asset_id}", tags=["Assets"])
async def update_asset(
    org_id: str, asset_id: str, req: AssetUpdateRequest, user_id: str = Query(...)
):
    """Update an asset."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "member")
    result = await _org_svc.update_asset(
        org_id, asset_id,
        display_name=req.display_name,
        cpe_string=req.cpe_string,
        criticality=req.criticality,
        owner_name=req.owner_name,
        notes=req.notes,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@org_router.delete("/api/orgs/{org_id}/assets/{asset_id}", tags=["Assets"])
async def delete_asset(org_id: str, asset_id: str, user_id: str = Query(...)):
    """Delete an asset."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "member")
    ok = await _org_svc.delete_asset(org_id, asset_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to delete asset")
    return {"status": "deleted"}


@org_router.get("/api/orgs/{org_id}/assets/cves", tags=["Assets"])
async def get_asset_cves(
    org_id: str,
    user_id: str = Query(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    client_id: Optional[str] = Query(None),
):
    """Get all CVEs matching org asset register."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    return await _org_svc.get_asset_cves(org_id, page=page, page_size=page_size, client_id=client_id)


# ══════════════════════════════════════════════════════════════════════════════
# Triage Board
# ══════════════════════════════════════════════════════════════════════════════

@org_router.get("/api/orgs/{org_id}/triage", tags=["Triage"])
async def list_triage_items(
    org_id: str,
    user_id: str = Query(...),
    status: Optional[str] = Query(None),
    client_id: Optional[str] = Query(None),
    assignee_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    overdue_only: bool = Query(False),
):
    """List triage items with CVE data enriched inline."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    items = await _org_svc.list_triage_items(
        org_id,
        status=status,
        client_id=client_id,
        assignee_id=assignee_id,
        severity=severity,
        overdue_only=overdue_only,
    )
    return {"data": items, "total": len(items)}


@org_router.post("/api/orgs/{org_id}/triage", tags=["Triage"])
async def create_triage_item(org_id: str, req: TriageCreateRequest, user_id: str = Query(...)):
    """Create a triage item."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "member")
    result = await _org_svc.create_triage_item(org_id, req.cve_id, client_id=req.client_id, notes=req.notes)
    if result is None:
        raise HTTPException(status_code=500, detail="Failed to create triage item")
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@org_router.patch("/api/orgs/{org_id}/triage/{item_id}", tags=["Triage"])
async def update_triage_item(
    org_id: str, item_id: str, req: TriageUpdateRequest, user_id: str = Query(...)
):
    """Update triage item status/assignment/notes."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "member")
    result = await _org_svc.update_triage_item(
        org_id, item_id,
        user_id=req.user_id or user_id,
        status=req.status,
        assignee_id=req.assignee_id,
        notes=req.notes,
    )
    if result is None:
        raise HTTPException(status_code=500, detail="Failed to update triage item")
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@org_router.delete("/api/orgs/{org_id}/triage/{item_id}", tags=["Triage"])
async def delete_triage_item(org_id: str, item_id: str, user_id: str = Query(...)):
    """Delete a triage item."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "member")
    ok = await _org_svc.delete_triage_item(org_id, item_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to delete triage item")
    return {"status": "deleted"}


@org_router.get("/api/orgs/{org_id}/triage/{item_id}/activity", tags=["Triage"])
async def get_triage_activity(org_id: str, item_id: str, user_id: str = Query(...)):
    """Get activity log for a triage item."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    activity = await _org_svc.get_triage_activity(item_id)
    return {"data": activity}


@org_router.post("/api/orgs/{org_id}/triage/auto-populate", tags=["Triage"])
async def auto_populate_triage(
    org_id: str,
    user_id: str = Query(...),
    client_id: Optional[str] = Query(None),
):
    """Add all CRITICAL/HIGH CVEs from assets not already in triage."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "member")
    count = await _org_svc.auto_populate_triage(org_id, client_id=client_id)
    return {"status": "ok", "items_added": count}


# ══════════════════════════════════════════════════════════════════════════════
# SLA Configuration
# ══════════════════════════════════════════════════════════════════════════════

@org_router.get("/api/orgs/{org_id}/sla", tags=["SLA"])
async def get_sla_config(org_id: str, user_id: str = Query(...)):
    """Get SLA configuration."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    config = await _org_svc.get_sla_config(org_id)
    return {"data": config}


@org_router.post("/api/orgs/{org_id}/sla", tags=["SLA"])
async def upsert_sla_config(org_id: str, req: SLAConfigRequest, user_id: str = Query(...)):
    """Upsert SLA hours per priority."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")
    config = {
        "CRITICAL": req.CRITICAL,
        "HIGH": req.HIGH,
        "MEDIUM": req.MEDIUM,
        "LOW": req.LOW,
    }
    ok = await _org_svc.upsert_sla_config(org_id, config)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to update SLA config")
    return {"status": "saved", "config": config}


# ══════════════════════════════════════════════════════════════════════════════
# MSSP Client Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@org_router.get("/api/orgs/{org_id}/clients", tags=["MSSP Clients"])
async def list_clients(org_id: str, user_id: str = Query(...)):
    """List all clients for an MSSP org."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    await _require_mssp(org_id)
    clients = await _org_svc.list_clients(org_id)
    return {"data": clients, "total": len(clients)}


@org_router.post("/api/orgs/{org_id}/clients", tags=["MSSP Clients"])
async def create_client(org_id: str, req: ClientCreateRequest, user_id: str = Query(...)):
    """Create a client."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")
    await _require_mssp(org_id)
    result = await _org_svc.create_client(org_id, req.name, req.contact_name, req.contact_email)
    if not result:
        raise HTTPException(status_code=500, detail="Failed to create client")
    return result


@org_router.patch("/api/orgs/{org_id}/clients/{client_id}", tags=["MSSP Clients"])
async def update_client(
    org_id: str, client_id: str, req: ClientUpdateRequest, user_id: str = Query(...)
):
    """Update a client."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")
    await _require_mssp(org_id)
    result = await _org_svc.update_client(
        org_id, client_id, name=req.name, contact_name=req.contact_name, contact_email=req.contact_email,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Client not found")
    return result


@org_router.delete("/api/orgs/{org_id}/clients/{client_id}", tags=["MSSP Clients"])
async def delete_client(org_id: str, client_id: str, user_id: str = Query(...)):
    """Delete a client (cascades assets + triage items)."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "admin")
    await _require_mssp(org_id)
    ok = await _org_svc.delete_client(org_id, client_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to delete client")
    return {"status": "deleted"}


@org_router.get("/api/orgs/{org_id}/clients/{client_id}/summary", tags=["MSSP Clients"])
async def get_client_summary(org_id: str, client_id: str, user_id: str = Query(...)):
    """Exposure score + open triage + overdue for one client."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    await _require_mssp(org_id)
    return await _org_svc.get_client_summary(org_id, client_id)


# ══════════════════════════════════════════════════════════════════════════════
# Exposure + Compliance
# ══════════════════════════════════════════════════════════════════════════════

@org_router.get("/api/orgs/{org_id}/exposure", tags=["Org Exposure"])
async def get_org_exposure(org_id: str, user_id: str = Query(...)):
    """Get latest org exposure score (recalculate if >1h old)."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    return await _org_svc.get_org_exposure(org_id)


@org_router.post("/api/orgs/{org_id}/exposure/recalculate", tags=["Org Exposure"])
async def recalculate_exposure(org_id: str, user_id: str = Query(...)):
    """Force recalculate exposure for all clients."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "member")
    results = await _org_svc.recalculate_all_clients(org_id)
    return {"status": "recalculated", "scores": results}


@org_router.get("/api/orgs/{org_id}/compliance", tags=["Compliance"])
async def get_compliance_data(
    org_id: str,
    user_id: str = Query(...),
    days: int = Query(30, ge=7, le=365),
    client_id: Optional[str] = Query(None),
):
    """Compliance snapshot data."""
    _ensure_svc()
    _ensure_db()
    await _require_access(org_id, user_id, "viewer")
    return await _org_svc.get_compliance_data(org_id, days=days, client_id=client_id)
