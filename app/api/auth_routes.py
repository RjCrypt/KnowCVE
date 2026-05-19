"""Phase 6 — Auth, Bookmark & Waitlist endpoints.

Completely separate from the existing routes.py.
Uses the same SupabaseService (_db) pattern.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr

logger = logging.getLogger(__name__)

auth_router = APIRouter()

# Injected by main.py at startup
_db = None
_watchlist_svc = None


def init_auth_routes(db=None, watchlist=None) -> None:
    global _db, _watchlist_svc
    _db = db
    _watchlist_svc = watchlist


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class ProfileUpsertRequest(BaseModel):
    id: str
    email: str
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None


class ProfileUpdateRequest(BaseModel):
    role: Optional[str] = None
    tech_context: Optional[str] = None
    onboarding_complete: Optional[bool] = None
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None


class BookmarkCreateRequest(BaseModel):
    user_id: str
    cve_id: str
    note: Optional[str] = None


class BookmarkUpdateRequest(BaseModel):
    note: Optional[str] = None


class WatchlistAddRequest(BaseModel):
    user_id: str
    cpe_string: str
    display_name: str
    criticality: str = "MEDIUM"


class WaitlistRequest(BaseModel):
    email: str
    tier: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ensure_db():
    if not _db or not _db.is_configured:
        raise HTTPException(status_code=503, detail="Database not configured")


async def _validate_user(user_id: str):
    """Verify the user_id exists in user_profiles.

    Retries once on transient DNS failures. On persistent network errors,
    logs a warning and allows the request through — downstream methods
    handle Supabase unavailability gracefully.
    """
    import asyncio

    for attempt in range(2):
        try:
            result = _db._client.table("user_profiles").select("id").eq("id", user_id).execute()
            if not result.data:
                raise HTTPException(status_code=404, detail="User not found")
            return  # success
        except HTTPException:
            raise
        except Exception as e:
            err_str = str(e)
            is_dns = "getaddrinfo" in err_str or "Name or service not known" in err_str or "nodename nor servname" in err_str
            if is_dns and attempt == 0:
                logger.warning(f"DNS resolution failed (attempt {attempt + 1}), retrying in 1s...")
                await asyncio.sleep(1)
                continue
            if is_dns:
                # Persistent DNS failure — allow request through; downstream handles it
                logger.warning(f"User validation skipped due to DNS failure for {user_id}: {e}")
                return
            logger.error(f"User validation failed: {e}")
            raise HTTPException(status_code=500, detail="User validation failed")


# ══════════════════════════════════════════════════════════════════════════════
# Auth / Profile Endpoints
# ══════════════════════════════════════════════════════════════════════════════


@auth_router.post("/api/auth/profile", tags=["Auth"])
async def upsert_profile(req: ProfileUpsertRequest):
    """
    Upsert user profile on first OAuth login.
    If user is new: creates user_profiles row, workspace, and workspace_member.
    Returns { profile, workspace_id, is_new_user }.
    """
    _ensure_db()

    is_new_user = False
    workspace_id = None

    try:
        # Check if user already exists
        existing = (
            _db._client.table("user_profiles")
            .select("*")
            .eq("id", req.id)
            .execute()
        )

        if existing.data and len(existing.data) > 0:
            # Existing user — update last login fields
            profile = existing.data[0]
            _db._client.table("user_profiles").update({
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "avatar_url": req.avatar_url or profile.get("avatar_url"),
                "display_name": req.display_name or profile.get("display_name"),
            }).eq("id", req.id).execute()

            # Fetch their workspace
            ws = (
                _db._client.table("workspaces")
                .select("id")
                .eq("owner_id", req.id)
                .limit(1)
                .execute()
            )
            workspace_id = ws.data[0]["id"] if ws.data else None
            profile = existing.data[0]
        else:
            # New user — create profile
            is_new_user = True
            insert_result = _db._client.table("user_profiles").insert({
                "id": req.id,
                "email": req.email,
                "display_name": req.display_name,
                "avatar_url": req.avatar_url,
                "role": "security_analyst",
                "onboarding_complete": False,
            }).execute()
            profile = insert_result.data[0] if insert_result.data else {}

            # Create workspace + membership
            ws_result = _db._client.table("workspaces").insert({
                "name": f"{req.display_name or req.email.split('@')[0]}'s Workspace",
                "owner_id": req.id,
                "workspace_type": "personal",
            }).execute()
            workspace_id = ws_result.data[0]["id"] if ws_result.data else None

            if workspace_id:
                _db._client.table("workspace_members").insert({
                    "workspace_id": workspace_id,
                    "user_id": req.id,
                    "member_role": "owner",
                }).execute()

        return {
            "profile": profile,
            "workspace_id": workspace_id,
            "is_new_user": is_new_user,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile upsert failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to upsert profile")


@auth_router.get("/api/auth/profile/{user_id}", tags=["Auth"])
async def get_profile(user_id: str):
    """Fetch user profile by ID."""
    _ensure_db()

    try:
        result = (
            _db._client.table("user_profiles")
            .select("*")
            .eq("id", user_id)
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=404, detail="User not found")
        return result.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile fetch failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch profile")


@auth_router.patch("/api/auth/profile/{user_id}", tags=["Auth"])
async def update_profile(user_id: str, req: ProfileUpdateRequest):
    """Update profile fields (role, tech_context, onboarding_complete)."""
    _ensure_db()
    await _validate_user(user_id)

    update_data: dict = {"updated_at": datetime.now(timezone.utc).isoformat()}
    if req.role is not None:
        if req.role not in ("security_analyst", "pentest_consultant", "mssp", "solo_researcher"):
            raise HTTPException(status_code=400, detail="Invalid role")
        update_data["role"] = req.role
    if req.tech_context is not None:
        update_data["tech_context"] = req.tech_context[:500]
    if req.onboarding_complete is not None:
        update_data["onboarding_complete"] = req.onboarding_complete
    if req.display_name is not None:
        update_data["display_name"] = req.display_name[:100]
    if req.avatar_url is not None:
        update_data["avatar_url"] = req.avatar_url

    try:
        result = (
            _db._client.table("user_profiles")
            .update(update_data)
            .eq("id", user_id)
            .execute()
        )
        return result.data[0] if result.data else {"status": "updated"}
    except Exception as e:
        logger.error(f"Profile update failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to update profile")


# ══════════════════════════════════════════════════════════════════════════════
# Bookmark Endpoints
# ══════════════════════════════════════════════════════════════════════════════


@auth_router.get("/api/bookmarks/{user_id}", tags=["Bookmarks"])
async def list_bookmarks(user_id: str):
    """List all bookmarks for a user, sorted by created_at desc."""
    _ensure_db()
    await _validate_user(user_id)

    try:
        result = (
            _db._client.table("user_bookmarks")
            .select("*")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )
        bookmarks = result.data or []

        # Enrich each bookmark with CVE summary data
        enriched = []
        for bm in bookmarks:
            cve_data = None
            try:
                cve_result = await _db.get_cve(bm["cve_id"])
                if cve_result:
                    cve_data = {
                        "cve_id": cve_result.cve_id,
                        "description": cve_result.description[:200] if cve_result.description else "",
                        "priority_score": cve_result.priority_score,
                        "priority_label": cve_result.priority_label,
                        "cvss_score": cve_result.cvss_score,
                        "published_date": cve_result.published_date.isoformat() if cve_result.published_date else None,
                    }
            except Exception:
                pass

            enriched.append({
                **bm,
                "cve_data": cve_data,
            })

        return enriched
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bookmark list failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to list bookmarks")


@auth_router.post("/api/bookmarks", tags=["Bookmarks"])
async def create_bookmark(req: BookmarkCreateRequest):
    """Create a CVE bookmark."""
    _ensure_db()
    await _validate_user(req.user_id)

    try:
        # Check bookmark limit for free tier (25)
        count_result = (
            _db._client.table("user_bookmarks")
            .select("id", count="exact")
            .eq("user_id", req.user_id)
            .execute()
        )
        if count_result.count is not None and count_result.count >= 25:
            raise HTTPException(
                status_code=403,
                detail="Free tier bookmark limit reached (25). Upgrade to Pro for unlimited bookmarks."
            )

        result = _db._client.table("user_bookmarks").insert({
            "user_id": req.user_id,
            "cve_id": req.cve_id.upper(),
            "note": req.note[:500] if req.note else None,
        }).execute()

        return result.data[0] if result.data else {"status": "created"}
    except HTTPException:
        raise
    except Exception as e:
        # Handle unique constraint violation (already bookmarked)
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            raise HTTPException(status_code=409, detail="CVE already bookmarked")
        logger.error(f"Bookmark create failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to create bookmark")


@auth_router.put("/api/bookmarks/{user_id}/{cve_id}", tags=["Bookmarks"])
async def update_bookmark(user_id: str, cve_id: str, req: BookmarkUpdateRequest):
    """Update bookmark note."""
    _ensure_db()
    await _validate_user(user_id)

    try:
        result = (
            _db._client.table("user_bookmarks")
            .update({
                "note": req.note[:500] if req.note else None,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            .eq("user_id", user_id)
            .eq("cve_id", cve_id.upper())
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=404, detail="Bookmark not found")
        return result.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bookmark update failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to update bookmark")


@auth_router.delete("/api/bookmarks/{user_id}/{cve_id}", tags=["Bookmarks"])
async def delete_bookmark(user_id: str, cve_id: str):
    """Remove a bookmark."""
    _ensure_db()
    await _validate_user(user_id)

    try:
        _db._client.table("user_bookmarks").delete().eq(
            "user_id", user_id
        ).eq("cve_id", cve_id.upper()).execute()
        return {"status": "deleted"}
    except Exception as e:
        logger.error(f"Bookmark delete failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete bookmark")


# ══════════════════════════════════════════════════════════════════════════════
# Waitlist Endpoint
# ══════════════════════════════════════════════════════════════════════════════

# Simple in-memory rate limiting
_waitlist_rate_limit: dict[str, list[float]] = {}
_WAITLIST_MAX_PER_HOUR = 5


@auth_router.post("/api/waitlist", tags=["Waitlist"])
async def join_waitlist(req: WaitlistRequest, request: Request):
    """Add email to waitlist for a paid tier. Rate limited."""
    _ensure_db()

    # Validate tier
    if req.tier not in ("pro", "team", "mssp"):
        raise HTTPException(status_code=400, detail="Tier must be pro, team, or mssp")

    # Simple rate limiting by IP
    import hashlib
    client_host = request.client.host if request.client else "unknown"
    ip_hash = hashlib.sha256(client_host.encode()).hexdigest()[:16]
    now = datetime.now(timezone.utc).timestamp()

    if ip_hash not in _waitlist_rate_limit:
        _waitlist_rate_limit[ip_hash] = []

    # Clean old entries (older than 1 hour)
    _waitlist_rate_limit[ip_hash] = [
        ts for ts in _waitlist_rate_limit[ip_hash]
        if now - ts < 3600
    ]

    if len(_waitlist_rate_limit[ip_hash]) >= _WAITLIST_MAX_PER_HOUR:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")

    _waitlist_rate_limit[ip_hash].append(now)

    # Validate email format (basic)
    email = req.email.strip().lower()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Invalid email address")

    try:
        # Try insert — ON CONFLICT DO NOTHING via upsert
        result = (
            _db._client.table("waitlist")
            .upsert(
                {"email": email, "tier": req.tier},
                on_conflict="email,tier",
            )
            .execute()
        )

        # Check if this was a new insert or existing
        check = (
            _db._client.table("waitlist")
            .select("created_at")
            .eq("email", email)
            .eq("tier", req.tier)
            .execute()
        )

        if check.data:
            created = check.data[0].get("created_at", "")
            # If created_at is within last 5 seconds, it's a new registration
            from datetime import timedelta
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                is_new = (datetime.now(timezone.utc) - created_dt) < timedelta(seconds=5)
            except Exception:
                is_new = True

            return {
                "success": True,
                "already_registered": not is_new,
            }

        return {"success": True, "already_registered": False}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Waitlist insert failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to join waitlist")


# ══════════════════════════════════════════════════════════════════════════════
# Phase 7 — Watchlist, Exposure Score, Digest
# ══════════════════════════════════════════════════════════════════════════════


def _ensure_watchlist():
    if not _watchlist_svc:
        raise HTTPException(status_code=503, detail="Watchlist service not configured")


@auth_router.get("/api/watchlist/{user_id}", tags=["Watchlist"])
async def get_watchlist(user_id: str):
    """List all watchlist items for a user."""
    _ensure_db()
    _ensure_watchlist()
    await _validate_user(user_id)
    return await _watchlist_svc.get_watchlist(user_id)


@auth_router.post("/api/watchlist", tags=["Watchlist"])
async def add_watchlist_item(req: WatchlistAddRequest):
    """Add a technology to the user's watchlist."""
    _ensure_db()
    _ensure_watchlist()
    await _validate_user(req.user_id)

    result = await _watchlist_svc.add_watchlist_item(
        user_id=req.user_id,
        cpe_string=req.cpe_string,
        display_name=req.display_name,
        criticality=req.criticality,
    )
    if result is None:
        raise HTTPException(status_code=500, detail="Failed to add item")
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@auth_router.delete("/api/watchlist/{user_id}/{item_id}", tags=["Watchlist"])
async def remove_watchlist_item(user_id: str, item_id: str):
    """Remove a technology from the user's watchlist."""
    _ensure_db()
    _ensure_watchlist()
    await _validate_user(user_id)
    ok = await _watchlist_svc.remove_watchlist_item(user_id, item_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to remove item")
    return {"status": "deleted"}


@auth_router.get("/api/exposure/{user_id}", tags=["Exposure"])
async def get_exposure(user_id: str):
    """Get latest exposure score (recalculates if older than 1h)."""
    _ensure_db()
    _ensure_watchlist()
    await _validate_user(user_id)
    return await _watchlist_svc.get_exposure(user_id)


@auth_router.post("/api/exposure/{user_id}/recalculate", tags=["Exposure"])
async def recalculate_exposure(user_id: str):
    """Force recalculate exposure score."""
    _ensure_db()
    _ensure_watchlist()
    await _validate_user(user_id)
    return await _watchlist_svc.calculate_exposure(user_id)


@auth_router.get("/api/watchlist/{user_id}/cves", tags=["Watchlist"])
async def get_watchlist_cves(
    user_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    """Get all CVEs matching user's watchlist, paginated."""
    _ensure_db()
    _ensure_watchlist()
    await _validate_user(user_id)
    result = await _watchlist_svc.get_matching_cves(user_id, page=page, page_size=page_size)
    # Serialize ProcessedCVE models to dicts
    cves = result.get("cves", [])
    serialized = []
    for c in cves:
        try:
            serialized.append(c.model_dump() if hasattr(c, 'model_dump') else c)
        except Exception:
            serialized.append(c)
    return {"cves": serialized, "total": result.get("total", 0), "page": result.get("page", 1)}


@auth_router.get("/api/digest/unsubscribe/{user_id}", tags=["Digest"])
async def unsubscribe_digest(user_id: str):
    """Unsubscribe from daily digest emails."""
    _ensure_db()
    _ensure_watchlist()
    ok = await _watchlist_svc.set_digest_enabled(user_id, False)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to unsubscribe")
    return {"status": "unsubscribed", "digest_enabled": False}


@auth_router.patch("/api/digest/resubscribe/{user_id}", tags=["Digest"])
async def resubscribe_digest(user_id: str):
    """Re-subscribe to daily digest emails."""
    _ensure_db()
    _ensure_watchlist()
    ok = await _watchlist_svc.set_digest_enabled(user_id, True)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to resubscribe")
    return {"status": "subscribed", "digest_enabled": True}


@auth_router.post("/api/digest/test/{user_id}", tags=["Digest"])
async def send_test_digest(user_id: str):
    """Send a test digest email immediately."""
    _ensure_db()
    _ensure_watchlist()
    await _validate_user(user_id)
    sent = await _watchlist_svc.send_test_digest(user_id)
    return {"status": "sent" if sent else "failed", "sent": sent}
