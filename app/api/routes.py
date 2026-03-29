"""FastAPI REST endpoints for KnowCVE."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import settings
from app.models.cve import PollResponse, ProcessedCVE, StatsResponse

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Auth ──────────────────────────────────────────────────────────────────────

security = HTTPBearer(auto_error=True)


def _check_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> bool:
    """Validate bearer token against APP_SECRET_KEY."""
    if not settings.APP_SECRET_KEY or settings.APP_SECRET_KEY == "change_me":
        raise HTTPException(
            status_code=503,
            detail="APP_SECRET_KEY not configured on server.",
        )
    if credentials.credentials != settings.APP_SECRET_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization token.",
        )
    return True


# These are injected by main.py at startup
_poller = None
_telegram_bot = None
_db = None


def init_routes(poller, telegram_bot, db=None) -> None:
    """Wire the poller, bot, and database so routes can access runtime state."""
    global _poller, _telegram_bot, _db
    _poller = poller
    _telegram_bot = telegram_bot
    _db = db


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health", tags=["Health"])
async def health():
    return {
        "status": "healthy",
        "service": "KnowCVE",
        "poller_active": _poller is not None and _poller.scheduler.running if _poller else False,
        "telegram_active": _telegram_bot is not None and _telegram_bot.app is not None,
        "db_active": _db is not None and _db.is_configured if _db else False,
    }


# ── CVE List ──────────────────────────────────────────────────────────────────

@router.get("/api/cves", response_model=list[ProcessedCVE], tags=["CVEs"])
async def list_cves(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    priority: Optional[str] = Query(None, description="Filter by priority label: CRITICAL, HIGH, MEDIUM, LOW"),
    min_score: Optional[int] = Query(None, ge=0, le=100),
):
    """List processed CVEs — tries Supabase first, falls back to in-memory."""
    # Try Supabase first
    if _db and _db.is_configured:
        try:
            db_cves = await _db.get_recent_cves(
                limit=page_size,
                min_priority=min_score or 0,
            )
            if db_cves:
                if priority:
                    db_cves = [c for c in db_cves if c.priority_label == priority.upper()]
                return db_cves
        except Exception as e:
            logger.warning(f"Supabase query failed, falling back to in-memory: {e}")

    # Fallback to in-memory
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cves = _poller.processed_cves

    if priority:
        cves = [c for c in cves if c.priority_label == priority.upper()]
    if min_score is not None:
        cves = [c for c in cves if c.priority_score >= min_score]

    cves.sort(key=lambda c: (c.priority_score, c.processed_at), reverse=True)

    start = (page - 1) * page_size
    end = start + page_size
    return cves[start:end]


# ── CVE Detail ────────────────────────────────────────────────────────────────

@router.get("/api/cves/{cve_id}", response_model=ProcessedCVE, tags=["CVEs"])
async def get_cve(cve_id: str):
    """Get a single processed CVE — tries Supabase first, falls back to in-memory."""
    cve_id_upper = cve_id.upper()

    # Try Supabase first
    if _db and _db.is_configured:
        try:
            db_cve = await _db.get_cve(cve_id_upper)
            if db_cve:
                return db_cve
        except Exception as e:
            logger.warning(f"Supabase get_cve failed, falling back: {e}")

    # Fallback to in-memory
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cve = _poller.get_cve(cve_id_upper)
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return cve


# ── Threats ──────────────────────────────────────────────────────────────────

@router.get("/api/threats", response_model=list[ProcessedCVE], tags=["Threats"])
async def get_threats(
    limit: int = Query(20, ge=1, le=100),
):
    """Breaking threats: CRITICAL CVEs (score ≥ 75) or in CISA KEV, last 7 days."""
    # Try Supabase first
    if _db and _db.is_configured:
        try:
            db_threats = await _db.get_threats(limit=limit)
            if db_threats:
                return db_threats
        except Exception as e:
            logger.warning(f"Supabase get_threats failed, falling back: {e}")

    # Fallback to in-memory
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    cves = _poller.processed_cves
    threats = [
        c for c in cves
        if (c.priority_score >= 75 or c.enrichment.in_kev)
        and c.published_date
        and (c.published_date.replace(tzinfo=timezone.utc) if c.published_date.tzinfo is None else c.published_date) >= cutoff
    ]
    threats.sort(key=lambda c: c.priority_score, reverse=True)
    return threats[:limit]


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/api/stats", response_model=StatsResponse, tags=["Stats"])
async def get_stats():
    """Return poller and CVE processing statistics."""
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cves = _poller.processed_cves
    next_job = _poller.scheduler.get_job("cve_poll")
    next_poll = next_job.next_run_time if next_job else None

    return StatsResponse(
        total_cves_processed=len(cves),
        critical_count=sum(1 for c in cves if c.priority_label == "CRITICAL"),
        high_count=sum(1 for c in cves if c.priority_label == "HIGH"),
        medium_count=sum(1 for c in cves if c.priority_label == "MEDIUM"),
        low_count=sum(1 for c in cves if c.priority_label == "LOW"),
        last_poll_time=_poller.last_poll_time,
        next_poll_time=next_poll,
        subscribers_count=_telegram_bot.subscribers_count if _telegram_bot else 0,
        kev_catalog_size=_poller.triage.kev.catalog_size if _poller else 0,
    )


# ── Manual Poll ───────────────────────────────────────────────────────────────

@router.post("/api/poll", tags=["Poller"])
async def trigger_poll(admin: bool = Depends(_check_admin)):
    """Manually trigger a poll cycle (fire-and-forget — returns immediately)."""
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    async def _run_poll():
        try:
            result = await _poller.poll_cycle()
            logger.info(f"Manual poll done: {result}")
        except Exception as e:
            logger.error(f"Manual poll error: {e}")

    asyncio.create_task(_run_poll())
    return {"status": "started", "message": "Poll cycle started in background. Check /api/stats for results."}
