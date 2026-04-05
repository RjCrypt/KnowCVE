"""FastAPI REST endpoints for KnowCVE."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import settings
from app.models.cve import (
    PollResponse, ProcessedCVE, StatsResponse,
    WildReport, WildReportSummary,
    ResearcherNote, ResearcherNoteResponse,
    ExploitIntelligence, ExploitIntelSummary,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Auth ──────────────────────────────────────────────────────────────────────

security = HTTPBearer(auto_error=True)


def _check_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> bool:
    if not settings.APP_SECRET_KEY or settings.APP_SECRET_KEY == "change_me":
        raise HTTPException(status_code=503, detail="APP_SECRET_KEY not configured on server.")
    if credentials.credentials != settings.APP_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid authorization token.")
    return True


# These are injected by main.py at startup
_poller = None
_telegram_bot = None
_db = None


def init_routes(poller, telegram_bot, db=None) -> None:
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
    page_size: int = Query(20, ge=1, le=200),
    priority: Optional[str] = Query(None, description="Filter by priority label"),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search CVE ID or description"),
):
    """List processed CVEs with optional category/search filter."""
    # If searching for a specific CVE ID, try direct lookup first
    if search and search.upper().startswith("CVE-"):
        cve_id = search.upper().strip()
        try:
            if _db and _db.is_configured:
                direct = await _db.get_cve(cve_id)
                if direct:
                    return [direct]
        except Exception:
            pass
        # Also try in-memory
        if _poller:
            direct = _poller.get_cve(cve_id)
            if direct:
                return [direct]

    # Try Supabase first
    if _db and _db.is_configured:
        try:
            # JUST_DROPPED: use time-based query (published < 48h) as
            # existing CVEs may not have the categories array populated yet
            if category and category.upper() == "JUST_DROPPED":
                db_cves = await _db.get_fresh_cves(limit=page_size)
            else:
                db_cves = await _db.get_recent_cves(
                    limit=page_size,
                    min_priority=min_score or 0,
                    category=category,
                )
            if db_cves:
                if priority:
                    db_cves = [c for c in db_cves if c.priority_label == priority.upper()]
                if search:
                    q = search.lower()
                    db_cves = [
                        c for c in db_cves
                        if q in c.cve_id.lower() or q in c.description.lower()
                    ]
                return db_cves
        except Exception as e:
            logger.warning(f"Supabase query failed, falling back to in-memory: {e}")

    # Fallback to in-memory
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cves = _poller.processed_cves

    if category:
        cat_upper = category.upper()
        if cat_upper == "JUST_DROPPED":
            cutoff_jd = datetime.now(timezone.utc) - timedelta(hours=48)
            cves = [
                c for c in cves
                if c.published_date
                and (c.published_date.replace(tzinfo=timezone.utc) if c.published_date.tzinfo is None else c.published_date) >= cutoff_jd
            ]
        else:
            cves = [c for c in cves if cat_upper in c.categories]
    if priority:
        cves = [c for c in cves if c.priority_label == priority.upper()]
    if min_score is not None:
        cves = [c for c in cves if c.priority_score >= min_score]
    if search:
        q = search.lower()
        cves = [c for c in cves if q in c.cve_id.lower() or q in c.description.lower()]

    cves.sort(key=lambda c: (c.priority_score, c.processed_at), reverse=True)

    start = (page - 1) * page_size
    end = start + page_size
    return cves[start:end]


# ══════════════════════════════════════════════════════════════════════════════
# IMPORTANT: Fixed-path routes MUST come BEFORE the {cve_id} catch-all,
# otherwise FastAPI matches "trending", "fresh", "category" as cve_id values.
# ══════════════════════════════════════════════════════════════════════════════


# ── CVE by Category ──────────────────────────────────────────────────────────

@router.get("/api/cves/category/{category}", response_model=list[ProcessedCVE], tags=["CVEs"])
async def get_cves_by_category(
    category: str,
    limit: int = Query(20, ge=1, le=100),
):
    """Filter CVEs by category: ACTIVELY_EXPLOITED, TRENDING, JUST_DROPPED, HIGH_EXPLOITABILITY, NO_AUTH_REQUIRED."""
    cat_upper = category.upper()

    # JUST_DROPPED: use time-based query as existing CVEs may lack categories
    if cat_upper == "JUST_DROPPED":
        if _db and _db.is_configured:
            try:
                db_cves = await _db.get_fresh_cves(limit=limit)
                if db_cves:
                    return db_cves
            except Exception as e:
                logger.warning(f"Supabase fresh query failed: {e}")
        if _poller:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=48)
            cves = [
                c for c in _poller.processed_cves
                if c.published_date
                and (c.published_date.replace(tzinfo=timezone.utc) if c.published_date.tzinfo is None else c.published_date) >= cutoff
            ]
            cves.sort(key=lambda c: c.published_date or datetime.min, reverse=True)
            return cves[:limit]
        return []

    if _db and _db.is_configured:
        try:
            db_cves = await _db.get_cves_by_category(cat_upper, limit=limit)
            if db_cves:
                return db_cves
        except Exception as e:
            logger.warning(f"Supabase category query failed: {e}")

    # Fallback to in-memory
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cves = [c for c in _poller.processed_cves if cat_upper in c.categories]
    cves.sort(key=lambda c: c.priority_score, reverse=True)
    return cves[:limit]


# ── Trending CVEs ─────────────────────────────────────────────────────────────

@router.get("/api/cves/trending", response_model=list[ProcessedCVE], tags=["CVEs"])
async def get_trending_cves():
    """Top 10 TRENDING CVEs sorted by dynamic_score."""
    if _db and _db.is_configured:
        try:
            db_cves = await _db.get_cves_by_category("TRENDING", limit=10)
            if db_cves:
                db_cves.sort(key=lambda c: c.dynamic_score, reverse=True)
                return db_cves
        except Exception as e:
            logger.warning(f"Supabase trending query failed: {e}")

    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    trending = [c for c in _poller.processed_cves if "TRENDING" in c.categories]
    trending.sort(key=lambda c: c.dynamic_score, reverse=True)
    return trending[:10]


# ── Fresh CVEs ────────────────────────────────────────────────────────────────

@router.get("/api/cves/fresh", response_model=list[ProcessedCVE], tags=["CVEs"])
async def get_fresh_cves(
    limit: int = Query(20, ge=1, le=100),
):
    """CVEs published in last 48 hours, any score, sorted by recency."""
    if _db and _db.is_configured:
        try:
            db_cves = await _db.get_fresh_cves(limit=limit)
            if db_cves:
                return db_cves
        except Exception as e:
            logger.warning(f"Supabase fresh query failed: {e}")

    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cutoff = datetime.now(timezone.utc) - timedelta(hours=48)
    cves = _poller.processed_cves
    fresh = [
        c for c in cves
        if c.published_date
        and (c.published_date.replace(tzinfo=timezone.utc) if c.published_date.tzinfo is None else c.published_date) >= cutoff
    ]
    fresh.sort(key=lambda c: c.published_date or datetime.min, reverse=True)
    return fresh[:limit]


# ── CVE Detail (MUST be AFTER fixed paths) ────────────────────────────────────

@router.get("/api/cves/{cve_id}", response_model=ProcessedCVE, tags=["CVEs"])
async def get_cve(cve_id: str):
    cve_id_upper = cve_id.upper()

    if _db and _db.is_configured:
        try:
            db_cve = await _db.get_cve(cve_id_upper)
            if db_cve:
                return db_cve
        except Exception as e:
            logger.warning(f"Supabase get_cve failed, falling back: {e}")

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
    """Breaking threats: CRITICAL CVEs or in CISA KEV, last 30 days."""
    if _db and _db.is_configured:
        try:
            db_threats = await _db.get_threats(limit=limit)
            # IMPORTANT: return even if empty — Supabase is the source of truth.
            # `if db_threats:` would cause an empty list to fall through to
            # the stale in-memory cache, making threats flicker in and out.
            if db_threats is not None:
                return db_threats
        except Exception as e:
            logger.warning(f"Supabase get_threats failed, falling back: {e}")

    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
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
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cves = _poller.processed_cves
    next_job = _poller.scheduler.get_job("fresh_cves")
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
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    async def _run_poll():
        try:
            result = await _poller.fresh_cves_job()
            logger.info(f"Manual poll done: {result}")
        except Exception as e:
            logger.error(f"Manual poll error: {e}")

    asyncio.create_task(_run_poll())
    return {"status": "started", "message": "Poll cycle started in background."}


# ── Exploit Intelligence (Phase 4.5) ─────────────────────────────────────────

@router.get("/api/exploit-intel", response_model=list[ExploitIntelSummary], tags=["Exploit Intel"])
async def get_exploit_intel_feed(
    limit: int = Query(default=20, le=50),
    offset: int = Query(default=0),
    ems_label: Optional[str] = Query(default=None),
    has_metasploit: bool = Query(default=False),
    has_nuclei: bool = Query(default=False),
):
    """Returns CVEs ranked by Exploit Maturity Score (EMS)."""
    if not _db or not _db.is_configured:
        return []

    try:
        intel_rows = await _db.get_exploit_intel_feed(
            limit=limit,
            offset=offset,
            ems_label=ems_label,
            has_metasploit=has_metasploit,
            has_nuclei=has_nuclei,
        )

        # Build summaries by joining with processed_cves data
        summaries = []
        for row in intel_rows:
            cve_id = row["cve_id"]
            # Get the CVE data
            cve_data = await _db.get_cve(cve_id) if _db else None
            if not cve_data and _poller:
                cve_data = _poller.get_cve(cve_id)

            exploitdb_entries = row.get("exploitdb_entries") or []
            poc_repos = row.get("poc_repos") or []
            max_stars = max((p.get("stars", 0) for p in poc_repos), default=0)

            # Check nuclei from enrichment data
            has_nuclei_template = False
            if cve_data and cve_data.enrichment:
                has_nuclei_template = cve_data.enrichment.has_nuclei_template

            summaries.append(ExploitIntelSummary(
                cve_id=cve_id,
                ems_score=row.get("ems_score", 0),
                ems_label=row.get("ems_label", "RESEARCH"),
                has_metasploit_module=row.get("has_metasploit_module", False),
                has_nuclei_template=has_nuclei_template,
                has_exploitdb_entry=len(exploitdb_entries) > 0,
                poc_count=len(poc_repos),
                max_poc_stars=max_stars,
                priority_score=cve_data.priority_score if cve_data else 0,
                priority_label=cve_data.priority_label if cve_data else "LOW",
                cvss_score=cve_data.cvss_score if cve_data else 0.0,
                description=cve_data.description[:200] if cve_data else "",
                published=(
                    cve_data.published_date.isoformat()
                    if cve_data and cve_data.published_date
                    else ""
                ),
            ))
        return summaries
    except Exception as e:
        logger.error(f"Exploit intel feed error: {e}")
        return []


@router.get("/api/exploit-intel/{cve_id}", response_model=ExploitIntelligence, tags=["Exploit Intel"])
async def get_exploit_intel_detail(cve_id: str):
    """Full exploit intelligence detail for a single CVE."""
    cve_id_upper = cve_id.upper()

    # Try DB first
    if _db and _db.is_configured:
        intel = await _db.get_exploit_intel(cve_id_upper)
        if intel:
            return intel

    # Try gathering on-the-fly
    cve = None
    if _poller:
        cve = _poller.get_cve(cve_id_upper)
    if not cve and _db and _db.is_configured:
        cve = await _db.get_cve(cve_id_upper)

    if cve and _poller:
        try:
            from app.services.exploit_intel import ExploitIntelligenceOrchestrator
            orchestrator = _poller.exploit_intel
            if not orchestrator._initialized:
                await orchestrator.initialize()

            intel = await orchestrator.gather(
                cve_id=cve.cve_id,
                poc_urls=cve.enrichment.poc_urls,
                has_nuclei=cve.enrichment.has_nuclei_template,
                nuclei_template_url=cve.enrichment.nuclei_template_url,
                in_kev=cve.enrichment.in_kev,
                is_being_scanned=cve.enrichment.is_being_scanned,
                greynoise_count=cve.enrichment.greynoise_scanner_count,
            )
            # Save to DB for future requests
            if _db and _db.is_configured:
                asyncio.create_task(_db.save_exploit_intel(intel))
            return intel
        except Exception as e:
            logger.error(f"On-the-fly exploit intel failed for {cve_id_upper}: {e}")

    raise HTTPException(status_code=404, detail=f"No exploit intelligence for {cve_id}")


# ── KRS Formula (Phase 4) ────────────────────────────────────────────────────

@router.get("/api/krs/formula", tags=["KRS"])
async def get_krs_formula():
    """Public endpoint explaining the KRS formula. Transparency builds trust."""
    return {
        "name": "KnowCVE Risk Score (KRS)",
        "version": "1.0",
        "description": "Open composite score measuring real-world exploitation risk (0-100)",
        "formula": {
            "base_components": {
                "cvss": {"weight": "35%", "calculation": "(cvss_score / 10) × 35"},
                "epss": {"weight": "25%", "calculation": "epss_score × 25"},
                "cisa_kev": {"weight": "20%", "calculation": "20 if in_kev else 0"},
                "poc_available": {"weight": "15%", "calculation": "15 if has_poc else 0"},
                "recency": {
                    "weight": "5%",
                    "calculation": "+15 if <24h, +8 if <72h, +3 if <7d, -10 if >30d"
                },
            },
            "dynamic_components": {
                "greynoise": "up to +20 points based on active scanning count",
                "trending": "up to +10 points based on EPSS/scanner momentum",
            },
            "labels": {
                "CRITICAL": "75-100",
                "HIGH": "50-74",
                "MEDIUM": "25-49",
                "LOW": "0-24",
            },
        },
        "rationale": (
            "KRS weights real-world exploitation signals more heavily than theoretical "
            "CVSS severity because an actively exploited vulnerability poses more "
            "immediate risk regardless of its CVSS score."
        ),
        "source": "https://github.com/RjCrypt/KnowCVE",
    }


# ── Nuclei Template (Phase 4) ────────────────────────────────────────────────

@router.get("/api/cves/{cve_id}/nuclei", tags=["CVEs"])
async def get_nuclei_info(cve_id: str):
    """Check if a Nuclei detection template exists for this CVE."""
    from app.services.enrichment import NucleiTemplateService

    service = NucleiTemplateService()
    data = await service.check_template(cve_id.upper())

    template_path = None
    nuclei_command = None
    if data["has_template"] and data.get("template_url"):
        # Extract template path from GitHub URL for the nuclei command
        url = data["template_url"]
        if "/blob/main/" in url:
            template_path = url.split("/blob/main/")[1]
            nuclei_command = f"nuclei -u https://TARGET -t {template_path} -v"

    return {
        "cve_id": cve_id.upper(),
        "has_template": data["has_template"],
        "template_url": data.get("template_url"),
        "nuclei_command": nuclei_command,
    }


# ── Community "Seen in Wild" Reporting (Phase 4) ─────────────────────────────

@router.post("/api/cves/{cve_id}/report-wild", tags=["Community"])
async def report_seen_in_wild(
    cve_id: str,
    report: WildReport,
    request: Request,
):
    """
    Anonymous one-click reporting: researcher saw this CVE being exploited.
    No account required. IP is hashed with date salt — never stored raw.
    Rate limited: one report per CVE per IP per day.
    """
    import hashlib
    from datetime import date

    if not _db or not _db.is_configured:
        raise HTTPException(status_code=503, detail="Database not configured")

    # Create anonymous identifier for dedup (IP + date, not stored raw)
    client_host = request.client.host if request.client else "unknown"
    raw_hash = f"{client_host}:{date.today().isoformat()}"
    reporter_hash = hashlib.sha256(raw_hash.encode()).hexdigest()

    # Check for duplicate submission today
    try:
        existing = (
            _db._client.table("cve_wild_reports")
            .select("id")
            .eq("cve_id", cve_id.upper())
            .eq("reporter_hash", reporter_hash)
            .execute()
        )
        if existing.data:
            return {"message": "Already reported today. Thank you.", "duplicate": True}
    except Exception as e:
        logger.warning(f"Wild report dedup check failed: {e}")

    # Truncate context to 200 chars max
    context = report.context[:200] if report.context else None

    try:
        _db._client.table("cve_wild_reports").insert({
            "cve_id": cve_id.upper(),
            "context": context,
            "reporter_hash": reporter_hash,
        }).execute()
    except Exception as e:
        logger.error(f"Failed to save wild report: {e}")
        raise HTTPException(status_code=500, detail="Failed to save report")

    return {"message": "Report submitted. Thank you for contributing to the community.", "duplicate": False}


@router.get("/api/cves/{cve_id}/wild-reports", response_model=WildReportSummary, tags=["Community"])
async def get_wild_reports(cve_id: str):
    """Get aggregated community reports for a CVE."""
    if not _db or not _db.is_configured:
        return WildReportSummary(cve_id=cve_id.upper(), report_count=0, last_reported_at=None)

    try:
        result = (
            _db._client.table("cve_wild_summary")
            .select("*")
            .eq("cve_id", cve_id.upper())
            .execute()
        )
        if not result.data:
            return WildReportSummary(cve_id=cve_id.upper(), report_count=0, last_reported_at=None)
        row = result.data[0]
        return WildReportSummary(
            cve_id=row["cve_id"],
            report_count=row["report_count"],
            last_reported_at=row.get("last_reported_at"),
        )
    except Exception as e:
        logger.warning(f"Wild reports query failed: {e}")
        return WildReportSummary(cve_id=cve_id.upper(), report_count=0, last_reported_at=None)


# ── Researcher Notes (Phase 4) ───────────────────────────────────────────────

@router.post("/api/cves/{cve_id}/notes", response_model=ResearcherNoteResponse, tags=["Community"])
async def add_note(cve_id: str, note: ResearcherNote):
    """
    Add a public researcher note to a CVE.
    No account required. Notes are public and moderated retroactively.
    """
    if not _db or not _db.is_configured:
        raise HTTPException(status_code=503, detail="Database not configured")

    # Truncate to 500 chars
    clean_note = note.note[:500].strip()
    if len(clean_note) < 10:
        raise HTTPException(status_code=400, detail="Note must be at least 10 characters.")

    # Basic content filter — reject obvious spam
    spam_patterns = ["http://", "buy now", "click here", "free money"]
    if any(p in clean_note.lower() for p in spam_patterns):
        raise HTTPException(status_code=400, detail="Note rejected by content filter.")

    alias = note.author_alias[:30] if note.author_alias else None

    try:
        result = _db._client.table("cve_notes").insert({
            "cve_id": cve_id.upper(),
            "note": clean_note,
            "author_alias": alias,
        }).execute()

        row = result.data[0]
        return ResearcherNoteResponse(**row)
    except Exception as e:
        logger.error(f"Failed to save note: {e}")
        raise HTTPException(status_code=500, detail="Failed to save note")


@router.get("/api/cves/{cve_id}/notes", response_model=list[ResearcherNoteResponse], tags=["Community"])
async def get_notes(cve_id: str, limit: int = Query(default=20, le=50)):
    """Get researcher notes for a CVE."""
    if not _db or not _db.is_configured:
        return []

    try:
        result = (
            _db._client.table("cve_notes")
            .select("*")
            .eq("cve_id", cve_id.upper())
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return [ResearcherNoteResponse(**row) for row in (result.data or [])]
    except Exception as e:
        logger.warning(f"Notes query failed: {e}")
        return []
