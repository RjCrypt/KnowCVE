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
_threat_actors_svc = None
_ransomware_svc = None
_ioc_svc = None
_news_svc = None
_breach_svc = None


def init_routes(
    poller, telegram_bot, db=None,
    threat_actors=None, ransomware=None, ioc=None, news=None, breaches=None,
) -> None:
    global _poller, _telegram_bot, _db
    global _threat_actors_svc, _ransomware_svc, _ioc_svc, _news_svc, _breach_svc
    _poller = poller
    _telegram_bot = telegram_bot
    _db = db
    _threat_actors_svc = threat_actors
    _ransomware_svc = ransomware
    _ioc_svc = ioc
    _news_svc = news
    _breach_svc = breaches


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

        # Dynamic fallback to NVD
        if _poller:
            try:
                direct = await _poller.fetch_and_process_single(cve_id)
                if direct:
                    logger.info(f"Dynamically fetched and added {cve_id} from search bar")
                    return [direct]
            except Exception as e:
                logger.error(f"Fallback fetch failed for {cve_id} in search: {e}")

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
                    priority_label=priority,
                )
            if db_cves:
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

# ── CVE by Priority Label ────────────────────────────────────────────────────

@router.get("/api/cves/priority/{label}", response_model=list[ProcessedCVE], tags=["CVEs"])
async def get_cves_by_priority(
    label: str,
    limit: int = Query(50, ge=1, le=200),
):
    """Filter CVEs by priority severity label: CRITICAL, HIGH, MEDIUM, LOW."""
    label_upper = label.upper()
    if label_upper not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        raise HTTPException(status_code=400, detail="Label must be CRITICAL, HIGH, MEDIUM, or LOW")

    # Try Supabase first
    if _db and _db.is_configured:
        try:
            db_cves = await _db.get_recent_cves(
                limit=limit, min_priority=0, priority_label=label_upper,
            )
            if db_cves:
                db_cves.sort(key=lambda c: c.priority_score, reverse=True)
                return db_cves
        except Exception as e:
            logger.warning(f"Supabase priority query failed: {e}")

    # Fallback to in-memory
    if not _poller:
        raise HTTPException(status_code=503, detail="Poller not initialized")

    cves = [c for c in _poller.processed_cves if c.priority_label == label_upper]
    cves.sort(key=lambda c: c.priority_score, reverse=True)
    return cves[:limit]


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
    if cve:
        return cve

    # Dynamic fallback to NVD
    try:
        cve = await _poller.fetch_and_process_single(cve_id_upper)
        if cve:
            logger.info(f"Dynamically fetched and added {cve_id_upper} from NVD")
            return cve
    except Exception as e:
        logger.error(f"Fallback fetch failed for {cve_id_upper}: {e}")

    raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")


# ── Re-explain CVE (Phase 5.5 backfill) ───────────────────────────────────────

@router.post("/api/cves/{cve_id}/re-explain", tags=["AI Assistant"])
async def re_explain_cve(cve_id: str):
    """Force regenerate AI explanation for a single CVE with the Phase 5.5 prompt.
    Used to backfill the new depth fields on existing cached records."""
    cve_id_upper = cve_id.upper()

    # Get the CVE from memory or DB
    cve = None
    if _poller:
        cve = _poller.get_cve(cve_id_upper)
    if not cve and _db and _db.is_configured:
        cve = await _db.get_cve(cve_id_upper)

    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    # Build a RawCVE proxy for the explainer
    from app.models.cve import RawCVE
    raw = RawCVE(
        cve_id=cve.cve_id,
        description=cve.description,
        cvss_score=cve.cvss_score,
        cvss_vector=cve.cvss_vector,
        cvss_version=cve.cvss_version,
        published_date=cve.published_date,
        last_modified=cve.last_modified,
        references=cve.references,
        weaknesses=cve.weaknesses,
    )

    # Generate new explanation
    from app.services.ai_explainer import GroqExplainer
    explainer = GroqExplainer()
    new_explanation = await explainer.explain_cve(
        raw=raw,
        enrichment=cve.enrichment,
        priority_label=cve.priority_label,
    )

    # Update in-memory cache
    if _poller:
        for i, cached in enumerate(_poller._processed_cves):
            if cached.cve_id == cve_id_upper:
                _poller._processed_cves[i].ai_explanation = new_explanation
                break

    # Update in DB
    if _db and _db.is_configured:
        cve.ai_explanation = new_explanation
        import asyncio
        asyncio.create_task(_db.save_cve(cve))

    return {
        "status": "ok",
        "cve_id": cve_id_upper,
        "has_vulnerability_class_analysis": bool(new_explanation.vulnerability_class_analysis),
        "has_adversarial_context": bool(new_explanation.adversarial_context),
        "has_exploit_narrative": bool(new_explanation.exploit_narrative),
        "has_attack_techniques": bool(new_explanation.attack_techniques and len(new_explanation.attack_techniques) > 0),
        "attack_technique_count": len(new_explanation.attack_techniques) if new_explanation.attack_techniques else 0,
    }


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

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)
    recent_cutoff = now - timedelta(hours=48)
    cves = _poller.processed_cves
    threats = [
        c for c in cves
        if (c.priority_score >= 75 or c.enrichment.in_kev or "SUPPLY_CHAIN" in c.categories)
        and c.published_date
        and (c.published_date.replace(tzinfo=timezone.utc) if c.published_date.tzinfo is None else c.published_date) >= cutoff
    ]

    # Time-bucketed sort: last-48h first, then older
    def _sort_key(c):
        pub = c.published_date
        if pub and pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)
        is_recent = 0 if (pub and pub >= recent_cutoff) else 1
        return (is_recent, -c.priority_score)

    threats.sort(key=_sort_key)
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
        # When filtering by nuclei, fetch extra rows since filtering happens
        # post-join (nuclei info lives in enrichment, not exploit_intelligence)
        fetch_limit = limit * 3 if has_nuclei else limit
        intel_rows = await _db.get_exploit_intel_feed(
            limit=fetch_limit,
            offset=offset,
            ems_label=ems_label,
            has_metasploit=has_metasploit,
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

            # Skip if nuclei filter is active but CVE has no nuclei template
            if has_nuclei and not has_nuclei_template:
                continue

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

            # Stop once we have enough results
            if len(summaries) >= limit:
                break

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


# ══════════════════════════════════════════════════════════════════════════════
# Phase 5 — Threat Intelligence Endpoints
# ══════════════════════════════════════════════════════════════════════════════


# ── Threat Actors ─────────────────────────────────────────────────────────────

@router.get("/api/threat-actors", tags=["Threat Actors"])
async def get_threat_actors(
    active_only: bool = False,
    motivation: Optional[str] = None,
    sophistication: Optional[str] = None,
):
    """Returns all threat actor profiles."""
    if not _threat_actors_svc:
        return []
    return await _threat_actors_svc.get_all_actors(active_only, motivation, sophistication)


@router.get("/api/threat-actors/{slug}", tags=["Threat Actors"])
async def get_threat_actor(slug: str):
    """Returns full actor profile + list of CVEs they exploit."""
    if not _threat_actors_svc:
        raise HTTPException(status_code=503, detail="Service unavailable")
    actor = await _threat_actors_svc.get_actor(slug)
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    return actor


@router.get("/api/threat-actors/{slug}/cves", tags=["Threat Actors"])
async def get_threat_actor_cves(slug: str):
    """Returns all CVEs linked to this actor."""
    if not _threat_actors_svc:
        return []
    return await _threat_actors_svc.get_cves_for_actor(slug)


@router.get("/api/cves/{cve_id}/threat-actors", tags=["Threat Actors"])
async def get_actors_for_cve(cve_id: str):
    """Returns all threat actors known to exploit this CVE."""
    if not _threat_actors_svc:
        return []
    return await _threat_actors_svc.get_actors_for_cve(cve_id)


@router.post("/api/threat-actors/{slug}/cves", tags=["Threat Actors"])
async def link_cve_to_actor(
    slug: str,
    cve_id: str = Query(...),
    confirmed: bool = Query(default=False),
    source_url: str = Query(default=""),
    notes: str = Query(default=""),
    admin: bool = Depends(_check_admin),
):
    """Links a CVE to a threat actor (admin auth required)."""
    if not _threat_actors_svc:
        raise HTTPException(status_code=503, detail="Service unavailable")
    await _threat_actors_svc.link_cve_to_actor(slug, cve_id.upper(), confirmed, source_url, notes)
    return {"status": "linked", "actor": slug, "cve": cve_id.upper()}


# ── Ransomware Tracker ────────────────────────────────────────────────────────

@router.get("/api/ransomware/campaigns", tags=["Ransomware"])
async def get_ransomware_campaigns(
    status: Optional[str] = None, actor_slug: Optional[str] = None,
):
    """Returns ransomware campaigns, optionally filtered."""
    if not _ransomware_svc:
        return []
    return await _ransomware_svc.get_active_campaigns(status, actor_slug)


@router.get("/api/ransomware/matrix", tags=["Ransomware"])
async def get_ransomware_matrix():
    """Returns ransomware group → CVEs matrix for the tracker table."""
    if not _ransomware_svc:
        return []
    return await _ransomware_svc.get_ransomware_cve_matrix()


@router.get("/api/ransomware/by-cve/{cve_id}", tags=["Ransomware"])
async def get_ransomware_by_cve(cve_id: str):
    """Returns which ransomware groups have used this CVE."""
    if not _ransomware_svc:
        return []
    return await _ransomware_svc.get_ransomware_by_cve(cve_id)


# ── IOC Pulse ─────────────────────────────────────────────────────────────────

@router.get("/api/ioc/lookup", tags=["IOC"])
async def lookup_ioc(q: str = Query(..., description="IP, domain, URL, or hash to look up")):
    """Auto-detects indicator type, returns full intelligence report. Cached 6h."""
    if not _ioc_svc:
        return {"error": "IOC service unavailable"}
    return await _ioc_svc.lookup(q)


@router.get("/api/ioc/feed", tags=["IOC"])
async def get_ioc_feed():
    """Returns latest 50 IOCs from ThreatFox. Cached 30 min."""
    if not _ioc_svc:
        return []
    return await _ioc_svc.get_live_ioc_feed()


@router.get("/api/ioc/stats", tags=["IOC"])
async def get_ioc_stats():
    """Returns IOC service stats: total lookups, cache hit rate, etc."""
    if not _ioc_svc:
        return {}
    return _ioc_svc.get_stats()


# ── Security News ─────────────────────────────────────────────────────────────

@router.get("/api/news", tags=["News"])
async def get_news(
    limit: int = Query(default=20, le=100),
    source: Optional[str] = None,
    has_cves: bool = False,
):
    """Returns recent news articles."""
    if not _db or not _db.is_configured:
        return []
    try:
        q = _db._client.table("security_news").select("*")
        if source:
            q = q.eq("source", source)
        if has_cves:
            q = q.not_("mentioned_cves", "eq", "{}")
        res = q.order("published_at", desc=True).limit(limit).execute()
        
        import html
        data = res.data or []
        for item in data:
            if item.get("title"):
                item["title"] = html.unescape(item["title"])
            if item.get("summary"):
                item["summary"] = html.unescape(item["summary"])
        return data
    except Exception as e:
        logger.error(f"News fetch failed: {e}")
        return []


@router.get("/api/news/cve/{cve_id}", tags=["News"])
async def get_news_for_cve(cve_id: str):
    """Returns all news articles mentioning this CVE."""
    if not _news_svc:
        return []
    return await _news_svc.get_articles_for_cve(cve_id)


@router.get("/api/news/briefing", tags=["News"])
async def get_news_briefing():
    """Returns today's AI-generated daily briefing."""
    if not _news_svc:
        return {"briefing": "News service not available."}
    text = await _news_svc.get_daily_briefing()
    return {"briefing": text}


@router.get("/api/news/sources", tags=["News"])
async def get_news_sources():
    """Returns list of configured RSS sources with article counts."""
    if not _news_svc:
        return []
    return await _news_svc.get_sources()


# ── Breach Intelligence ───────────────────────────────────────────────────────

@router.get("/api/breaches", tags=["Breaches"])
async def get_breaches(
    limit: int = Query(default=20, le=100),
    actor_slug: Optional[str] = None,
    cve_id: Optional[str] = None,
    verified_only: bool = True,
    category: Optional[str] = None,
):
    """Returns breach records sorted by breach_date desc."""
    if not _breach_svc:
        return []
    return await _breach_svc.get_breaches(
        cve_id=cve_id, actor_slug=actor_slug, limit=limit, verified_only=verified_only, category=category,
    )


@router.get("/api/breaches/search", tags=["Breaches"])
async def search_breaches(q: str = Query(..., description="Company name to search")):
    """Case-insensitive search for company name in breach records."""
    if not _breach_svc:
        return []
    return await _breach_svc.search_breaches(q)


@router.get("/api/breaches/cve/{cve_id}", tags=["Breaches"])
async def get_breaches_for_cve(cve_id: str):
    """Returns all breaches where this CVE was used for initial access."""
    if not _breach_svc:
        return []
    return await _breach_svc.get_breaches_for_cve(cve_id)


@router.get("/api/breaches/stats", tags=["Breaches"])
async def get_breach_stats(
    category: Optional[str] = None,
    q: Optional[str] = None,
):
    """Returns aggregate breach statistics."""
    if not _breach_svc:
        return {}
    return await _breach_svc.get_breach_stats(category=category, query=q)


@router.post("/api/breaches", tags=["Breaches"])
async def add_breach(
    request: Request,
    admin: bool = Depends(_check_admin),
):
    """Manually add a verified breach entry (admin auth required)."""
    if not _breach_svc:
        raise HTTPException(status_code=503, detail="Service unavailable")
    body = await request.json()
    if not _db or not _db.is_configured:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        _db._client.table("breach_intelligence").insert(body).execute()
        return {"status": "created"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── CVE Full Context (aggregates Phase 5 data) ───────────────────────────────

@router.get("/api/cves/{cve_id}/full", tags=["CVEs"])
async def get_cve_full(cve_id: str):
    """
    Returns { cve: ProcessedCVE, context: CVEContext } — enriched CVE with
    threat actors, ransomware, news, and breach context.
    Backward compatible: GET /api/cves/{cve_id} remains unchanged.
    """
    cve_id = cve_id.upper()

    # Get the CVE itself (from poller memory, then DB fallback)
    cve = _poller.get_cve(cve_id) if _poller else None
    if not cve and _db and _db.is_configured:
        cve = await _db.get_cve(cve_id)
    if not cve:
        # Dynamic fallback to NVD
        if _poller:
            try:
                cve = await _poller.fetch_and_process_single(cve_id)
                if cve:
                    logger.info(f"Dynamically fetched and added {cve_id} from NVD for /full context")
            except Exception as e:
                logger.error(f"Fallback fetch failed for {cve_id}: {e}")

        if not cve:
            raise HTTPException(status_code=404, detail=f"{cve_id} not found")

    # Fire all context queries concurrently
    async def _empty_list(): return []

    actor_task = _threat_actors_svc.get_actors_for_cve(cve_id) if _threat_actors_svc else _empty_list()
    ransom_task = _ransomware_svc.get_ransomware_by_cve(cve_id) if _ransomware_svc else _empty_list()
    news_task = _news_svc.get_articles_for_cve(cve_id) if _news_svc else _empty_list()
    breach_task = _breach_svc.get_breaches_for_cve(cve_id) if _breach_svc else _empty_list()

    actors, ransomware_groups, news_articles, breaches = await asyncio.gather(
        actor_task, ransom_task, news_task, breach_task,
        return_exceptions=True,
    )

    return {
        "cve": cve.model_dump() if hasattr(cve, "model_dump") else cve,
        "context": {
            "threat_actors": actors if not isinstance(actors, Exception) else [],
            "ransomware_groups": ransomware_groups if not isinstance(ransomware_groups, Exception) else [],
            "news_articles": news_articles if not isinstance(news_articles, Exception) else [],
            "breaches": breaches if not isinstance(breaches, Exception) else [],
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# Phase 5.5 — Interactive CVE Assistant
# ══════════════════════════════════════════════════════════════════════════════


@router.post("/api/cve-assistant", tags=["AI Assistant"])
async def cve_assistant(request: Request):
    """
    Backend proxy for the interactive CVE assistant.
    Accepts { cve_id, message, history: [{role, content}] }.
    Injects CVE context as system prompt, forwards to Groq/Cerebras/Gemini.
    """
    body = await request.json()
    cve_id = (body.get("cve_id") or "").upper()
    user_message = (body.get("message") or "").strip()
    history = body.get("history") or []

    if not cve_id or not user_message:
        raise HTTPException(status_code=400, detail="cve_id and message are required")

    # Limit history to last 5 exchanges to control context size
    history = history[-10:]  # 5 user + 5 assistant messages max

    # Load CVE data for context
    cve = None
    if _poller:
        cve = _poller.get_cve(cve_id)
    if not cve and _db and _db.is_configured:
        cve = await _db.get_cve(cve_id)

    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    # Build system prompt with CVE context
    ai = cve.ai_explanation
    context_parts = [
        f"You are KnowCVE's interactive threat analyst assistant. You are answering follow-up questions about {cve_id}.",
        f"Be concise and technical. Keep responses under 300 words. Answer ONLY within the scope of this CVE.",
        f"\n--- CVE CONTEXT ---",
        f"CVE ID: {cve_id}",
        f"CVSS: {cve.cvss_score} ({cve.cvss_version})",
        f"Description: {cve.description}",
        f"Weaknesses: {', '.join(cve.weaknesses) if cve.weaknesses else 'N/A'}",
        f"CISA KEV: {cve.enrichment.in_kev}",
        f"EPSS: {cve.enrichment.epss_score:.4f}",
    ]
    if ai:
        context_parts.append(f"Technical Detail: {ai.technical_detail}")
        if ai.exploit_narrative:
            context_parts.append(f"Exploit Narrative: {ai.exploit_narrative}")
        if ai.vulnerability_class_analysis:
            context_parts.append(f"Vulnerability Class Analysis: {ai.vulnerability_class_analysis}")
        if ai.adversarial_context:
            context_parts.append(f"Adversarial Context: {ai.adversarial_context}")
        if ai.attack_techniques:
            techniques_str = ", ".join(
                f"{t.technique_id} ({t.technique_name})" for t in ai.attack_techniques
            )
            context_parts.append(f"ATT&CK Chain: {techniques_str}")
    context_parts.append("--- END CONTEXT ---")

    system_prompt = "\n".join(context_parts)

    # Build messages
    messages = [{"role": "system", "content": system_prompt}]
    for msg in history:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": user_message})

    # Try Groq → Cerebras → Gemini
    reply = None
    providers = []

    if settings.GROQ_API_KEY:
        providers.append(("groq", settings.GROQ_API_KEY))
    if settings.CEREBRAS_API_KEY:
        providers.append(("cerebras", settings.CEREBRAS_API_KEY))
    if settings.GEMINI_API_KEY:
        providers.append(("gemini", settings.GEMINI_API_KEY))

    for provider_name, api_key in providers:
        try:
            if provider_name == "groq":
                from groq import AsyncGroq
                client = AsyncGroq(api_key=api_key)
                completion = await client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=messages,
                    temperature=0.4,
                    max_tokens=800,
                )
                reply = completion.choices[0].message.content
                break
            elif provider_name == "cerebras":
                from cerebras.cloud.sdk import AsyncCerebras
                client = AsyncCerebras(api_key=api_key)
                completion = await client.chat.completions.create(
                    model="llama3.3-70b",
                    messages=messages,
                    temperature=0.4,
                    max_tokens=800,
                )
                reply = completion.choices[0].message.content
                break
            elif provider_name == "gemini":
                from google import genai
                from google.genai import types
                client = genai.Client(api_key=api_key)
                full_prompt = system_prompt + "\n\n" + "\n".join(
                    f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}"
                    for m in messages[1:]
                )
                response = await client.aio.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=full_prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.4,
                        max_output_tokens=800,
                    ),
                )
                reply = response.text
                break
        except Exception as e:
            logger.warning(f"CVE assistant {provider_name} failed: {e}")
            continue

    if not reply:
        raise HTTPException(status_code=503, detail="All AI providers unavailable")

    return {"reply": reply}


# ══════════════════════════════════════════════════════════════════════════════
# Supply Chain Advisories
# ══════════════════════════════════════════════════════════════════════════════


@router.get("/api/advisories/supply-chain", tags=["Advisories"])
async def get_supply_chain_advisories(
    ecosystem: Optional[str] = Query(default=None, description="Filter by ecosystem: npm, pip, go"),
    limit: int = Query(default=20, le=50),
):
    """Returns recent supply chain / malware advisories from GitHub Advisory DB + OSV.dev.

    These advisories cover package ecosystem threats that may not yet have NVD CVE entries,
    including malicious packages, account hijacks, backdoors, and dependency confusion attacks.
    """
    if not _db or not _db.is_configured:
        return []

    try:
        alerts = await _db.get_supply_chain_alerts(
            ecosystem=ecosystem,
            limit=limit,
        )
        return alerts
    except Exception as e:
        logger.error(f"Supply chain advisories error: {e}")
        return []


@router.get("/api/cves/category/SUPPLY_CHAIN", response_model=list[ProcessedCVE], tags=["CVEs"])
async def get_supply_chain_cves(
    limit: int = Query(20, ge=1, le=100),
):
    """CVEs flagged as supply chain threats (malicious packages, backdoors, etc.)."""
    if _db and _db.is_configured:
        try:
            db_cves = await _db.get_cves_by_category("SUPPLY_CHAIN", limit=limit)
            if db_cves is not None:
                return db_cves
        except Exception as e:
            logger.warning(f"Supabase supply chain query failed: {e}")

    if not _poller:
        return []

    cves = [c for c in _poller.processed_cves if "SUPPLY_CHAIN" in c.categories]
    cves.sort(key=lambda c: c.priority_score, reverse=True)
    return cves[:limit]
