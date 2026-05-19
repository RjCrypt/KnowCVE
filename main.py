"""KnowCVE — FastAPI entry point with lifespan lifecycle."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import init_routes, router
from app.api.auth_routes import init_auth_routes, auth_router
from app.services.ai_explainer import GroqExplainer
from app.services.enrichment import CISAKEVService, EPSSService, GitHubAdvisoryService, GreyNoiseService
from app.services.database import SupabaseService
from app.services.poller import CVEPoller
from app.services.telegram_bot import TelegramAlertBot
from app.services.triage import TriageEngine

# Phase 5 services
from app.services.threat_actors import ThreatActorService
from app.services.ransomware_tracker import RansomwareTrackerService
from app.services.ioc_pulse import IOCPulseService
from app.services.news_intel import NewsIntelService
from app.services.breach_intel import BreachIntelService

# Phase 7
from app.services.watchlist_service import WatchlistService

from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Shared service instances ──────────────────────────────────────────────────
kev_service = CISAKEVService()
epss_service = EPSSService()
github_service = GitHubAdvisoryService()
greynoise_service = GreyNoiseService()
explainer = GroqExplainer()
db_service = SupabaseService()

triage_engine = TriageEngine(
    kev_service=kev_service,
    epss_service=epss_service,
    github_service=github_service,
    explainer=explainer,
    greynoise_service=greynoise_service,
)

poller = CVEPoller(triage_engine=triage_engine)
telegram_bot = TelegramAlertBot()

# Phase 5 services — all independent of the CVE polling pipeline
threat_actor_service = ThreatActorService()
ransomware_tracker = RansomwareTrackerService()
ioc_pulse = IOCPulseService()
news_intel = NewsIntelService()
breach_intel = BreachIntelService()

# Phase 7
watchlist_service = WatchlistService(db=db_service)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("🚀 KnowCVE starting up…")

    # 1. Load CISA KEV catalog
    try:
        await kev_service.load_catalog()
    except Exception as e:
        logger.warning(f"Failed to load KEV catalog (non-fatal): {e}")

    # 2. Wire Telegram ↔ Poller + Phase 5 services
    telegram_bot.set_poller(poller)
    telegram_bot.set_news_intel(news_intel)
    telegram_bot.set_threat_actors(threat_actor_service)
    telegram_bot.set_ransomware(ransomware_tracker)
    telegram_bot.set_breach_intel(breach_intel)
    telegram_bot.set_ioc_pulse(ioc_pulse)
    poller.set_alert_callback(telegram_bot.broadcast_alert)
    poller.set_breaking_threat_callback(telegram_bot.broadcast_breaking_threat)
    poller.set_database(db_service)

    # 3. Seed Phase 5 data (only runs if tables are empty)
    try:
        await threat_actor_service.seed_initial_actors()
        await ransomware_tracker.seed_initial_campaigns()
        await breach_intel.seed_initial_breaches()
    except Exception as e:
        logger.warning(f"Phase 5 seeding failed (non-fatal): {e}")

    # 4. Start Telegram bot (non-fatal — server works without it)
    try:
        await telegram_bot.start()
    except Exception as e:
        logger.warning(f"Telegram bot failed to start (non-fatal): {e}")

    # 5. Start poller and Phase 5 scheduled jobs
    poller.start()

    # Weekly MITRE ATT&CK sync — runs independently of CVE pipeline
    poller.scheduler.add_job(
        threat_actor_service.sync_all_mitre_data,
        trigger=IntervalTrigger(weeks=1),
        id="mitre_sync",
        next_run_time=datetime.now(timezone.utc),
        max_instances=1,
    )

    async def fetch_news_and_extract_breaches():
        await news_intel.fetch_all_feeds()
        await breach_intel.extract_breaches_from_news()

    # Fetch news every 2 hours — independent of CVE pipeline
    poller.scheduler.add_job(
        fetch_news_and_extract_breaches,
        trigger=IntervalTrigger(hours=2),
        id="news_fetch",
        next_run_time=datetime.now(timezone.utc),
        max_instances=1,
    )

    # Daily briefing via Telegram at 8am UTC
    async def send_daily_briefing():
        briefing = await news_intel.get_daily_briefing()
        await telegram_bot.broadcast_text(briefing)

    poller.scheduler.add_job(
        send_daily_briefing,
        trigger=CronTrigger(hour=8, minute=0),
        id="daily_briefing",
        max_instances=1,
    )

    # Run advisory feed immediately on startup to catch recent supply chain attacks
    poller.scheduler.add_job(
        poller.advisory_feed_job,
        trigger=IntervalTrigger(hours=2),
        id="advisory_feed_startup",
        next_run_time=datetime.now(timezone.utc),
        max_instances=1,
        replace_existing=True,
    )

    # Phase 7 — Daily digest email at 08:00 UTC
    poller.scheduler.add_job(
        watchlist_service.run_daily_digest_job,
        trigger=CronTrigger(hour=8, minute=0),
        id="daily_digest",
        max_instances=1,
    )

    logger.info("✅ KnowCVE ready — Phase 5 threat intelligence + supply chain detection + Phase 7 watchlist active")
    yield

    # Shutdown
    logger.info("🛑 KnowCVE shutting down…")
    poller.stop()
    await telegram_bot.stop()
    logger.info("👋 KnowCVE stopped")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="KnowCVE",
    description="Real-time CVE monitoring, enrichment, AI explanation, threat intelligence, and Telegram alerting",
    version="3.0.0",
    lifespan=lifespan,
)

# ── CORS — allow the dashboard to call us ─────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Wire routes with runtime state — includes all Phase 5 services
init_routes(
    poller=poller,
    telegram_bot=telegram_bot,
    db=db_service,
    threat_actors=threat_actor_service,
    ransomware=ransomware_tracker,
    ioc=ioc_pulse,
    news=news_intel,
    breaches=breach_intel,
)
app.include_router(router)

# Phase 6 — Auth, Bookmarks, Waitlist + Phase 7 — Watchlist
init_auth_routes(db=db_service, watchlist=watchlist_service)
app.include_router(auth_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
