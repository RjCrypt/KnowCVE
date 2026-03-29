"""KnowCVE — FastAPI entry point with lifespan lifecycle."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import init_routes, router
from app.services.ai_explainer import GroqExplainer
from app.services.enrichment import CISAKEVService, EPSSService, GitHubAdvisoryService, GreyNoiseService
from app.services.database import SupabaseService
from app.services.poller import CVEPoller
from app.services.telegram_bot import TelegramAlertBot
from app.services.triage import TriageEngine

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

    # 2. Wire Telegram ↔ Poller
    telegram_bot.set_poller(poller)
    poller.set_alert_callback(telegram_bot.broadcast_alert)
    poller.set_breaking_threat_callback(telegram_bot.broadcast_breaking_threat)
    poller.set_database(db_service)

    # 3. Start Telegram bot (non-fatal — server works without it)
    try:
        await telegram_bot.start()
    except Exception as e:
        logger.warning(f"Telegram bot failed to start (non-fatal): {e}")

    # 4. Start poller
    poller.start()

    logger.info("✅ KnowCVE ready")
    yield

    # Shutdown
    logger.info("🛑 KnowCVE shutting down…")
    poller.stop()
    await telegram_bot.stop()
    logger.info("👋 KnowCVE stopped")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="KnowCVE",
    description="Real-time CVE monitoring, enrichment, AI explanation, and Telegram alerting",
    version="2.0.0",
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

# Wire routes with runtime state
init_routes(poller=poller, telegram_bot=telegram_bot, db=db_service)
app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
