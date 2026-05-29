"""Application settings loaded from .env via Pydantic Settings."""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """All configuration for KnowCVE, sourced from environment variables."""

    # ── API Keys ──────────────────────────────────────────────────────────
    NVD_API_KEY: str = Field(default="", description="NVD API key for higher rate limits")
    GROQ_API_KEY: str = Field(default="", description="Groq cloud API key")
    CEREBRAS_API_KEY: str = Field(default="", description="Cerebras cloud API key")
    GEMINI_API_KEY: str = Field(default="", description="Google Gemini API key")
    TELEGRAM_BOT_TOKEN: str = Field(default="", description="Telegram Bot API token")
    GITHUB_TOKEN: str = Field(default="", description="GitHub PAT for advisory search")
    GREYNOISE_API_KEY: str = Field(default="", description="GreyNoise community API key (optional)")
    SUPABASE_URL: str = Field(default="", description="Supabase project URL")
    SUPABASE_KEY: str = Field(default="", description="Supabase anon key")
    APP_SECRET_KEY: str = Field(default="", description="Secret key for admin endpoints (poll trigger)")
    ABUSEIPDB_API_KEY: str = Field(default="", description="AbuseIPDB API key for IOC lookups")
    SENDGRID_API_KEY: str = Field(default="", description="SendGrid API key for email delivery")
    SENDGRID_FROM_EMAIL: str = Field(default="", description="SendGrid sender email address")
    SENDGRID_FROM_NAME: str = Field(default="KnowCVE", description="SendGrid sender name")
    FRONTEND_URL: str = Field(default="https://know-cve.vercel.app", description="Frontend URL for email links")

    # ── Service URLs ──────────────────────────────────────────────────────
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"
    KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # ── Poller ────────────────────────────────────────────────────────────
    POLL_INTERVAL_MINUTES: int = Field(default=15, description="Minutes between NVD poll cycles")

    # ── AI Model ──────────────────────────────────────────────────────────
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": True, "extra": "ignore"}


settings = Settings()
