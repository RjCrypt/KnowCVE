"""Pydantic data models for KnowCVE — hybrid refactor final version."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ── Raw NVD data ──────────────────────────────────────────────────────────────

class RawCVE(BaseModel):
    """CVE record parsed directly from the NVD API v2 response."""

    cve_id: str = Field(..., description="e.g. CVE-2024-12345")
    description: str = ""
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str = ""
    cvss_version: str = ""
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    references: list[str] = Field(default_factory=list)
    weaknesses: list[str] = Field(default_factory=list)


# ── Enrichment ────────────────────────────────────────────────────────────────

class EnrichmentData(BaseModel):
    """Aggregated enrichment from CISA KEV, EPSS, GitHub advisories, and GreyNoise."""

    in_kev: bool = False
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    epss_percentile: float = Field(default=0.0, ge=0.0, le=1.0)
    poc_urls: list[str] = Field(default_factory=list)
    has_poc: bool = False
    greynoise_scanner_count: int = Field(default=0, ge=0)
    is_being_scanned: bool = False


# ── AI Explanation ────────────────────────────────────────────────────────────

class AIExplanation(BaseModel):
    """Groq-generated 4-layer explanation of a CVE."""

    summary: str = ""
    technical_detail: str = ""
    impact: str = ""
    remediation: str = ""
    tags: list[str] = Field(default_factory=list)
    affected_tech: list[str] = Field(default_factory=list)


# ── Processed CVE ─────────────────────────────────────────────────────────────

class ProcessedCVE(BaseModel):
    """Fully enriched + scored + explained CVE ready for API / Telegram."""

    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cvss_version: str = ""
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    references: list[str] = Field(default_factory=list)
    weaknesses: list[str] = Field(default_factory=list)

    enrichment: EnrichmentData = Field(default_factory=EnrichmentData)
    ai_explanation: Optional[AIExplanation] = None
    priority_score: int = Field(default=0, ge=0, le=100)
    priority_label: str = "LOW"
    processed_at: datetime = Field(default_factory=datetime.utcnow)


# ── Telegram Subscriptions ───────────────────────────────────────────────────

class UserSubscription(BaseModel):
    """A Telegram user's alert subscription."""

    chat_id: int
    subscribed_at: datetime = Field(default_factory=datetime.utcnow)
    min_priority: int = Field(default=25, ge=0, le=100, description="Minimum priority score to receive alerts")
    alert_mode: str = Field(default="important", description="continuous|important|critical")
    paused: bool = Field(default=False, description="When True, no alerts sent until resumed")


# ── API Response Models ──────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    """Response shape for /api/stats."""

    total_cves_processed: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    last_poll_time: Optional[datetime] = None
    next_poll_time: Optional[datetime] = None
    subscribers_count: int = 0
    kev_catalog_size: int = 0


class PollResponse(BaseModel):
    """Response shape for /api/poll."""

    status: str = "ok"
    new_cves_found: int = 0
    cves_processed: int = 0
    alerts_sent: int = 0
    errors: list[str] = Field(default_factory=list)
