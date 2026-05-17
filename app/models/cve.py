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

    # Trend tracking (populated by trending_refresh_job)
    previous_epss_score: float = 0.0
    previous_scanner_count: int = 0
    epss_trend: str = "stable"       # "rising", "falling", "stable"
    scanner_trend: str = "stable"    # "rising", "falling", "stable", "new"

    # Nuclei template detection (Phase 4)
    has_nuclei_template: bool = False
    nuclei_template_url: Optional[str] = None


# ── ATT&CK Technique (Phase 5.5) ─────────────────────────────────────────────

class AttackTechnique(BaseModel):
    """A single MITRE ATT&CK technique in a CVE-specific kill chain."""

    technique_id: str = ""          # "T1190"
    technique_name: str = ""        # "Exploit Public-Facing Application"
    tactic: str = ""                # "Initial Access"
    tactic_phase: int = 1           # 1-12 ordering per ATT&CK tactic order
    description: str = ""           # CVE-specific application of this technique
    is_pivot: bool = False          # True if this is the key exploitation step


# ── AI Explanation ────────────────────────────────────────────────────────────

class AIExplanation(BaseModel):
    """AI-generated threat intelligence explanation of a CVE."""

    summary: str = ""
    technical_detail: str = ""
    impact: str = ""
    remediation: str = ""
    tags: list[str] = Field(default_factory=list)
    affected_tech: list[str] = Field(default_factory=list)
    mitre_techniques: list[dict] = Field(default_factory=list)
    # Each dict: {"technique_id": "T1190", "technique_name": "...", "tactic": "...", "url": "..."}

    # Phase 5.5 — AI Depth Upgrade fields
    vulnerability_class_analysis: Optional[str] = None
    adversarial_context: Optional[str] = None
    exploit_narrative: Optional[str] = None
    attack_techniques: Optional[list[AttackTechnique]] = None


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

    # Dynamic scoring & categorisation (new)
    categories: list[str] = Field(default_factory=list)
    # e.g. ["ACTIVELY_EXPLOITED", "TRENDING", "JUST_DROPPED", "SUPPLY_CHAIN"]
    dynamic_score: int = 0
    # the momentum/dynamic portion of the score
    last_rescored_at: Optional[datetime] = None
    # when this CVE was last re-evaluated

    # Advisory source tracking (supply chain detection)
    ghsa_id: Optional[str] = None
    ecosystem: Optional[str] = None          # "npm", "PyPI", etc.
    is_malware_advisory: bool = False        # True for supply chain malware
    affected_packages: list[dict] = Field(default_factory=list)

    # KRS (KnowCVE Risk Score) aliases — Phase 4
    @property
    def krs_score(self) -> int:
        return self.priority_score

    @property
    def krs_label(self) -> str:
        return self.priority_label

    model_config = {"arbitrary_types_allowed": True}


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


# ── Community Intelligence (Phase 4) ─────────────────────────────────────────

class WildReport(BaseModel):
    """Request body for reporting a CVE seen in the wild."""
    cve_id: str
    context: Optional[str] = None  # optional free-text, max 200 chars


class WildReportSummary(BaseModel):
    """Aggregated wild exploitation reports for a CVE."""
    cve_id: str
    report_count: int = 0
    last_reported_at: Optional[str] = None


class ResearcherNote(BaseModel):
    """Request body for adding a researcher note."""
    cve_id: str
    note: str           # max 500 chars
    author_alias: Optional[str] = None  # optional display name


class ResearcherNoteResponse(BaseModel):
    """Response shape for researcher notes."""
    id: int
    cve_id: str
    note: str
    author_alias: Optional[str] = None
    created_at: str


# ── Exploit Intelligence (Phase 4.5) ─────────────────────────────────────────

class ExploitEntry(BaseModel):
    """A single exploit entry from ExploitDB."""
    id: str
    description: str
    date: str
    type: str
    platform: str
    url: str


class PoCRepo(BaseModel):
    """A GitHub PoC repository with quality signals."""
    url: str
    stars: int = 0
    forks: int = 0
    last_updated: Optional[str] = None


class ExploitIntelligence(BaseModel):
    """
    Full exploit ecosystem intelligence for a single CVE.
    Stored separately from ProcessedCVE to avoid bloating the main table.
    """
    cve_id: str

    # Metasploit
    has_metasploit_module: bool = False
    metasploit_module_url: Optional[str] = None
    metasploit_module_path: Optional[str] = None

    # ExploitDB
    exploitdb_entries: list[ExploitEntry] = Field(default_factory=list)

    # GitHub PoC repos with quality signals
    poc_repos: list[PoCRepo] = Field(default_factory=list)

    # Exploit Maturity Score
    ems_score: int = 0
    ems_label: str = "RESEARCH"   # WEAPONIZED / FUNCTIONAL / THEORETICAL / RESEARCH

    # Computed commands
    metasploit_command: Optional[str] = None   # ready msfconsole command stub
    nuclei_command: Optional[str] = None       # ready nuclei command
    searchsploit_command: Optional[str] = None # searchsploit command

    # Meta
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class ExploitIntelSummary(BaseModel):
    """Lightweight summary for feed cards — no full exploit details."""
    cve_id: str
    ems_score: int
    ems_label: str
    has_metasploit_module: bool
    has_nuclei_template: bool
    has_exploitdb_entry: bool
    poc_count: int
    max_poc_stars: int
    priority_score: int
    priority_label: str
    cvss_score: float
    description: str
    published: str


# ── Advisory Feed (Supply Chain Detection) ────────────────────────────────────

class AdvisoryRecord(BaseModel):
    """A security advisory from GitHub Advisory Database or OSV.dev."""

    ghsa_id: Optional[str] = None           # e.g., "GHSA-xxxx-xxxx-xxxx"
    cve_id: Optional[str] = None            # may be None for malware advisories
    source: str = "github"                  # "github" or "osv"
    ecosystem: str = "npm"                  # "npm", "PyPI", "Go", etc.
    severity: str = "unknown"               # "critical", "high", "medium", "low"
    summary: str = ""
    description: str = ""
    affected_packages: list[dict] = Field(default_factory=list)
    # Each dict: {"name": str, "ecosystem": str, "version_range": str}
    references: list[str] = Field(default_factory=list)
    published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_malware: bool = False                # True for supply chain / malware advisories
    withdrawn: bool = False                 # True if advisory was withdrawn

