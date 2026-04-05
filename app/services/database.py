"""Supabase persistence layer for KnowCVE — graceful fallback when unconfigured."""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.core.config import settings
from app.models.cve import ProcessedCVE, EnrichmentData, AIExplanation

logger = logging.getLogger(__name__)


class SupabaseService:
    """Supabase wrapper. Returns None/empty if Supabase is not configured."""

    def __init__(self) -> None:
        self._client = None
        if settings.SUPABASE_URL and settings.SUPABASE_KEY:
            try:
                from supabase import create_client
                self._client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                logger.info("Supabase client initialized")
            except Exception as e:
                logger.warning(f"Supabase init failed (running without persistence): {e}")
        else:
            logger.info("Supabase not configured — running in-memory only")

    @property
    def is_configured(self) -> bool:
        return self._client is not None

    # ── write ──────────────────────────────────────────────────────────────

    async def save_cve(self, cve: ProcessedCVE) -> None:
        """Upsert a processed CVE into the processed_cves table."""
        if not self._client:
            return

        try:
            row = {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "published": cve.published_date.isoformat() if cve.published_date else None,
                "last_modified": cve.last_modified.isoformat() if cve.last_modified else None,
                "cvss_score": cve.cvss_score,
                "cvss_severity": cve.cvss_version,
                "priority_score": cve.priority_score,
                "priority_label": cve.priority_label,
                "enrichment": cve.enrichment.model_dump() if cve.enrichment else {},
                "ai_explanation": cve.ai_explanation.model_dump() if cve.ai_explanation else None,
                "affected_products": cve.ai_explanation.affected_tech if cve.ai_explanation else [],
                "cwe_ids": cve.weaknesses,
                "references": cve.references,
                "alert_sent": True,
                "categories": cve.categories,
                "dynamic_score": cve.dynamic_score,
                "last_rescored_at": cve.last_rescored_at.isoformat() if cve.last_rescored_at else None,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            self._client.table("processed_cves").upsert(row, on_conflict="cve_id").execute()
        except Exception as e:
            logger.error(f"Supabase save_cve error for {cve.cve_id}: {e}")

    async def update_cve_score(
        self,
        cve_id: str,
        priority_score: int,
        priority_label: str,
        categories: list[str],
        dynamic_score: int,
        enrichment: EnrichmentData,
        last_rescored_at: datetime,
    ) -> None:
        """Partial update — only score-related fields. Won't overwrite ai_explanation."""
        if not self._client:
            return
        try:
            self._client.table("processed_cves").update({
                "priority_score": priority_score,
                "priority_label": priority_label,
                "categories": categories,
                "dynamic_score": dynamic_score,
                "enrichment": enrichment.model_dump(),
                "last_rescored_at": last_rescored_at.isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("cve_id", cve_id).execute()
        except Exception as e:
            logger.error(f"Supabase update_cve_score error for {cve_id}: {e}")

    # ── read ──────────────────────────────────────────────────────────────

    async def get_recent_cves(
        self,
        limit: int = 100,
        min_priority: int = 0,
        category: Optional[str] = None,
    ) -> list[ProcessedCVE]:
        """Query processed CVEs with filters, ordered by published DESC."""
        if not self._client:
            return []

        import time
        import asyncio

        try:
            query = (
                self._client.table("processed_cves")
                .select("*")
                .gte("priority_score", min_priority)
                .order("published", desc=True)
                .limit(limit)
            )
            if category:
                query = query.contains("categories", [category])

            # Retry logic for transient DNS drops
            result = None
            for attempt in range(3):
                try:
                    result = query.execute()
                    break
                except Exception as e:
                    if "getaddrinfo failed" in str(e) and attempt < 2:
                        await asyncio.sleep(0.5)
                        continue
                    raise

            return [self._row_to_cve(row) for row in (result.data or [])]
        except Exception as e:
            if "getaddrinfo failed" in str(e):
                logger.warning(f"Transient network error in get_recent_cves: {e}")
            else:
                logger.error(f"Supabase get_recent_cves error: {e}")
            return []

    async def get_cve(self, cve_id: str) -> Optional[ProcessedCVE]:
        """Retrieve a single CVE by ID."""
        if not self._client:
            return None

        try:
            result = (
                self._client.table("processed_cves")
                .select("*")
                .eq("cve_id", cve_id)
                .limit(1)
                .execute()
            )
            if result.data:
                return self._row_to_cve(result.data[0])
            return None
        except Exception as e:
            logger.error(f"Supabase get_cve error for {cve_id}: {e}")
            return None

    async def get_explanation(self, cve_id: str) -> Optional[AIExplanation]:
        """Check if an AI explanation already exists in Supabase for this CVE."""
        if not self._client:
            return None
        try:
            result = (
                self._client
                .table("processed_cves")
                .select("ai_explanation")
                .eq("cve_id", cve_id)
                .not_.is_("ai_explanation", "null")
                .single()
                .execute()
            )
            if result.data and result.data.get("ai_explanation"):
                return AIExplanation(**result.data["ai_explanation"])
            return None
        except Exception as e:
            logger.debug(f"Cache miss for {cve_id}: {e}")
            return None

    async def get_threats(self, limit: int = 20) -> list[ProcessedCVE]:
        """Get high-priority CVEs — score >= 60 from last 30 days.

        Uses a single broad query to avoid fragile JSON path filters.
        The caller / frontend handles the "breaking threat" display logic.
        """
        if not self._client:
            return []

        try:
            # Wider window (30 days) and lower threshold (60) to ensure
            # we always have data. The route layer re-applies the strict
            # score >= 75 / KEV filter before returning.
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            result = (
                self._client.table("processed_cves")
                .select("*")
                .gte("published", cutoff)
                .gte("priority_score", 60)
                .order("priority_score", desc=True)
                .limit(limit * 3)  # fetch extra so filtering still yields enough
                .execute()
            )
            cves = [self._row_to_cve(row) for row in (result.data or [])]

            # Apply the threat filter: score >= 75 OR in KEV
            threats = [
                c for c in cves
                if c.priority_score >= 75 or c.enrichment.in_kev
            ]
            threats.sort(key=lambda c: c.priority_score, reverse=True)
            return threats[:limit]
        except Exception as e:
            logger.error(f"Supabase get_threats error: {e}")
            return []

    async def get_unscored_cves(self, days_back: int = 14) -> list[str]:
        """Returns cve_id list for CVEs with missing/zero CVSS scores."""
        if not self._client:
            return []
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()
            result = (
                self._client.table("processed_cves")
                .select("cve_id")
                .or_("cvss_score.eq.0,cvss_score.is.null")
                .gte("published", cutoff)
                .execute()
            )
            return [row["cve_id"] for row in (result.data or [])]
        except Exception as e:
            logger.error(f"Supabase get_unscored_cves error: {e}")
            return []

    async def get_cves_for_refresh(self, limit: int = 50) -> list[ProcessedCVE]:
        """Returns top CVEs by score for trending refresh."""
        if not self._client:
            return []
        try:
            result = (
                self._client.table("processed_cves")
                .select("*")
                .order("priority_score", desc=True)
                .limit(limit)
                .execute()
            )
            return [self._row_to_cve(row) for row in (result.data or [])]
        except Exception as e:
            logger.error(f"Supabase get_cves_for_refresh error: {e}")
            return []

    async def get_cves_by_category(self, category: str, limit: int = 20) -> list[ProcessedCVE]:
        """Query CVEs containing a specific category using Postgres array contains."""
        if not self._client:
            return []
        try:
            result = (
                self._client.table("processed_cves")
                .select("*")
                .contains("categories", [category])
                .order("priority_score", desc=True)
                .limit(limit)
                .execute()
            )
            return [self._row_to_cve(row) for row in (result.data or [])]
        except Exception as e:
            logger.error(f"Supabase get_cves_by_category error: {e}")
            return []

    async def get_fresh_cves(self, limit: int = 20) -> list[ProcessedCVE]:
        """Get CVEs published in last 48 hours, any score, sorted by recency."""
        if not self._client:
            return []
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
            result = (
                self._client.table("processed_cves")
                .select("*")
                .gte("published", cutoff)
                .order("published", desc=True)
                .limit(limit)
                .execute()
            )
            return [self._row_to_cve(row) for row in (result.data or [])]
        except Exception as e:
            logger.error(f"Supabase get_fresh_cves error: {e}")
            return []

    async def get_stats_counts(self) -> dict:
        """Return counts grouped by priority_label."""
        if not self._client:
            return {}

        try:
            result = self._client.table("processed_cves").select("priority_label").execute()
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
            for row in (result.data or []):
                label = row.get("priority_label", "LOW")
                counts[label] = counts.get(label, 0) + 1
                counts["total"] += 1
            return counts
        except Exception as e:
            logger.error(f"Supabase get_stats_counts error: {e}")
            return {}

    # ── row conversion ────────────────────────────────────────────────────

    @staticmethod
    def _row_to_cve(row: dict) -> ProcessedCVE:
        """Convert a Supabase row dict into a ProcessedCVE model."""
        enrichment_data = row.get("enrichment", {})
        ai_data = row.get("ai_explanation")

        return ProcessedCVE(
            cve_id=row["cve_id"],
            description=row.get("description", ""),
            cvss_score=row.get("cvss_score", 0.0),
            cvss_vector="",
            cvss_version=row.get("cvss_severity", ""),
            published_date=row.get("published"),
            last_modified=row.get("last_modified"),
            references=row.get("references", []),
            weaknesses=row.get("cwe_ids", []),
            enrichment=EnrichmentData(**enrichment_data) if enrichment_data else EnrichmentData(),
            ai_explanation=AIExplanation(**ai_data) if ai_data else None,
            priority_score=row.get("priority_score", 0),
            priority_label=row.get("priority_label", "LOW"),
            categories=row.get("categories", []),
            dynamic_score=row.get("dynamic_score", 0),
            last_rescored_at=row.get("last_rescored_at"),
        )

    # ── Exploit Intelligence persistence ──────────────────────────────────

    async def save_exploit_intel(self, intel) -> None:
        """Upsert an exploit intelligence record."""
        if not self._client:
            return
        try:
            row = {
                "cve_id": intel.cve_id,
                "has_metasploit_module": intel.has_metasploit_module,
                "metasploit_module_url": intel.metasploit_module_url,
                "metasploit_module_path": intel.metasploit_module_path,
                "exploitdb_entries": [e.model_dump() for e in intel.exploitdb_entries],
                "poc_repos": [p.model_dump() for p in intel.poc_repos],
                "ems_score": intel.ems_score,
                "ems_label": intel.ems_label,
                "metasploit_command": intel.metasploit_command,
                "nuclei_command": intel.nuclei_command,
                "searchsploit_command": intel.searchsploit_command,
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
            self._client.table("exploit_intelligence").upsert(
                row, on_conflict="cve_id"
            ).execute()
        except Exception as e:
            logger.error(f"Supabase save_exploit_intel error for {intel.cve_id}: {e}")

    async def get_exploit_intel(self, cve_id: str):
        """Retrieve exploit intelligence for a single CVE."""
        if not self._client:
            return None
        try:
            from app.models.cve import ExploitIntelligence, ExploitEntry, PoCRepo

            result = (
                self._client.table("exploit_intelligence")
                .select("*")
                .eq("cve_id", cve_id)
                .limit(1)
                .execute()
            )
            if not result.data:
                return None
            row = result.data[0]
            return ExploitIntelligence(
                cve_id=row["cve_id"],
                has_metasploit_module=row.get("has_metasploit_module", False),
                metasploit_module_url=row.get("metasploit_module_url"),
                metasploit_module_path=row.get("metasploit_module_path"),
                exploitdb_entries=[ExploitEntry(**e) for e in (row.get("exploitdb_entries") or [])],
                poc_repos=[PoCRepo(**p) for p in (row.get("poc_repos") or [])],
                ems_score=row.get("ems_score", 0),
                ems_label=row.get("ems_label", "RESEARCH"),
                metasploit_command=row.get("metasploit_command"),
                nuclei_command=row.get("nuclei_command"),
                searchsploit_command=row.get("searchsploit_command"),
                last_updated=row.get("last_updated"),
            )
        except Exception as e:
            logger.error(f"Supabase get_exploit_intel error for {cve_id}: {e}")
            return None

    async def get_exploit_intel_feed(
        self,
        limit: int = 20,
        offset: int = 0,
        ems_label: str | None = None,
        has_metasploit: bool = False,
        has_nuclei: bool = False,
    ) -> list[dict]:
        """Returns exploit_intelligence records sorted by EMS score desc."""
        if not self._client:
            return []
        try:
            query = (
                self._client.table("exploit_intelligence")
                .select("*")
                .order("ems_score", desc=True)
                .range(offset, offset + limit - 1)
            )
            if ems_label:
                query = query.eq("ems_label", ems_label.upper())
            if has_metasploit:
                query = query.eq("has_metasploit_module", True)
            if has_nuclei:
                query = query.not_("nuclei_command", "is", "null")

            result = query.execute()
            return result.data or []
        except Exception as e:
            logger.error(f"Supabase get_exploit_intel_feed error: {e}")
            return []

