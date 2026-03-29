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
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            self._client.table("processed_cves").upsert(row, on_conflict="cve_id").execute()
        except Exception as e:
            logger.error(f"Supabase save_cve error for {cve.cve_id}: {e}")

    # ── read ──────────────────────────────────────────────────────────────

    async def get_recent_cves(
        self,
        limit: int = 100,
        min_priority: int = 0,
        kev_only: bool = False,
        has_poc: bool = False,
    ) -> list[ProcessedCVE]:
        """Query processed CVEs with filters, ordered by published DESC."""
        if not self._client:
            return []

        try:
            query = (
                self._client.table("processed_cves")
                .select("*")
                .gte("priority_score", min_priority)
                .order("published", desc=True)
                .limit(limit)
            )
            if kev_only:
                query = query.eq("enrichment->>in_kev", "true")
            if has_poc:
                query = query.eq("enrichment->>has_poc", "true")

            result = query.execute()
            return [self._row_to_cve(row) for row in (result.data or [])]
        except Exception as e:
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

    async def get_threats(self, limit: int = 20) -> list[ProcessedCVE]:
        """Get CVEs where priority_score >= 75 OR in_kev, last 7 days."""
        if not self._client:
            return []

        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            result = (
                self._client.table("processed_cves")
                .select("*")
                .gte("published", cutoff)
                .gte("priority_score", 75)
                .order("published", desc=True)
                .limit(limit)
                .execute()
            )
            threats = [self._row_to_cve(row) for row in (result.data or [])]

            # Also fetch KEV CVEs from last 7 days
            kev_result = (
                self._client.table("processed_cves")
                .select("*")
                .gte("published", cutoff)
                .eq("enrichment->>in_kev", "true")
                .order("published", desc=True)
                .limit(limit)
                .execute()
            )
            kev_ids = {t.cve_id for t in threats}
            for row in (kev_result.data or []):
                cve = self._row_to_cve(row)
                if cve.cve_id not in kev_ids:
                    threats.append(cve)

            threats.sort(key=lambda c: c.priority_score, reverse=True)
            return threats[:limit]
        except Exception as e:
            logger.error(f"Supabase get_threats error: {e}")
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
        )
