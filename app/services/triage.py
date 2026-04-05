"""KnowCVE Risk Score (KRS) — Open Scoring Formula
=================================================
KRS is a 0-100 composite score measuring real-world exploitation risk.

Base Score (static, computed once):
  CVSS severity    → 35% weight  (score/10 * 35)
  EPSS probability → 25% weight  (epss_score * 25)
  CISA KEV status  → 20% weight  (20 if in KEV, else 0)
  PoC availability → 15% weight  (15 if PoC exists, else 0)
  Age bonus        →  5% weight  (recency adjustment)

Dynamic Score (updated hourly):
  GreyNoise scanning activity → up to +20 points
  Trending signals            → up to +10 points

Labels:
  75-100 → CRITICAL
  50-74  → HIGH
  25-49  → MEDIUM
  0-24   → LOW

KRS intentionally weights real-world exploitation signals (KEV, EPSS, PoC)
more heavily than theoretical severity (CVSS) because a CVSS 7.5 that is
actively exploited poses more immediate risk than a CVSS 9.8 with no known
exploitation activity.

Priority scoring engine with dynamic scoring, category assignment,
and CVE enrichment pipeline.
"""

from __future__ import annotations

import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.models.cve import EnrichmentData, ProcessedCVE, RawCVE, AIExplanation
from app.services.enrichment import CISAKEVService, EPSSService, GitHubAdvisoryService, GreyNoiseService, NucleiTemplateService
from app.services.ai_explainer import GroqExplainer

logger = logging.getLogger(__name__)

# ── Priority labels ──────────────────────────────────────────────────────────
LABEL_CRITICAL = "CRITICAL"
LABEL_HIGH = "HIGH"
LABEL_MEDIUM = "MEDIUM"
LABEL_LOW = "LOW"

# ── Thresholds ───────────────────────────────────────────────────────────────
THRESHOLD_ALERT = 25          # alert on MEDIUM+
THRESHOLD_AI_EXPLAIN = 50     # only spend tokens explaining HIGH+ or KEV


def _score_to_label(score: int) -> str:
    if score >= 75:
        return LABEL_CRITICAL
    if score >= 50:
        return LABEL_HIGH
    if score >= 25:
        return LABEL_MEDIUM
    return LABEL_LOW


def _recency_adjustment(published: Optional[datetime]) -> int:
    """Return a score adjustment based on how recently the CVE was published."""
    if not published:
        return 0
    now = datetime.now(timezone.utc)
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    age = now - published
    if age < timedelta(hours=24):
        return 15
    if age < timedelta(hours=72):
        return 8
    if age < timedelta(days=7):
        return 3
    if age < timedelta(days=30):
        return 0
    return -10


def _assign_categories(
    raw: RawCVE,
    enrichment: EnrichmentData,
    priority_score: int,
    previous_epss: float,
    previous_scanner_count: int,
) -> list[str]:
    """Assign category labels based on enrichment data and score."""
    categories: list[str] = []

    # ACTIVELY_EXPLOITED: in KEV or heavy scanning
    if enrichment.in_kev or enrichment.greynoise_scanner_count > 100:
        categories.append("ACTIVELY_EXPLOITED")

    # TRENDING: momentum indicators
    scanner_jumped = (
        previous_scanner_count > 0
        and enrichment.greynoise_scanner_count > previous_scanner_count * 1.5
    )
    epss_jumped = enrichment.epss_score > previous_epss + 0.10
    new_poc = enrichment.has_poc  # simplified — full tracking would need previous has_poc

    published = raw.published_date
    is_recent_hot = False
    if published:
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        is_recent_hot = (
            (datetime.now(timezone.utc) - published) < timedelta(hours=72)
            and priority_score >= 60
        )

    if scanner_jumped or epss_jumped or is_recent_hot:
        categories.append("TRENDING")

    # JUST_DROPPED: fresh and meaningful
    if raw.published_date:
        pub = raw.published_date
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - pub
        if age < timedelta(hours=48) and priority_score >= 40:
            categories.append("JUST_DROPPED")

    # HIGH_EXPLOITABILITY: high EPSS + network + easy access
    vector = raw.cvss_vector or ""
    if (
        enrichment.epss_score > 0.5
        and "AV:N" in vector
        and ("PR:N" in vector or "AC:L" in vector)
    ):
        categories.append("HIGH_EXPLOITABILITY")

    # NO_AUTH_REQUIRED: network + no privileges
    if "AV:N" in vector and "PR:N" in vector:
        categories.append("NO_AUTH_REQUIRED")

    return categories


class TriageEngine:
    """Scores, enriches, and explains CVEs through the full pipeline."""

    def __init__(
        self,
        kev_service: CISAKEVService,
        epss_service: EPSSService,
        github_service: GitHubAdvisoryService,
        explainer: GroqExplainer,
        greynoise_service: Optional[GreyNoiseService] = None,
    ) -> None:
        self.kev = kev_service
        self.epss = epss_service
        self.github = github_service
        self.explainer = explainer
        self.greynoise = greynoise_service or GreyNoiseService()

    async def _get_explanation(
        self, raw: RawCVE, enrichment: EnrichmentData,
        priority_score: int, priority_label: str
    ) -> Optional[AIExplanation]:
        explanation = None

        # Step 1: Check Supabase cache first
        try:
            from app.services.database import SupabaseService
            db = SupabaseService()
            cached = await db.get_explanation(raw.cve_id)
            if cached:
                logger.info(f"Cache hit for {raw.cve_id} — skipping AI call")
                explanation = cached
        except Exception as e:
            logger.debug(f"Cache check failed for {raw.cve_id}: {e}")

        # Step 2: Generate explanation if not cached
        if explanation is None:
            if priority_score >= THRESHOLD_AI_EXPLAIN or enrichment.in_kev:
                try:
                    explanation = await self.explainer.explain_cve(
                        raw, enrichment, priority_label=priority_label
                    )
                    logger.info(f"AI explanation generated for {raw.cve_id} (score {priority_score})")
                    await asyncio.sleep(0.3)
                except Exception as e:
                    logger.error(f"AI explanation failed for {raw.cve_id}: {e}")
                    explanation = self.explainer.generate_lightweight_explanation(
                        raw, enrichment
                    )
            else:
                logger.info(
                    f"Lightweight explanation for {raw.cve_id} "
                    f"(score {priority_score} — below AI threshold)"
                )
                explanation = self.explainer.generate_lightweight_explanation(
                    raw, enrichment
                )
        return explanation

    # ── scoring ──────────────────────────────────────────────────────────

    @staticmethod
    def calculate_priority(
        raw: RawCVE,
        enrichment: EnrichmentData,
        previous_epss: float = 0.0,
        previous_scanner_count: int = 0,
    ) -> tuple[int, str, list[str]]:
        """Weighted priority score (0–100) with dynamic bonuses and category assignment.

        Returns (score, label, categories).
        """
        # ── Base score components ────────────────────────────────────
        # Handle missing CVSS — assume moderate until enriched
        if raw.cvss_score > 0:
            cvss_component = (raw.cvss_score / 10.0) * 35
        else:
            cvss_component = 10  # default for missing CVSS

        epss_component = enrichment.epss_score * 25
        kev_component = 20 if enrichment.in_kev else 0
        poc_component = 15 if enrichment.has_poc else 0

        base_score = int(cvss_component + epss_component + kev_component + poc_component)

        # ── Recency adjustment ───────────────────────────────────────
        base_score += _recency_adjustment(raw.published_date)

        # ── GreyNoise tiered bonus ───────────────────────────────────
        sc = enrichment.greynoise_scanner_count
        if sc > 500:
            base_score += 20
        elif sc > 100:
            base_score += 12
        elif sc > 10:
            base_score += 6

        # ── Dynamic/trending bonuses ─────────────────────────────────
        dynamic = 0

        # Scanner count trending up (50% increase)
        if previous_scanner_count > 0 and sc > previous_scanner_count * 1.5:
            dynamic += 10

        # EPSS jumped significantly (+0.10)
        if enrichment.epss_score > previous_epss + 0.10:
            dynamic += 10

        # New PoC appeared (simplified check)
        # Full implementation would compare previous has_poc
        # For now, PoC bonus is already in base via poc_component

        total_score = max(0, min(100, base_score + dynamic))
        label = _score_to_label(total_score)

        # ── Category assignment ──────────────────────────────────────
        categories = _assign_categories(
            raw, enrichment, total_score, previous_epss, previous_scanner_count
        )

        return total_score, label, categories

    # ── public API ────────────────────────────────────────────────────────

    async def process_cve(self, raw: RawCVE) -> ProcessedCVE:
        """Full pipeline: enrich → score → AI explain → ProcessedCVE."""
        enrichment = await self._build_enrichment(raw)
        priority_score, priority_label, categories = self.calculate_priority(raw, enrichment)

        # Calculate dynamic portion
        dynamic_score = max(0, priority_score - int(
            ((raw.cvss_score / 10.0) * 35 if raw.cvss_score > 0 else 10)
            + enrichment.epss_score * 25
            + (20 if enrichment.in_kev else 0)
            + (15 if enrichment.has_poc else 0)
        ))

        ai_explanation = await self._get_explanation(raw, enrichment, priority_score, priority_label)

        return ProcessedCVE(
            cve_id=raw.cve_id,
            description=raw.description,
            cvss_score=raw.cvss_score,
            cvss_vector=raw.cvss_vector,
            cvss_version=raw.cvss_version,
            published_date=raw.published_date,
            last_modified=raw.last_modified,
            references=raw.references,
            weaknesses=raw.weaknesses,
            enrichment=enrichment,
            ai_explanation=ai_explanation,
            priority_score=priority_score,
            priority_label=priority_label,
            categories=categories,
            dynamic_score=dynamic_score,
        )

    async def process_cve_with_epss(
        self, raw: RawCVE, epss_map: dict[str, dict]
    ) -> ProcessedCVE:
        """Process a single CVE using a pre-fetched EPSS map."""
        enrichment = await self._build_enrichment(raw, epss_map=epss_map)
        priority_score, priority_label, categories = self.calculate_priority(raw, enrichment)

        dynamic_score = max(0, priority_score - int(
            ((raw.cvss_score / 10.0) * 35 if raw.cvss_score > 0 else 10)
            + enrichment.epss_score * 25
            + (20 if enrichment.in_kev else 0)
            + (15 if enrichment.has_poc else 0)
        ))

        ai_explanation = await self._get_explanation(raw, enrichment, priority_score, priority_label)

        return ProcessedCVE(
            cve_id=raw.cve_id,
            description=raw.description,
            cvss_score=raw.cvss_score,
            cvss_vector=raw.cvss_vector,
            cvss_version=raw.cvss_version,
            published_date=raw.published_date,
            last_modified=raw.last_modified,
            references=raw.references,
            weaknesses=raw.weaknesses,
            enrichment=enrichment,
            ai_explanation=ai_explanation,
            priority_score=priority_score,
            priority_label=priority_label,
            categories=categories,
            dynamic_score=dynamic_score,
        )

    async def process_batch(self, raws: list[RawCVE]) -> list[ProcessedCVE]:
        """Process a batch of CVEs with shared EPSS lookup."""
        if not raws:
            return []

        cve_ids = [r.cve_id for r in raws]
        try:
            epss_map = await self.epss.get_scores(cve_ids)
        except Exception as e:
            logger.warning(f"Batch EPSS fetch failed (proceeding without): {e}")
            epss_map = {}

        results: list[ProcessedCVE] = []
        for raw in raws:
            try:
                enrichment = await self._build_enrichment(raw, epss_map=epss_map)
                priority_score, priority_label, categories = self.calculate_priority(raw, enrichment)

                dynamic_score = max(0, priority_score - int(
                    ((raw.cvss_score / 10.0) * 35 if raw.cvss_score > 0 else 10)
                    + enrichment.epss_score * 25
                    + (20 if enrichment.in_kev else 0)
                    + (15 if enrichment.has_poc else 0)
                ))

                ai_explanation = await self._get_explanation(raw, enrichment, priority_score, priority_label)

                results.append(
                    ProcessedCVE(
                        cve_id=raw.cve_id,
                        description=raw.description,
                        cvss_score=raw.cvss_score,
                        cvss_vector=raw.cvss_vector,
                        cvss_version=raw.cvss_version,
                        published_date=raw.published_date,
                        last_modified=raw.last_modified,
                        references=raw.references,
                        weaknesses=raw.weaknesses,
                        enrichment=enrichment,
                        ai_explanation=ai_explanation,
                        priority_score=priority_score,
                        priority_label=priority_label,
                        categories=categories,
                        dynamic_score=dynamic_score,
                    )
                )
            except Exception as e:
                logger.error(f"Failed to process {raw.cve_id}: {e}")
                continue

        logger.info(f"Batch done: {len(results)}/{len(raws)} CVEs processed")
        return results

    # ── enrichment builder ────────────────────────────────────────────────

    async def _build_enrichment(
        self,
        cve: RawCVE,
        epss_map: dict[str, dict] | None = None,
    ) -> EnrichmentData:
        """Gather enrichment data from all sources for a single CVE."""
        in_kev = self.kev.is_in_kev(cve.cve_id)

        if epss_map is not None:
            epss_data = epss_map.get(cve.cve_id)
        else:
            epss_data = await self.epss.get_score(cve.cve_id)

        epss_score = epss_data["epss_score"] if epss_data else 0.0
        epss_percentile = epss_data["percentile"] if epss_data else 0.0

        poc_urls: list[str] = []
        try:
            poc_urls = await self.github.search_pocs(cve.cve_id)
        except Exception as e:
            logger.debug(f"GitHub PoC search failed for {cve.cve_id}: {e}")

        greynoise_data = {"scanner_count": 0, "is_being_scanned": False}
        try:
            greynoise_data = await self.greynoise.get_scanning_activity(cve.cve_id)
        except Exception as e:
            logger.debug(f"GreyNoise lookup failed for {cve.cve_id}: {e}")

        # Nuclei template check (only for HIGH+ CVEs to conserve GitHub API quota)
        has_nuclei = False
        nuclei_url = None
        base_score_est = (cve.cvss_score / 10.0) * 35 + epss_score * 25 + (20 if in_kev else 0) + (15 if len(poc_urls) > 0 else 0)
        if base_score_est >= 50 or in_kev:
            try:
                nuclei_service = NucleiTemplateService()
                nuclei_data = await nuclei_service.check_template(cve.cve_id)
                has_nuclei = nuclei_data["has_template"]
                nuclei_url = nuclei_data.get("template_url")
            except Exception as e:
                logger.debug(f"Nuclei template check failed for {cve.cve_id}: {e}")

        return EnrichmentData(
            in_kev=in_kev,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            poc_urls=poc_urls,
            has_poc=len(poc_urls) > 0,
            greynoise_scanner_count=greynoise_data["scanner_count"],
            is_being_scanned=greynoise_data["is_being_scanned"],
            has_nuclei_template=has_nuclei,
            nuclei_template_url=nuclei_url,
        )
