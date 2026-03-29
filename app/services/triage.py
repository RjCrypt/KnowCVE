"""Priority scoring engine with recency decay and full CVE enrichment pipeline."""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.models.cve import EnrichmentData, ProcessedCVE, RawCVE
from app.services.enrichment import CISAKEVService, EPSSService, GitHubAdvisoryService, GreyNoiseService
from app.services.ai_explainer import GroqExplainer

logger = logging.getLogger(__name__)

# ── Scoring weights (must sum to 1.0) ────────────────────────────────────────
W_CVSS = 0.40
W_EPSS = 0.25
W_KEV = 0.20
W_POC = 0.15

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
    # Make published timezone-aware if it isn't
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

    # ── public API ────────────────────────────────────────────────────────

    @staticmethod
    def calculate_priority(
        raw: RawCVE, enrichment: EnrichmentData
    ) -> tuple[int, str]:
        """Weighted priority score (0–100) with recency decay + GreyNoise bonus."""
        cvss_norm = (raw.cvss_score / 10.0) * 100
        epss_norm = enrichment.epss_score * 100
        kev_norm = 100.0 if enrichment.in_kev else 0.0
        poc_norm = 100.0 if enrichment.has_poc else 0.0

        score = int(
            W_CVSS * cvss_norm
            + W_EPSS * epss_norm
            + W_KEV * kev_norm
            + W_POC * poc_norm
        )

        # Recency adjustment
        score += _recency_adjustment(raw.published_date)

        # GreyNoise bonus — actively scanned in the wild
        if enrichment.is_being_scanned:
            score += 10

        score = max(0, min(100, score))
        return score, _score_to_label(score)

    async def process_cve(self, raw: RawCVE) -> ProcessedCVE:
        """Full pipeline: enrich → score → AI explain → ProcessedCVE."""
        enrichment = await self._build_enrichment(raw)
        priority_score, priority_label = self.calculate_priority(raw, enrichment)

        ai_explanation = None
        if priority_score >= THRESHOLD_AI_EXPLAIN or enrichment.in_kev:
            try:
                ai_explanation = await self.explainer.explain_cve(
                    raw, enrichment, priority_label=priority_label
                )
            except Exception as e:
                logger.debug(f"AI explanation skipped for {raw.cve_id}: {e}")

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
        )

    async def process_cve_with_epss(
        self, raw: RawCVE, epss_map: dict[str, dict]
    ) -> ProcessedCVE:
        """Process a single CVE using a pre-fetched EPSS map."""
        enrichment = await self._build_enrichment(raw, epss_map=epss_map)
        priority_score, priority_label = self.calculate_priority(raw, enrichment)

        ai_explanation = None
        if priority_score >= THRESHOLD_AI_EXPLAIN or enrichment.in_kev:
            try:
                ai_explanation = await self.explainer.explain_cve(
                    raw, enrichment, priority_label=priority_label
                )
            except Exception as e:
                logger.debug(f"AI explanation skipped for {raw.cve_id}: {e}")

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
                priority_score, priority_label = self.calculate_priority(raw, enrichment)

                ai_explanation = None
                if priority_score >= THRESHOLD_AI_EXPLAIN or enrichment.in_kev:
                    try:
                        ai_explanation = await self.explainer.explain_cve(
                            raw, enrichment, priority_label=priority_label
                        )
                    except Exception as e:
                        logger.debug(f"AI explanation skipped for {raw.cve_id}: {e}")

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
        # KEV check
        in_kev = self.kev.is_in_kev(cve.cve_id)

        # EPSS
        if epss_map is not None:
            epss_data = epss_map.get(cve.cve_id)
        else:
            epss_data = await self.epss.get_score(cve.cve_id)

        epss_score = epss_data["epss_score"] if epss_data else 0.0
        epss_percentile = epss_data["percentile"] if epss_data else 0.0

        # GitHub PoCs
        poc_urls: list[str] = []
        try:
            poc_urls = await self.github.search_pocs(cve.cve_id)
        except Exception as e:
            logger.debug(f"GitHub PoC search failed for {cve.cve_id}: {e}")

        # GreyNoise — live scanning activity
        greynoise_data = {"scanner_count": 0, "is_being_scanned": False}
        try:
            greynoise_data = await self.greynoise.get_scanning_activity(cve.cve_id)
        except Exception as e:
            logger.debug(f"GreyNoise lookup failed for {cve.cve_id}: {e}")

        return EnrichmentData(
            in_kev=in_kev,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            poc_urls=poc_urls,
            has_poc=len(poc_urls) > 0,
            greynoise_scanner_count=greynoise_data["scanner_count"],
            is_being_scanned=greynoise_data["is_being_scanned"],
        )
