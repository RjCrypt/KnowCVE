"""APScheduler-based poll loop — three independent jobs for CVE lifecycle management."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.core.config import settings
from app.models.cve import ProcessedCVE, EnrichmentData
from app.services.nvd_client import NVDClient
from app.services.triage import TriageEngine
from app.services.exploit_intel import ExploitIntelligenceOrchestrator

logger = logging.getLogger(__name__)


class CVEPoller:
    """Three-job polling architecture for CVE fetching, enrichment, and trending."""

    def __init__(self, triage_engine: TriageEngine) -> None:
        self.triage = triage_engine
        self.scheduler = AsyncIOScheduler()
        self.nvd_client = NVDClient()
        self.exploit_intel = ExploitIntelligenceOrchestrator()

        # In-memory state
        self._seen_ids: set[str] = set()
        self._processed_cves: list[ProcessedCVE] = []
        self._last_poll: datetime | None = None
        self._poll_count: int = 0

        # Callbacks
        self._alert_callback = None
        self._breaking_threat_callback = None
        self._db = None

    # ── state accessors ───────────────────────────────────────────────────

    @property
    def processed_cves(self) -> list[ProcessedCVE]:
        return list(self._processed_cves)

    @property
    def last_poll_time(self) -> datetime | None:
        return self._last_poll

    @property
    def total_processed(self) -> int:
        return len(self._processed_cves)

    def get_cve(self, cve_id: str) -> ProcessedCVE | None:
        for cve in self._processed_cves:
            if cve.cve_id == cve_id:
                return cve
        return None

    def set_alert_callback(self, callback) -> None:
        self._alert_callback = callback

    def set_breaking_threat_callback(self, callback) -> None:
        self._breaking_threat_callback = callback

    def set_database(self, db) -> None:
        self._db = db

    # ── lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Register three independent scheduler jobs and start."""
        interval = settings.POLL_INTERVAL_MINUTES

        # Job 1: Fresh CVEs (every 15 min)
        self.scheduler.add_job(
            self.fresh_cves_job,
            "interval",
            minutes=interval,
            id="fresh_cves",
            replace_existing=True,
            max_instances=1,
        )

        # Job 2: Enrichment sweep (every 6 hours)
        self.scheduler.add_job(
            self.enrichment_sweep_job,
            "interval",
            hours=6,
            id="enrichment_sweep",
            replace_existing=True,
            max_instances=1,
        )

        # Job 3: Trending refresh (every 1 hour)
        self.scheduler.add_job(
            self.trending_refresh_job,
            "interval",
            hours=1,
            id="trending_refresh",
            replace_existing=True,
            max_instances=1,
        )

        # Job 4: ExploitDB refresh (every 24 hours)
        self.scheduler.add_job(
            self.exploit_intel.refresh_exploitdb_if_stale,
            "interval",
            hours=24,
            id="exploitdb_refresh",
            replace_existing=True,
            max_instances=1,
        )

        self.scheduler.start()

        # Initialize ExploitDB CSV in background
        asyncio.ensure_future(self._init_exploit_intel())

        logger.info(
            f"CVE poller started — fresh every {interval}min, "
            f"enrichment sweep every 6h, trending refresh every 1h, "
            f"ExploitDB refresh every 24h"
        )

    async def _init_exploit_intel(self) -> None:
        """Initialize ExploitDB data at startup."""
        try:
            await self.exploit_intel.initialize()
        except Exception as e:
            logger.warning(f"ExploitDB initialization failed (non-fatal): {e}")

    def stop(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("CVE poller stopped")

    # ══════════════════════════════════════════════════════════════════════
    # Job 1 — FRESH CVEs (replaces old poll_cycle)
    # ══════════════════════════════════════════════════════════════════════

    async def fresh_cves_job(self) -> dict:
        """Fetch new CVEs, triage, enrich, explain, alert."""
        logger.info("🔄 Starting fresh CVEs job…")
        self._poll_count += 1
        self._last_poll = datetime.now(timezone.utc)
        errors: list[str] = []
        alerts_sent = 0
        processed_count = 0

        # Wider window: 3h (first poll 24h to catch up)
        try:
            lookback = 24 if self._poll_count == 1 else 3
            raw_cves = await self.nvd_client.fetch_recent_cves(hours_back=lookback)
        except Exception as e:
            msg = f"NVD fetch error: {e}"
            logger.error(msg)
            return {"new_cves_found": 0, "cves_processed": 0, "alerts_sent": 0, "errors": [msg]}

        # Deduplicate
        new_raws = [r for r in raw_cves if r.cve_id not in self._seen_ids]
        logger.info(f"Fresh #{self._poll_count}: {len(raw_cves)} fetched, {len(new_raws)} new")

        if not new_raws:
            return {"new_cves_found": 0, "cves_processed": 0, "alerts_sent": 0, "errors": []}

        # Batch EPSS
        cve_ids = [r.cve_id for r in new_raws]
        try:
            epss_map = await self.triage.epss.get_scores(cve_ids)
        except Exception as e:
            logger.warning(f"Batch EPSS fetch failed: {e}")
            epss_map = {}

        # Process each CVE
        for raw in new_raws:
            try:
                pcve = await self.triage.process_cve_with_epss(raw, epss_map)
                self._seen_ids.add(pcve.cve_id)
                self._processed_cves.append(pcve)
                processed_count += 1

                # Save to DB
                if self._db:
                    asyncio.create_task(self._db.save_cve(pcve))

                # Breaking threat (CRITICAL + KEV)
                if (
                    self._breaking_threat_callback
                    and pcve.priority_score >= 75
                    and pcve.enrichment.in_kev
                ):
                    try:
                        await self._breaking_threat_callback(pcve)
                    except Exception as e:
                        logger.error(f"Breaking threat alert error for {pcve.cve_id}: {e}")

                # Regular alert
                if self._alert_callback and pcve.priority_score >= 25:
                    try:
                        await self._alert_callback(pcve)
                        alerts_sent += 1
                    except Exception as e:
                        msg = f"Alert error for {pcve.cve_id}: {e}"
                        logger.error(msg)
                        errors.append(msg)
            except Exception as e:
                logger.error(f"Failed to process {raw.cve_id}: {e}")
                self._seen_ids.add(raw.cve_id)
                continue

        logger.info(f"Fresh #{self._poll_count} done: {processed_count}/{len(new_raws)} processed, {alerts_sent} alerts")

        # Gather exploit intelligence for HIGH+ CVEs in background
        for pcve in self._processed_cves[-processed_count:]:
            if pcve.priority_score >= 50 or pcve.enrichment.in_kev:
                asyncio.create_task(self._gather_and_save_exploit_intel(pcve))

        return {
            "new_cves_found": len(new_raws),
            "cves_processed": processed_count,
            "alerts_sent": alerts_sent,
            "errors": errors,
        }

    async def _gather_and_save_exploit_intel(self, cve: ProcessedCVE) -> None:
        """Gather exploit intel for a single CVE and save to DB."""
        try:
            intel = await self.exploit_intel.gather(
                cve_id=cve.cve_id,
                poc_urls=cve.enrichment.poc_urls,
                has_nuclei=cve.enrichment.has_nuclei_template,
                nuclei_template_url=cve.enrichment.nuclei_template_url,
                in_kev=cve.enrichment.in_kev,
                is_being_scanned=cve.enrichment.is_being_scanned,
                greynoise_count=cve.enrichment.greynoise_scanner_count,
            )
            if self._db:
                await self._db.save_exploit_intel(intel)
            logger.info(f"🔫 Exploit intel for {cve.cve_id}: EMS {intel.ems_score} ({intel.ems_label})")
        except Exception as e:
            logger.error(f"Exploit intel failed for {cve.cve_id}: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # Job 2 — ENRICHMENT SWEEP (re-fetch CVEs with missing CVSS)
    # ══════════════════════════════════════════════════════════════════════

    async def enrichment_sweep_job(self) -> None:
        """Re-fetch CVEs with missing/zero CVSS from NVD and re-score."""
        logger.info("🔍 Starting enrichment sweep…")
        if not self._db or not self._db.is_configured:
            logger.info("Enrichment sweep skipped — no database configured")
            return

        try:
            unscored_ids = await self._db.get_unscored_cves(days_back=14)
        except Exception as e:
            logger.error(f"Enrichment sweep — failed to query unscored CVEs: {e}")
            return

        if not unscored_ids:
            logger.info("Enrichment sweep: no unscored CVEs found")
            return

        logger.info(f"Enrichment sweep: {len(unscored_ids)} CVEs to re-check")
        updated = 0

        for cve_id in unscored_ids:
            try:
                # Get current record for comparison
                existing = await self._db.get_cve(cve_id)
                old_score = existing.priority_score if existing else 0
                old_label = existing.priority_label if existing else "LOW"

                # Re-fetch from NVD
                raw = await self.nvd_client.fetch_cve_by_id(cve_id)
                if not raw:
                    continue

                # Skip if CVSS still missing
                if raw.cvss_score == 0:
                    continue

                # Re-enrich and re-score
                enrichment = await self.triage._build_enrichment(raw)

                # Carry forward previous trend data
                if existing and existing.enrichment:
                    enrichment.previous_epss_score = existing.enrichment.epss_score
                    enrichment.previous_scanner_count = existing.enrichment.greynoise_scanner_count

                new_score, new_label, categories = self.triage.calculate_priority(
                    raw, enrichment,
                    previous_epss=enrichment.previous_epss_score,
                    previous_scanner_count=enrichment.previous_scanner_count,
                )

                dynamic_score = max(0, new_score - int(
                    ((raw.cvss_score / 10.0) * 35 if raw.cvss_score > 0 else 10)
                    + enrichment.epss_score * 25
                    + (20 if enrichment.in_kev else 0)
                    + (15 if enrichment.has_poc else 0)
                ))

                # Update DB
                now = datetime.now(timezone.utc)
                await self._db.update_cve_score(
                    cve_id=cve_id,
                    priority_score=new_score,
                    priority_label=new_label,
                    categories=categories,
                    dynamic_score=dynamic_score,
                    enrichment=enrichment,
                    last_rescored_at=now,
                )
                updated += 1

                # Update in-memory cache
                for i, pcve in enumerate(self._processed_cves):
                    if pcve.cve_id == cve_id:
                        self._processed_cves[i].priority_score = new_score
                        self._processed_cves[i].priority_label = new_label
                        self._processed_cves[i].categories = categories
                        self._processed_cves[i].dynamic_score = dynamic_score
                        self._processed_cves[i].enrichment = enrichment
                        self._processed_cves[i].cvss_score = raw.cvss_score
                        self._processed_cves[i].last_rescored_at = now
                        break

                # Re-broadcast if score jumped >= 20
                score_jump = new_score - old_score
                if score_jump >= 20 and self._alert_callback:
                    logger.info(f"⬆️ {cve_id} priority upgraded: {old_label} → {new_label} (+{score_jump})")
                    if existing:
                        existing.priority_score = new_score
                        existing.priority_label = new_label
                        existing.categories = categories
                        try:
                            await self._alert_callback(existing)
                        except Exception as e:
                            logger.error(f"Re-broadcast alert error for {cve_id}: {e}")

                await asyncio.sleep(0.5)  # rate limit NVD

            except Exception as e:
                logger.error(f"Enrichment sweep error for {cve_id}: {e}")
                continue

        logger.info(f"Enrichment sweep done: {updated}/{len(unscored_ids)} CVEs updated")

    # ══════════════════════════════════════════════════════════════════════
    # Job 3 — TRENDING REFRESH (KEV re-check + GreyNoise + re-score)
    # ══════════════════════════════════════════════════════════════════════

    async def trending_refresh_job(self) -> None:
        """Re-check KEV, GreyNoise, and recalculate scores for top CVEs."""
        logger.info("📈 Starting trending refresh…")
        if not self._db or not self._db.is_configured:
            logger.info("Trending refresh skipped — no database configured")
            return

        # Step 1: Re-load KEV catalog
        try:
            await self.triage.kev.load_catalog()
            logger.info("KEV catalog refreshed")
        except Exception as e:
            logger.warning(f"KEV refresh failed (non-fatal): {e}")

        # Step 2: Get top 50 CVEs for re-scoring
        try:
            top_cves = await self._db.get_cves_for_refresh(limit=50)
        except Exception as e:
            logger.error(f"Trending refresh — failed to get CVEs: {e}")
            return

        if not top_cves:
            logger.info("Trending refresh: no CVEs to refresh")
            return

        logger.info(f"Trending refresh: re-scoring {len(top_cves)} CVEs")
        updated = 0

        for pcve in top_cves:
            try:
                old_score = pcve.priority_score
                old_in_kev = pcve.enrichment.in_kev

                # Save previous values for trend detection
                prev_epss = pcve.enrichment.epss_score
                prev_scanner = pcve.enrichment.greynoise_scanner_count

                # Re-check KEV
                new_in_kev = self.triage.kev.is_in_kev(pcve.cve_id)

                # Re-check GreyNoise
                greynoise_data = {"scanner_count": 0, "is_being_scanned": False}
                try:
                    greynoise_data = await self.triage.greynoise.get_scanning_activity(pcve.cve_id)
                except Exception:
                    pass

                # Build updated enrichment
                enrichment = pcve.enrichment.model_copy()
                enrichment.previous_epss_score = prev_epss
                enrichment.previous_scanner_count = prev_scanner
                enrichment.in_kev = new_in_kev
                enrichment.greynoise_scanner_count = greynoise_data["scanner_count"]
                enrichment.is_being_scanned = greynoise_data["is_being_scanned"]

                # Compute trends
                if enrichment.greynoise_scanner_count > prev_scanner * 1.5 and prev_scanner > 0:
                    enrichment.scanner_trend = "rising"
                elif enrichment.greynoise_scanner_count < prev_scanner * 0.5 and prev_scanner > 0:
                    enrichment.scanner_trend = "falling"
                elif prev_scanner == 0 and enrichment.greynoise_scanner_count > 0:
                    enrichment.scanner_trend = "new"
                else:
                    enrichment.scanner_trend = "stable"

                if enrichment.epss_score > prev_epss + 0.05:
                    enrichment.epss_trend = "rising"
                elif enrichment.epss_score < prev_epss - 0.05:
                    enrichment.epss_trend = "falling"
                else:
                    enrichment.epss_trend = "stable"

                # Build a temporary RawCVE for re-scoring
                from app.models.cve import RawCVE
                raw_proxy = RawCVE(
                    cve_id=pcve.cve_id,
                    description=pcve.description,
                    cvss_score=pcve.cvss_score,
                    cvss_vector=getattr(pcve, "cvss_vector", ""),
                    cvss_version=getattr(pcve, "cvss_version", ""),
                    published_date=pcve.published_date,
                    last_modified=pcve.last_modified,
                    weaknesses=pcve.weaknesses,
                )

                new_score, new_label, categories = self.triage.calculate_priority(
                    raw_proxy, enrichment,
                    previous_epss=prev_epss,
                    previous_scanner_count=prev_scanner,
                )

                dynamic_score = max(0, new_score - int(
                    ((pcve.cvss_score / 10.0) * 35 if pcve.cvss_score > 0 else 10)
                    + enrichment.epss_score * 25
                    + (20 if enrichment.in_kev else 0)
                    + (15 if enrichment.has_poc else 0)
                ))

                # Only update if something changed
                if (
                    new_score != old_score
                    or categories != pcve.categories
                    or enrichment.scanner_trend != "stable"
                    or enrichment.epss_trend != "stable"
                    or new_in_kev != old_in_kev
                ):
                    now = datetime.now(timezone.utc)
                    await self._db.update_cve_score(
                        cve_id=pcve.cve_id,
                        priority_score=new_score,
                        priority_label=new_label,
                        categories=categories,
                        dynamic_score=dynamic_score,
                        enrichment=enrichment,
                        last_rescored_at=now,
                    )
                    updated += 1

                    # Update in-memory
                    for i, cached in enumerate(self._processed_cves):
                        if cached.cve_id == pcve.cve_id:
                            self._processed_cves[i].priority_score = new_score
                            self._processed_cves[i].priority_label = new_label
                            self._processed_cves[i].categories = categories
                            self._processed_cves[i].dynamic_score = dynamic_score
                            self._processed_cves[i].enrichment = enrichment
                            self._processed_cves[i].last_rescored_at = now
                            break

                    # Newly in KEV and score jumped >= 15: breaking threat alert
                    score_jump = new_score - old_score
                    if (
                        not old_in_kev and new_in_kev
                        and score_jump >= 15
                        and self._breaking_threat_callback
                    ):
                        logger.info(f"🚨 {pcve.cve_id} newly in KEV — breaking threat alert")
                        pcve.priority_score = new_score
                        pcve.priority_label = new_label
                        pcve.categories = categories
                        try:
                            await self._breaking_threat_callback(pcve)
                        except Exception as e:
                            logger.error(f"Breaking threat re-alert error for {pcve.cve_id}: {e}")

                await asyncio.sleep(0.3)  # rate limit

            except Exception as e:
                logger.error(f"Trending refresh error for {pcve.cve_id}: {e}")
                continue

        logger.info(f"Trending refresh done: {updated}/{len(top_cves)} CVEs updated")

    # ── Legacy compatibility ──────────────────────────────────────────────

    async def poll_cycle(self) -> dict:
        """Legacy alias — delegates to fresh_cves_job."""
        return await self.fresh_cves_job()
