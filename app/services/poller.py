"""APScheduler-based poll loop — orchestrates each CVE fetch cycle."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.core.config import settings
from app.models.cve import ProcessedCVE
from app.services.nvd_client import NVDClient
from app.services.triage import TriageEngine

logger = logging.getLogger(__name__)


class CVEPoller:
    """Periodically fetches new CVEs, deduplicates, and processes them."""

    def __init__(self, triage_engine: TriageEngine) -> None:
        self.triage = triage_engine
        self.scheduler = AsyncIOScheduler()
        self.nvd_client = NVDClient()

        # In-memory state
        self._seen_ids: set[str] = set()
        self._processed_cves: list[ProcessedCVE] = []
        self._last_poll: datetime | None = None
        self._poll_count: int = 0

        # Callback set by the Telegram bot to receive new alerts
        self._alert_callback = None
        # Optional breaking-threat callback (bypasses mode filter)
        self._breaking_threat_callback = None
        # Database service (optional — set by main.py)
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
        """Register an async callback(processed_cve) for new high-priority CVEs."""
        self._alert_callback = callback

    def set_breaking_threat_callback(self, callback) -> None:
        """Register callback for CRITICAL + KEV breaking threats."""
        self._breaking_threat_callback = callback

    def set_database(self, db) -> None:
        """Set the Supabase service for persistence."""
        self._db = db

    # ── lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Schedule the poll job and KEV sweep, then start the scheduler."""
        interval = settings.POLL_INTERVAL_MINUTES
        self.scheduler.add_job(
            self.poll_cycle,
            "interval",
            minutes=interval,
            id="cve_poll",
            replace_existing=True,
        )
        # Weekly KEV sweep — Sundays at 00:00 UTC
        self.scheduler.add_job(
            self.kev_sweep,
            "cron",
            day_of_week="sun",
            hour=0,
            minute=0,
            id="kev_sweep",
            replace_existing=True,
        )
        self.scheduler.start()
        logger.info(f"CVE poller started — polling every {interval} minutes + weekly KEV sweep")

    def stop(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("CVE poller stopped")

    # ── poll cycle ────────────────────────────────────────────────────────

    async def poll_cycle(self) -> dict:
        """Run one full poll: fetch → deduplicate → triage → alert."""
        logger.info("Starting poll cycle…")
        self._poll_count += 1
        self._last_poll = datetime.now(timezone.utc)
        errors: list[str] = []
        alerts_sent = 0
        processed_count = 0

        # 1. Fetch — first poll looks back 24h to catch up; subsequent polls 4h
        try:
            lookback = 24 if self._poll_count == 1 else 4
            raw_cves = await self.nvd_client.fetch_recent_cves(hours_back=lookback)
        except Exception as e:
            msg = f"NVD fetch error: {e}"
            logger.error(msg)
            return {"new_cves_found": 0, "cves_processed": 0, "alerts_sent": 0, "errors": [msg]}

        # 2. Deduplicate
        new_raws = [r for r in raw_cves if r.cve_id not in self._seen_ids]
        logger.info(f"Poll #{self._poll_count}: {len(raw_cves)} fetched, {len(new_raws)} new")

        if not new_raws:
            return {"new_cves_found": 0, "cves_processed": 0, "alerts_sent": 0, "errors": []}

        # 3. Batch EPSS fetch (non-fatal)
        cve_ids = [r.cve_id for r in new_raws]
        try:
            epss_map = await self.triage.epss.get_scores(cve_ids)
        except Exception as e:
            logger.warning(f"Batch EPSS fetch failed: {e}")
            epss_map = {}

        # 4. Process each CVE individually and store IMMEDIATELY
        for raw in new_raws:
            try:
                pcve = await self.triage.process_cve_with_epss(raw, epss_map)
                self._seen_ids.add(pcve.cve_id)
                self._processed_cves.append(pcve)
                processed_count += 1

                # Fire-and-forget DB save
                if self._db:
                    asyncio.create_task(self._db.save_cve(pcve))

                # Breaking threat broadcast (CRITICAL + KEV) — bypasses mode
                if (
                    self._breaking_threat_callback
                    and pcve.priority_score >= 75
                    and pcve.enrichment.in_kev
                ):
                    try:
                        await self._breaking_threat_callback(pcve)
                    except Exception as e:
                        logger.error(f"Breaking threat alert error for {pcve.cve_id}: {e}")

                # Regular alert broadcast
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

        logger.info(f"Poll #{self._poll_count} done: {processed_count}/{len(new_raws)} processed, {alerts_sent} alerts")
        return {
            "new_cves_found": len(new_raws),
            "cves_processed": processed_count,
            "alerts_sent": alerts_sent,
            "errors": errors,
        }

    # ── weekly KEV sweep ──────────────────────────────────────────────────

    async def kev_sweep(self) -> None:
        """Re-fetch CISA KEV catalog and process any CVEs not yet seen."""
        logger.info("Starting weekly KEV sweep…")
        try:
            await self.triage.kev.load_catalog()
            kev_ids = list(self.triage.kev._kev_ids)
            new_kev = [kid for kid in kev_ids if kid not in self._seen_ids]
            logger.info(f"KEV sweep: {len(kev_ids)} total, {len(new_kev)} unseen")

            if not new_kev:
                return

            # Fetch details from NVD for unseen KEV CVEs (in batches of 20)
            for i in range(0, len(new_kev), 20):
                batch = new_kev[i:i + 20]
                for cve_id in batch:
                    try:
                        raw_cves = await self.nvd_client.fetch_cve_by_id(cve_id)
                        if raw_cves:
                            pcve = await self.triage.process_cve(raw_cves)
                            self._seen_ids.add(pcve.cve_id)
                            self._processed_cves.append(pcve)
                            if self._db:
                                asyncio.create_task(self._db.save_cve(pcve))
                    except Exception as e:
                        logger.error(f"KEV sweep error for {cve_id}: {e}")

            logger.info("KEV sweep complete")
        except Exception as e:
            logger.error(f"KEV sweep failed: {e}")
