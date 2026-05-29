"""NVD API v2 client — fetches and parses recent CVEs."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from app.core.config import settings
from app.models.cve import RawCVE

logger = logging.getLogger(__name__)


class NVDClient:
    """Async client for the NVD CVE API v2."""

    def __init__(self) -> None:
        self.base_url = settings.NVD_BASE_URL
        self.api_key = settings.NVD_API_KEY

    # ── public ────────────────────────────────────────────────────────────

    async def fetch_recent_cves(self, hours_back: int = 4) -> list[RawCVE]:
        """Return CVEs published OR modified in the last *hours_back* hours.

        Runs two NVD queries (by lastMod, then by pub date) and deduplicates
        so freshly published CVEs are never missed.
        """
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours_back)
        start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        seen_ids: set[str] = set()
        all_cves: list[RawCVE] = []

        # Query 1: recently MODIFIED CVEs
        await self._paginated_fetch(
            headers,
            {"lastModStartDate": start_str, "lastModEndDate": end_str},
            all_cves,
            seen_ids,
        )

        # Query 2: recently PUBLISHED CVEs (catches brand-new ones)
        await self._paginated_fetch(
            headers,
            {"pubStartDate": start_str, "pubEndDate": end_str},
            all_cves,
            seen_ids,
        )

        logger.info(
            f"Fetched {len(all_cves)} unique CVEs from NVD (last {hours_back}h)"
        )
        return all_cves

    async def fetch_cve_by_id(self, cve_id: str) -> Optional[RawCVE]:
        """Fetch a single CVE by its ID. Returns None if not found."""
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    self.base_url,
                    params={"cveId": cve_id},
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    return self._parse_vuln(vulns[0])
        except Exception as e:
            logger.error(f"NVD fetch_cve_by_id error for {cve_id}: {e}")
        return None

    # ── pagination helper ─────────────────────────────────────────────────

    async def _paginated_fetch(
        self,
        headers: dict[str, str],
        date_params: dict[str, str],
        out: list[RawCVE],
        seen: set[str],
    ) -> None:
        """Fetch all pages for a single NVD query and append unique results."""
        params: dict[str, object] = {
            **date_params,
            "resultsPerPage": 100,
            "startIndex": 0,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                try:
                    resp = await client.get(
                        self.base_url, params=params, headers=headers
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as e:
                    logger.error(f"NVD API error: {e}")
                    break

                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break
                    
                for item in vulns:
                    raw = self._parse_vuln(item)
                    if raw and raw.cve_id not in seen:
                        seen.add(raw.cve_id)
                        out.append(raw)

                total = data.get("totalResults", 0)
                fetched = int(params["startIndex"]) + len(vulns)  # type: ignore[arg-type]
                if fetched >= total:
                    break
                params["startIndex"] = fetched

    # ── parsing ───────────────────────────────────────────────────────────

    @staticmethod
    def _parse_vuln(item: dict) -> Optional[RawCVE]:
        """Parse a single NVD vulnerability object into a RawCVE."""
        try:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # Description (English preferred)
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # CVSS — try 3.1 → 3.0 → 2.0
            cvss_score = 0.0
            cvss_vector = ""
            cvss_version = ""
            metrics = cve_data.get("metrics", {})
            for ver_key, ver_label in [
                ("cvssMetricV31", "3.1"),
                ("cvssMetricV30", "3.0"),
                ("cvssMetricV2", "2.0"),
            ]:
                metric_list = metrics.get(ver_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_vector = cvss_data.get("vectorString", "")
                    cvss_version = ver_label
                    break

            # References
            refs = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")]

            # Weaknesses
            weaknesses: list[str] = []
            for w in cve_data.get("weaknesses", []):
                for desc in w.get("description", []):
                    val = desc.get("value", "")
                    if val and val != "NVD-CWE-noinfo":
                        weaknesses.append(val)

            # Dates
            published = cve_data.get("published")
            modified = cve_data.get("lastModified")

            return RawCVE(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cvss_version=cvss_version,
                published_date=datetime.fromisoformat(published) if published else None,
                last_modified=datetime.fromisoformat(modified) if modified else None,
                references=refs,
                weaknesses=weaknesses,
            )
        except Exception as e:
            logger.warning(f"Failed to parse CVE item: {e}")
            return None
