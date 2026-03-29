"""Enrichment services — CISA KEV, EPSS scores, GitHub PoC/advisory search."""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

KEV_URL = settings.KEV_URL
EPSS_URL = settings.EPSS_BASE_URL


# ── CISA KEV ──────────────────────────────────────────────────────────────────

class CISAKEVService:
    """Loads and caches the CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self) -> None:
        self._kev_ids: set[str] = set()

    @property
    def catalog_size(self) -> int:
        return len(self._kev_ids)

    async def load_catalog(self) -> None:
        """Fetch the full KEV JSON and cache CVE IDs in memory."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(KEV_URL)
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                self._kev_ids = {v.get("cveID", "") for v in vulns if v.get("cveID")}
                logger.info(f"Loaded {len(self._kev_ids)} CVEs from CISA KEV catalog")
        except Exception as e:
            logger.error(f"Failed to load KEV catalog: {e}")

    def is_in_kev(self, cve_id: str) -> bool:
        return cve_id in self._kev_ids


# ── EPSS ──────────────────────────────────────────────────────────────────────

class EPSSService:
    """Queries the FIRST.org EPSS API for exploit-probability scores."""

    async def get_scores(self, cve_ids: list[str]) -> dict[str, dict]:
        """Batch-fetch EPSS scores. Returns {cve_id: {"epss_score": float, "percentile": float}}."""
        if not cve_ids:
            return {}
        results: dict[str, dict] = {}
        chunk_size = 100
        async with httpx.AsyncClient(timeout=30.0) as client:
            for i in range(0, len(cve_ids), chunk_size):
                chunk = cve_ids[i : i + chunk_size]
                try:
                    resp = await client.get(EPSS_URL, params={"cve": ",".join(chunk)})
                    resp.raise_for_status()
                    for entry in resp.json().get("data", []):
                        cve_id = entry.get("cve", "")
                        if cve_id:
                            results[cve_id] = {
                                "epss_score": float(entry.get("epss", 0.0)),
                                "percentile": float(entry.get("percentile", 0.0)),
                            }
                except Exception as e:
                    logger.error(f"EPSS API error for chunk {i}: {e}")
        return results

    async def get_score(self, cve_id: str) -> Optional[dict]:
        """Get EPSS data for a single CVE."""
        results = await self.get_scores([cve_id])
        return results.get(cve_id)


# ── GitHub PoC / Advisory Search ──────────────────────────────────────────────

class GitHubAdvisoryService:
    """Searches GitHub for proof-of-concept repos and security advisories."""

    def __init__(self) -> None:
        self.token = settings.GITHUB_TOKEN

    async def search_pocs(self, cve_id: str) -> list[str]:
        """Return URLs of GitHub repos / advisories related to a CVE."""
        urls: list[str] = []

        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        async with httpx.AsyncClient(timeout=20.0) as client:
            # 1. Repository search
            try:
                resp = await client.get(
                    "https://api.github.com/search/repositories",
                    params={"q": cve_id, "sort": "updated", "per_page": 5},
                    headers=headers,
                )
                if resp.status_code == 200:
                    for item in resp.json().get("items", []):
                        html_url = item.get("html_url", "")
                        if html_url:
                            urls.append(html_url)
            except Exception as e:
                logger.debug(f"GitHub repo search error for {cve_id}: {e}")

            # 2. Security advisory search
            try:
                resp = await client.get(
                    "https://api.github.com/advisories",
                    params={"cve_id": cve_id, "per_page": 5},
                    headers=headers,
                )
                if resp.status_code == 200:
                    for item in resp.json():
                        html_url = item.get("html_url", "")
                        if html_url and html_url not in urls:
                            urls.append(html_url)
            except Exception as e:
                logger.debug(f"GitHub advisory search error for {cve_id}: {e}")

        return urls


# ── GreyNoise — Live Exploitation Activity ────────────────────────────────────

class GreyNoiseService:
    """Checks GreyNoise for live scanning/exploitation activity on CVEs."""

    COMMUNITY_URL = "https://api.greynoise.io/v3/community"

    def __init__(self) -> None:
        self.api_key = settings.GREYNOISE_API_KEY
        self._cache: dict[str, tuple[dict, float]] = {}  # cve_id -> (result, timestamp)
        self._cache_ttl = 3600  # 1 hour

    async def get_scanning_activity(self, cve_id: str) -> dict:
        """Return {scanner_count: int, is_being_scanned: bool} for a CVE."""
        import time

        # Check cache
        if cve_id in self._cache:
            result, ts = self._cache[cve_id]
            if time.time() - ts < self._cache_ttl:
                return result

        default = {"scanner_count": 0, "is_being_scanned": False}

        if not self.api_key:
            return default

        try:
            headers = {"Accept": "application/json", "key": self.api_key}
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self.COMMUNITY_URL}/{cve_id}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    count = data.get("count", 0) if isinstance(data, dict) else 0
                    result = {
                        "scanner_count": count,
                        "is_being_scanned": count > 0,
                    }
                elif resp.status_code == 404:
                    # Not found in GreyNoise — no scanners
                    result = default
                else:
                    logger.debug(f"GreyNoise {resp.status_code} for {cve_id}")
                    result = default
        except Exception as e:
            logger.debug(f"GreyNoise lookup failed for {cve_id}: {e}")
            result = default

        self._cache[cve_id] = (result, time.time())
        return result

