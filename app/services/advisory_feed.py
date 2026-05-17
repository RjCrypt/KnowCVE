"""
Advisory Feed Service — GitHub Advisory Database + OSV.dev
==========================================================
Polls ecosystem-specific advisory sources to catch supply chain attacks
and malware packages that the NVD misses or publishes days late.

Sources:
  1. GitHub Advisory Database (GET /advisories)
     - Filtered by ecosystem (npm, PyPI, Go, etc.)
     - Includes `type=malware` for supply chain attack detection
     - Requires GITHUB_TOKEN for higher rate limits (5k/hr vs 60/hr)

  2. OSV.dev (POST /v1/query)
     - No API key, no rate limits
     - Covers npm, PyPI, Go, Rust, Maven, NuGet, and more
     - Used as enrichment + fallback when GHSA misses something
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from app.core.config import settings
from app.models.cve import AdvisoryRecord

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Ecosystems to monitor — expand as needed
MONITORED_ECOSYSTEMS = ["npm", "pip", "go"]

# GitHub Advisory DB uses different ecosystem names than OSV
GITHUB_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pip": "pip",
    "go": "go",
}

OSV_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pip": "PyPI",
    "go": "Go",
}


# ── GitHub Advisory Database Service ──────────────────────────────────────────

class GitHubAdvisoryFeedService:
    """Fetches security advisories from the GitHub Advisory Database REST API."""

    def __init__(self) -> None:
        self.token = settings.GITHUB_TOKEN

    async def fetch_advisories(
        self,
        ecosystem: str = "npm",
        hours_back: int = 6,
        include_malware: bool = True,
    ) -> list[AdvisoryRecord]:
        """Fetch recent advisories for an ecosystem.

        Runs two queries:
          1. type=reviewed — standard CVE advisories
          2. type=malware — supply chain / malicious package advisories
        """
        now = datetime.now(timezone.utc)
        since = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")

        gh_ecosystem = GITHUB_ECOSYSTEM_MAP.get(ecosystem, ecosystem)

        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        all_advisories: list[AdvisoryRecord] = []
        seen_ghsa: set[str] = set()

        # Query 1: Reviewed advisories (standard CVE-backed)
        await self._fetch_type(
            headers, gh_ecosystem, "reviewed", since,
            all_advisories, seen_ghsa, ecosystem,
        )

        # Query 2: Malware advisories (supply chain attacks)
        if include_malware:
            await self._fetch_type(
                headers, gh_ecosystem, "malware", since,
                all_advisories, seen_ghsa, ecosystem,
            )

        logger.info(
            f"GitHub Advisory: {len(all_advisories)} advisories for "
            f"{ecosystem} (last {hours_back}h)"
        )
        return all_advisories

    async def _fetch_type(
        self,
        headers: dict,
        gh_ecosystem: str,
        advisory_type: str,
        since: str,
        out: list[AdvisoryRecord],
        seen: set[str],
        ecosystem: str,
    ) -> None:
        """Paginate through one advisory type (reviewed or malware)."""
        params: dict = {
            "ecosystem": gh_ecosystem,
            "type": advisory_type,
            "updated": f">{since}",
            "per_page": 30,
            "sort": "updated",
            "direction": "desc",
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            for page in range(1, 4):  # Max 3 pages = 90 advisories
                params["page"] = page
                try:
                    resp = await client.get(
                        GITHUB_ADVISORIES_URL,
                        params=params,
                        headers=headers,
                    )

                    if resp.status_code == 403:
                        logger.warning("GitHub Advisory API rate limited — skipping")
                        break
                    if resp.status_code != 200:
                        logger.warning(
                            f"GitHub Advisory API {resp.status_code}: {resp.text[:200]}"
                        )
                        break

                    items = resp.json()
                    if not items:
                        break

                    for item in items:
                        record = self._parse_advisory(item, ecosystem, advisory_type)
                        if record and record.ghsa_id not in seen:
                            seen.add(record.ghsa_id)
                            out.append(record)

                    # Stop if we got fewer than per_page (last page)
                    if len(items) < 30:
                        break

                except Exception as e:
                    logger.error(f"GitHub Advisory fetch error (page {page}): {e}")
                    break

    @staticmethod
    def _parse_advisory(
        item: dict, ecosystem: str, advisory_type: str
    ) -> Optional[AdvisoryRecord]:
        """Parse a single GitHub advisory JSON object."""
        try:
            ghsa_id = item.get("ghsa_id", "").upper()
            if not ghsa_id:
                return None

            # CVE ID — check top-level field first, then identifiers
            cve_id = item.get("cve_id")
            if cve_id:
                cve_id = cve_id.upper()
            else:
                for ident in item.get("identifiers", []):
                    if ident.get("type") == "CVE":
                        cve_id = ident.get("value", "").upper()
                        break

            # Extract affected packages
            affected_packages = []
            for vuln in item.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                version_range = vuln.get("vulnerable_version_range", "")
                first_patched = vuln.get("first_patched_version") or ""
                # first_patched_version can be a string or None
                if isinstance(first_patched, dict):
                    first_patched = first_patched.get("identifier", "")

                affected_packages.append({
                    "name": pkg.get("name", ""),
                    "ecosystem": pkg.get("ecosystem", ecosystem),
                    "version_range": version_range,
                    "patched_version": first_patched or "",
                })

            # References — GitHub returns these as plain URL strings
            raw_refs = item.get("references", [])
            refs = []
            for r in raw_refs:
                if isinstance(r, str) and r:
                    refs.append(r)
                elif isinstance(r, dict) and r.get("url"):
                    refs.append(r["url"])
            html_url = item.get("html_url", "")
            if html_url and html_url not in refs:
                refs.insert(0, html_url)

            # Dates
            published_at = None
            if item.get("published_at"):
                published_at = datetime.fromisoformat(
                    item["published_at"].replace("Z", "+00:00")
                )
            updated_at = None
            if item.get("updated_at"):
                updated_at = datetime.fromisoformat(
                    item["updated_at"].replace("Z", "+00:00")
                )

            return AdvisoryRecord(
                ghsa_id=ghsa_id,
                cve_id=cve_id,
                source="github",
                ecosystem=ecosystem,
                severity=item.get("severity", "unknown") or "unknown",
                summary=item.get("summary", "")[:500],
                description=(item.get("description") or "")[:2000],
                affected_packages=affected_packages,
                references=refs,
                published_at=published_at,
                updated_at=updated_at,
                is_malware=(advisory_type == "malware"),
                withdrawn=item.get("withdrawn_at") is not None,
            )
        except Exception as e:
            logger.warning(f"Failed to parse GitHub advisory: {e}")
            return None


# ── OSV.dev Service ───────────────────────────────────────────────────────────

class OSVFeedService:
    """Queries OSV.dev for ecosystem-specific vulnerabilities."""

    async def fetch_recent(
        self, ecosystem: str = "npm", hours_back: int = 24
    ) -> list[AdvisoryRecord]:
        """Query OSV.dev for recent vulnerabilities in an ecosystem.

        OSV doesn't support date-range queries directly, so we query for
        known high-profile packages and recently-reported vulns.
        We use the /v1/query endpoint with ecosystem filter.
        """
        osv_ecosystem = OSV_ECOSYSTEM_MAP.get(ecosystem, ecosystem)
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=hours_back)

        advisories: list[AdvisoryRecord] = []
        seen_ids: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # OSV doesn't have a "list recent" endpoint, but we can query
                # by ecosystem using the vulnerabilities list endpoint
                resp = await client.get(
                    f"https://api.osv.dev/v1/vulns",
                    params={
                        "ecosystem": osv_ecosystem,
                        "page_token": "",
                    },
                    timeout=30.0,
                )

                if resp.status_code != 200:
                    logger.debug(f"OSV list endpoint {resp.status_code}")
                    return advisories

                data = resp.json()
                vulns = data.get("vulns", [])

                for vuln in vulns[:100]:  # Cap at 100
                    record = self._parse_osv_vuln(vuln, ecosystem)
                    if record and record.ghsa_id not in seen_ids:
                        # Filter by date — only recent ones
                        pub = record.published_at or record.updated_at
                        if pub and pub >= cutoff:
                            seen_ids.add(record.ghsa_id or record.cve_id or "")
                            advisories.append(record)

        except Exception as e:
            logger.debug(f"OSV fetch failed for {ecosystem}: {e}")

        logger.info(f"OSV.dev: {len(advisories)} advisories for {ecosystem}")
        return advisories

    async def enrich_advisory(self, cve_id: str) -> Optional[dict]:
        """Get additional details for a single CVE from OSV.dev."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    OSV_QUERY_URL,
                    json={"cve": cve_id},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulns", [])
                    if vulns:
                        return vulns[0]
        except Exception as e:
            logger.debug(f"OSV enrich failed for {cve_id}: {e}")
        return None

    @staticmethod
    def _parse_osv_vuln(
        vuln: dict, ecosystem: str
    ) -> Optional[AdvisoryRecord]:
        """Parse a single OSV vulnerability object."""
        try:
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                return None

            # Extract CVE alias
            cve_id = None
            ghsa_id = None
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                elif alias.startswith("GHSA-"):
                    ghsa_id = alias

            if vuln_id.startswith("GHSA-"):
                ghsa_id = vuln_id
            elif vuln_id.startswith("CVE-"):
                cve_id = vuln_id

            # Affected packages
            affected_packages = []
            for affected in vuln.get("affected", []):
                pkg = affected.get("package", {})
                ranges = affected.get("ranges", [])
                version_str = ""
                for r in ranges:
                    events = r.get("events", [])
                    introduced = None
                    fixed = None
                    for ev in events:
                        if "introduced" in ev:
                            introduced = ev["introduced"]
                        if "fixed" in ev:
                            fixed = ev["fixed"]
                    if introduced and fixed:
                        version_str = f">= {introduced}, < {fixed}"
                    elif introduced:
                        version_str = f">= {introduced}"

                affected_packages.append({
                    "name": pkg.get("name", ""),
                    "ecosystem": pkg.get("ecosystem", ecosystem),
                    "version_range": version_str,
                })

            # References
            refs = [
                r.get("url", "")
                for r in vuln.get("references", [])
                if r.get("url")
            ]

            # Severity
            severity = "unknown"
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    # Parse CVSS score from vector if available
                    severity = "medium"  # default
                    # Check database_specific for severity
                    break
            db_specific = vuln.get("database_specific", {})
            if db_specific.get("severity"):
                severity = db_specific["severity"].lower()

            # Dates
            published_at = None
            if vuln.get("published"):
                try:
                    published_at = datetime.fromisoformat(
                        vuln["published"].replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    pass

            modified_at = None
            if vuln.get("modified"):
                try:
                    modified_at = datetime.fromisoformat(
                        vuln["modified"].replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    pass

            # Detect malware
            is_malware = False
            summary = (vuln.get("summary") or "")[:500]
            details = (vuln.get("details") or "")[:2000]
            malware_keywords = [
                "malicious", "malware", "backdoor", "trojan",
                "supply chain", "typosquatting", "credential theft",
            ]
            text_lower = (summary + " " + details).lower()
            if any(kw in text_lower for kw in malware_keywords):
                is_malware = True

            return AdvisoryRecord(
                ghsa_id=ghsa_id,
                cve_id=cve_id,
                source="osv",
                ecosystem=ecosystem,
                severity=severity,
                summary=summary,
                description=details,
                affected_packages=affected_packages,
                references=refs,
                published_at=published_at,
                updated_at=modified_at,
                is_malware=is_malware,
                withdrawn=vuln.get("withdrawn") is not None,
            )
        except Exception as e:
            logger.warning(f"Failed to parse OSV vuln: {e}")
            return None


# ── Main Orchestrator ─────────────────────────────────────────────────────────

class AdvisoryFeedService:
    """Orchestrates advisory polling from GitHub Advisory DB + OSV.dev.

    Called by the poller every 2 hours to catch supply chain attacks
    and ecosystem-specific vulnerabilities that NVD misses.
    """

    def __init__(self) -> None:
        self.github = GitHubAdvisoryFeedService()
        self.osv = OSVFeedService()
        self._last_poll: Optional[datetime] = None

    async def poll_advisories(
        self,
        hours_back: int = 6,
    ) -> list[AdvisoryRecord]:
        """Main entry point: fetch advisories from all sources and deduplicate.

        Returns a deduplicated list of AdvisoryRecord objects
        from both GitHub Advisory DB and OSV.dev.
        """
        all_advisories: list[AdvisoryRecord] = []
        seen_keys: set[str] = set()

        for ecosystem in MONITORED_ECOSYSTEMS:
            # 1. GitHub Advisory Database (primary — faster, includes malware)
            try:
                github_advisories = await self.github.fetch_advisories(
                    ecosystem=ecosystem,
                    hours_back=hours_back,
                )
                for adv in github_advisories:
                    key = adv.ghsa_id or adv.cve_id or ""
                    if key and key not in seen_keys:
                        seen_keys.add(key)
                        all_advisories.append(adv)
            except Exception as e:
                logger.error(f"GitHub Advisory poll failed for {ecosystem}: {e}")

            # 2. OSV.dev (supplementary — catches things GHSA misses)
            try:
                osv_advisories = await self.osv.fetch_recent(
                    ecosystem=ecosystem,
                    hours_back=max(hours_back, 12),  # wider window for OSV
                )
                for adv in osv_advisories:
                    # Deduplicate by GHSA ID or CVE ID
                    key = adv.ghsa_id or adv.cve_id or ""
                    if key and key not in seen_keys:
                        seen_keys.add(key)
                        all_advisories.append(adv)
                    elif adv.cve_id and adv.cve_id not in seen_keys:
                        seen_keys.add(adv.cve_id)
                        all_advisories.append(adv)
            except Exception as e:
                logger.error(f"OSV poll failed for {ecosystem}: {e}")

        self._last_poll = datetime.now(timezone.utc)

        # Sort: malware first, then by severity, then by date
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        all_advisories.sort(key=lambda a: (
            0 if a.is_malware else 1,
            severity_order.get(a.severity, 4),
            -(a.published_at or datetime.min.replace(tzinfo=timezone.utc)).timestamp(),
        ))

        logger.info(
            f"Advisory feed poll complete: {len(all_advisories)} total advisories "
            f"across {MONITORED_ECOSYSTEMS}"
        )
        return all_advisories
