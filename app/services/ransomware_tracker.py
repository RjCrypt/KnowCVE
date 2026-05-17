"""
Ransomware Campaign Tracker
============================
Tracks active ransomware campaigns and their CVE exploitation patterns.

Data flow:
  1. Seed initial campaigns from known public reporting
  2. Hourly check: scan CISA KEV additions for ransomware-linked CVEs
  3. Cross-reference with existing threat_actor_cves table
  4. Alert via Telegram when a tracked ransomware group adopts a new CVE
"""

from __future__ import annotations

import asyncio
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Seed Campaigns ───────────────────────────────────────────────────────────

SEED_CAMPAIGNS = [
    {
        "actor_slug": "qilin",
        "campaign_name": "Qilin Fortinet Campaign 2024-2025",
        "cve_ids": ["CVE-2024-21762", "CVE-2024-55591"],
        "sectors": ["Healthcare", "Finance", "Manufacturing"],
        "countries": ["United States", "United Kingdom", "Australia"],
        "status": "active",
        "description": "Qilin exploiting Fortinet VPN vulnerabilities for initial access, followed by double extortion. Primarily targeting English-speaking organizations.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "cl0p",
        "campaign_name": "Cl0p MOVEit Campaign 2023",
        "cve_ids": ["CVE-2023-34362"],
        "sectors": ["Finance", "Healthcare", "Legal", "Government"],
        "countries": ["United States", "United Kingdom", "Germany", "Global"],
        "status": "historical",
        "description": "Mass exploitation of MOVEit Transfer zero-day affecting 2,500+ organizations globally. Largest single ransomware campaign on record.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "cl0p",
        "campaign_name": "Cl0p GoAnywhere Campaign 2023",
        "cve_ids": ["CVE-2023-0669"],
        "sectors": ["Finance", "Healthcare", "Government"],
        "countries": ["United States", "Global"],
        "status": "historical",
        "description": "Mass exploitation of GoAnywhere MFT zero-day affecting 130+ organizations.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "ransomhub",
        "campaign_name": "RansomHub PAN-OS Campaign 2024",
        "cve_ids": ["CVE-2024-3400"],
        "sectors": ["Healthcare", "Finance", "Critical Infrastructure"],
        "countries": ["United States", "United Kingdom", "Global"],
        "status": "active",
        "description": "RansomHub affiliates exploiting Palo Alto PAN-OS command injection for initial access, deploying ransomware with double extortion.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "blackcat",
        "campaign_name": "ALPHV Change Healthcare Attack",
        "cve_ids": ["CVE-2024-3400"],
        "sectors": ["Healthcare"],
        "countries": ["United States"],
        "status": "historical",
        "description": "Devastating attack on Change Healthcare, disrupting US prescription processing for weeks. 100M+ patient records exposed. ALPHV collected $22M ransom before exit scam.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "lockbit",
        "campaign_name": "LockBit Citrix Bleed Campaign",
        "cve_ids": ["CVE-2023-4966"],
        "sectors": ["Finance", "Technology", "Government"],
        "countries": ["Global"],
        "status": "historical",
        "description": "LockBit affiliates mass-exploiting Citrix Bleed vulnerability for initial access, including the attack on ICBC Financial Services.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "akira",
        "campaign_name": "Akira Cisco VPN Campaign",
        "cve_ids": ["CVE-2020-3259", "CVE-2023-20269"],
        "sectors": ["Manufacturing", "Education", "Professional Services"],
        "countries": ["United States", "Europe"],
        "status": "active",
        "description": "Akira consistently targeting organizations with unpatched Cisco ASA/FTD VPN appliances for credential theft and initial network access.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "play",
        "campaign_name": "Play Exchange & FortiOS Campaign",
        "cve_ids": ["CVE-2022-41082", "CVE-2024-21762"],
        "sectors": ["Government", "Finance", "Healthcare"],
        "countries": ["Latin America", "Europe", "United States"],
        "status": "active",
        "description": "Play ransomware exploiting Microsoft Exchange ProxyNotShell and FortiOS vulnerabilities for initial access across government and financial targets.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "bianlian",
        "campaign_name": "BianLian Extortion-Only Campaign 2024",
        "cve_ids": ["CVE-2024-21762"],
        "sectors": ["Healthcare", "Manufacturing", "Education"],
        "countries": ["United States", "Australia"],
        "status": "active",
        "description": "BianLian has shifted to pure data exfiltration and extortion without encryption, using Fortinet VPN flaws and stolen credentials for access.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "scattered-spider",
        "campaign_name": "Scattered Spider Social Engineering Campaign",
        "cve_ids": [],
        "sectors": ["Technology", "Telecommunications", "Hospitality"],
        "countries": ["United States", "Global"],
        "status": "active",
        "description": "Help-desk impersonation, MFA fatigue, and SIM swap attacks. Partnered with ALPHV/BlackCat for the MGM Resorts and Caesars Entertainment breaches.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "safepay",
        "campaign_name": "SafePay/BlackSuit Edge Infrastructure Campaign",
        "cve_ids": [],
        "sectors": ["Healthcare", "Manufacturing", "Government"],
        "countries": ["United States", "United Kingdom", "Canada"],
        "status": "active",
        "description": "SafePay (BlackSuit rebrand from Royal/Conti lineage) targeting vulnerable edge appliances and using double extortion.",
        "source_url": "https://www.cisa.gov",
    },
    {
        "actor_slug": "ransomhub",
        "campaign_name": "RansomHub Post-BlackCat Affiliate Surge",
        "cve_ids": [],
        "sectors": ["Healthcare", "Finance", "Critical Infrastructure"],
        "countries": ["United States", "Global"],
        "status": "active",
        "description": "After ALPHV/BlackCat's exit scam, many affiliates migrated to RansomHub, making it the most active RaaS operation in late 2024/2025.",
        "source_url": "https://www.cisa.gov",
    },
]


class RansomwareTrackerService:
    """Tracks active ransomware campaigns and their CVE exploitation patterns."""

    def __init__(self) -> None:
        self._client = None
        if settings.SUPABASE_URL and settings.SUPABASE_KEY:
            try:
                from supabase import create_client
                self._client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                logger.info("RansomwareTrackerService: Supabase client initialized")
            except Exception as e:
                logger.warning(f"RansomwareTrackerService init failed: {e}")

    async def seed_initial_campaigns(self) -> None:
        """Seeds known ransomware campaigns (only if table is empty)."""
        if not self._client:
            return
        try:
            count_res = self._client.table("ransomware_campaigns").select("id", count="exact").limit(1).execute()
            if count_res.count and count_res.count > 0:
                logger.info("Ransomware campaigns already seeded — skipping")
                return

            logger.info("Seeding ransomware campaigns...")
            for campaign in SEED_CAMPAIGNS:
                try:
                    self._client.table("ransomware_campaigns").insert(campaign).execute()
                except Exception as e:
                    logger.warning(f"Failed to seed campaign '{campaign['campaign_name']}': {e}")

            logger.info("✅ Ransomware campaign seeding complete")
        except Exception as e:
            logger.error(f"Failed to seed ransomware campaigns: {e}")

    async def check_new_kev_for_ransomware(self) -> list[dict]:
        """Called hourly. Checks for new KEV entries linked to ransomware actors."""
        if not self._client:
            return []
        # Placeholder for hourly KEV cross-reference — actual implementation
        # would check CISA KEV feed additions against threat_actor_cves table
        return []

    async def get_active_campaigns(
        self, status: str | None = None, actor_slug: str | None = None
    ) -> list[dict]:
        """Returns campaigns with optional filtering, joined with actor data."""
        if not self._client:
            return []
        try:
            # Try embedded join — works if Supabase detects FK relationship
            try:
                q = self._client.table("ransomware_campaigns").select("*, threat_actors(name, motivation, origin_country)")
            except Exception:
                q = self._client.table("ransomware_campaigns").select("*")
            if status:
                q = q.eq("status", status)
            if actor_slug:
                q = q.eq("actor_slug", actor_slug)
            res = q.order("created_at", desc=True).execute()

            # Build actor name cache for fallback
            actor_cache = {}
            results = []
            for row in (res.data or []):
                actor = row.pop("threat_actors", None)
                slug = row.get("actor_slug", "")
                if actor and isinstance(actor, dict):
                    row["actor_name"] = actor.get("name", slug)
                    row["motivation"] = actor.get("motivation", "")
                    row["origin_country"] = actor.get("origin_country", "")
                else:
                    # Fallback: look up actor name from threat_actors table
                    if slug and slug not in actor_cache:
                        try:
                            ar = self._client.table("threat_actors").select("name, motivation, origin_country").eq("slug", slug).limit(1).execute()
                            actor_cache[slug] = ar.data[0] if ar.data else {}
                        except Exception:
                            actor_cache[slug] = {}
                    cached = actor_cache.get(slug, {})
                    row["actor_name"] = cached.get("name", slug)
                    row["motivation"] = cached.get("motivation", "")
                    row["origin_country"] = cached.get("origin_country", "")
                results.append(row)
            return results
        except Exception as e:
            logger.error(f"get_active_campaigns failed: {e}")
            return []

    async def get_ransomware_cve_matrix(self) -> list[dict]:
        """Returns matrix view: for each active ransomware group, list their CVEs."""
        if not self._client:
            return []
        try:
            res = (
                self._client.table("ransomware_campaigns")
                .select("*")
                .order("status")
                .execute()
            )

            # Build actor name cache
            actor_cache = {}
            try:
                actors_res = self._client.table("threat_actors").select("slug, name, motivation, origin_country, is_active").execute()
                for a in (actors_res.data or []):
                    actor_cache[a["slug"]] = a
            except Exception:
                pass

            matrix = []
            for row in (res.data or []):
                slug = row.get("actor_slug", "")
                actor = actor_cache.get(slug, {})
                matrix.append({
                    "actor_slug": slug,
                    "actor_name": actor.get("name", slug),
                    "motivation": actor.get("motivation", ""),
                    "origin_country": actor.get("origin_country", ""),
                    "campaign_name": row.get("campaign_name", ""),
                    "cves": row.get("cve_ids", []),
                    "cve_ids": row.get("cve_ids", []),
                    "sectors": row.get("sectors", []),
                    "countries": row.get("countries", []),
                    "status": row.get("status", "unknown"),
                    "description": row.get("description", ""),
                })
            return matrix
        except Exception as e:
            logger.error(f"get_ransomware_cve_matrix failed: {e}")
            return []

    async def get_ransomware_by_cve(self, cve_id: str) -> list[dict]:
        """Returns which ransomware groups have used this CVE."""
        if not self._client:
            return []
        try:
            res = (
                self._client.table("ransomware_campaigns")
                .select("*")
                .contains("cve_ids", [cve_id.upper()])
                .execute()
            )

            # Build actor name cache
            actor_cache = {}
            slugs = list(set(r.get("actor_slug") for r in (res.data or []) if r.get("actor_slug")))
            if slugs:
                try:
                    ar = self._client.table("threat_actors").select("slug, name, motivation").in_("slug", slugs).execute()
                    for a in (ar.data or []):
                        actor_cache[a["slug"]] = a
                except Exception:
                    pass

            results = []
            for row in (res.data or []):
                slug = row.get("actor_slug", "")
                actor = actor_cache.get(slug, {})
                row["actor_name"] = actor.get("name", slug)
                row["motivation"] = actor.get("motivation", "")
                results.append(row)
            return results
        except Exception as e:
            logger.error(f"get_ransomware_by_cve({cve_id}) failed: {e}")
            return []
