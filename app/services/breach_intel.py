"""
Breach Intelligence Monitor
============================
Tracks publicly disclosed data breaches and connects them to:
  - CVEs used for initial access
  - Threat actor groups responsible
  - KnowCVE intelligence for each linked CVE

Data sources:
  - CISA alerts (parsed for breach mentions)
  - News intel feed (extracted breach reports)
  - Manual admin entries via API
  - Seed data for major 2024-2025 breaches

This is NOT a personal data lookup tool.
All data is from public breach disclosures only.
"""

from __future__ import annotations

import asyncio
import logging
import json
import re
from datetime import datetime, timezone, timedelta

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Seed Breaches (major publicly disclosed breaches) ────────────────────────

SEED_BREACHES = [
    {
        "company_name": "Change Healthcare",
        "breach_date": "2024-02-21",
        "disclosed_date": "2024-02-29",
        "actor_slug": "blackcat",
        "cve_ids": [],
        "data_exposed": ["PII", "Medical Records", "Financial", "Insurance Claims"],
        "records_count": 100000000,
        "sectors": ["Healthcare"],
        "description": "ALPHV/BlackCat ransomware attack on Change Healthcare disrupted US prescription processing for weeks. One of the largest healthcare breaches in US history, affecting 100M+ patients.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "Snowflake Customer Breach",
        "breach_date": "2024-05-01",
        "disclosed_date": "2024-06-01",
        "actor_slug": "scattered-spider",
        "cve_ids": [],
        "data_exposed": ["Credentials", "PII", "Financial", "Call Records"],
        "records_count": None,
        "sectors": ["Technology", "Finance", "Retail", "Telecommunications"],
        "description": "Credential-based attacks against Snowflake customers affected 165+ organizations including Ticketmaster, Santander, AT&T, and LendingTree. No CVE — pure credential stuffing using stolen credentials.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "MOVEit Mass Exploitation",
        "breach_date": "2023-05-27",
        "disclosed_date": "2023-06-01",
        "actor_slug": "cl0p",
        "cve_ids": ["CVE-2023-34362"],
        "data_exposed": ["PII", "Financial", "Government Records"],
        "records_count": 77000000,
        "sectors": ["Government", "Finance", "Healthcare", "Education"],
        "description": "Cl0p mass-exploited MOVEit Transfer zero-day affecting 2,500+ organizations and 77M+ individuals. Largest single ransomware campaign in history.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "MGM Resorts",
        "breach_date": "2023-09-10",
        "disclosed_date": "2023-09-11",
        "actor_slug": "scattered-spider",
        "cve_ids": [],
        "data_exposed": ["PII", "Financial", "Loyalty Program Data"],
        "records_count": None,
        "sectors": ["Hospitality"],
        "description": "Scattered Spider partnered with ALPHV/BlackCat to breach MGM Resorts via help-desk social engineering. Caused ~$100M in losses, shut down slot machines and room keys.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "CDK Global",
        "breach_date": "2024-06-18",
        "disclosed_date": "2024-06-19",
        "actor_slug": "safepay",
        "cve_ids": [],
        "data_exposed": ["PII", "Financial", "Vehicle Records"],
        "records_count": None,
        "sectors": ["Automotive", "Retail"],
        "description": "BlackSuit (SafePay rebrand) ransomware attack on CDK Global shut down 15,000+ car dealership operations across North America for weeks.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "NHS Synnovis (UK)",
        "breach_date": "2024-06-03",
        "disclosed_date": "2024-06-04",
        "actor_slug": "qilin",
        "cve_ids": ["CVE-2024-21762"],
        "data_exposed": ["Medical Records", "PII", "Blood Test Results"],
        "records_count": None,
        "sectors": ["Healthcare"],
        "description": "Qilin ransomware attacked Synnovis, a UK NHS pathology lab provider, causing thousands of cancelled blood tests and surgeries across London hospitals.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "ICBC Financial Services",
        "breach_date": "2023-11-08",
        "disclosed_date": "2023-11-09",
        "actor_slug": "lockbit",
        "cve_ids": ["CVE-2023-4966"],
        "data_exposed": ["Financial", "Trade Settlement Data"],
        "records_count": None,
        "sectors": ["Finance"],
        "description": "LockBit exploited Citrix Bleed to breach ICBC Financial Services (the largest bank in the world), disrupting US Treasury bond trading.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "Ivanti VPN Mass Exploitation",
        "breach_date": "2024-01-10",
        "disclosed_date": "2024-01-10",
        "actor_slug": "volt-typhoon",
        "cve_ids": ["CVE-2023-46805", "CVE-2024-21887"],
        "data_exposed": ["Credentials", "Network Access"],
        "records_count": None,
        "sectors": ["Government", "Defense", "Technology"],
        "description": "Mass exploitation of chained Ivanti Connect Secure VPN zero-days. CISA ordered emergency disconnect of all federal Ivanti devices. Multiple nation-state actors involved.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "Boeing",
        "breach_date": "2023-10-27",
        "disclosed_date": "2023-11-01",
        "actor_slug": "lockbit",
        "cve_ids": ["CVE-2023-4966"],
        "data_exposed": ["Internal Documents", "Technical Data"],
        "records_count": None,
        "sectors": ["Defense", "Aerospace"],
        "description": "LockBit breached Boeing via Citrix Bleed, exfiltrating 43GB of data. Boeing refused to pay, and LockBit published all stolen data.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "AT&T",
        "breach_date": "2024-04-01",
        "disclosed_date": "2024-07-12",
        "actor_slug": None,
        "cve_ids": [],
        "data_exposed": ["Call Records", "SMS Metadata", "PII"],
        "records_count": 110000000,
        "sectors": ["Telecommunications"],
        "description": "Nearly all AT&T cellular customer call and text records from 2022 exposed via compromised Snowflake account. Affected 110M customers.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "Ascension Health",
        "breach_date": "2024-05-08",
        "disclosed_date": "2024-05-09",
        "actor_slug": "safepay",
        "cve_ids": [],
        "data_exposed": ["Medical Records", "PII"],
        "records_count": 5600000,
        "sectors": ["Healthcare"],
        "description": "Black Basta ransomware attack on Ascension, one of the largest health systems in the US, forced ambulance diversions and suspended clinical operations at 140 hospitals.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "Dell Technologies",
        "breach_date": "2024-05-01",
        "disclosed_date": "2024-05-09",
        "actor_slug": None,
        "cve_ids": [],
        "data_exposed": ["PII", "Purchase History", "Hardware Serial Numbers"],
        "records_count": 49000000,
        "sectors": ["Technology"],
        "description": "Threat actor 'Menelik' scraped Dell's partner portal API using brute-force to access records of 49M customers. Data sold on breach forums.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "Fortinet FortiGate Config Leak",
        "breach_date": "2025-01-14",
        "disclosed_date": "2025-01-15",
        "actor_slug": None,
        "cve_ids": ["CVE-2024-55591"],
        "data_exposed": ["Configurations", "Credentials", "VPN Rules"],
        "records_count": 15000,
        "sectors": ["All sectors"],
        "description": "Threat actor 'Belsen Group' leaked 15,000 FortiGate firewall configs including VPN credentials, harvested via CVE-2024-55591 authentication bypass.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "Caesars Entertainment",
        "breach_date": "2023-08-27",
        "disclosed_date": "2023-09-14",
        "actor_slug": "scattered-spider",
        "cve_ids": [],
        "data_exposed": ["PII", "Loyalty Program Data", "SSNs", "Driver License Numbers"],
        "records_count": None,
        "sectors": ["Hospitality"],
        "description": "Scattered Spider breached Caesars via social engineering targeting an outsourced IT support vendor. Caesars reportedly paid $15M ransom.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "Clorox",
        "breach_date": "2023-08-14",
        "disclosed_date": "2023-08-14",
        "actor_slug": "scattered-spider",
        "cve_ids": [],
        "data_exposed": ["Internal Systems", "Production Data"],
        "records_count": None,
        "sectors": ["Manufacturing"],
        "description": "Scattered Spider disrupted Clorox production causing product shortages and $356M in losses from delayed orders and manual processing.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
    {
        "company_name": "SolarWinds",
        "breach_date": "2020-03-01",
        "disclosed_date": "2020-12-13",
        "actor_slug": "apt29",
        "cve_ids": ["CVE-2020-10148"],
        "data_exposed": ["Internal Systems", "Source Code", "Network Access"],
        "records_count": 18000,
        "sectors": ["Technology", "Government"],
        "description": "APT29 (Cozy Bear) compromised the SolarWinds Orion build system, deploying the SUNBURST backdoor to ~18,000 customers, including multiple US federal agencies and Fortune 500 companies.",
        "source_urls": ["https://www.cisa.gov"],
        "verified": True,
    },
]


class BreachIntelService:
    """Tracks publicly disclosed data breaches linked to CVEs and threat actors."""

    def __init__(self) -> None:
        self._client = None
        if settings.SUPABASE_URL and settings.SUPABASE_KEY:
            try:
                from supabase import create_client
                self._client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                logger.info("BreachIntelService: Supabase client initialized")
            except Exception as e:
                logger.warning(f"BreachIntelService init failed: {e}")

    async def seed_initial_breaches(self) -> None:
        """Seeds major publicly disclosed breaches (only if table is empty)."""
        if not self._client:
            return
        try:
            count_res = self._client.table("breach_intelligence").select("id", count="exact").limit(1).execute()
            if count_res.count and count_res.count > 0:
                logger.info("Breach intelligence already seeded — skipping")
                return

            logger.info("Seeding breach intelligence data...")
            for breach in SEED_BREACHES:
                try:
                    self._client.table("breach_intelligence").insert(breach).execute()
                except Exception as e:
                    logger.warning(f"Failed to seed breach '{breach['company_name']}': {e}")

            logger.info("✅ Breach intelligence seeding complete")
        except Exception as e:
            logger.error(f"Failed to seed breaches: {e}")

    async def extract_breaches_from_news(self) -> None:
        """Scans new news articles for breach-related keywords. Draft entries with verified=False."""
        if not self._client:
            return
            
        logger.info("🔍 Scanning recent news for new data breaches...")
        try:
            # Get articles from last 24 hours
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            res = (
                self._client.table("security_news")
                .select("id, title, summary, url, source, mentioned_cves, mentioned_actors")
                .gte("published_at", cutoff)
                .execute()
            )
            articles = res.data or []
            
            # Filter locally for breach keywords to save AI calls
            keywords = ["breach", "leak", "hacked", "stolen", "exposed", "compromised", "ransomware", "data theft"]
            breach_articles = []
            for art in articles:
                text = f"{art.get('title', '')} {art.get('summary', '')}".lower()
                if any(kw in text for kw in keywords):
                    breach_articles.append(art)
                    
            if not breach_articles:
                logger.info("No breach-related articles found in the last 24 hours.")
                return
                
            logger.info(f"Found {len(breach_articles)} potential breach articles. Analyzing with AI...")
            
            # Limit to top 10 to avoid excessive API calls
            from groq import AsyncGroq
            if not settings.GROQ_API_KEY:
                logger.warning("GROQ_API_KEY not set. Cannot run breach extraction.")
                return
                
            client = AsyncGroq(api_key=settings.GROQ_API_KEY)
            
            prompt_system = (
                "You are a threat intelligence analyst. Read the following security news summary. "
                "If it describes a distinct, real-world data breach or ransomware attack against a specific organization, extract the details into a JSON object. "
                "Return ONLY a valid JSON object. If it's NOT a specific breach, return an empty JSON object: {}. "
                "Format: {"
                ' "company_name": "Name of breached organization", '
                ' "breach_date": "YYYY-MM-DD or null", '
                ' "actor_slug": "Threat actor name or slug if mentioned, else null", '
                ' "cve_ids": ["CVE-YYYY-NNNNN"], '
                ' "data_exposed": ["PII", "Credentials", etc], '
                ' "records_count": integer or null, '
                ' "sectors": ["Finance", "Healthcare", etc], '
                ' "description": "1-2 sentence summary of the breach" '
                "}"
            )
            
            inserted = 0
            for art in breach_articles[:10]:
                text_to_analyze = f"Title: {art.get('title')}\nSummary: {art.get('summary')}"
                try:
                    resp = await client.chat.completions.create(
                        model=settings.GROQ_MODEL,
                        messages=[
                            {"role": "system", "content": prompt_system},
                            {"role": "user", "content": text_to_analyze},
                        ],
                        max_tokens=300,
                        temperature=0.1,
                    )
                    reply = resp.choices[0].message.content.strip()
                    
                    # Extract json from markdown if present
                    json_str = reply
                    if "```json" in reply:
                        json_str = reply.split("```json")[1].split("```")[0].strip()
                    elif "```" in reply:
                        json_str = reply.split("```")[1].split("```")[0].strip()
                        
                    data = json.loads(json_str)
                    
                    if data and data.get("company_name"):
                        # Check if company already in DB to avoid dupes
                        exists = self._client.table("breach_intelligence").select("id").ilike("company_name", data["company_name"]).execute()
                        if exists.data:
                            continue
                            
                        # Format the data
                        cve_ids = data.get("cve_ids", [])
                        if not isinstance(cve_ids, list): cve_ids = []
                        # merge with already extracted CVEs from news
                        cve_ids = list(set(cve_ids + (art.get("mentioned_cves") or [])))
                        
                        breach_record = {
                            "company_name": data.get("company_name"),
                            "breach_date": data.get("breach_date"),
                            "disclosed_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                            "actor_slug": data.get("actor_slug"),
                            "cve_ids": cve_ids,
                            "data_exposed": data.get("data_exposed", []),
                            "records_count": data.get("records_count"),
                            "sectors": data.get("sectors", []),
                            "description": data.get("description", art.get("summary")),
                            "source_urls": [art.get("url")],
                            "verified": False,  # Draft status
                        }
                        self._client.table("breach_intelligence").insert(breach_record).execute()
                        inserted += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to extract breach from article '{art.get('title')}': {e}")
                    
            logger.info(f"✅ AI Breach Extraction complete. Added {inserted} new unverified breaches.")
            
        except Exception as e:
            logger.error(f"Error in extract_breaches_from_news: {e}")

    async def get_breaches(
        self, cve_id: str | None = None,
        actor_slug: str | None = None,
        limit: int = 20,
        verified_only: bool = True,
        category: str | None = None,
    ) -> list[dict]:
        """Returns breach records with optional filtering."""
        if not self._client:
            return []
        try:
            q = self._client.table("breach_intelligence").select("*")
            
            # Category overrides
            if category == "active":
                q = q.eq("verified", False)
            elif verified_only and category != "active":
                q = q.eq("verified", True)
                
            if category == "major":
                q = q.gte("records_count", 1000000)
            elif category == "latest":
                q = q.or_("records_count.lt.1000000,records_count.is.null")
                
            if actor_slug:
                q = q.eq("actor_slug", actor_slug)
            if cve_id:
                q = q.contains("cve_ids", [cve_id.upper()])
                
            # Sorting based on category
            if category == "major":
                q = q.order("records_count", desc=True)
            else:
                q = q.order("breach_date", desc=True)
                
            res = q.limit(limit).execute()
            
            data = res.data or []

            # Build actor name cache
            actor_cache = {}
            slugs = list(set(r.get("actor_slug") for r in data if r.get("actor_slug")))
            if slugs:
                try:
                    ar = self._client.table("threat_actors").select("slug, name").in_("slug", slugs).execute()
                    for a in (ar.data or []):
                        actor_cache[a["slug"]] = a["name"]
                except Exception:
                    pass

            results = []
            for row in data:
                slug = row.get("actor_slug")
                row["actor_name"] = actor_cache.get(slug, slug or "Unknown")
                results.append(row)
            return results
        except Exception as e:
            logger.error(f"get_breaches failed: {e}")
            return []

    async def search_breaches(self, query: str) -> list[dict]:
        """Case-insensitive search for company name or description."""
        if not self._client or not query:
            return []
        try:
            search_term = query.strip().replace(" ", "%")
            res = (
                self._client.table("breach_intelligence")
                .select("*")
                .or_(f"company_name.ilike.%{search_term}%,description.ilike.%{search_term}%,actor_slug.ilike.%{search_term}%")
                .order("breach_date", desc=True)
                .limit(50)
                .execute()
            )

            # Build actor name cache
            actor_cache = {}
            slugs = list(set(r.get("actor_slug") for r in (res.data or []) if r.get("actor_slug")))
            if slugs:
                try:
                    ar = self._client.table("threat_actors").select("slug, name").in_("slug", slugs).execute()
                    for a in (ar.data or []):
                        actor_cache[a["slug"]] = a["name"]
                except Exception:
                    pass

            results = []
            for row in (res.data or []):
                slug = row.get("actor_slug")
                row["actor_name"] = actor_cache.get(slug, slug or "Unknown")
                results.append(row)
            return results
        except Exception as e:
            logger.error(f"search_breaches({company_name}) failed: {e}")
            return []

    async def get_breaches_for_cve(self, cve_id: str) -> list[dict]:
        """Returns all breaches where this CVE was used for initial access."""
        return await self.get_breaches(cve_id=cve_id)

    async def get_breach_stats(self, category: str | None = None, query: str | None = None) -> dict:
        """Returns aggregate breach statistics dynamically filtered by category and query."""
        if not self._client:
            return {"total_breaches": 0, "total_records": 0, "top_sectors": []}
        try:
            q = self._client.table("breach_intelligence").select("*")
            
            if query:
                search_term = query.strip().replace(" ", "%")
                q = q.or_(f"company_name.ilike.%{search_term}%,description.ilike.%{search_term}%,actor_slug.ilike.%{search_term}%")
            else:
                if category == "active":
                    q = q.eq("verified", False)
                else:
                    q = q.eq("verified", True)
                    
                if category == "major":
                    q = q.gte("records_count", 1000000)
                elif category == "latest":
                    q = q.or_("records_count.lt.1000000,records_count.is.null")
                    
            res = q.execute()
            breaches = res.data or []

            total_records = sum(b.get("records_count") or 0 for b in breaches)
            sector_counts: dict[str, int] = {}
            for b in breaches:
                for s in b.get("sectors", []):
                    sector_counts[s] = sector_counts.get(s, 0) + 1

            top_sectors = sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)[:5]

            return {
                "total_breaches": len(breaches),
                "total_records": total_records,
                "top_sectors": [{"sector": s, "count": c} for s, c in top_sectors],
            }
        except Exception as e:
            logger.error(f"get_breach_stats failed: {e}")
            return {"total_breaches": 0, "total_records": 0, "top_sectors": []}
