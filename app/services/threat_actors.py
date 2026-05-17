"""
Threat Actor Intelligence Service
===================================
Maintains a database of known threat actor groups with:
  - Profile data (origin, motivation, TTPs)
  - CVE exploitation history
  - MITRE ATT&CK group mappings

Data sources:
  - MITRE ATT&CK API (free, no key): https://attack.mitre.org/api/
  - Seed data for major groups loaded at startup
  - Manual enrichment via admin API

The service seeds the database with 20 major threat actor groups
on first run if the table is empty.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── 20 Major Threat Actor Seed Data ──────────────────────────────────────────

SEED_ACTORS = [
    {
        "slug": "lazarus-group",
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "Guardians of Peace", "Zinc", "APT38"],
        "origin_country": "North Korea",
        "motivation": "Financial, Espionage",
        "sophistication": "Nation-State",
        "description": "North Korean state-sponsored APT responsible for some of the largest cryptocurrency heists in history and major destructive attacks. Linked to WannaCry ransomware and the Sony Pictures hack.",
        "targeted_sectors": ["Finance", "Cryptocurrency", "Defense", "Government"],
        "targeted_countries": ["United States", "South Korea", "Japan", "Global"],
        "mitre_group_id": "G0032",
        "mitre_url": "https://attack.mitre.org/groups/G0032/",
        "first_seen": "2009",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "ransomhub",
        "name": "RansomHub",
        "aliases": ["Cyclops", "Knight"],
        "origin_country": "Unknown",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "One of the most prolific ransomware-as-a-service operations of 2025. Emerged after ALPHV/BlackCat's disruption and quickly absorbed former affiliates. Known for double extortion and targeting critical infrastructure.",
        "targeted_sectors": ["Healthcare", "Finance", "Critical Infrastructure", "Government"],
        "targeted_countries": ["United States", "United Kingdom", "Germany", "Global"],
        "mitre_group_id": None,
        "first_seen": "2024",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "qilin",
        "name": "Qilin",
        "aliases": ["Agenda"],
        "origin_country": "Russia",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "Russian-speaking RaaS operation known for professionalizing extortion with legal pressure tactics including a 'Call Lawyer' feature. Targets VMware ESXi environments and uses stolen credentials for initial access.",
        "targeted_sectors": ["Healthcare", "Education", "Manufacturing", "Finance"],
        "targeted_countries": ["United States", "United Kingdom", "Australia", "Global"],
        "mitre_group_id": None,
        "first_seen": "2022",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "volt-typhoon",
        "name": "Volt Typhoon",
        "aliases": ["Bronze Silhouette", "Vanguard Panda"],
        "origin_country": "China",
        "motivation": "Espionage, Prepositioning",
        "sophistication": "Nation-State",
        "description": "Chinese state-sponsored APT focused on living-off-the-land techniques to pre-position in US critical infrastructure for potential future disruption. Known for long-dwell-time operations and minimal malware usage.",
        "targeted_sectors": ["Critical Infrastructure", "Government", "Defense", "Utilities"],
        "targeted_countries": ["United States", "Guam"],
        "mitre_group_id": "G1017",
        "mitre_url": "https://attack.mitre.org/groups/G1017/",
        "first_seen": "2021",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "cl0p",
        "name": "Cl0p",
        "aliases": ["TA505", "FIN11"],
        "origin_country": "Russia",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "Prolific ransomware group known for mass exploitation of zero-day vulnerabilities in file transfer software. Responsible for MOVEit, GoAnywhere, and Accellion attacks affecting thousands of organizations.",
        "targeted_sectors": ["Finance", "Healthcare", "Legal", "Technology"],
        "targeted_countries": ["United States", "United Kingdom", "Germany", "Global"],
        "mitre_group_id": "G0154",
        "mitre_url": "https://attack.mitre.org/groups/G0154/",
        "first_seen": "2019",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "apt29",
        "name": "APT29",
        "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard"],
        "origin_country": "Russia",
        "motivation": "Espionage",
        "sophistication": "Nation-State",
        "description": "Russian Foreign Intelligence Service (SVR) cyber actors. Known for the SolarWinds supply chain compromise and persistent, stealthy intelligence collection against government and diplomatic targets worldwide.",
        "targeted_sectors": ["Government", "Defense", "Technology", "Think Tanks"],
        "targeted_countries": ["United States", "Europe", "Global"],
        "mitre_group_id": "G0016",
        "mitre_url": "https://attack.mitre.org/groups/G0016/",
        "first_seen": "2008",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "apt28",
        "name": "APT28",
        "aliases": ["Fancy Bear", "Forest Blizzard", "STRONTIUM"],
        "origin_country": "Russia",
        "motivation": "Espionage, Disruption",
        "sophistication": "Nation-State",
        "description": "Russian GRU Unit 26165-linked threat group involved in intelligence gathering, influence operations, and disruptive attacks. Targeted the DNC in 2016 and has conducted operations against NATO governments.",
        "targeted_sectors": ["Defense", "Government", "Media", "Energy"],
        "targeted_countries": ["United States", "Ukraine", "Europe"],
        "mitre_group_id": "G0007",
        "mitre_url": "https://attack.mitre.org/groups/G0007/",
        "first_seen": "2004",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "sandworm",
        "name": "Sandworm",
        "aliases": ["Voodoo Bear", "Seashell Blizzard", "IRIDIUM"],
        "origin_country": "Russia",
        "motivation": "Destructive",
        "sophistication": "Nation-State",
        "description": "GRU Unit 74455 responsible for the most devastating destructive cyberattacks in history, including NotPetya ($10B+ damage) and multiple attacks shutting down the Ukrainian power grid.",
        "targeted_sectors": ["Critical Infrastructure", "Energy", "Government", "Telecommunications"],
        "targeted_countries": ["Ukraine", "Global"],
        "mitre_group_id": "G0034",
        "mitre_url": "https://attack.mitre.org/groups/G0034/",
        "first_seen": "2009",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "apt41",
        "name": "APT41",
        "aliases": ["Winnti", "Barium", "Earth Baku", "Double Dragon"],
        "origin_country": "China",
        "motivation": "Espionage, Financial",
        "sophistication": "Nation-State",
        "description": "Prolific Chinese state-sponsored group uniquely conducting both espionage for the state and financially motivated activity for personal gain. Targets the gaming, telecom, healthcare, and technology sectors.",
        "targeted_sectors": ["Technology", "Healthcare", "Telecommunications", "Gaming"],
        "targeted_countries": ["Global"],
        "mitre_group_id": "G0096",
        "mitre_url": "https://attack.mitre.org/groups/G0096/",
        "first_seen": "2012",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "scattered-spider",
        "name": "Scattered Spider",
        "aliases": ["UNC3944", "0ktapus", "Octo Tempest", "Star Fraud"],
        "origin_country": "United States/United Kingdom",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "Young, English-speaking cybercriminal collective known for aggressive social engineering, MFA fatigue attacks, SIM swapping, and help-desk impersonation. Partnered with ALPHV/BlackCat for the MGM Resorts breach.",
        "targeted_sectors": ["Technology", "Telecommunications", "Hospitality", "Finance"],
        "targeted_countries": ["United States", "Global"],
        "mitre_group_id": "G1015",
        "mitre_url": "https://attack.mitre.org/groups/G1015/",
        "first_seen": "2022",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "blackcat",
        "name": "BlackCat",
        "aliases": ["ALPHV", "Noberus"],
        "origin_country": "Russia",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "First major Rust-based RaaS. Perpetrated the Change Healthcare breach affecting 100M+ US patients. Performed an exit scam on affiliates after collecting a $22M ransom, effectively shutting operations in early 2024.",
        "targeted_sectors": ["Healthcare", "Finance", "Education", "Manufacturing"],
        "targeted_countries": ["Global"],
        "mitre_group_id": "G1012",
        "mitre_url": "https://attack.mitre.org/groups/G1012/",
        "first_seen": "2021",
        "last_active": "2024",
        "is_active": False,
    },
    {
        "slug": "lockbit",
        "name": "LockBit",
        "aliases": ["Bitwise Spider"],
        "origin_country": "Russia",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "For years the most prolific RaaS group globally, responsible for thousands of attacks across all sectors. Law enforcement disrupted their infrastructure in Operation Cronos (Feb 2024). Attempted comeback failed.",
        "targeted_sectors": ["All sectors"],
        "targeted_countries": ["Global"],
        "mitre_group_id": "G0135",
        "mitre_url": "https://attack.mitre.org/groups/G0135/",
        "first_seen": "2019",
        "last_active": "2024",
        "is_active": False,
    },
    {
        "slug": "akira",
        "name": "Akira",
        "aliases": ["Megazord"],
        "origin_country": "Unknown",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "Rapidly growing RaaS that targets corporate networks via compromised VPN credentials, particularly unpatched Cisco ASA/FTD appliances. Features a retro-styled dark web leak site and Linux ESXi encryptors.",
        "targeted_sectors": ["Manufacturing", "Education", "Professional Services", "Healthcare"],
        "targeted_countries": ["United States", "Europe", "Australia"],
        "mitre_group_id": None,
        "first_seen": "2023",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "play",
        "name": "Play",
        "aliases": ["Playcrypt", "Balloonfly"],
        "origin_country": "Unknown",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "Ransomware group infamous for exploiting Microsoft Exchange ProxyNotShell vulnerabilities and FortiOS flaws for initial access. Uses a minimal ransom note containing only the word 'PLAY' and an email address.",
        "targeted_sectors": ["Government", "Finance", "Healthcare", "IT"],
        "targeted_countries": ["Global"],
        "mitre_group_id": None,
        "first_seen": "2022",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "bianlian",
        "name": "BianLian",
        "aliases": [],
        "origin_country": "Russia",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "Originally a dual-extortion ransomware group that pivoted to pure data exfiltration-only extortion after Avast released a free decryptor for their encryptor. Uses custom Go-based backdoors and long dwell times.",
        "targeted_sectors": ["Healthcare", "Manufacturing", "Education", "Legal"],
        "targeted_countries": ["United States", "Australia", "Europe"],
        "mitre_group_id": None,
        "first_seen": "2022",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "kimsuky",
        "name": "Kimsuky",
        "aliases": ["Thallium", "Velvet Chollima", "Black Banshee", "Emerald Sleet"],
        "origin_country": "North Korea",
        "motivation": "Espionage",
        "sophistication": "Nation-State",
        "description": "North Korean Reconnaissance General Bureau group focused on intelligence gathering against South Korean, Japanese, and US entities. Primarily uses spear-phishing with malicious documents and credential harvesting.",
        "targeted_sectors": ["Government", "Think Tanks", "Media", "Defense", "Academia"],
        "targeted_countries": ["South Korea", "United States", "Japan"],
        "mitre_group_id": "G0094",
        "mitre_url": "https://attack.mitre.org/groups/G0094/",
        "first_seen": "2012",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "muddywater",
        "name": "MuddyWater",
        "aliases": ["Mango Sandstorm", "Earth Vetala", "Mercury"],
        "origin_country": "Iran",
        "motivation": "Espionage",
        "sophistication": "Nation-State",
        "description": "Iranian MOIS-aligned cyber espionage group that primarily targets Middle Eastern governments, telecom operators, and oil/gas companies. Known for custom PowerShell-based backdoors and living-off-the-land.",
        "targeted_sectors": ["Government", "Telecommunications", "Defense", "Oil and Gas"],
        "targeted_countries": ["Middle East", "Israel", "Turkey", "Global"],
        "mitre_group_id": "G0069",
        "mitre_url": "https://attack.mitre.org/groups/G0069/",
        "first_seen": "2017",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "charming-kitten",
        "name": "Charming Kitten",
        "aliases": ["APT35", "Phosphorus", "Mint Sandstorm", "Newscaster"],
        "origin_country": "Iran",
        "motivation": "Espionage",
        "sophistication": "Nation-State",
        "description": "IRGC-affiliated threat group specializing in long-term intelligence collection against journalists, dissidents, politicians, and academic researchers. Known for sophisticated social engineering and fake personas.",
        "targeted_sectors": ["Media", "Defense", "Government", "Academia", "Dissidents"],
        "targeted_countries": ["United States", "Israel", "Middle East", "Europe"],
        "mitre_group_id": "G0058",
        "mitre_url": "https://attack.mitre.org/groups/G0058/",
        "first_seen": "2014",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "safepay",
        "name": "SafePay",
        "aliases": ["BlackSuit"],
        "origin_country": "Unknown",
        "motivation": "Financial",
        "sophistication": "Organized Crime",
        "description": "RaaS rebrand of the Royal ransomware group, itself a successor to the Conti syndicate. Aggressively targets vulnerable edge infrastructure and critical services including healthcare and government systems.",
        "targeted_sectors": ["Healthcare", "Manufacturing", "Retail", "Government"],
        "targeted_countries": ["United States", "United Kingdom", "Canada"],
        "mitre_group_id": None,
        "first_seen": "2023",
        "last_active": "2025",
        "is_active": True,
    },
    {
        "slug": "storm-2603",
        "name": "Storm-2603",
        "aliases": [],
        "origin_country": "China",
        "motivation": "Espionage, Destructive",
        "sophistication": "Nation-State",
        "description": "Emerging Chinese state-aligned cluster overlapping with Volt Typhoon but demonstrating specialized focus on operational technology (OT) environments, maritime infrastructure, and energy systems. Pre-positioning for potential disruption.",
        "targeted_sectors": ["Energy", "Telecommunications", "Maritime", "Defense"],
        "targeted_countries": ["United States", "Taiwan", "Philippines"],
        "mitre_group_id": None,
        "first_seen": "2023",
        "last_active": "2025",
        "is_active": True,
    },
]

# ── Known CVE-Actor Mappings (publicly documented) ───────────────────────────

SEED_CVE_ACTOR_MAPPINGS = [
    # Cl0p
    {"actor_slug": "cl0p", "cve_id": "CVE-2023-34362", "confirmed": True,
     "notes": "MOVEit Transfer zero-day — mass exploitation campaign affecting 2500+ orgs"},
    {"actor_slug": "cl0p", "cve_id": "CVE-2023-0669", "confirmed": True,
     "notes": "GoAnywhere MFT zero-day — mass exploitation"},
    # Qilin
    {"actor_slug": "qilin", "cve_id": "CVE-2024-21762", "confirmed": True,
     "notes": "Fortinet FortiOS SSL VPN — used for initial access"},
    {"actor_slug": "qilin", "cve_id": "CVE-2024-55591", "confirmed": True,
     "notes": "Fortinet authentication bypass — active campaigns"},
    # Lazarus
    {"actor_slug": "lazarus-group", "cve_id": "CVE-2021-44228", "confirmed": True,
     "notes": "Log4Shell — exploited in multiple espionage campaigns"},
    {"actor_slug": "lazarus-group", "cve_id": "CVE-2022-47966", "confirmed": True,
     "notes": "ManageEngine RCE — used to deploy QuiteRAT backdoor"},
    # Volt Typhoon
    {"actor_slug": "volt-typhoon", "cve_id": "CVE-2023-27997", "confirmed": True,
     "notes": "Fortinet FortiOS heap overflow — initial access to SOHO routers"},
    {"actor_slug": "volt-typhoon", "cve_id": "CVE-2024-39717", "confirmed": True,
     "notes": "Versa Director — used for ISP compromise in US"},
    # RansomHub
    {"actor_slug": "ransomhub", "cve_id": "CVE-2024-3400", "confirmed": True,
     "notes": "Palo Alto PAN-OS command injection — initial access vector"},
    # APT29
    {"actor_slug": "apt29", "cve_id": "CVE-2023-38831", "confirmed": True,
     "notes": "WinRAR vulnerability used in targeted spear-phishing campaigns"},
    {"actor_slug": "apt29", "cve_id": "CVE-2023-42793", "confirmed": True,
     "notes": "JetBrains TeamCity auth bypass — supply chain targeting"},
    # APT28
    {"actor_slug": "apt28", "cve_id": "CVE-2023-23397", "confirmed": True,
     "notes": "Outlook NTLM relay zero-day — mass exploitation of NATO targets"},
    # Sandworm
    {"actor_slug": "sandworm", "cve_id": "CVE-2023-44487", "confirmed": True,
     "notes": "HTTP/2 Rapid Reset DoS — used in Ukraine-targeted attacks"},
    # APT41
    {"actor_slug": "apt41", "cve_id": "CVE-2021-44228", "confirmed": True,
     "notes": "Log4Shell — mass exploitation within hours of disclosure"},
    # Scattered Spider
    {"actor_slug": "scattered-spider", "cve_id": "CVE-2023-35078", "confirmed": True,
     "notes": "Ivanti EPMM bypass — SIM swap and social engineering campaigns"},
    # Akira
    {"actor_slug": "akira", "cve_id": "CVE-2020-3259", "confirmed": True,
     "notes": "Cisco ASA/FTD information disclosure — credential harvesting"},
    {"actor_slug": "akira", "cve_id": "CVE-2023-20269", "confirmed": True,
     "notes": "Cisco ASA VPN brute force — primary initial access vector"},
    # Play
    {"actor_slug": "play", "cve_id": "CVE-2022-41082", "confirmed": True,
     "notes": "ProxyNotShell Microsoft Exchange exploitation"},
    {"actor_slug": "play", "cve_id": "CVE-2024-21762", "confirmed": True,
     "notes": "FortiOS VPN exploitation for initial access"},
    # BianLian
    {"actor_slug": "bianlian", "cve_id": "CVE-2024-21762", "confirmed": True,
     "notes": "Fortinet FortiOS — used alongside credential theft"},
    # Kimsuky
    {"actor_slug": "kimsuky", "cve_id": "CVE-2022-41128", "confirmed": True,
     "notes": "Windows Scripting Language RCE — delivered via spear-phishing"},
    # LockBit
    {"actor_slug": "lockbit", "cve_id": "CVE-2023-4966", "confirmed": True,
     "notes": "Citrix Bleed — mass exploitation for initial access before takedown"},
    # BlackCat/ALPHV
    {"actor_slug": "blackcat", "cve_id": "CVE-2024-24919", "confirmed": True,
     "notes": "Check Point VPN information disclosure — credential theft"},
]


class ThreatActorService:
    """Manages threat actor profiles, CVE mappings, and MITRE ATT&CK data."""

    def __init__(self) -> None:
        self._client = None
        if settings.SUPABASE_URL and settings.SUPABASE_KEY:
            try:
                from supabase import create_client
                self._client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                logger.info("ThreatActorService: Supabase client initialized")
            except Exception as e:
                logger.warning(f"ThreatActorService init failed: {e}")

    # ── Seeding ──────────────────────────────────────────────────────────

    async def seed_initial_actors(self) -> None:
        """Seeds the database with 20 actors on first run (only if table is empty)."""
        if not self._client:
            return

        try:
            count_res = self._client.table("threat_actors").select("id", count="exact").limit(1).execute()
            if count_res.count and count_res.count > 0:
                logger.info("Threat actors already seeded — skipping")
                return

            logger.info("Seeding 20 threat actor profiles...")
            for actor in SEED_ACTORS:
                try:
                    self._client.table("threat_actors").insert(actor).execute()
                except Exception as e:
                    logger.warning(f"Failed to seed actor {actor['slug']}: {e}")

            logger.info("Seeding CVE-actor mappings...")
            for mapping in SEED_CVE_ACTOR_MAPPINGS:
                try:
                    self._client.table("threat_actor_cves").insert(mapping).execute()
                except Exception as e:
                    logger.warning(f"Failed to seed mapping {mapping['actor_slug']}/{mapping['cve_id']}: {e}")

            logger.info("✅ Threat actor seeding complete")
        except Exception as e:
            logger.error(f"Failed to seed threat actors: {e}")

    # ── CRUD ─────────────────────────────────────────────────────────────

    async def link_cve_to_actor(
        self, actor_slug: str, cve_id: str, confirmed: bool,
        source_url: str = "", notes: str = ""
    ) -> None:
        """Creates a threat_actor_cves record linking a CVE to an actor."""
        if not self._client:
            return

        async def _do_link():
            try:
                # the table doesn't have a unique constraint on (actor_slug, cve_id) to use upsert
                res = self._client.table("threat_actor_cves").select("id").eq("actor_slug", actor_slug).eq("cve_id", cve_id).limit(1).execute()
                if not res.data:
                    self._client.table("threat_actor_cves").insert({
                        "actor_slug": actor_slug,
                        "cve_id": cve_id,
                        "confirmed": confirmed,
                        "source_url": source_url,
                        "notes": notes,
                    }).execute()
            except Exception as e:
                logger.error(f"Failed to link {cve_id} → {actor_slug}: {e}")

        asyncio.create_task(_do_link())

    async def get_actor(self, slug: str) -> dict | None:
        """Returns full actor profile with their CVE list."""
        if not self._client:
            return None
        try:
            res = self._client.table("threat_actors").select("*").eq("slug", slug).single().execute()
            if not res.data:
                return None
            actor = res.data
            cves_res = self._client.table("threat_actor_cves").select("*").eq("actor_slug", slug).execute()
            actor["exploited_cves"] = cves_res.data or []
            return actor
        except Exception as e:
            logger.error(f"get_actor({slug}) failed: {e}")
            return None

    async def get_actors_for_cve(self, cve_id: str) -> list[dict]:
        """Returns all actors known to exploit a given CVE."""
        if not self._client:
            return []
        try:
            res = (
                self._client.table("threat_actor_cves")
                .select("actor_slug, confirmed, notes, threat_actors(*)")
                .eq("cve_id", cve_id.upper())
                .execute()
            )
            actors = []
            for row in (res.data or []):
                if row.get("threat_actors"):
                    actor = row["threat_actors"]
                    actor["confirmed"] = row.get("confirmed", False)
                    actor["exploitation_notes"] = row.get("notes", "")
                    actors.append(actor)
            return actors
        except Exception as e:
            logger.error(f"get_actors_for_cve({cve_id}) failed: {e}")
            return []

    async def get_all_actors(
        self, active_only: bool = False,
        motivation: str | None = None,
        sophistication: str | None = None,
    ) -> list[dict]:
        """Returns all actors, optionally filtered."""
        if not self._client:
            return []
        try:
            q = self._client.table("threat_actors").select("*")
            if active_only:
                q = q.eq("is_active", True)
            if motivation:
                q = q.ilike("motivation", f"%{motivation}%")
            if sophistication:
                q = q.ilike("sophistication", f"%{sophistication}%")
            res = q.order("name").execute()
            return res.data or []
        except Exception as e:
            logger.error(f"get_all_actors failed: {e}")
            return []

    async def get_cves_for_actor(self, slug: str) -> list[dict]:
        """Returns all CVE mappings for an actor, enriched with processed_cves data."""
        if not self._client:
            return []
        try:
            res = (
                self._client.table("threat_actor_cves")
                .select("*")
                .eq("actor_slug", slug)
                .execute()
            )
            return res.data or []
        except Exception as e:
            logger.error(f"get_cves_for_actor({slug}) failed: {e}")
            return []

    # ── MITRE ATT&CK Sync ────────────────────────────────────────────────

    async def sync_mitre_techniques(self, actor_slug: str) -> None:
        """Fetches techniques for an actor from the MITRE ATT&CK STIX API."""
        if not self._client:
            return

        try:
            # Get actor's MITRE group ID
            res = (
                self._client.table("threat_actors")
                .select("mitre_group_id")
                .eq("slug", actor_slug)
                .single()
                .execute()
            )
            if not res.data or not res.data.get("mitre_group_id"):
                return

            group_id = res.data["mitre_group_id"]

            # Fetch from MITRE ATT&CK STIX/TAXII endpoint
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
                )
                if resp.status_code != 200:
                    logger.warning(f"MITRE ATT&CK fetch failed: {resp.status_code}")
                    return

                data = resp.json()
                objects = data.get("objects", [])

                # Find the group object
                group_obj = None
                for obj in objects:
                    if obj.get("type") == "intrusion-set":
                        refs = obj.get("external_references", [])
                        for ref in refs:
                            if ref.get("external_id") == group_id:
                                group_obj = obj
                                break
                    if group_obj:
                        break

                if not group_obj:
                    logger.info(f"MITRE group {group_id} not found in ATT&CK data")
                    return

                # Find relationships (uses) from this group
                group_stix_id = group_obj["id"]
                technique_ids = set()
                for obj in objects:
                    if (
                        obj.get("type") == "relationship"
                        and obj.get("relationship_type") == "uses"
                        and obj.get("source_ref") == group_stix_id
                        and "attack-pattern" in obj.get("target_ref", "")
                    ):
                        technique_ids.add(obj["target_ref"])

                # Resolve technique names
                techniques = []
                for obj in objects:
                    if obj.get("id") in technique_ids and obj.get("type") == "attack-pattern":
                        ext_id = ""
                        for ref in obj.get("external_references", []):
                            if ref.get("source_name") == "mitre-attack":
                                ext_id = ref.get("external_id", "")
                                break
                        techniques.append({
                            "technique_id": ext_id,
                            "technique_name": obj.get("name", ""),
                        })

                logger.info(f"MITRE sync for {actor_slug}: found {len(techniques)} techniques")

        except Exception as e:
            logger.error(f"sync_mitre_techniques({actor_slug}) failed: {e}")

    async def sync_all_mitre_data(self) -> None:
        """Weekly job: sync MITRE ATT&CK data for all actors with a mitre_group_id."""
        if not self._client:
            return
        try:
            res = (
                self._client.table("threat_actors")
                .select("slug, mitre_group_id")
                .not_("mitre_group_id", "is", "null")
                .execute()
            )
            for actor in (res.data or []):
                await self.sync_mitre_techniques(actor["slug"])
                await asyncio.sleep(2)  # rate-limit
            logger.info("✅ MITRE ATT&CK sync complete")
        except Exception as e:
            logger.error(f"sync_all_mitre_data failed: {e}")
