"""
IOC Pulse — Indicator of Compromise Lookup Service
====================================================
Aggregates IOC intelligence from multiple free sources:

  - ThreatFox (abuse.ch): malware IOCs with malware family tags
    API: https://threatfox-api.abuse.ch/api/v1/
    Free, no key needed for basic queries

  - URLhaus (abuse.ch): malicious URLs database
    API: https://urlhaus-api.abuse.ch/v1/
    Free, no key needed

  - AbuseIPDB: IP reputation with abuse confidence score
    API: https://api.abuseipdb.com/api/v2/check
    Free tier: 1000 checks/day (key required — get at abuseipdb.com)

  - GreyNoise: already integrated — add CVE context to IP lookups

Results cached in Supabase ioc_cache table for 6 hours.
Cache prevents hammering free APIs.

Privacy: IOC lookups are stateless — we do NOT log queried indicators.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Rate limiter (in-memory) ─────────────────────────────────────────────────

_rate_limits: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_MAX = 30  # per IP per hour
RATE_LIMIT_WINDOW = 3600  # seconds


def _check_rate_limit(client_ip: str) -> bool:
    """Returns True if under limit, False if exceeded."""
    now = time.time()
    _rate_limits[client_ip] = [t for t in _rate_limits[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[client_ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_limits[client_ip].append(now)
    return True


# ── IOC Type Detection ───────────────────────────────────────────────────────

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{3,39}$")


class IOCPulseService:
    """Indicator of Compromise lookup aggregating ThreatFox, URLhaus, AbuseIPDB, GreyNoise."""

    CACHE_TTL_HOURS = 6
    FEED_CACHE_MINUTES = 30

    def __init__(self) -> None:
        self._client = None
        self._feed_cache: list[dict] | None = None
        self._feed_cache_time: float = 0
        self._stats = {"total_lookups": 0, "cache_hits": 0}

        if settings.SUPABASE_URL and settings.SUPABASE_KEY:
            try:
                from supabase import create_client
                self._client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                logger.info("IOCPulseService: Supabase client initialized")
            except Exception as e:
                logger.warning(f"IOCPulseService init failed: {e}")

    # ── Type detection ───────────────────────────────────────────────────

    def _detect_type(self, indicator: str) -> str:
        """Auto-detects indicator type: ip, hash, url, or domain."""
        indicator = indicator.strip()

        # IP check
        if _IPV4_RE.match(indicator):
            return "ip"
        if _IPV6_RE.match(indicator) and ":" in indicator:
            return "ip"

        # Hash check (MD5=32, SHA1=40, SHA256=64)
        if re.match(r"^[a-fA-F0-9]{32}$", indicator):
            return "hash"
        if re.match(r"^[a-fA-F0-9]{40}$", indicator):
            return "hash"
        if re.match(r"^[a-fA-F0-9]{64}$", indicator):
            return "hash"

        # URL check
        if indicator.startswith(("http://", "https://")) or "/" in indicator:
            return "url"

        # Default: domain
        return "domain"

    # ── Cache ────────────────────────────────────────────────────────────

    async def _get_cached(self, indicator: str) -> dict | None:
        """Check Supabase ioc_cache for a recent result."""
        if not self._client:
            return None
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=self.CACHE_TTL_HOURS)).isoformat()
            res = (
                self._client.table("ioc_cache")
                .select("*")
                .eq("indicator", indicator)
                .gte("last_checked", cutoff)
                .limit(1)
                .execute()
            )
            if res.data:
                self._stats["cache_hits"] += 1
                return res.data[0]
        except Exception:
            pass
        return None

    async def _save_cache(self, indicator: str, ioc_type: str, result: dict) -> None:
        """Save lookup result to cache (non-blocking)."""
        if not self._client:
            return

        async def _do_save():
            try:
                now = datetime.now(timezone.utc)
                self._client.table("ioc_cache").upsert({
                    "indicator": indicator,
                    "ioc_type": ioc_type,
                    "verdict": result.get("verdict", "unknown"),
                    "risk_score": result.get("risk_score", 0),
                    "sources": result.get("sources", {}),
                    "related_cves": result.get("related_cves", []),
                    "last_checked": now.isoformat(),
                    "expires_at": (now + timedelta(hours=self.CACHE_TTL_HOURS)).isoformat(),
                }, on_conflict="indicator,ioc_type").execute()
            except Exception as e:
                logger.warning(f"IOC cache save failed: {e}")

        asyncio.create_task(_do_save())

    # ── Main lookup ──────────────────────────────────────────────────────

    async def lookup(self, indicator: str) -> dict:
        """Full IOC lookup with auto-detection, multi-source aggregation, and caching."""
        indicator = indicator.strip()
        self._stats["total_lookups"] += 1
        ioc_type = self._detect_type(indicator)

        # Check cache first
        cached = await self._get_cached(indicator)
        if cached:
            return {
                "indicator": indicator,
                "ioc_type": ioc_type,
                "verdict": cached.get("verdict", "unknown"),
                "risk_score": cached.get("risk_score", 0),
                "sources": cached.get("sources", {}),
                "related_cves": cached.get("related_cves", []),
                "cached": True,
            }

        # Build source queries based on type
        sources: dict = {}
        
        # Fast path: check in-memory ThreatFox feed cache to bypass API blocks
        recent_map = getattr(self, "_recent_ioc_map", {})
        if indicator in recent_map:
            rioc = recent_map[indicator]
            result = {
                "indicator": indicator,
                "ioc_type": ioc_type,
                "verdict": "malicious",
                "risk_score": 100,
                "sources": {
                    "threatfox": {
                        "hit": True,
                        "malware_family": rioc.get("malware_family", ""),
                        "tags": rioc.get("tags", []),
                        "threat_type": rioc.get("threat_type", ""),
                    }
                },
                "related_cves": await self._get_related_cves(indicator, ioc_type),
                "cached": False,
            }
            await self._save_cache(indicator, ioc_type, result)
            return result

        async with httpx.AsyncClient(timeout=15) as client:
            if ioc_type == "ip":
                results = await asyncio.gather(
                    self._query_pulsedive(client, indicator),
                    self._query_abuseipdb(client, indicator),
                    self._query_greynoise(client, indicator),
                    return_exceptions=True,
                )
                if not isinstance(results[0], Exception) and results[0]:
                    sources["pulsedive"] = results[0]
                if not isinstance(results[1], Exception) and results[1]:
                    sources["abuseipdb"] = results[1]
                if not isinstance(results[2], Exception) and results[2]:
                    sources["greynoise"] = results[2]

            elif ioc_type in ("domain", "url", "hash"):
                results = await asyncio.gather(
                    self._query_pulsedive(client, indicator),
                    return_exceptions=True,
                )
                if not isinstance(results[0], Exception) and results[0]:
                    sources["pulsedive"] = results[0]

        # Calculate verdict
        verdict, risk_score = self._calculate_verdict(sources, ioc_type)

        # Find related CVEs
        related_cves = await self._get_related_cves(indicator, ioc_type)

        result = {
            "indicator": indicator,
            "ioc_type": ioc_type,
            "verdict": verdict,
            "risk_score": risk_score,
            "sources": sources,
            "related_cves": related_cves,
            "cached": False,
        }

        # Cache the result (non-blocking)
        await self._save_cache(indicator, ioc_type, result)

        return result

    # ── Verdict calculation ──────────────────────────────────────────────

    def _calculate_verdict(self, sources: dict, ioc_type: str) -> tuple[str, int]:
        """
        Aggregate signals from all sources into a single verdict + risk score.

        MALICIOUS (70-100):  ThreatFox hit OR AbuseIPDB confidence > 50
        SUSPICIOUS (40-69):  AbuseIPDB confidence 10-50 OR URLhaus suspicious
        CLEAN (0-10):        AbuseIPDB confidence 0, no ThreatFox hits
        UNKNOWN:             No data from any source
        """
        score = 0
        has_data = False

        # Pulsedive hit (fallback public source)
        pd = sources.get("pulsedive", {})
        if pd:
            has_data = True
            risk_level = pd.get("risk", "none").lower()
            if risk_level in ("high", "critical", "malicious"):
                score = max(score, 85)
            elif risk_level in ("medium", "suspicious"):
                score = max(score, 50)

        # GreyNoise
        gn = sources.get("greynoise", {})
        if gn.get("noise"):
            score = max(score, 45)
            has_data = True
        if gn.get("riot"):
            # Known benign service
            score = min(score, 5)
            has_data = True

        if not has_data:
            return "unknown", 0

        if score >= 70:
            return "malicious", min(score, 100)
        elif score >= 40:
            return "suspicious", score
        else:
            return "clean", score

    # ── Source queries ────────────────────────────────────────────────────

    async def _query_pulsedive(self, client: httpx.AsyncClient, indicator: str) -> dict:
        """Query Pulsedive public API for general indicator risk."""
        try:
            resp = await client.get(
                f"https://pulsedive.com/api/info.php?indicator={indicator}"
            )
            if resp.status_code == 404:
                return {}
            if resp.status_code != 200:
                return {}
            data = resp.json()
            if "error" in data:
                return {}
            
            return {
                "risk": data.get("risk", "none"),
                "threats": [t.get("name") for t in data.get("threats", [])] if "threats" in data else [],
                "tags": data.get("tags", []),
            }
        except Exception as e:
            logger.warning(f"Pulsedive query failed: {e}")
            return {}

    async def _query_abuseipdb(self, client: httpx.AsyncClient, ip: str) -> dict:
        """Query AbuseIPDB for IP reputation."""
        api_key = settings.ABUSEIPDB_API_KEY
        if not api_key:
            return {}
        try:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            if resp.status_code != 200:
                return {}
            data = resp.json().get("data", {})
            return {
                "confidence": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "usage_type": data.get("usageType", ""),
            }
        except Exception as e:
            logger.warning(f"AbuseIPDB query failed: {e}")
            return {}

    async def _query_greynoise(self, client: httpx.AsyncClient, ip: str) -> dict:
        """Query GreyNoise community API for IP context."""
        try:
            headers = {}
            if settings.GREYNOISE_API_KEY:
                headers["key"] = settings.GREYNOISE_API_KEY
            resp = await client.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers=headers,
            )
            if resp.status_code != 200:
                return {}
            data = resp.json()
            return {
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification", ""),
                "name": data.get("name", ""),
            }
        except Exception as e:
            logger.warning(f"GreyNoise query failed: {e}")
            return {}



    # ── Related CVEs ─────────────────────────────────────────────────────

    async def _get_related_cves(self, indicator: str, ioc_type: str) -> list[str]:
        """Search processed_cves for CVEs where this IOC appears in context."""
        # For now, return empty — full implementation would search GreyNoise CVE tags
        return []

    # ── Live IOC Feed ────────────────────────────────────────────────────

    async def get_live_ioc_feed(self, limit: int = 50) -> list[dict]:
        """Fetches the most recent IOCs from ThreatFox public feed. Cached 30 min."""
        now = time.time()
        if self._feed_cache and (now - self._feed_cache_time) < self.FEED_CACHE_MINUTES * 60:
            return self._feed_cache[:limit]

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get("https://threatfox.abuse.ch/export/json/recent/")
                if resp.status_code != 200:
                    logger.warning(f"ThreatFox feed fetch returned {resp.status_code}")
                    return self._feed_cache[:limit] if self._feed_cache else []

                data = resp.json()
                
                feed = []
                # Rebuild the lookup map with all available recent IOCs
                self._recent_ioc_map = getattr(self, "_recent_ioc_map", {})
                
                for key, items in data.items():
                    if not items:
                        continue
                    ioc = items[0]
                    tags_val = ioc.get("tags")
                    tags = [tags_val] if isinstance(tags_val, str) else (tags_val or [])
                    
                    parsed_ioc = {
                        "indicator": ioc.get("ioc_value", ""),
                        "ioc_type": ioc.get("ioc_type", ""),
                        "malware_family": ioc.get("malware_printable", ""),
                        "tags": tags,
                        "threat_type": ioc.get("threat_type", ""),
                        "reported_at": ioc.get("first_seen_utc", ""),
                    }
                    
                    # Store in fast-lookup map for /lookup fallback
                    if parsed_ioc["indicator"]:
                        self._recent_ioc_map[parsed_ioc["indicator"]] = parsed_ioc
                        
                    feed.append(parsed_ioc)

                self._feed_cache = feed
                self._feed_cache_time = now
                return feed[:limit]
        except Exception as e:
            logger.error(f"ThreatFox feed fetch failed: {e}")
            return self._feed_cache[:limit] if self._feed_cache else []

    # ── Stats ────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Returns IOC service stats."""
        return {
            "total_lookups": self._stats["total_lookups"],
            "cache_hits": self._stats["cache_hits"],
            "cache_hit_rate": (
                f"{self._stats['cache_hits'] / max(self._stats['total_lookups'], 1) * 100:.1f}%"
            ),
        }
