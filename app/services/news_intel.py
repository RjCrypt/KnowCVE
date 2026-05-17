"""
Security News Intelligence
===========================
Aggregates security news from RSS feeds, extracts CVEs and threat actor
mentions, generates AI summaries, and links articles to KnowCVE data.

Processing pipeline per article:
  1. Download RSS feeds concurrently, parse with feedparser (in executor)
  2. Regex extract CVE IDs (CVE-YYYY-NNNNN pattern)
  3. Match threat actor names against threat_actors table
  4. AI summarize (use lightweight Groq call, ~200 tokens max)
  5. Store in security_news table
  6. Link to processed_cves for mentioned CVEs

IMPORTANT: feedparser is synchronous — always run in asyncio.run_in_executor()
"""

from __future__ import annotations

import asyncio
import logging
import re
import html
from datetime import datetime, timezone

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── RSS Feed Sources ─────────────────────────────────────────────────────────

RSS_SOURCES = [
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed_full.xml"},
    {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/advisories.xml"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "Schneier on Security", "url": "https://www.schneier.com/feed/atom/"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
    {"name": "SecurityWeek", "url": "https://feeds.feedburner.com/securityweek"},
    {"name": "Threat Post", "url": "https://threatpost.com/feed/"},
    {"name": "Recorded Future", "url": "https://www.recordedfuture.com/feed"},
    {"name": "US-CERT Alerts", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
    {"name": "Naked Security", "url": "https://nakedsecurity.sophos.com/feed/"},
    {"name": "Graham Cluley", "url": "https://grahamcluley.com/feed/"},
    {"name": "CyberScoop", "url": "https://cyberscoop.com/feed/"},
    {"name": "The Register Security", "url": "https://www.theregister.com/security/headlines.atom"},
]

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

FEED_TIMEOUT = 10  # seconds per feed — never block on a slow source


class NewsIntelService:
    """Aggregates security news from RSS, extracts CVEs, AI-summarizes."""

    def __init__(self) -> None:
        self._client = None
        self._known_actors: list[dict] | None = None
        self._briefing_cache: str | None = None
        self._briefing_date: str | None = None

        if settings.SUPABASE_URL and settings.SUPABASE_KEY:
            try:
                from supabase import create_client
                self._client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                logger.info("NewsIntelService: Supabase client initialized")
            except Exception as e:
                logger.warning(f"NewsIntelService init failed: {e}")

    # ── CVE/Actor extraction ─────────────────────────────────────────────

    def _extract_cves(self, text: str) -> list[str]:
        """Regex-extract all CVE IDs from text, deduplicated and uppercased."""
        if not text:
            return []
        return list(set(m.upper() for m in CVE_PATTERN.findall(text)))

    def _extract_actor_mentions(self, text: str, known_actors: list[dict]) -> list[str]:
        """Check text for mentions of known actor names and aliases."""
        if not text or not known_actors:
            return []
        text_lower = text.lower()
        found = []
        for actor in known_actors:
            # Check name
            if actor.get("name", "").lower() in text_lower:
                found.append(actor["name"])
                continue
            # Check aliases
            for alias in actor.get("aliases", []):
                if alias.lower() in text_lower:
                    found.append(actor["name"])
                    break
        return list(set(found))

    # ── AI Summarization ─────────────────────────────────────────────────

    async def ai_summarize(self, title: str, description: str) -> str:
        """Summarize a news article in 2 sentences using existing AI chain."""
        text = f"{title}. {description}"[:2000]

        # Try Groq → Cerebras → Gemini fallback
        for provider in self._get_ai_providers():
            try:
                summary = await provider(text)
                if summary:
                    return summary
            except Exception:
                continue

        return ""

    def _get_ai_providers(self):
        """Returns list of AI summarization callables in priority order."""
        providers = []

        if settings.GROQ_API_KEY:
            providers.append(self._summarize_groq)
        if settings.CEREBRAS_API_KEY:
            providers.append(self._summarize_cerebras)
        if settings.GEMINI_API_KEY:
            providers.append(self._summarize_gemini)

        return providers

    async def _summarize_groq(self, text: str) -> str:
        """Summarize via Groq."""
        from groq import AsyncGroq
        client = AsyncGroq(api_key=settings.GROQ_API_KEY)
        resp = await client.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=[
                {"role": "system", "content": "Summarize this cybersecurity news article in 2 sentences. Focus on: what happened, what was exploited, who was affected. Be concise."},
                {"role": "user", "content": text},
            ],
            max_tokens=200,
            temperature=0.3,
        )
        return resp.choices[0].message.content.strip()

    async def _summarize_cerebras(self, text: str) -> str:
        """Summarize via Cerebras."""
        from cerebras.cloud.sdk import AsyncCerebras
        client = AsyncCerebras(api_key=settings.CEREBRAS_API_KEY)
        resp = await client.chat.completions.create(
            model="llama-3.3-70b",
            messages=[
                {"role": "system", "content": "Summarize this cybersecurity news article in 2 sentences. Focus on: what happened, what was exploited, who was affected. Be concise."},
                {"role": "user", "content": text},
            ],
            max_tokens=200,
            temperature=0.3,
        )
        return resp.choices[0].message.content.strip()

    async def _summarize_gemini(self, text: str) -> str:
        """Summarize via Google Gemini."""
        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-2.0-flash")
        resp = await asyncio.to_thread(
            model.generate_content,
            f"Summarize this cybersecurity news article in 2 sentences. Focus on: what happened, what was exploited, who was affected. Be concise.\n\n{text}",
        )
        return resp.text.strip()

    # ── Feed Fetching ────────────────────────────────────────────────────

    async def _fetch_single_feed(self, source: dict) -> list[dict]:
        """Fetch and parse a single RSS feed. Runs feedparser in executor."""
        import feedparser

        try:
            async with httpx.AsyncClient(timeout=FEED_TIMEOUT) as client:
                resp = await client.get(source["url"])
                if resp.status_code != 200:
                    logger.warning(f"Feed {source['name']}: HTTP {resp.status_code}")
                    return []

            # feedparser is synchronous — run in executor
            loop = asyncio.get_running_loop()
            parsed = await loop.run_in_executor(None, feedparser.parse, resp.text)

            articles = []
            for entry in parsed.entries:
                title = html.unescape(entry.get("title", "").strip())
                if not title:
                    continue

                # Get description text
                desc = ""
                if entry.get("summary"):
                    desc = entry.summary
                elif entry.get("description"):
                    desc = entry.description

                # Strip HTML tags from description and unescape
                desc = html.unescape(re.sub(r"<[^>]+>", "", desc).strip())[:3000]

                # Published date
                pub = entry.get("published_parsed") or entry.get("updated_parsed")
                if pub:
                    try:
                        pub_dt = datetime(*pub[:6], tzinfo=timezone.utc).isoformat()
                    except Exception:
                        pub_dt = datetime.now(timezone.utc).isoformat()
                else:
                    pub_dt = datetime.now(timezone.utc).isoformat()

                url = entry.get("link", "")

                # Extract CVEs and actors
                full_text = f"{title} {desc}"
                cves = self._extract_cves(full_text)
                actors = self._extract_actor_mentions(full_text, self._known_actors or [])

                articles.append({
                    "title": title[:500],
                    "url": url,
                    "source": source["name"],
                    "published_at": pub_dt,
                    "raw_description": desc[:2000],  # temp field for AI summarization, not inserted
                    "mentioned_cves": cves,
                    "mentioned_actors": actors,
                    "tags": [],
                })

            return articles
        except asyncio.TimeoutError:
            logger.warning(f"Feed {source['name']}: timeout after {FEED_TIMEOUT}s")
            return []
        except Exception as e:
            logger.warning(f"Feed {source['name']}: {e}")
            return []

    async def fetch_all_feeds(self) -> None:
        """Downloads all RSS feeds concurrently, deduplicates, stores new articles."""
        logger.info("📰 Fetching security news from all feeds...")

        # Load known actors for mention matching
        if self._client:
            try:
                res = self._client.table("threat_actors").select("name, aliases").execute()
                self._known_actors = res.data or []
            except Exception:
                self._known_actors = []

        # Fetch all feeds concurrently
        tasks = [self._fetch_single_feed(src) for src in RSS_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_articles = []
        for result in results:
            if isinstance(result, Exception):
                continue
            all_articles.extend(result)

        logger.info(f"Fetched {len(all_articles)} articles across {len(RSS_SOURCES)} feeds")

        if not self._client or not all_articles:
            return

        # Deduplicate by URL against existing DB entries
        try:
            urls = [a["url"] for a in all_articles if a["url"]]
            existing_res = (
                self._client.table("security_news")
                .select("url")
                .in_("url", urls[:200])  # Supabase limit
                .execute()
            )
            existing_urls = {r["url"] for r in (existing_res.data or [])}
            new_articles = [a for a in all_articles if a["url"] and a["url"] not in existing_urls]
        except Exception as e:
            logger.warning(f"Dedup check failed, inserting all: {e}")
            new_articles = all_articles

        if not new_articles:
            logger.info("No new articles to insert")
            return

        # AI summarize (batch, with rate limiting)
        for article in new_articles[:20]:  # Limit AI calls per batch
            try:
                summary = await self.ai_summarize(article["title"], article.get("raw_description", ""))
                article["summary"] = summary
                article["ai_processed"] = bool(summary)
            except Exception:
                article["summary"] = ""
                article["ai_processed"] = False

        # Insert new articles
        inserted = 0
        for article in new_articles:
            try:
                self._client.table("security_news").insert({
                    "title": article["title"],
                    "url": article["url"],
                    "source": article["source"],
                    "published_at": article["published_at"],
                    "summary": article.get("summary", ""),
                    "mentioned_cves": article["mentioned_cves"],
                    "mentioned_actors": article["mentioned_actors"],
                    "tags": article.get("tags", []),
                    "ai_processed": article.get("ai_processed", False),
                }).execute()
                inserted += 1
            except Exception as e:
                logger.warning(f"Failed to insert article '{article['title'][:50]}': {e}")

        logger.info(f"✅ Inserted {inserted} new articles")

    # ── Query Methods ────────────────────────────────────────────────────

    async def get_articles_for_cve(self, cve_id: str) -> list[dict]:
        """Returns all news articles mentioning this CVE."""
        if not self._client:
            return []
        try:
            res = (
                self._client.table("security_news")
                .select("*")
                .contains("mentioned_cves", [cve_id.upper()])
                .order("published_at", desc=True)
                .limit(10)
                .execute()
            )
            data = res.data or []
            for item in data:
                if item.get("title"):
                    item["title"] = html.unescape(item["title"])
                if item.get("summary"):
                    item["summary"] = html.unescape(item["summary"])
            return data
        except Exception as e:
            logger.warning(f"get_articles_for_cve({cve_id}) failed: {e}")
            return []

    async def get_sources(self) -> list[dict]:
        """Returns configured RSS sources with article counts."""
        sources = []
        for src in RSS_SOURCES:
            entry = {"name": src["name"], "url": src["url"], "article_count": 0}
            if self._client:
                try:
                    res = (
                        self._client.table("security_news")
                        .select("id", count="exact")
                        .eq("source", src["name"])
                        .execute()
                    )
                    entry["article_count"] = res.count or 0
                except Exception:
                    pass
            sources.append(entry)
        return sources

    # ── Daily Briefing ───────────────────────────────────────────────────

    async def get_daily_briefing(self) -> str:
        """Generates a daily digest formatted for Telegram and Dashboard."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Removed aggressive daily cache so the dashboard always gets live data


        if not self._client:
            return "📰 KnowCVE Daily Briefing — No data available."

        try:
            # Get today's critical CVEs count
            cve_count = 0
            try:
                cve_res = (
                    self._client.table("processed_cves")
                    .select("cve_id", count="exact")
                    .gte("published_date", f"{today}T00:00:00Z")
                    .gte("priority_score", 70)
                    .execute()
                )
                cve_count = cve_res.count or 0
            except Exception:
                pass

            # Get active campaign count
            campaign_count = 0
            try:
                camp_res = (
                    self._client.table("ransomware_campaigns")
                    .select("id", count="exact")
                    .eq("status", "active")
                    .execute()
                )
                campaign_count = camp_res.count or 0
            except Exception:
                pass

            # Get top 5 recent articles
            articles = []
            try:
                art_res = (
                    self._client.table("security_news")
                    .select("title, summary, source")
                    .order("published_at", desc=True)
                    .limit(5)
                    .execute()
                )
                articles = art_res.data or []
            except Exception:
                pass

            # Build briefing text with Key Insights
            lines = [
                f"📰 KnowCVE Daily Executive Briefing — {today}",
                "",
                "📊 Global Threat Landscape:",
                f" • 🔴 Critical CVEs Detected: {cve_count}",
                f" • 🦠 Active Ransomware Campaigns: {campaign_count}",
                f" • 📡 Fresh Intel Reports Analyzed: {len(articles)}",
                "",
                "💡 Key Intelligence Insights:",
            ]
            
            # Show just the summaries for a brief read instead of duplicating titles
            added_insights = 0
            for art in articles:
                summary = art.get("summary", "").strip()
                if summary:
                    # Clean up and ensure it's unescaped
                    clean_summary = html.unescape(summary)
                    lines.append(f" • {clean_summary}\n")
                    added_insights += 1
                if added_insights >= 3:
                    break
                    
            if not added_insights:
                lines.append(" • Monitoring feeds for fresh analytical summaries...")

            briefing = "\n".join(lines)
            self._briefing_cache = briefing
            self._briefing_date = today
            return briefing

        except Exception as e:
            logger.error(f"get_daily_briefing failed: {e}")
            return "📰 KnowCVE Daily Briefing — Error generating briefing."
