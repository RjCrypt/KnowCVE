"""Telegram bot — commands, subscriber management, alert broadcasting with modes."""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

from app.core.config import settings
from app.models.cve import ProcessedCVE, UserSubscription

logger = logging.getLogger(__name__)

# Alert mode thresholds
MODE_THRESHOLDS = {
    "continuous": 25,   # all triaged CVEs (MEDIUM+)
    "important": 50,    # HIGH + CRITICAL
    "critical": 75,     # CRITICAL + KEV only
}


class TelegramAlertBot:
    """Manages Telegram bot commands and broadcasts CVE alerts to subscribers."""

    def __init__(self) -> None:
        self.token = settings.TELEGRAM_BOT_TOKEN
        self.app: Application | None = None
        self._subscribers: dict[int, UserSubscription] = {}
        self._poller = None
        self._news_intel = None
        self._threat_actors = None
        self._ransomware = None
        self._breach_intel = None
        self._ioc_pulse = None

    @property
    def subscribers_count(self) -> int:
        return len(self._subscribers)

    def set_poller(self, poller) -> None:
        """Link the poller so /latest and /stats can access data."""
        self._poller = poller

    def set_news_intel(self, news_intel) -> None:
        """Link the news intel service for /briefing command."""
        self._news_intel = news_intel

    def set_threat_actors(self, threat_actors) -> None:
        self._threat_actors = threat_actors

    def set_ransomware(self, ransomware) -> None:
        self._ransomware = ransomware

    def set_breach_intel(self, breach_intel) -> None:
        self._breach_intel = breach_intel

    def set_ioc_pulse(self, ioc_pulse) -> None:
        self._ioc_pulse = ioc_pulse

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Build the bot application and start polling Telegram."""
        if not self.token:
            logger.warning("TELEGRAM_BOT_TOKEN not set — bot disabled")
            return

        self.app = Application.builder().token(self.token).build()

        # Register command handlers
        self.app.add_handler(CommandHandler("start", self._cmd_start))
        self.app.add_handler(CommandHandler("help", self._cmd_help))
        self.app.add_handler(CommandHandler("subscribe", self._cmd_subscribe))
        self.app.add_handler(CommandHandler("unsubscribe", self._cmd_unsubscribe))
        self.app.add_handler(CommandHandler("latest", self._cmd_latest))
        self.app.add_handler(CommandHandler("stats", self._cmd_stats))
        self.app.add_handler(CommandHandler("mode", self._cmd_mode))
        self.app.add_handler(CommandHandler("pause", self._cmd_pause))
        self.app.add_handler(CommandHandler("resume", self._cmd_resume))
        self.app.add_handler(CommandHandler("digest", self._cmd_digest))
        self.app.add_handler(CommandHandler("briefing", self._cmd_briefing))
        # Phase 5 intelligence commands
        self.app.add_handler(CommandHandler("news", self._cmd_news))
        self.app.add_handler(CommandHandler("actors", self._cmd_actors))
        self.app.add_handler(CommandHandler("ransomware", self._cmd_ransomware))
        self.app.add_handler(CommandHandler("breaches", self._cmd_breaches))
        self.app.add_handler(CommandHandler("ioc", self._cmd_ioc))
        self.app.add_handler(CallbackQueryHandler(self._handle_mode_callback, pattern="^mode_"))

        await self.app.initialize()
        await self.app.start()
        await self.app.updater.start_polling(drop_pending_updates=True)
        logger.info("Telegram bot started")

    async def stop(self) -> None:
        if self.app and self.app.running:
            await self.app.updater.stop()
            await self.app.stop()
            await self.app.shutdown()
            logger.info("Telegram bot stopped")

    # ── alert broadcast ───────────────────────────────────────────────────

    async def broadcast_alert(self, cve: ProcessedCVE) -> int:
        """Send a formatted alert to subscribers whose mode/threshold allows it."""
        if not self.app:
            return 0

        message = self._format_alert(cve)
        sent = 0

        for chat_id, sub in list(self._subscribers.items()):
            # Skip paused subscribers
            if sub.paused:
                continue

            # Check alert mode threshold
            mode_threshold = MODE_THRESHOLDS.get(sub.alert_mode, 50)
            if sub.alert_mode == "critical":
                # Critical mode: score >= 75 OR in KEV
                if cve.priority_score < 75 and not cve.enrichment.in_kev:
                    continue
            elif cve.priority_score < mode_threshold:
                continue

            try:
                await self.app.bot.send_message(
                    chat_id=chat_id,
                    text=message,
                    parse_mode="HTML",
                    disable_web_page_preview=True,
                )
                sent += 1
            except Exception as e:
                logger.error(f"Failed to send alert to {chat_id}: {e}")

        return sent

    async def broadcast_breaking_threat(self, cve: ProcessedCVE) -> int:
        """Send a BREAKING THREAT alert to ALL active subscribers regardless of mode."""
        if not self.app:
            return 0

        message = self._format_breaking_threat(cve)
        sent = 0

        for chat_id, sub in list(self._subscribers.items()):
            if sub.paused:
                continue
            try:
                await self.app.bot.send_message(
                    chat_id=chat_id,
                    text=message,
                    parse_mode="HTML",
                    disable_web_page_preview=True,
                )
                sent += 1
            except Exception as e:
                logger.error(f"Failed to send breaking threat to {chat_id}: {e}")

        return sent

    async def broadcast_text(self, text: str) -> int:
        """Send a plain text message to all active subscribers."""
        if not self.app:
            return 0
        sent = 0
        for chat_id, sub in list(self._subscribers.items()):
            if sub.paused:
                continue
            try:
                await self.app.bot.send_message(
                    chat_id=chat_id,
                    text=text,
                    parse_mode=None,
                    disable_web_page_preview=True,
                )
                sent += 1
            except Exception as e:
                logger.error(f"Failed to send text to {chat_id}: {e}")
        return sent

    async def broadcast_ransomware_alert(self, actor_name: str, cve_id: str, cve: ProcessedCVE) -> int:
        """Send ransomware CVE adoption alert to ALL active subscribers."""
        if not self.app:
            return 0
        message = (
            f"\U0001f9a0 RANSOMWARE CVE ALERT\n\n"
            f"{actor_name} is now exploiting {cve_id}\n\n"
            f"CVE: {cve_id}\n"
            f"KRS: {cve.priority_score}/100 · {cve.priority_label}\n"
            f"CVSS: {cve.cvss_score}\n"
            f"Group: {actor_name}\n\n"
            f"View exploit intelligence → /exploit-intel/{cve_id}"
        )
        sent = 0
        for chat_id, sub in list(self._subscribers.items()):
            if sub.paused:
                continue
            try:
                await self.app.bot.send_message(
                    chat_id=chat_id, text=message, disable_web_page_preview=True,
                )
                sent += 1
            except Exception as e:
                logger.error(f"Failed to send ransomware alert to {chat_id}: {e}")
        return sent

    # ── command handlers ──────────────────────────────────────────────────

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(
            "🛡 <b>KnowCVE Intelligence Bot</b>\n\n"
            "Real-time CVE alerts, threat actor tracking, ransomware campaigns, breach intelligence, and IOC lookups — all in one place.\n\n"
            "<b>📡 Alerts &amp; Subscriptions</b>\n"
            "/subscribe — Start receiving CVE alerts\n"
            "/unsubscribe — Stop alerts\n"
            "/mode — Set alert threshold (continuous/important/critical)\n"
            "/pause — Pause alerts temporarily\n"
            "/resume — Resume alerts\n\n"
            "<b>🔍 CVE Intelligence</b>\n"
            "/latest — 5 most recent CVEs\n"
            "/digest — Last 24h CVE summary\n"
            "/stats — Poller &amp; pipeline stats\n\n"
            "<b>📰 News &amp; Briefings</b>\n"
            "/briefing — Today's executive security briefing\n"
            "/news — Latest security news headlines\n\n"
            "<b>🎯 Threat Intelligence</b>\n"
            "/actors — Active threat actor groups\n"
            "/ransomware — Active ransomware campaigns\n"
            "/breaches — Recent major data breaches\n"
            "/ioc [indicator] — Lookup an IP, domain, hash, or URL\n\n"
            "/help — Full command reference",
            parse_mode="HTML",
        )

    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(
            "📖 <b>KnowCVE — Full Command Reference</b>\n\n"
            "<b>📡 Subscriptions</b>\n"
            "/subscribe — Subscribe to CVE alerts\n"
            "/unsubscribe — Unsubscribe\n"
            "/mode [continuous|important|critical] — Set alert threshold\n"
            "/pause · /resume — Pause or resume alerts\n\n"
            "<b>🔍 CVE Intelligence</b>\n"
            "/latest — 5 most recent CVEs\n"
            "/digest — Last 24h summary by severity\n"
            "/stats — Pipeline &amp; poller statistics\n\n"
            "<b>📰 News</b>\n"
            "/briefing — Daily executive briefing\n"
            "/news — Latest security news (top 5 headlines)\n\n"
            "<b>🎯 Threat Intelligence</b>\n"
            "/actors — Nation-state &amp; criminal threat groups\n"
            "/ransomware — Active ransomware campaigns\n"
            "/breaches — Recent major data breaches\n"
            "/ioc [indicator] — IOC lookup (IP/domain/hash/URL)\n\n"
            "<b>Alert Modes:</b>\n"
            "• <b>continuous</b> — All triaged CVEs (score ≥ 25)\n"
            "• <b>important</b> — HIGH + CRITICAL only (recommended)\n"
            "• <b>critical</b> — CRITICAL + actively exploited (KEV) only",
            parse_mode="HTML",
        )

    async def _cmd_subscribe(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id

        self._subscribers[chat_id] = UserSubscription(
            chat_id=chat_id,
            subscribed_at=datetime.now(timezone.utc),
            alert_mode="important",
        )

        # Send inline keyboard for mode selection
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("📢 All CVEs", callback_data="mode_continuous"),
                InlineKeyboardButton("⚡ HIGH + CRITICAL", callback_data="mode_important"),
                InlineKeyboardButton("🔴 CRITICAL Only", callback_data="mode_critical"),
            ]
        ])

        await update.message.reply_text(
            "✅ Subscribed! Choose your alert mode:\n\n"
            "• <b>All CVEs</b> — Everything scored MEDIUM+\n"
            "• <b>HIGH + CRITICAL</b> — Important vulns only (recommended)\n"
            "• <b>CRITICAL Only</b> — Only actively exploited & critical\n\n"
            "You can change this anytime with /mode",
            parse_mode="HTML",
            reply_markup=keyboard,
        )

    async def _handle_mode_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle inline keyboard mode selection."""
        query = update.callback_query
        await query.answer()

        chat_id = query.message.chat_id
        mode = query.data.replace("mode_", "")

        if chat_id in self._subscribers:
            self._subscribers[chat_id].alert_mode = mode
            mode_desc = {
                "continuous": "📢 All CVEs (MEDIUM+)",
                "important": "⚡ HIGH + CRITICAL only",
                "critical": "🔴 CRITICAL + actively exploited only",
            }.get(mode, mode)
            await query.edit_message_text(
                f"✅ Alert mode set to: <b>{mode_desc}</b>",
                parse_mode="HTML",
            )
        else:
            await query.edit_message_text("⚠️ Please /subscribe first.")

    async def _cmd_unsubscribe(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id
        if chat_id in self._subscribers:
            del self._subscribers[chat_id]
            await update.message.reply_text("🔕 Unsubscribed from CVE alerts.")
        else:
            await update.message.reply_text("You weren't subscribed.")

    async def _cmd_mode(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id

        if chat_id not in self._subscribers:
            await update.message.reply_text("⚠️ Not subscribed. Use /subscribe first.")
            return

        sub = self._subscribers[chat_id]

        # If argument provided, set mode
        if context.args:
            mode = context.args[0].lower()
            if mode not in MODE_THRESHOLDS:
                await update.message.reply_text(
                    "⚠️ Usage: /mode [continuous|important|critical]"
                )
                return

            sub.alert_mode = mode
            examples = {
                "continuous": "You'll receive all triaged CVEs (MEDIUM and above, score ≥ 25)",
                "important": "You'll receive HIGH and CRITICAL CVEs only (score ≥ 50)",
                "critical": "You'll receive only CRITICAL severity and actively exploited (KEV) CVEs",
            }
            await update.message.reply_text(
                f"✅ Alert mode set to <b>{mode}</b>\n\n{examples[mode]}",
                parse_mode="HTML",
            )
        else:
            # Show current mode
            await update.message.reply_text(
                f"📋 Current alert mode: <b>{sub.alert_mode}</b>\n"
                f"Paused: {'Yes ⏸' if sub.paused else 'No ▶️'}\n\n"
                "Change with: /mode [continuous|important|critical]",
                parse_mode="HTML",
            )

    async def _cmd_pause(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id
        if chat_id not in self._subscribers:
            await update.message.reply_text("⚠️ Not subscribed. Use /subscribe first.")
            return

        self._subscribers[chat_id].paused = True
        await update.message.reply_text(
            "⏸ Alerts paused — use /resume to restart."
        )

    async def _cmd_resume(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat_id = update.effective_chat.id
        if chat_id not in self._subscribers:
            await update.message.reply_text("⚠️ Not subscribed. Use /subscribe first.")
            return

        self._subscribers[chat_id].paused = False
        mode = self._subscribers[chat_id].alert_mode
        await update.message.reply_text(
            f"▶️ Alerts resumed in <b>{mode}</b> mode.",
            parse_mode="HTML",
        )

    async def _cmd_digest(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Send a summary of the last 24 hours."""
        if not self._poller or not self._poller.processed_cves:
            await update.message.reply_text("No CVEs processed yet. Check back later!")
            return

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        recent = [
            c for c in self._poller.processed_cves
            if c.published_date and (
                c.published_date.replace(tzinfo=timezone.utc)
                if c.published_date.tzinfo is None else c.published_date
            ) >= cutoff
        ]

        if not recent:
            await update.message.reply_text("📊 No CVEs in the last 24 hours.")
            return

        # Count by priority
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for c in recent:
            counts[c.priority_label] = counts.get(c.priority_label, 0) + 1

        # Top 3 critical
        critical = sorted(
            [c for c in recent if c.priority_label == "CRITICAL"],
            key=lambda c: c.priority_score,
            reverse=True,
        )[:3]

        lines = [
            "📊 <b>24-Hour CVE Digest</b>\n",
            f"Total: {len(recent)} new CVEs\n",
            f"🔴 Critical: {counts['CRITICAL']}",
            f"🟠 High: {counts['HIGH']}",
            f"🟡 Medium: {counts['MEDIUM']}",
            f"🟢 Low: {counts['LOW']}",
        ]

        if critical:
            lines.append("\n<b>Top Critical CVEs:</b>")
            for c in critical:
                summary = c.ai_explanation.summary[:100] if c.ai_explanation else c.description[:100]
                lines.append(f"\n🔴 <b>{c.cve_id}</b> ({c.priority_score}/100)")
                lines.append(f"   {summary}…")

        await update.message.reply_text("\n".join(lines), parse_mode="HTML")

    async def _cmd_latest(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._poller or not self._poller.processed_cves:
            await update.message.reply_text("No CVEs processed yet. Check back later!")
            return

        latest = self._poller.processed_cves[-5:]
        lines = ["🔍 <b>Latest CVEs</b>\n"]
        for cve in reversed(latest):
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                cve.priority_label, "⚪"
            )
            lines.append(
                f"{emoji} <b>{cve.cve_id}</b> — {cve.priority_score}/100 {cve.priority_label}\n"
                f"   CVSS {cve.cvss_score} | {cve.description[:100]}…"
            )

        await update.message.reply_text("\n".join(lines), parse_mode="HTML")

    async def _cmd_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._poller:
            await update.message.reply_text("Poller not initialized yet.")
            return

        cves = self._poller.processed_cves
        critical = sum(1 for c in cves if c.priority_label == "CRITICAL")
        high = sum(1 for c in cves if c.priority_label == "HIGH")
        medium = sum(1 for c in cves if c.priority_label == "MEDIUM")
        low = sum(1 for c in cves if c.priority_label == "LOW")

        last_poll = self._poller.last_poll_time
        last_str = last_poll.strftime("%Y-%m-%d %H:%M UTC") if last_poll else "Never"

        await update.message.reply_text(
            f"📊 <b>KnowCVE Stats</b>\n\n"
            f"Total CVEs processed: {len(cves)}\n"
            f"🔴 Critical: {critical}\n"
            f"🟠 High: {high}\n"
            f"🟡 Medium: {medium}\n"
            f"🟢 Low: {low}\n\n"
            f"Subscribers: {self.subscribers_count}\n"
            f"Last poll: {last_str}\n"
            f"Poll interval: {settings.POLL_INTERVAL_MINUTES} min",
            parse_mode="HTML",
        )

    async def _cmd_briefing(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Get today's security intelligence briefing on demand."""
        if not self._news_intel:
            await update.message.reply_text("📰 News intelligence service not available yet. Check back later!")
            return

        await update.message.reply_text("📰 Generating briefing...")
        try:
            briefing = await self._news_intel.get_daily_briefing()
            await update.message.reply_text(briefing)
        except Exception as e:
            logger.error(f"Briefing generation failed: {e}")
            await update.message.reply_text("❌ Failed to generate briefing. Try again later.")

    # ── Phase 5 intelligence commands ────────────────────────────────────

    async def _cmd_news(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show top 5 latest security news headlines."""
        if not self._news_intel:
            await update.message.reply_text("📰 News service not available yet.")
            return
        try:
            from app.core.config import settings
            client = self._news_intel._client
            if not client:
                await update.message.reply_text("📰 Database not connected.")
                return
            res = (
                client.table("security_news")
                .select("title, source, url, summary, published_at")
                .order("published_at", desc=True)
                .limit(5)
                .execute()
            )
            articles = res.data or []
            if not articles:
                await update.message.reply_text("📰 No news articles yet. Check back soon!")
                return
            lines = ["📰 <b>Latest Security News</b>\n"]
            for a in articles:
                title = a.get("title", "")[:120]
                source = a.get("source", "")
                url = a.get("url", "")
                summary = a.get("summary", "")[:150]
                lines.append(f"• <b>{title}</b>")
                lines.append(f"  📡 {source}")
                if summary:
                    lines.append(f"  {summary}")
                if url:
                    lines.append(f"  <a href='{url}'>Read more</a>")
                lines.append("")
            await update.message.reply_text("\n".join(lines), parse_mode="HTML", disable_web_page_preview=True)
        except Exception as e:
            logger.error(f"_cmd_news failed: {e}")
            await update.message.reply_text("❌ Could not fetch news. Try again later.")

    async def _cmd_actors(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show active threat actor groups."""
        if not self._threat_actors:
            await update.message.reply_text("🎯 Threat actor service not available.")
            return
        try:
            actors = await self._threat_actors.get_all_actors(active_only=True)
            if not actors:
                await update.message.reply_text("🎯 No active threat actors found.")
                return
            nation_state = [a for a in actors if "Nation-State" in a.get("sophistication", "")]
            org_crime = [a for a in actors if "Organized Crime" in a.get("sophistication", "")]
            lines = ["🎯 <b>Active Threat Actor Groups</b>\n"]
            if nation_state:
                lines.append("<b>🏴 Nation-State APTs</b>")
                for a in nation_state[:6]:
                    flag = {"Russia": "🇷🇺", "China": "🇨🇳", "North Korea": "🇰🇵", "Iran": "🇮🇷"}.get(a.get("origin_country", ""), "🌐")
                    lines.append(f"  {flag} <b>{a['name']}</b> — {a.get('motivation', '')}")
                lines.append("")
            if org_crime:
                lines.append("<b>💰 Organized Crime / RaaS</b>")
                for a in org_crime[:6]:
                    lines.append(f"  🦠 <b>{a['name']}</b> — {', '.join(a.get('targeted_sectors', [])[:2])}")
            lines.append("\nUse /ransomware for active campaigns.")
            await update.message.reply_text("\n".join(lines), parse_mode="HTML")
        except Exception as e:
            logger.error(f"_cmd_actors failed: {e}")
            await update.message.reply_text("❌ Could not fetch threat actors.")

    async def _cmd_ransomware(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show active ransomware campaigns."""
        if not self._ransomware:
            await update.message.reply_text("🦠 Ransomware tracker not available.")
            return
        try:
            campaigns = await self._ransomware.get_active_campaigns(status="active")
            if not campaigns:
                await update.message.reply_text("🦠 No active campaigns found.")
                return
            lines = ["🦠 <b>Active Ransomware Campaigns</b>\n"]
            for c in campaigns[:6]:
                name = c.get("actor_name") or c.get("actor_slug", "Unknown")
                campaign = c.get("campaign_name", "")[:80]
                cves = c.get("cve_ids", [])
                sectors = ", ".join(c.get("sectors", [])[:2])
                lines.append(f"🔴 <b>{name}</b>")
                lines.append(f"   📋 {campaign}")
                if cves:
                    lines.append(f"   🎯 CVEs: {', '.join(cves[:3])}")
                if sectors:
                    lines.append(f"   🏢 Targets: {sectors}")
                lines.append("")
            await update.message.reply_text("\n".join(lines), parse_mode="HTML")
        except Exception as e:
            logger.error(f"_cmd_ransomware failed: {e}")
            await update.message.reply_text("❌ Could not fetch ransomware data.")

    async def _cmd_breaches(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show recent major data breaches."""
        if not self._breach_intel:
            await update.message.reply_text("💀 Breach intel service not available.")
            return
        try:
            breaches = await self._breach_intel.get_breaches(limit=5)
            if not breaches:
                await update.message.reply_text("💀 No breach records found.")
                return
            lines = ["💀 <b>Recent Major Data Breaches</b>\n"]
            for b in breaches:
                company = b.get("company_name", "Unknown")
                actor = b.get("actor_name") or "Unknown actor"
                date = (b.get("breach_date") or "")[:10]
                records = b.get("records_count")
                sectors = ", ".join(b.get("sectors", [])[:2])
                cves = b.get("cve_ids", [])
                lines.append(f"🔓 <b>{company}</b> ({date})")
                lines.append(f"   👤 Actor: {actor}")
                if records:
                    lines.append(f"   📊 Records: {records:,}")
                if sectors:
                    lines.append(f"   🏢 Sector: {sectors}")
                if cves:
                    lines.append(f"   🎯 CVEs: {', '.join(cves[:2])}")
                lines.append("")
            await update.message.reply_text("\n".join(lines), parse_mode="HTML")
        except Exception as e:
            logger.error(f"_cmd_breaches failed: {e}")
            await update.message.reply_text("❌ Could not fetch breach data.")

    async def _cmd_ioc(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Lookup an IOC (IP, domain, hash, or URL)."""
        if not context.args:
            await update.message.reply_text(
                "🔎 <b>IOC Lookup</b>\n\nUsage: /ioc [indicator]\n\n"
                "Examples:\n"
                "  /ioc 185.220.101.5\n"
                "  /ioc malware.example.com\n"
                "  /ioc d41d8cd98f00b204e9800998ecf8427e",
                parse_mode="HTML",
            )
            return
        if not self._ioc_pulse:
            await update.message.reply_text("🔎 IOC lookup service not available.")
            return
        indicator = context.args[0].strip()
        await update.message.reply_text(f"🔎 Looking up <code>{indicator}</code>...", parse_mode="HTML")
        try:
            result = await self._ioc_pulse.lookup(indicator)
            verdict = result.get("verdict", "unknown").upper()
            risk = result.get("risk_score", 0)
            ioc_type = result.get("ioc_type", "unknown")
            cached = "(cached)" if result.get("cached") else ""
            verdict_emoji = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟠", "CLEAN": "🟢"}.get(verdict, "⚪")
            lines = [
                f"🔎 <b>IOC Report</b> {cached}\n",
                f"Indicator: <code>{indicator}</code>",
                f"Type: {ioc_type.upper()}",
                f"Verdict: {verdict_emoji} <b>{verdict}</b>",
                f"Risk Score: {risk}/100",
            ]
            sources = result.get("sources", {})
            if sources:
                lines.append("\n<b>Sources:</b>")
                for src, data in sources.items():
                    if isinstance(data, dict):
                        if data.get("hit"):
                            family = data.get("malware_family", "")
                            lines.append(f"  • {src.title()}: ✅ HIT{' — ' + family if family else ''}")
                        elif data.get("confidence"):
                            lines.append(f"  • {src.title()}: {data['confidence']}% abuse confidence")
                        elif data.get("noise"):
                            lines.append(f"  • GreyNoise: 🔥 Internet scanner")
                        elif data.get("riot"):
                            lines.append(f"  • GreyNoise: ✅ Known benign service")
            related = result.get("related_cves", [])
            if related:
                lines.append(f"\n🎯 Related CVEs: {', '.join(related[:3])}")
            await update.message.reply_text("\n".join(lines), parse_mode="HTML")
        except Exception as e:
            logger.error(f"_cmd_ioc failed: {e}")
            await update.message.reply_text("❌ IOC lookup failed. Try again later.")

    # ── alert formatting ──────────────────────────────────────────────────

    @staticmethod
    def _format_alert(cve: ProcessedCVE) -> str:
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            cve.priority_label, "⚪"
        )

        lines = [
            f"{emoji} <b>New CVE Alert: {cve.cve_id}</b>",
            f"Priority: {cve.priority_score}/100 {cve.priority_label}",
            f"CVSS: {cve.cvss_score} ({cve.cvss_version})",
            "",
            f"<b>Description:</b> {cve.description[:300]}",
        ]

        if cve.enrichment.in_kev:
            lines.append("\n⚠️ <b>CISA KEV: Actively exploited!</b>")

        if cve.enrichment.is_being_scanned:
            lines.append(f"🔥 <b>GreyNoise:</b> {cve.enrichment.greynoise_scanner_count} IPs actively scanning")

        if cve.enrichment.epss_score > 0:
            lines.append(
                f"📈 EPSS: {cve.enrichment.epss_score:.2%} "
                f"(top {(1 - cve.enrichment.epss_percentile):.1%})"
            )

        if cve.enrichment.has_poc:
            lines.append(f"🧪 Public PoCs: {len(cve.enrichment.poc_urls)}")

        if cve.ai_explanation:
            lines.append(f"\n💡 <b>Summary:</b> {cve.ai_explanation.summary}")
            if cve.ai_explanation.remediation:
                lines.append(f"🛠 <b>Remediation:</b> {cve.ai_explanation.remediation[:200]}")
            if cve.ai_explanation.tags:
                lines.append(f"🏷 Tags: {', '.join(cve.ai_explanation.tags)}")

        return "\n".join(lines)

    @staticmethod
    def _format_breaking_threat(cve: ProcessedCVE) -> str:
        lines = [
            "🚨🚨🚨 <b>BREAKING THREAT</b> 🚨🚨🚨",
            "",
            f"🔴 <b>{cve.cve_id}</b> — {cve.priority_score}/100 CRITICAL",
            f"CVSS: {cve.cvss_score} ({cve.cvss_version})",
            "",
            "⚠️ <b>ACTIVELY EXPLOITED — CISA KEV</b>",
            "",
            f"<b>Description:</b> {cve.description[:400]}",
        ]

        if cve.enrichment.is_being_scanned:
            lines.append(f"\n🔥 <b>{cve.enrichment.greynoise_scanner_count} IPs actively scanning for this vulnerability</b>")

        if cve.ai_explanation:
            lines.append(f"\n💡 <b>Summary:</b> {cve.ai_explanation.summary}")
            if cve.ai_explanation.remediation:
                lines.append(f"\n🛠 <b>Immediate Action:</b> {cve.ai_explanation.remediation[:300]}")

        lines.append(f"\n🔗 https://nvd.nist.gov/vuln/detail/{cve.cve_id}")

        return "\n".join(lines)
