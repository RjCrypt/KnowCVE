"""Phase 7 — WatchlistService: CPE matching, exposure scoring, daily digest.

All Phase 7 backend logic lives here as a single class.
Does NOT modify any existing service files or model fields.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


class WatchlistService:
    """Manages user tech-stack watchlists, exposure scoring, and daily digest."""

    def __init__(self, db=None) -> None:
        self._db = db

    # ══════════════════════════════════════════════════════════════════════
    # CRUD — Watchlist Items
    # ══════════════════════════════════════════════════════════════════════

    async def get_watchlist(self, user_id: str) -> list[dict]:
        """Return all watchlist items for a user."""
        if not self._db or not self._db.is_configured:
            return []
        try:
            result = (
                self._db._client.table("user_watchlist")
                .select("*")
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .execute()
            )
            return result.data or []
        except Exception as e:
            logger.error(f"get_watchlist failed for {user_id}: {e}")
            return []

    async def add_watchlist_item(
        self, user_id: str, cpe_string: str, display_name: str, criticality: str
    ) -> dict | None:
        """Add a technology to the user's watchlist. Max 20 items (free tier)."""
        if not self._db or not self._db.is_configured:
            return None
        try:
            # Check count
            count_result = (
                self._db._client.table("user_watchlist")
                .select("id", count="exact")
                .eq("user_id", user_id)
                .execute()
            )
            if count_result.count is not None and count_result.count >= 20:
                return {"error": "Free tier limit reached (20 items)"}

            criticality_upper = criticality.upper()
            if criticality_upper not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return {"error": "Criticality must be CRITICAL, HIGH, MEDIUM, or LOW"}

            result = self._db._client.table("user_watchlist").insert({
                "user_id": user_id,
                "cpe_string": cpe_string.strip().lower(),
                "display_name": display_name.strip(),
                "criticality": criticality_upper,
            }).execute()

            return result.data[0] if result.data else {"status": "created"}
        except Exception as e:
            if "duplicate" in str(e).lower() or "unique" in str(e).lower():
                return {"error": "Technology already in watchlist"}
            logger.error(f"add_watchlist_item failed: {e}")
            return None

    async def remove_watchlist_item(self, user_id: str, item_id: str) -> bool:
        """Remove a watchlist item by ID."""
        if not self._db or not self._db.is_configured:
            return False
        try:
            self._db._client.table("user_watchlist").delete().eq(
                "id", item_id
            ).eq("user_id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"remove_watchlist_item failed: {e}")
            return False

    # ══════════════════════════════════════════════════════════════════════
    # CPE Matching
    # ══════════════════════════════════════════════════════════════════════

    async def get_matching_cves(
        self,
        user_id: str,
        page: int = 1,
        page_size: int = 20,
        since_hours: int | None = None,
    ) -> dict:
        """Find CVEs whose affected_products match the user's watchlist.

        Returns { cves: [...], total: int, page: int }.
        """
        if not self._db or not self._db.is_configured:
            return {"cves": [], "total": 0, "page": page}

        watchlist = await self.get_watchlist(user_id)
        if not watchlist:
            return {"cves": [], "total": 0, "page": page}

        # Build search terms from watchlist
        search_terms = []
        for item in watchlist:
            search_terms.append(item["cpe_string"].lower())
            search_terms.append(item["display_name"].lower())
        # Deduplicate
        search_terms = list(set(t for t in search_terms if t))

        try:
            # Fetch a broad set of CVEs to filter
            query = (
                self._db._client.table("processed_cves")
                .select("*")
                .not_.is_("affected_products", "null")
                .order("priority_score", desc=True)
                .limit(500)
            )
            if since_hours:
                cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
                query = query.gte("published", cutoff)

            result = query.execute()
            all_cves = result.data or []

            # Filter: case-insensitive substring match
            matched = []
            for cve_row in all_cves:
                affected = cve_row.get("affected_products") or []
                if not affected:
                    continue
                # affected_products is a JSON array of strings
                affected_lower = [str(a).lower() for a in affected]
                affected_joined = " ".join(affected_lower)

                for term in search_terms:
                    if term in affected_joined:
                        matched.append(cve_row)
                        break

            # Sort by priority_score descending
            matched.sort(key=lambda c: c.get("priority_score", 0), reverse=True)

            total = len(matched)
            start = (page - 1) * page_size
            end = start + page_size
            page_cves = matched[start:end]

            # Convert to ProcessedCVE models
            from app.services.database import SupabaseService
            converted = [SupabaseService._row_to_cve(row) for row in page_cves]

            return {"cves": converted, "total": total, "page": page}
        except Exception as e:
            logger.error(f"get_matching_cves failed for {user_id}: {e}")
            return {"cves": [], "total": 0, "page": page}

    # ══════════════════════════════════════════════════════════════════════
    # Exposure Score
    # ══════════════════════════════════════════════════════════════════════

    async def calculate_exposure(self, user_id: str) -> dict:
        """Compute exposure score 0-100 and store in exposure_scores table."""
        match_result = await self.get_matching_cves(user_id, page=1, page_size=500)
        cves = match_result.get("cves", [])

        critical_count = sum(1 for c in cves if c.priority_label == "CRITICAL")
        high_count = sum(1 for c in cves if c.priority_label == "HIGH")
        medium_count = sum(1 for c in cves if c.priority_label == "MEDIUM")

        # Base score
        base = min(100, critical_count * 10 + high_count * 4 + medium_count * 1)

        # KEV multiplier
        actively_exploited_count = sum(1 for c in cves if c.enrichment and c.enrichment.in_kev)
        score = base
        if actively_exploited_count > 0:
            score = min(100, int(base * 1.3))

        # Top 5 CVEs by KRS
        top_cves = []
        sorted_cves = sorted(cves, key=lambda c: c.priority_score, reverse=True)[:5]
        for c in sorted_cves:
            top_cves.append({
                "cve_id": c.cve_id,
                "priority_score": c.priority_score,
                "priority_label": c.priority_label,
                "description": c.description[:150] if c.description else "",
                "in_kev": c.enrichment.in_kev if c.enrichment else False,
                "ai_summary": (c.ai_explanation.summary[:100] if c.ai_explanation and c.ai_explanation.summary else ""),
            })

        # Store in exposure_scores (delete+insert since table may lack unique constraint)
        if self._db and self._db.is_configured:
            try:
                self._db._client.table("exposure_scores").delete().eq("user_id", user_id).execute()
                self._db._client.table("exposure_scores").insert({
                    "user_id": user_id,
                    "score": score,
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "actively_exploited_count": actively_exploited_count,
                    "calculated_at": datetime.now(timezone.utc).isoformat(),
                }).execute()
            except Exception as e:
                logger.error(f"Failed to store exposure score: {e}")

        return {
            "score": score,
            "critical_count": critical_count,
            "high_count": high_count,
            "actively_exploited_count": actively_exploited_count,
            "top_cves": top_cves,
            "calculated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def get_exposure(self, user_id: str) -> dict:
        """Get latest exposure score, recalculating if older than 1 hour."""
        if not self._db or not self._db.is_configured:
            return await self.calculate_exposure(user_id)

        try:
            result = (
                self._db._client.table("exposure_scores")
                .select("*")
                .eq("user_id", user_id)
                .order("calculated_at", desc=True)
                .limit(1)
                .execute()
            )
            if result.data:
                row = result.data[0]
                calc_at = row.get("calculated_at", "")
                try:
                    calc_dt = datetime.fromisoformat(calc_at.replace("Z", "+00:00"))
                    if (datetime.now(timezone.utc) - calc_dt) < timedelta(hours=1):
                        # Still fresh — add top_cves from a quick match
                        match_result = await self.get_matching_cves(user_id, page=1, page_size=5)
                        top_cves = []
                        for c in match_result.get("cves", [])[:5]:
                            top_cves.append({
                                "cve_id": c.cve_id,
                                "priority_score": c.priority_score,
                                "priority_label": c.priority_label,
                                "description": c.description[:150] if c.description else "",
                                "in_kev": c.enrichment.in_kev if c.enrichment else False,
                                "ai_summary": (c.ai_explanation.summary[:100] if c.ai_explanation and c.ai_explanation.summary else ""),
                            })
                        return {
                            "score": row.get("score", 0),
                            "critical_count": row.get("critical_count", 0),
                            "high_count": row.get("high_count", 0),
                            "actively_exploited_count": row.get("actively_exploited_count", 0),
                            "top_cves": top_cves,
                            "calculated_at": calc_at,
                        }
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Failed to fetch cached exposure: {e}")

        # Recalculate
        return await self.calculate_exposure(user_id)

    # ══════════════════════════════════════════════════════════════════════
    # Digest — Email
    # ══════════════════════════════════════════════════════════════════════

    async def send_daily_digest(self, user_id: str) -> bool:
        """Send daily digest email for a single user. Returns True if sent."""
        if not self._db or not self._db.is_configured:
            return False
        if not settings.SENDGRID_API_KEY or not settings.SENDGRID_FROM_EMAIL:
            logger.warning("SendGrid not configured, skipping digest")
            return False

        try:
            # Fetch profile
            profile_result = (
                self._db._client.table("user_profiles")
                .select("*")
                .eq("id", user_id)
                .execute()
            )
            if not profile_result.data:
                return False
            profile = profile_result.data[0]

            # Check digest_enabled
            if not profile.get("digest_enabled", True):
                return False

            email = profile.get("email")
            if not email:
                return False

            display_name = profile.get("display_name") or email.split("@")[0]

            # Get CVEs from last 24h
            match_result = await self.get_matching_cves(user_id, page=1, page_size=10, since_hours=24)
            new_cves = match_result.get("cves", [])
            logger.info(f"Digest for {user_id}: {len(new_cves)} new CVEs in last 24h")

            # If no 24h CVEs, fall back to top matching CVEs (all time)
            if not new_cves:
                match_result = await self.get_matching_cves(user_id, page=1, page_size=10)
                new_cves = match_result.get("cves", [])
                logger.info(f"Digest for {user_id}: falling back to {len(new_cves)} all-time CVEs")

            # Still nothing — user's watchlist doesn't match any CVEs
            if not new_cves:
                logger.info(f"No matching CVEs at all for {user_id}, skipping digest")
                return False

            # Get exposure score
            score_data = await self.get_exposure(user_id)

            # Get KEV CVEs from matches
            kev_cves = [c for c in new_cves if c.enrichment and c.enrichment.in_kev][:3]

            # Build and send email
            html = self._build_digest_html(profile, score_data, new_cves[:5], kev_cves)
            sent = await self._send_email(email, f"KnowCVE Daily Digest — {datetime.now(timezone.utc).strftime('%b %d, %Y')}", html)
            logger.info(f"Digest for {user_id}: sent={sent}")
            return sent

        except Exception as e:
            logger.error(f"send_daily_digest failed for {user_id}: {e}")
            return False

    async def send_test_digest(self, user_id: str) -> bool:
        """Send test digest regardless of time filter or digest_enabled."""
        if not self._db or not self._db.is_configured:
            return False
        if not settings.SENDGRID_API_KEY or not settings.SENDGRID_FROM_EMAIL:
            return False

        try:
            profile_result = (
                self._db._client.table("user_profiles")
                .select("*")
                .eq("id", user_id)
                .execute()
            )
            if not profile_result.data:
                return False
            profile = profile_result.data[0]
            email = profile.get("email")
            if not email:
                return False

            # Get ALL matching CVEs (not just 24h)
            match_result = await self.get_matching_cves(user_id, page=1, page_size=10)
            cves = match_result.get("cves", [])
            score_data = await self.get_exposure(user_id)
            kev_cves = [c for c in cves if c.enrichment and c.enrichment.in_kev][:3]

            html = self._build_digest_html(profile, score_data, cves[:5], kev_cves)
            return await self._send_email(
                email,
                f"[TEST] KnowCVE Daily Digest — {datetime.now(timezone.utc).strftime('%b %d, %Y')}",
                html,
            )
        except Exception as e:
            logger.error(f"send_test_digest failed for {user_id}: {e}")
            return False

    async def run_daily_digest_job(self) -> None:
        """Scheduled job: send digest to all eligible users."""
        logger.info("Daily digest job triggered")

        if not self._db or not self._db.is_configured:
            logger.warning("Daily digest skipped: database not configured")
            return

        try:
            # Find users who have watchlist items (they're the ones who need digests)
            watchlist_result = (
                self._db._client.table("user_watchlist")
                .select("user_id")
                .execute()
            )
            # Deduplicate user IDs
            user_ids = list(set(row["user_id"] for row in (watchlist_result.data or [])))

            if not user_ids:
                logger.info("Daily digest: no users with watchlists found")
                return

            logger.info(f"Daily digest: processing {len(user_ids)} users with watchlists")

            sent_count = 0
            for uid in user_ids:
                try:
                    result = await self.send_daily_digest(uid)
                    if result:
                        sent_count += 1
                except Exception as e:
                    logger.error(f"Digest failed for {uid}: {e}")
                await asyncio.sleep(2)  # Rate limiting

            logger.info(f"Daily digest job complete: {sent_count}/{len(user_ids)} sent")
        except Exception as e:
            logger.error(f"run_daily_digest_job failed: {e}")

    # ── Digest Preferences ────────────────────────────────────────────

    async def set_digest_enabled(self, user_id: str, enabled: bool) -> bool:
        """Set digest_enabled on user_profiles."""
        if not self._db or not self._db.is_configured:
            return False
        try:
            self._db._client.table("user_profiles").update({
                "digest_enabled": enabled,
            }).eq("id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"set_digest_enabled failed for {user_id}: {e}")
            return False

    # ── Email Internals ───────────────────────────────────────────────

    async def _send_email(self, to_email: str, subject: str, html_content: str) -> bool:
        """Send an email via SendGrid."""
        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail

            message = Mail(
                from_email=(settings.SENDGRID_FROM_EMAIL, settings.SENDGRID_FROM_NAME),
                to_emails=to_email,
                subject=subject,
                html_content=html_content,
            )
            sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
            response = sg.send(message)
            logger.info(f"Email sent to {to_email}: {response.status_code}")
            return response.status_code in (200, 201, 202)
        except Exception as e:
            logger.error(f"SendGrid send failed to {to_email}: {e}")
            return False

    def _build_digest_html(
        self,
        profile: dict,
        score_data: dict,
        new_cves: list,
        kev_cves: list,
    ) -> str:
        """Build dark-themed HTML email with inline styles."""
        base_url = settings.FRONTEND_URL
        score = score_data.get("score", 0)
        display_name = profile.get("display_name") or profile.get("email", "").split("@")[0]
        date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")
        user_id = profile.get("id", "")

        # Score color
        if score < 30:
            score_color = "#00ff88"
        elif score <= 70:
            score_color = "#f59e0b"
        else:
            score_color = "#ef4444"

        # Build CVE rows
        cve_rows = ""
        for cve in new_cves:
            sev_label = cve.priority_label
            sev_colors = {
                "CRITICAL": ("#ef4444", "#450a0a"),
                "HIGH": ("#f59e0b", "#451a03"),
                "MEDIUM": ("#eab308", "#422006"),
                "LOW": ("#3b82f6", "#172554"),
            }
            sc, bg = sev_colors.get(sev_label, ("#9ca3af", "#1f2937"))
            summary = ""
            if cve.ai_explanation and cve.ai_explanation.summary:
                summary = cve.ai_explanation.summary[:120] + "..."
            else:
                summary = cve.description[:120] + "..." if cve.description else ""

            cve_rows += f"""
            <tr>
              <td style="padding:12px 16px;border-bottom:1px solid #1e293b;">
                <a href="{base_url}/cve/{cve.cve_id}" style="color:#00ff88;font-family:'JetBrains Mono',monospace;font-size:14px;text-decoration:none;font-weight:600;">{cve.cve_id}</a>
                <span style="display:inline-block;margin-left:8px;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;color:{sc};background:{bg};font-family:'JetBrains Mono',monospace;">{sev_label}</span>
                <span style="display:inline-block;margin-left:8px;font-size:11px;color:#6b7280;font-family:'JetBrains Mono',monospace;">KRS {cve.priority_score}</span>
                <p style="margin:4px 0 0;font-size:13px;color:#9ca3af;line-height:1.5;">{summary}</p>
              </td>
            </tr>"""

        # KEV section
        kev_section = ""
        if kev_cves:
            kev_rows = ""
            for cve in kev_cves:
                kev_rows += f"""
                <div style="padding:8px 12px;border-left:3px solid #ef4444;margin-bottom:8px;background:#450a0a33;border-radius:0 4px 4px 0;">
                  <a href="{base_url}/cve/{cve.cve_id}" style="color:#ef4444;font-family:'JetBrains Mono',monospace;font-size:13px;text-decoration:none;font-weight:600;">{cve.cve_id}</a>
                  <span style="color:#9ca3af;font-size:12px;margin-left:8px;">CISA KEV — Active Exploitation</span>
                </div>"""
            kev_section = f"""
            <div style="margin:24px 0;padding:16px;background:#0f172a;border-radius:8px;border:1px solid #1e293b;">
              <h2 style="margin:0 0 12px;font-size:16px;color:#ef4444;font-family:'Syne',sans-serif;">🔴 Actively Exploited Today</h2>
              {kev_rows}
            </div>"""

        return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#080a0f;font-family:'DM Sans',-apple-system,sans-serif;">
  <div style="max-width:600px;margin:0 auto;padding:24px;">
    <!-- Header -->
    <div style="text-align:center;padding:24px 0;border-bottom:1px solid #1e293b;">
      <div style="font-family:'Syne',sans-serif;font-size:24px;font-weight:700;color:#e6edf3;">
        Know<span style="color:#00ff88;">CVE</span>
      </div>
      <p style="margin:4px 0 0;font-size:14px;color:#6b7280;">Daily Vulnerability Digest · {date_str}</p>
    </div>

    <!-- Greeting -->
    <p style="margin:20px 0 8px;font-size:15px;color:#9ca3af;">Hi {display_name},</p>

    <!-- Exposure Score -->
    <div style="margin:16px 0;padding:24px;background:#0f172a;border-radius:12px;border:1px solid #1e293b;text-align:center;">
      <p style="margin:0 0 8px;font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;font-family:'JetBrains Mono',monospace;">Your Exposure Score</p>
      <div style="font-size:56px;font-weight:800;color:{score_color};font-family:'Syne',sans-serif;line-height:1;">{score}</div>
      <p style="margin:12px 0 0;font-size:12px;color:#6b7280;">
        <span style="color:#ef4444;">{score_data.get('critical_count', 0)} Critical</span> ·
        <span style="color:#f59e0b;">{score_data.get('high_count', 0)} High</span> ·
        <span style="color:#ef4444;">{score_data.get('actively_exploited_count', 0)} Actively Exploited</span>
      </p>
    </div>

    <!-- New CVEs -->
    <div style="margin:24px 0;">
      <h2 style="margin:0 0 12px;font-size:16px;color:#e6edf3;font-family:'Syne',sans-serif;">⚡ New CVEs Matching Your Stack</h2>
      <table style="width:100%;border-collapse:collapse;background:#0f172a;border-radius:8px;border:1px solid #1e293b;overflow:hidden;">
        {cve_rows if cve_rows else '<tr><td style="padding:16px;color:#6b7280;text-align:center;font-size:13px;">No new CVEs matching your stack today.</td></tr>'}
      </table>
    </div>

    {kev_section}

    <!-- Footer -->
    <div style="margin:32px 0 0;padding:20px 0 0;border-top:1px solid #1e293b;text-align:center;">
      <p style="font-size:11px;color:#4b5563;line-height:1.8;">
        You're receiving this because you have a tech stack watchlist on KnowCVE.<br>
        <a href="{base_url}/workspace" style="color:#00ff88;text-decoration:none;">Manage your watchlist →</a>
        &nbsp;·&nbsp;
        <a href="{base_url}/api/digest/unsubscribe/{user_id}" style="color:#6b7280;text-decoration:none;">Unsubscribe</a>
      </p>
    </div>
  </div>
</body>
</html>"""
