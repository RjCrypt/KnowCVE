"""Multi-provider AI CVE explanation engine with automatic fallback.

Provider chain: Groq → Cerebras → Gemini
When a provider hits rate limits (429), it's marked unavailable for a cooldown
period parsed from the error message. The next provider is tried automatically.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.core.config import settings
from app.models.cve import AIExplanation, EnrichmentData, RawCVE

logger = logging.getLogger(__name__)

# ── Models ────────────────────────────────────────────────────────────────────
MODEL_GROQ_LARGE = "llama-3.3-70b-versatile"
MODEL_GROQ_SMALL = "llama-3.1-8b-instant"
MODEL_CEREBRAS = "llama3.3-70b"
MODEL_GEMINI = "gemini-1.5-flash"

DEFAULT_COOLDOWN_MINUTES = 60

# ── Shared prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are KnowCVE — an expert security educator for penetration testers and bug bounty hunters.

Be concise. Each field must be under 150 words. Total response must stay under 800 tokens.

Given a CVE record and its enrichment data, produce a structured JSON explanation with exactly these keys:

{
  "summary": "1–2 sentence plain-English overview of what this vulnerability is.",
  "technical_detail": "Detailed technical explanation of the vulnerability mechanism, attack vector, and exploitation method.",
  "impact": "What systems, data, or operations are at risk. Business impact and blast radius.",
  "remediation": "Specific steps to patch or mitigate, including version numbers where available.",
  "tags": ["tag1", "tag2"],
  "affected_tech": ["technology1", "technology2"]
}

Rules:
- Output ONLY the JSON object, no markdown fences, no commentary.
- tags: 3–6 short labels (e.g. "RCE", "authentication-bypass", "web", "critical").
- affected_tech: specific software/library names affected.
- Keep each field concise but informative.
"""


def _build_user_prompt(raw: RawCVE, enrichment: EnrichmentData) -> str:
    """Build the user prompt from CVE and enrichment data."""
    parts = [
        f"CVE ID: {raw.cve_id}",
        f"Description: {raw.description}",
        f"CVSS Score: {raw.cvss_score} ({raw.cvss_version})",
        f"CVSS Vector: {raw.cvss_vector}",
    ]
    if raw.weaknesses:
        parts.append(f"CWE: {', '.join(raw.weaknesses)}")
    if raw.references:
        parts.append(f"References: {', '.join(raw.references[:5])}")

    parts.append(f"\nEnrichment:")
    parts.append(f"  In CISA KEV: {enrichment.in_kev}")
    parts.append(f"  EPSS Score: {enrichment.epss_score:.4f} (percentile {enrichment.epss_percentile:.2f})")
    parts.append(f"  Public PoCs: {len(enrichment.poc_urls)} found")
    if enrichment.poc_urls:
        parts.append(f"  PoC URLs: {', '.join(enrichment.poc_urls[:3])}")

    return "\n".join(parts)


def _parse_json_response(text: str) -> dict:
    """Strip markdown fences and parse JSON from LLM output."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
    if text.endswith("```"):
        text = text.rsplit("```", 1)[0]
    text = text.strip()
    return json.loads(text)


def _parse_cooldown_from_error(error_msg: str) -> int:
    """Try to parse retry-after duration from error messages.

    Groq includes patterns like "try again in 59.94s" or "try again in 2m30s".
    Returns cooldown in minutes (minimum 1).
    """
    # Match "Xm" or "Xm Ys"
    m = re.search(r"try again in (\d+)m", error_msg)
    if m:
        return max(1, int(m.group(1)))

    # Match "X.Ys" (seconds)
    m = re.search(r"try again in (\d+(?:\.\d+)?)s", error_msg)
    if m:
        seconds = float(m.group(1))
        return max(1, int(seconds / 60) + 1)

    # Match "Retry-After: X" header-style
    m = re.search(r"retry.after:\s*(\d+)", error_msg, re.IGNORECASE)
    if m:
        return max(1, int(int(m.group(1)) / 60) + 1)

    return DEFAULT_COOLDOWN_MINUTES


# ── Base provider ABC ─────────────────────────────────────────────────────────


class RateLimitError(Exception):
    """Raised when a provider returns 429 rate limit error."""

    def __init__(self, message: str, cooldown_minutes: int = DEFAULT_COOLDOWN_MINUTES):
        super().__init__(message)
        self.cooldown_minutes = cooldown_minutes


class BaseExplainer(ABC):
    """Abstract base class for AI explanation providers."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._rate_limited_until: datetime | None = None

    async def is_available(self) -> bool:
        """Check if provider is currently available (not rate-limited)."""
        if self._rate_limited_until is None:
            return True
        if datetime.now(timezone.utc) >= self._rate_limited_until:
            self._rate_limited_until = None
            logger.info(f"Provider {self.name} cooldown expired — re-enabled")
            return True
        remaining = (self._rate_limited_until - datetime.now(timezone.utc)).total_seconds() / 60
        logger.debug(f"Provider {self.name} rate-limited for {remaining:.0f} more minutes")
        return False

    def mark_rate_limited(self, cooldown_minutes: int) -> None:
        """Mark this provider as temporarily unavailable."""
        self._rate_limited_until = datetime.now(timezone.utc) + timedelta(minutes=cooldown_minutes)
        logger.warning(
            f"Provider {self.name} rate-limited — disabled for {cooldown_minutes}m "
            f"(until {self._rate_limited_until.strftime('%H:%M UTC')})"
        )

    @abstractmethod
    async def generate(
        self, raw: RawCVE, enrichment: EnrichmentData, priority_label: str
    ) -> AIExplanation:
        """Generate an AI explanation. Must raise RateLimitError on 429."""
        ...


# ── Groq provider ────────────────────────────────────────────────────────────


class GroqProvider(BaseExplainer):
    """Groq cloud provider using groq SDK."""

    def __init__(self) -> None:
        super().__init__("Groq")
        from groq import AsyncGroq

        self.client = AsyncGroq(api_key=settings.GROQ_API_KEY)

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    async def generate(
        self, raw: RawCVE, enrichment: EnrichmentData, priority_label: str
    ) -> AIExplanation:
        model = (
            MODEL_GROQ_LARGE
            if priority_label in ("CRITICAL", "HIGH") or enrichment.in_kev
            else MODEL_GROQ_SMALL
        )
        user_content = _build_user_prompt(raw, enrichment)

        try:
            completion = await self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                temperature=0.3,
                max_tokens=1200,
            )
            text = completion.choices[0].message.content or "{}"
            data = _parse_json_response(text)
            return AIExplanation(**data)
        except Exception as e:
            err_msg = str(e).lower()
            if "429" in err_msg or "rate_limit" in err_msg or "rate limit" in err_msg:
                cooldown = _parse_cooldown_from_error(str(e))
                raise RateLimitError(str(e), cooldown) from e
            raise


# ── Cerebras provider ────────────────────────────────────────────────────────


class CerebrasProvider(BaseExplainer):
    """Cerebras cloud provider using cerebras-cloud-sdk."""

    def __init__(self) -> None:
        super().__init__("Cerebras")
        from cerebras.cloud.sdk import AsyncCerebras

        self.client = AsyncCerebras(api_key=settings.CEREBRAS_API_KEY)

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    async def generate(
        self, raw: RawCVE, enrichment: EnrichmentData, priority_label: str
    ) -> AIExplanation:
        user_content = _build_user_prompt(raw, enrichment)

        try:
            completion = await self.client.chat.completions.create(
                model=MODEL_CEREBRAS,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                temperature=0.3,
                max_tokens=1200,
            )
            text = completion.choices[0].message.content or "{}"
            data = _parse_json_response(text)
            return AIExplanation(**data)
        except Exception as e:
            err_msg = str(e).lower()
            if "429" in err_msg or "rate_limit" in err_msg or "rate limit" in err_msg:
                cooldown = _parse_cooldown_from_error(str(e))
                raise RateLimitError(str(e), cooldown) from e
            raise


# ── Gemini provider ──────────────────────────────────────────────────────────


class GeminiProvider(BaseExplainer):
    """Google Gemini provider using google-generativeai SDK (sync → async)."""

    def __init__(self) -> None:
        super().__init__("Gemini")
        import google.generativeai as genai

        genai.configure(api_key=settings.GEMINI_API_KEY)
        self._genai = genai
        self._model = genai.GenerativeModel(MODEL_GEMINI)

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    async def generate(
        self, raw: RawCVE, enrichment: EnrichmentData, priority_label: str
    ) -> AIExplanation:
        user_content = _build_user_prompt(raw, enrichment)
        full_prompt = f"{SYSTEM_PROMPT}\n\n{user_content}"

        try:
            # Gemini SDK is synchronous — run in executor to not block
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self._model.generate_content(
                    full_prompt,
                    generation_config=self._genai.GenerationConfig(
                        temperature=0.3,
                        max_output_tokens=1200,
                    ),
                ),
            )
            text = response.text or "{}"
            data = _parse_json_response(text)
            return AIExplanation(**data)
        except Exception as e:
            err_msg = str(e).lower()
            if "429" in err_msg or "rate_limit" in err_msg or "resource_exhausted" in err_msg:
                cooldown = _parse_cooldown_from_error(str(e))
                raise RateLimitError(str(e), cooldown) from e
            raise


# ── Main explainer (public interface) ─────────────────────────────────────────


class GroqExplainer:
    """Multi-provider AI explainer with automatic fallback.

    Public interface remains identical — only internals changed.
    Tries providers in order: Groq → Cerebras → Gemini.
    """

    def __init__(self) -> None:
        self._providers: list[BaseExplainer] = []

        # Register only providers whose API keys are configured
        if settings.GROQ_API_KEY:
            self._providers.append(GroqProvider())
            logger.info("AI provider registered: Groq")

        if settings.CEREBRAS_API_KEY:
            self._providers.append(CerebrasProvider())
            logger.info("AI provider registered: Cerebras")

        if settings.GEMINI_API_KEY:
            self._providers.append(GeminiProvider())
            logger.info("AI provider registered: Gemini")

        if not self._providers:
            logger.warning("No AI providers configured — explanations will be placeholders")

        # Token budget tracking (per-day)
        self._tokens_used_today = 0
        self._budget_date = date.today()
        self._daily_budget = 90_000

    # ── budget helpers ────────────────────────────────────────────────────

    def _check_budget(self, estimated_tokens: int = 900) -> bool:
        if date.today() != self._budget_date:
            self._tokens_used_today = 0
            self._budget_date = date.today()
        return (self._tokens_used_today + estimated_tokens) < self._daily_budget

    # ── public method (unchanged signature) ───────────────────────────────

    async def explain_cve(
        self,
        raw: RawCVE,
        enrichment: EnrichmentData,
        priority_label: str = "HIGH",
    ) -> AIExplanation:
        """Generate an AI explanation, trying providers in order with fallback."""
        if not self._providers:
            return AIExplanation(summary="AI explanation unavailable (no API keys configured)")

        if not self._check_budget():
            logger.warning(
                f"Daily token budget exhausted ({self._tokens_used_today}/{self._daily_budget}). "
                f"Skipping AI for {raw.cve_id}."
            )
            return self._budget_exceeded_explanation(raw)

        last_error: Optional[Exception] = None

        for provider in self._providers:
            if not await provider.is_available():
                continue

            try:
                logger.info(f"Explaining {raw.cve_id} via {provider.name}")
                result = await provider.generate(raw, enrichment, priority_label)
                self._tokens_used_today += 900  # estimate
                return result
            except RateLimitError as e:
                logger.warning(f"{provider.name} rate-limited for {raw.cve_id}: {e}")
                provider.mark_rate_limited(e.cooldown_minutes)
                last_error = e
                continue
            except json.JSONDecodeError:
                logger.error(f"{provider.name} returned invalid JSON for {raw.cve_id}")
                last_error = ValueError("Invalid JSON")
                continue
            except Exception as e:
                logger.error(f"{provider.name} failed for {raw.cve_id}: {e}")
                last_error = e
                continue

        # All providers failed
        logger.warning(f"All AI providers failed for {raw.cve_id}: {last_error}")
        return AIExplanation(
            summary=f"{raw.cve_id}: {raw.description[:200]}. "
            "AI explanation unavailable — all providers exhausted.",
            technical_detail="All AI providers are currently rate-limited or unavailable.",
            impact=f"CVSS: {raw.cvss_score}. Check NVD for full details.",
            remediation=f"Visit https://nvd.nist.gov/vuln/detail/{raw.cve_id}",
            tags=[],
            affected_tech=[],
        )

    # ── fallback explanations ─────────────────────────────────────────────

    def _budget_exceeded_explanation(self, raw: RawCVE) -> AIExplanation:
        return AIExplanation(
            summary=(
                f"{raw.cve_id}: {raw.description[:200]}. "
                "AI explanation unavailable — daily token budget reached, resets at midnight UTC."
            ),
            technical_detail="Token budget exhausted for today. Raw description above is from NVD.",
            impact=f"CVSS: {raw.cvss_score}. Check NVD for full details.",
            remediation=f"Visit https://nvd.nist.gov/vuln/detail/{raw.cve_id}",
            tags=[],
            affected_tech=[],
        )
