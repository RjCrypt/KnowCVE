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
from app.models.cve import AIExplanation, AttackTechnique, EnrichmentData, RawCVE

logger = logging.getLogger(__name__)

# ── Models ────────────────────────────────────────────────────────────────────
MODEL_GROQ_LARGE = "llama-3.3-70b-versatile"
MODEL_GROQ_SMALL = "llama-3.1-8b-instant"
MODEL_CEREBRAS = "llama3.1-8b"
MODEL_GEMINI = "gemini-2.0-flash"

DEFAULT_COOLDOWN_MINUTES = 60

# ── Shared prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are KnowCVE's threat intelligence engine. You reason like a senior offensive security researcher who also understands defensive operations. Your job is not to summarise advisories — it is to perform original technical analysis of vulnerabilities.

You will receive structured CVE data. You must produce a JSON object with exactly these fields:

EXISTING FIELDS (preserve quality, elevate depth):
- summary: 2-3 sentences. Lead with the vulnerability primitive (buffer overflow, use-after-free, SSRF, etc.), the affected component, and the worst-case impact. No marketing language.
- technical_detail: Explain the vulnerability mechanism at the code/architecture level. For memory corruption: describe the vulnerable code path, the memory primitive created (controlled write, type confusion, etc.), and the exploitation path from that primitive to code execution or privilege escalation. For logic flaws: describe the state machine failure or trust assumption that breaks. For injection: explain the parser/interpreter context and why the sanitisation fails. Minimum 150 words.
- impact: Business and operational impact. Distinguish between direct impact (what the attacker gets from this CVE alone) and chained impact (what doors this opens in a typical environment). Include specific examples of what an attacker can do post-exploitation.
- remediation: Explain WHY the patch works at a technical level, not just what version to upgrade to. What primitive does the fix close? What is the defender's detection window? What compensating controls reduce risk before patching?
- tags: Array of strings. Include: CVE ID, vulnerability class (CWE), affected vendor/product, MITRE tactics present.
- affected_tech: Array of specific technology strings (e.g., "Apache HTTP Server 2.4.x", "Linux kernel < 6.1.72").
- mitre_techniques: Array of objects with technique_id, technique_name, tactic, and url fields. Map this CVE to 1-3 most relevant MITRE ATT&CK techniques. Include url as "https://attack.mitre.org/techniques/{technique_id}". If unsure, return an empty array.

NEW FIELDS (this is where you differentiate):
- vulnerability_class_analysis: Situate this CVE within its vulnerability class historically. How does this compare to similar bugs in the same component or class? What does the presence of this bug reveal about the codebase's security posture? What related attack surface should a researcher examine? This is your technical depth showcase — 100-200 words.
- adversarial_context: Threat actor and campaign context. Which threat actor groups (APT or eCrime) historically target this CVE class or this specific software? What does the typical exploit deployment timeline look like (days from disclosure to weaponisation, typical dwell time)? What post-exploitation activity follows initial access through this vector? Ground this in real historical patterns, not speculation. If the CVE is in KEV, state what is known about its exploitation. 100-150 words.
- exploit_narrative: Walk through the exploit chain as an educational step-by-step sequence. This is NOT a working exploit or weaponised guidance — it is the logical sequence an attacker would follow: reconnaissance step, triggering condition, what happens in memory/application state, the controlled primitive, and the final capability achieved. Write for a penetration tester who needs to understand the technique to build a test case. 150-200 words.
- attack_techniques: Array of ATT&CK technique objects for the kill chain specific to this CVE. Include 4-7 techniques covering the full chain from initial access through impact. Each object must have:
  - technique_id: MITRE ATT&CK ID (e.g., "T1190", "T1059.001")
  - technique_name: Official technique name
  - tactic: Parent tactic name (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact)
  - tactic_phase: Integer 1-12 corresponding to tactic order in ATT&CK
  - description: 1-2 sentences on how this technique applies specifically to exploitation of THIS CVE in a realistic intrusion scenario
  - is_pivot: true only for the single technique that represents the core exploitation step

Respond ONLY with a valid JSON object. No preamble, no markdown fences, no explanation outside the JSON.
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
                max_tokens=2400,
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
                max_tokens=2400,
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
    """Google Gemini provider using the new google-genai SDK (native async)."""

    def __init__(self) -> None:
        super().__init__("Gemini")
        from google import genai

        self._client = genai.Client(api_key=settings.GEMINI_API_KEY)

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    async def generate(
        self, raw: RawCVE, enrichment: EnrichmentData, priority_label: str
    ) -> AIExplanation:
        from google.genai import types

        user_content = _build_user_prompt(raw, enrichment)
        full_prompt = f"{SYSTEM_PROMPT}\n\n{user_content}"

        try:
            response = await self._client.aio.models.generate_content(
                model=MODEL_GEMINI,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=2400,
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
            try:
                self._providers.append(GeminiProvider())
                logger.info("AI provider registered: Gemini")
            except ImportError as e:
                logger.warning(f"Gemini provider unavailable (install google-genai): {e}")

        if not self._providers:
            logger.warning("No AI providers configured — explanations will be placeholders")

        # Token budget tracking (per-day)
        self._tokens_used_today = 0
        self._budget_date = date.today()
        self._daily_budget = 180_000

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
                self._tokens_used_today += 2000  # estimate (Phase 5.5 expanded output)
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

    def generate_lightweight_explanation(
        self,
        cve: RawCVE,
        enrichment: EnrichmentData,
    ) -> AIExplanation:
        """
        Build a basic AIExplanation from raw NVD data without calling any AI provider.
        Used for MEDIUM priority CVEs (score 25-49) to conserve API tokens.
        Quality is lower than a full AI explanation but still useful.
        """
        vector_string = cve.cvss_vector or ""

        # Build plain-English CVSS breakdown for technical_detail
        vector_parts = []
        tags = []
        
        # Simple lookup tables for CVSS v3/3.1
        if "AV:N" in vector_string:
            vector_parts.append("Attack vector: Network")
            tags.append("Network")
        elif "AV:A" in vector_string:
            vector_parts.append("Attack vector: Adjacent Network")
        elif "AV:L" in vector_string:
            vector_parts.append("Attack vector: Local")
        elif "AV:P" in vector_string:
            vector_parts.append("Attack vector: Physical")
            
        if "AC:L" in vector_string:
            vector_parts.append("Complexity: Low")
            tags.append("Low Complexity")
        elif "AC:H" in vector_string:
            vector_parts.append("Complexity: High")
            
        if "PR:N" in vector_string:
            vector_parts.append("Privileges required: None")
            tags.append("No Auth Required")
        elif "PR:L" in vector_string:
            vector_parts.append("Privileges required: Low")
        elif "PR:H" in vector_string:
            vector_parts.append("Privileges required: High")
            
        if "UI:N" in vector_string:
            vector_parts.append("User interaction: None")
            tags.append("No User Interaction")
        elif "UI:R" in vector_string:
            vector_parts.append("User interaction: Required")

        if enrichment.in_kev:
            tags.append('Actively Exploited')
        if enrichment.has_poc:
            tags.append('PoC Available')

        cvss_score = cve.cvss_score or "Unknown"
        cvss_severity = cve.cvss_version or "Unknown"
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"

        return AIExplanation(
            summary=(
                f"{cve.cve_id} is a {cvss_severity} severity vulnerability "
                f"(CVSS {cvss_score}). {cve.description[:250]}"
            ),
            technical_detail=(
                f"CVSS Score: {cvss_score} ({cvss_severity})\n"
                f"{chr(10).join(vector_parts)}\n"
                f"CWE: {', '.join(cve.weaknesses) if cve.weaknesses else 'Not specified'}\n"
                f"Vector string: {vector_string if vector_string else 'Not available'}"
            ),
            impact=(
                f"{'Actively exploited in the wild (CISA KEV confirmed). ' if enrichment.in_kev else ''}"
                f"{'Public PoC exploit code available. ' if enrichment.has_poc else ''}"
                f"EPSS exploit probability: {enrichment.epss_score * 100:.1f}%."
            ),
            remediation=(
                f"1. Check the vendor advisory for patch information.\n"
                f"2. Monitor CISA KEV for active exploitation status.\n"
                f"3. Full details: {nvd_url}"
            ),
            tags=tags,
            affected_tech=[],
        )
