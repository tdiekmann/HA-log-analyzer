"""OpenRouter (OpenAI-compatible) chat-completions client.

Used to analyze a *redacted* log and recommend fixes. Anything PII-bearing
must be replaced with placeholders by ``redactor.redact()`` before being
passed in here — this module does not redact, it only sends.
"""
from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any

import aiohttp


_LOGGER = logging.getLogger(__name__)


SYSTEM_PROMPT = (
    "You are an expert Home Assistant troubleshooter. "
    "You will be given a preamble with the current time and log time range, followed by "
    "a log excerpt from a Home Assistant installation. "
    "Sensitive values have already been replaced with bracketed placeholders such as "
    "[PASSWORD], [TOKEN], [EMAIL], [IP_ADDRESS], [API_KEY]. Treat those tokens as opaque. "
    "Analyze the log, identify the most important issues (ranked by severity), and for "
    "each one provide: a short title, the affected integration / component, the likely "
    "root cause, a concrete recommended fix, and a **Last seen** line showing the "
    "timestamp of the most recent log entry for that issue and its age relative to the "
    "current time given in the preamble (e.g. 'Last seen: 2026-05-05 10:28:55 · 2m ago'). "
    "Prefer brevity. Respond in Markdown with one H2 per issue."
)


class AnalyzerError(RuntimeError):
    """Raised when the LLM call fails or returns an unusable response."""


@dataclass
class AnalysisResult:
    model: str
    content: str
    prompt_tokens: int | None
    completion_tokens: int | None


async def analyze(
    *,
    api_key: str,
    redacted_log: str,
    model: str,
    base_url: str,
    session: aiohttp.ClientSession,
    extra_instructions: str | None = None,
    timeout_seconds: int = 120,
) -> AnalysisResult:
    """Send ``redacted_log`` to the configured OpenAI-compatible endpoint.

    OpenRouter accepts the OpenAI ``/chat/completions`` schema unchanged, so
    this function works against either as long as ``base_url`` points at the
    correct ``/v1`` root.
    """
    if not api_key:
        raise AnalyzerError("API key is empty")
    if not redacted_log.strip():
        raise AnalyzerError("Redacted log is empty — nothing to analyze")

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        # OpenRouter recommends these so calls show up correctly in the dashboard.
        "HTTP-Referer": "https://github.com/timdiekmann/HA-log-analyzer",
        "X-Title": "Home Assistant HA Log Analyzer",
    }
    user_content = redacted_log
    if extra_instructions:
        user_content = f"{extra_instructions}\n\n---\n\n{redacted_log}"

    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.2,
    }

    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    try:
        async with session.post(url, headers=headers, json=payload, timeout=timeout) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise AnalyzerError(
                    f"Upstream returned HTTP {resp.status}: {text[:500]}"
                )
            try:
                data = await resp.json(content_type=None)
            except aiohttp.ContentTypeError as exc:
                raise AnalyzerError(f"Non-JSON response: {text[:500]}") from exc
    except aiohttp.ClientError as exc:
        raise AnalyzerError(f"HTTP error contacting {url}: {exc}") from exc

    try:
        choice = data["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AnalyzerError(f"Unexpected response shape: {data!r}") from exc

    usage = data.get("usage") or {}
    return AnalysisResult(
        model=data.get("model", model),
        content=content,
        prompt_tokens=usage.get("prompt_tokens"),
        completion_tokens=usage.get("completion_tokens"),
    )


async def validate_api_key(
    *, api_key: str, base_url: str, session: aiohttp.ClientSession
) -> None:
    """Hit ``/models`` as a cheap auth check. Raises on failure."""
    url = base_url.rstrip("/") + "/models"
    headers = {"Authorization": f"Bearer {api_key}"}
    timeout = aiohttp.ClientTimeout(total=20)
    async with session.get(url, headers=headers, timeout=timeout) as resp:
        if resp.status == 401:
            raise AnalyzerError("Invalid API key")
        if resp.status >= 400:
            text = await resp.text()
            raise AnalyzerError(f"Auth check failed: HTTP {resp.status}: {text[:200]}")
