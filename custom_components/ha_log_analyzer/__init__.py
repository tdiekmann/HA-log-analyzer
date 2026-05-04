"""HA Log Analyzer — a HACS integration that scrubs Home Assistant logs of
secrets and PII before sending them to an LLM (OpenRouter / OpenAI-compatible)
for analysis and remediation suggestions.

All redaction happens locally; only the redacted text leaves the host.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import logging
import os
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import analyzer, ha_log, redactor
from .const import (
    ATTR_LEVELS,
    ATTR_LINES,
    ATTR_LOG_PATH,
    ATTR_MODEL,
    ATTR_STYLE,
    ATTR_TEXT,
    CONF_API_KEY,
    CONF_BASE_URL,
    CONF_DEFAULT_LEVELS,
    CONF_DEFAULT_LINES,
    CONF_MODEL,
    CONF_REDACTION_STYLE,
    DEFAULT_BASE_URL,
    DEFAULT_LEVELS,
    DEFAULT_LINES,
    DEFAULT_MODEL,
    DEFAULT_REDACTION_STYLE,
    DOMAIN,
    NOTIFICATION_ID,
    PLATFORMS,
    SERVICE_ANALYZE_LOG,
    SERVICE_REDACT_TEXT,
)

_LOGGER = logging.getLogger(__name__)


ANALYZE_LOG_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_LOG_PATH): cv.string,
        vol.Optional(ATTR_LINES): vol.All(vol.Coerce(int), vol.Range(min=1, max=20000)),
        vol.Optional(ATTR_LEVELS): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(ATTR_MODEL): cv.string,
    }
)


REDACT_TEXT_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_TEXT): cv.string,
        vol.Optional(ATTR_STYLE, default=DEFAULT_REDACTION_STYLE): vol.In(["typed", "fixed"]),
    }
)


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Component-wide setup — services live here so they exist even before a
    config entry is added (the redact_text service needs no API key)."""
    hass.data.setdefault(DOMAIN, {})

    async def handle_redact_text(call: ServiceCall) -> ServiceResponse:
        text = call.data[ATTR_TEXT]
        style = call.data.get(ATTR_STYLE, DEFAULT_REDACTION_STYLE)
        redacted, findings = await hass.async_add_executor_job(
            redactor.redact, text, style
        )
        return {
            "redacted_text": redacted,
            "finding_count": len(findings),
            "kinds": dict(Counter(f.kind for f in findings)),
        }

    hass.services.async_register(
        DOMAIN,
        SERVICE_REDACT_TEXT,
        handle_redact_text,
        schema=REDACT_TEXT_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Per-entry setup — registers the analyze service that needs the API key."""
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "latest": None,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    async def handle_analyze_log(call: ServiceCall) -> ServiceResponse:
        return await _async_analyze(hass, entry, call)

    hass.services.async_register(
        DOMAIN,
        SERVICE_ANALYZE_LOG,
        handle_analyze_log,
        schema=ANALYZE_LOG_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        # Only drop the per-entry service if no other entries remain.
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_ANALYZE_LOG)
    return unloaded


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the entry when options change (model, default lines, etc.)."""
    await hass.config_entries.async_reload(entry.entry_id)


def _resolve_log_path(hass: HomeAssistant, override: str | None) -> str:
    if override:
        return override
    # HA writes to <config>/home-assistant.log on container/core installs.
    return hass.config.path("home-assistant.log")


def _options(entry: ConfigEntry) -> dict[str, Any]:
    """Merge data + options so callers see the latest values."""
    return {**entry.data, **entry.options}


async def _async_analyze(
    hass: HomeAssistant, entry: ConfigEntry, call: ServiceCall
) -> ServiceResponse:
    opts = _options(entry)
    api_key: str = opts[CONF_API_KEY]
    base_url: str = opts.get(CONF_BASE_URL, DEFAULT_BASE_URL)
    model: str = call.data.get(ATTR_MODEL) or opts.get(CONF_MODEL, DEFAULT_MODEL)
    lines: int = call.data.get(ATTR_LINES) or opts.get(CONF_DEFAULT_LINES, DEFAULT_LINES)
    levels: list[str] = call.data.get(ATTR_LEVELS) or opts.get(
        CONF_DEFAULT_LEVELS, DEFAULT_LEVELS
    )
    style: str = opts.get(CONF_REDACTION_STYLE, DEFAULT_REDACTION_STYLE)

    log_path = _resolve_log_path(hass, call.data.get(ATTR_LOG_PATH))
    if not os.path.exists(log_path):
        raise HomeAssistantError(f"Log file not found: {log_path}")

    raw = await hass.async_add_executor_job(_read_text, log_path)
    entries = ha_log.filter_entries(ha_log.parse_text(raw), levels=levels, last_n=lines)
    if not entries:
        raise HomeAssistantError(
            f"No log entries matched levels={levels} in last {lines} lines of {log_path}"
        )

    selected_text = ha_log.to_text(entries)
    redacted_text, findings = await hass.async_add_executor_job(
        redactor.redact, selected_text, style
    )

    session = async_get_clientsession(hass)
    try:
        result = await analyzer.analyze(
            api_key=api_key,
            redacted_log=redacted_text,
            model=model,
            base_url=base_url,
            session=session,
        )
    except analyzer.AnalyzerError as exc:
        raise HomeAssistantError(f"LLM analysis failed: {exc}") from exc

    kinds = dict(Counter(f.kind for f in findings))
    summary = {
        "model": result.model,
        "log_path": log_path,
        "entries_analyzed": len(entries),
        "redactions": len(findings),
        "redaction_kinds": kinds,
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "analysis": result.content,
    }

    hass.data[DOMAIN][entry.entry_id]["latest"] = summary

    # Push a persistent notification so the user immediately sees the report.
    await hass.services.async_call(
        "persistent_notification",
        "create",
        {
            "title": f"HA Log Analyzer: {len(findings)} redactions, {len(entries)} entries",
            "message": result.content,
            "notification_id": NOTIFICATION_ID,
        },
        blocking=False,
    )

    # Fire an event so automations can react to a finished analysis.
    hass.bus.async_fire(
        f"{DOMAIN}_analysis_complete",
        {k: v for k, v in summary.items() if k != "analysis"},
    )

    # Update sensor state.
    async_dispatch = hass.data[DOMAIN][entry.entry_id].get("update_sensor")
    if async_dispatch is not None:
        async_dispatch(summary)

    return summary


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()
