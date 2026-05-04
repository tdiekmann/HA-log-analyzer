"""Config + options flow for HA Log Analyzer."""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import analyzer
from .const import (
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
)


_LEVEL_CHOICES = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def _user_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(CONF_API_KEY, default=defaults.get(CONF_API_KEY, "")): str,
            vol.Required(
                CONF_MODEL, default=defaults.get(CONF_MODEL, DEFAULT_MODEL)
            ): str,
            vol.Required(
                CONF_BASE_URL, default=defaults.get(CONF_BASE_URL, DEFAULT_BASE_URL)
            ): str,
        }
    )


class LocalRedactorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the initial setup flow."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input is not None:
            session = async_get_clientsession(self.hass)
            try:
                await analyzer.validate_api_key(
                    api_key=user_input[CONF_API_KEY],
                    base_url=user_input[CONF_BASE_URL],
                    session=session,
                )
            except analyzer.AnalyzerError as exc:
                msg = str(exc).lower()
                if "invalid" in msg or "401" in msg:
                    errors["base"] = "invalid_auth"
                else:
                    errors["base"] = "cannot_connect"
            else:
                # Single-instance integration — one entry per HA install.
                await self.async_set_unique_id(DOMAIN)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title="HA Log Analyzer",
                    data=user_input,
                    options={
                        CONF_DEFAULT_LINES: DEFAULT_LINES,
                        CONF_DEFAULT_LEVELS: DEFAULT_LEVELS,
                        CONF_REDACTION_STYLE: DEFAULT_REDACTION_STYLE,
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_user_schema(user_input),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> "LocalRedactorOptionsFlow":
        return LocalRedactorOptionsFlow(config_entry)


class LocalRedactorOptionsFlow(config_entries.OptionsFlow):
    """Edit defaults after install."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self.config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        opts = self.config_entry.options
        data = self.config_entry.data
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_MODEL, default=opts.get(CONF_MODEL, data.get(CONF_MODEL, DEFAULT_MODEL))
                ): str,
                vol.Optional(
                    CONF_DEFAULT_LINES,
                    default=opts.get(CONF_DEFAULT_LINES, DEFAULT_LINES),
                ): vol.All(int, vol.Range(min=10, max=20000)),
                vol.Optional(
                    CONF_DEFAULT_LEVELS,
                    default=opts.get(CONF_DEFAULT_LEVELS, DEFAULT_LEVELS),
                ): cv_multi_select(_LEVEL_CHOICES),
                vol.Optional(
                    CONF_REDACTION_STYLE,
                    default=opts.get(CONF_REDACTION_STYLE, DEFAULT_REDACTION_STYLE),
                ): vol.In(["typed", "fixed"]),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)


def cv_multi_select(options: list[str]):
    """Lazy import wrapper so this module imports fine in unit tests."""
    from homeassistant.helpers import config_validation as cv

    return cv.multi_select(options)
