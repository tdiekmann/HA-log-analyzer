"""Sensor that exposes the most recent analysis as state + attributes."""
from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SENSOR_NAME, SENSOR_UNIQUE_ID_SUFFIX


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    sensor = LocalRedactorSensor(entry)
    async_add_entities([sensor])

    @callback
    def push(summary: dict[str, Any]) -> None:
        sensor.update_from_summary(summary)

    hass.data[DOMAIN][entry.entry_id]["update_sensor"] = push


class LocalRedactorSensor(SensorEntity):
    """State = number of redactions on the last run; attributes hold details."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_icon = "mdi:shield-search"
    _attr_name = SENSOR_NAME

    def __init__(self, entry: ConfigEntry) -> None:
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}{SENSOR_UNIQUE_ID_SUFFIX}"
        self._attr_native_value: int | None = None
        self._attrs: dict[str, Any] = {}

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return self._attrs

    @callback
    def update_from_summary(self, summary: dict[str, Any]) -> None:
        self._attr_native_value = summary.get("redactions")
        # Drop the full markdown body from the attribute payload so the entity
        # state stays small. Truncate aggressively — full report is in the
        # persistent notification + service response.
        analysis = summary.get("analysis") or ""
        preview = analysis[:1000] + ("…" if len(analysis) > 1000 else "")
        self._attrs = {
            "model": summary.get("model"),
            "log_path": summary.get("log_path"),
            "entries_analyzed": summary.get("entries_analyzed"),
            "redaction_kinds": summary.get("redaction_kinds"),
            "prompt_tokens": summary.get("prompt_tokens"),
            "completion_tokens": summary.get("completion_tokens"),
            "analyzed_at": summary.get("analyzed_at"),
            "analysis_preview": preview,
        }
        self.async_write_ha_state()
