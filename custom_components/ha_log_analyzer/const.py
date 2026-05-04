"""Constants for the HA Log Analyzer integration."""
from __future__ import annotations

DOMAIN = "ha_log_analyzer"
PLATFORMS = ["sensor"]

# Config-entry keys
CONF_API_KEY = "api_key"
CONF_MODEL = "model"
CONF_BASE_URL = "base_url"
CONF_DEFAULT_LINES = "default_lines"
CONF_DEFAULT_LEVELS = "default_levels"
CONF_REDACTION_STYLE = "redaction_style"

# Defaults
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "anthropic/claude-haiku-4.5"
DEFAULT_LINES = 500
DEFAULT_LEVELS = ["WARNING", "ERROR", "CRITICAL"]
DEFAULT_REDACTION_STYLE = "typed"

# Service names
SERVICE_ANALYZE_LOG = "analyze_log"
SERVICE_REDACT_TEXT = "redact_text"

# Service field names
ATTR_LOG_PATH = "log_path"
ATTR_LINES = "lines"
ATTR_LEVELS = "levels"
ATTR_MODEL = "model"
ATTR_TEXT = "text"
ATTR_STYLE = "style"

# Notification id
NOTIFICATION_ID = "ha_log_analyzer_analysis"

# Sensor / entity
SENSOR_NAME = "HA Log Analyzer"
SENSOR_UNIQUE_ID_SUFFIX = "_analysis"
