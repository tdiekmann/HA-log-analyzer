# HA Log Analyzer

Analyzes your Home Assistant log with AI. All secrets and PII are redacted
**locally** before anything leaves the host — only the sanitised text is sent
to the LLM.

Supports OpenRouter and any OpenAI-compatible endpoint.

## What gets redacted

- Passwords, API keys, generic secrets (`password=…`, `client_secret=…`)
- Bearer / access / refresh tokens, including `Authorization: Bearer …`
- HA long-lived access tokens (JWT-shaped)
- OpenRouter / OpenAI / Stripe / GitHub key prefixes (`sk-…`, `sk-or-…`, `ghp_…`)
- AWS access key IDs (`AKIA…`)
- PEM-encoded private keys (full block)
- URL-embedded credentials (`https://user:pass@host`)
- Email addresses, MAC addresses, IPv4 / IPv6 (full + `::` shorthand)
- Latitude / longitude assignments
- HA `user_id` / `device_id` / `entry_id` / `webhook_id` (32-char hex)
- UUIDs, Wi-Fi SSIDs, credit-card-shaped digit runs

---

## Installation — HA Add-on (recommended)

The add-on runs as a Docker container managed by Home Assistant and exposes a
web UI in the sidebar. It reads logs directly from the Supervisor — no file
copying needed, and works on HA OS 2026.04 and later where
`home-assistant.log` is no longer written to disk.

### 1. Add the repository

In Home Assistant:

**Settings → Add-ons → Add-on store → ⋮ (top-right) → Repositories**

Paste the URL and click **Add**:

```
https://github.com/tdiekmann/HA-log-analyzer
```

### 2. Install the add-on

Refresh the store page if needed. Find **HA Log Analyzer**, click it, then
click **Install**.

### 3. Configure

Open the add-on's **Configuration** tab and fill in:

| Option | Description | Default |
|--------|-------------|---------|
| `api_key` | OpenRouter (or other) API key | *(required)* |
| `model` | Model ID passed to the API | `anthropic/claude-haiku-4-5` |
| `base_url` | API base URL — any OpenRouter-compatible endpoint | `https://openrouter.ai/api/v1` |
| `default_lines` | How many matching log entries to include | `500` |
| `default_levels` | Log levels to analyse | `WARNING, ERROR, CRITICAL` |
| `redaction_style` | `typed` → `[API_KEY]`, `fixed` → `[REDACTED]` | `typed` |

### 4. Start and open

Click **Start**, then **Open Web UI** (or use the sidebar panel **Log Analyzer**).

The UI gives you two ways to analyse logs:

- **Live Analysis** — fetches the current log from the Supervisor with one
  click. Works on all HA OS versions including those where
  `home-assistant.log` is no longer written to disk.
- **Upload Log File** — drag-and-drop (or browse) a `home-assistant.log` file
  from your computer.

### How log fetching works

The add-on tries several Supervisor API endpoints in order and uses the first
one that returns usable data:

1. `GET /core/api/error_log` — HA Core in-memory log handler (no disk file needed)
2. `GET /core/logs/identifiers/homeassistant` — journald filtered to HA entries
3. `GET /host/logs` — full host journal, HA entries extracted and syslog headers stripped
4. `GET /core/logs` — Supervisor native endpoint (fallback)
5. `/config/home-assistant.log` — filesystem fallback for non-HAOS installs

If all sources fail the error message includes the specific HTTP status from
each attempt to aid troubleshooting.

---

## Installation — HACS Custom Integration (alternative)

If you prefer the services-based approach (automations, scripts, sensor entity)
instead of the web UI, install the custom integration via HACS.

### 1. Add as a custom repository

**HACS → ⋮ → Custom repositories**

Paste the URL, select category **Integration**, click **Add**:

```
https://github.com/tdiekmann/HA-log-analyzer
```

### 2. Install and restart

Click **HA Log Analyzer → Download**, then restart Home Assistant.

### 3. Configure the integration

**Settings → Devices & Services → Add Integration → HA Log Analyzer**

Enter your API key, model ID, and base URL. The key is validated before the
entry is created.

### What the integration provides

| Item | Description |
|------|-------------|
| Service `ha_log_analyzer.analyze_log` | Reads `home-assistant.log`, redacts locally, calls the LLM, posts a persistent notification, fires `ha_log_analyzer_analysis_complete`, and returns the result via service response. |
| Service `ha_log_analyzer.redact_text` | Runs the redactor on any string. No network call. |
| Sensor `sensor.ha_log_analyzer` | State = redaction count on last run. Attributes hold a 1 KB analysis preview, model name, token counts, and redaction kind breakdown. |

#### Service example

```yaml
service: ha_log_analyzer.analyze_log
data:
  lines: 500
  levels: [WARNING, ERROR, CRITICAL]
response_variable: result
```

The full markdown analysis lands in a persistent notification; `result.analysis`
holds the same body for use in scripts and automations.

---

## Privacy guarantees

- `redactor.py` has zero third-party dependencies — nothing leaves the host
  during the redaction step.
- Only the redacted string and prompt headers are sent to the configured
  base URL.
- The `redact_text` service (integration) and the redaction step in the add-on
  both run entirely in-process with no network calls.

## Repository layout

```
ha_log_analyzer/              ← HA add-on (Docker container + web UI)
├── Dockerfile
├── config.yaml
├── build.yaml
└── app/
    ├── main.py               aiohttp web server + multi-source log fetching
    ├── analyzer.py           OpenRouter / OpenAI client
    ├── ha_log.py             HA log parser
    ├── redactor.py           pure-Python regex redactor (zero deps)
    └── static/index.html     single-page web UI

custom_components/ha_log_analyzer/   ← HACS custom integration
├── __init__.py               services + entry setup
├── analyzer.py
├── config_flow.py
├── const.py
├── ha_log.py
├── manifest.json
├── redactor.py
├── sensor.py
├── services.yaml
├── strings.json
└── translations/en.json
```

`redactor.py` and `ha_log.py` are intentionally mirrored in both trees.
Keep them in sync when changing patterns.
