"""HA Log Analyzer add-on web server."""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path

import aiohttp
import markdown as md_lib
from aiohttp import web

from analyzer import AnalyzerError, analyze
from ha_log import filter_entries, parse_text, to_text
from redactor import apply as redact_apply
from redactor import detect, merge

_LOGGER = logging.getLogger(__name__)

_OPTIONS_FILE = Path("/data/options.json")
_STATIC_DIR = Path(__file__).parent / "static"

_DEFAULTS = {
    "model": "anthropic/claude-haiku-4-5",
    "base_url": "https://openrouter.ai/api/v1",
    "default_lines": 500,
    "default_levels": ["WARNING", "ERROR", "CRITICAL"],
    "redaction_style": "typed",
}

_SUPERVISOR_URL = "http://supervisor"

# Fallback: HA mounts the config dir at /config (HAOS) or /homeassistant
_LOG_CANDIDATES = [
    Path("/config/home-assistant.log"),
    Path("/homeassistant/home-assistant.log"),
]

# ANSI escape strip
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# journald export block separator
_JOURNALD_HA_ID = "homeassistant"

# Syslog-format line from plain-text journald output:
#   2026-05-05 03:13:39.915 hostname service[pid]: message body
_SYSLOG_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\S+\s+([^\s\[]+)(?:\[\d+\])?: (.*)",
    re.MULTILINE,
)

# HA log line pattern: timestamp LEVEL (thread) [logger] — used for content-based matching
# when the syslog service identifier isn't "homeassistant"
_HA_MSG_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ "
    r"(?:DEBUG|INFO|WARNING|ERROR|CRITICAL) "
    r"\([^)]+\) \["
)


def _supervisor_token() -> str:
    return os.environ.get("SUPERVISOR_TOKEN", "")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _filter_syslog_for_ha(text: str) -> tuple[str, str]:
    """From plain syslog output extract HA log lines, returning (lines, debug_info).

    Strategy 1 — service name: keep lines where service == 'homeassistant'.
    Strategy 2 — content match: keep message bodies that look like HA log entries
                 (timestamp LEVEL (thread) [logger]). Handles containers whose
                 syslog identifier isn't 'homeassistant'.
    debug_info includes the unique service names seen, for diagnostics.
    """
    by_service: list[str] = []
    by_content: list[str] = []
    services: set[str] = set()

    for m in _SYSLOG_LINE_RE.finditer(text):
        svc = m.group(1)
        msg = m.group(2)
        services.add(svc)
        if svc == "homeassistant":
            by_service.append(msg)
        if _HA_MSG_RE.match(msg):
            by_content.append(msg)

    svc_summary = ", ".join(sorted(services)[:20]) or "none"
    debug = f"services seen: {svc_summary}"

    if by_service:
        return "\n".join(by_service), debug
    if by_content:
        return "\n".join(by_content), debug + " (matched by content)"
    return "", debug


def _parse_journald_export(raw: str) -> str:
    """Extract HA log lines from journald export format (KEY=VALUE blocks)."""
    lines: list[str] = []
    block: dict[str, str] = {}
    for line in raw.splitlines():
        if line == "":
            syslog_id = block.get("SYSLOG_IDENTIFIER", "")
            if syslog_id == _JOURNALD_HA_ID or not syslog_id:
                msg = block.get("MESSAGE", "")
                if msg:
                    lines.append(msg)
            block = {}
        elif "=" in line:
            key, _, val = line.partition("=")
            block[key] = val
    # handle last block without trailing blank line
    syslog_id = block.get("SYSLOG_IDENTIFIER", "")
    if (syslog_id == _JOURNALD_HA_ID or not syslog_id):
        msg = block.get("MESSAGE", "")
        if msg:
            lines.append(msg)
    return "\n".join(lines)


def _looks_like_supervisor_error(text: str) -> bool:
    """Return True only if the response is a Supervisor internal error, not real HA logs.

    Real HA logs often contain Python tracebacks from logged exceptions — we must
    not discard them just because "Traceback" appears somewhere in the body.
    A genuine Supervisor crash response starts with the error near the top and
    contains no HA-format log lines at all.
    """
    stripped = _strip_ansi(text).lstrip()
    early = stripped[:600]
    has_early_error = (
        early.startswith("^") or early.startswith("~")
        or "Traceback (most recent call last)" in early
        or "AttributeError:" in early[:200]
        or "Exception:" in early[:200]
    )
    if not has_early_error:
        return False
    # If genuine HA log lines exist anywhere, keep the content
    return not bool(_HA_MSG_RE.search(stripped))


def _find_log_file() -> Path | None:
    for p in _LOG_CANDIDATES:
        if p.exists():
            return p
    return None


def _load_options() -> dict:
    try:
        return json.loads(_OPTIONS_FILE.read_text())
    except Exception:
        return {}


def _parse_log_ts(ts: str) -> datetime | None:
    try:
        # Accept "2026-05-05 10:30:45.123" or "2026-05-05T10:30:45"
        return datetime.fromisoformat(ts.replace("T", " ").split(".")[0])
    except ValueError:
        return None


def _age_str(dt: datetime, now: datetime) -> str:
    s = max(0, int((now - dt).total_seconds()))
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        m, sec = divmod(s, 60)
        return f"{m}m {sec}s ago"
    if s < 86400:
        h, rem = divmod(s, 3600)
        return f"{h}h {rem // 60}m ago"
    d, rem = divmod(s, 86400)
    return f"{d}d {rem // 3600}h ago"


def _log_time_context(filtered: list, now: datetime) -> str:
    """Build a short preamble describing the log's time range relative to now."""
    timestamps = [_parse_log_ts(e.timestamp) for e in filtered if e.timestamp]
    timestamps = [t for t in timestamps if t is not None]
    if not timestamps:
        return f"Current time: {now.strftime('%Y-%m-%d %H:%M:%S')}"
    first, last = timestamps[0], timestamps[-1]
    return (
        f"Current time: {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Log range: {first.strftime('%Y-%m-%d %H:%M:%S')} → "
        f"{last.strftime('%Y-%m-%d %H:%M:%S')} "
        f"(most recent entry: {_age_str(last, now)})"
    )


async def _get(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    timeout: int = 30,
) -> tuple[str | None, str]:
    """Return (body_text, error_detail). error_detail is empty on success."""
    try:
        async with session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                snippet = text[:200].replace("\n", " ")
                return None, f"HTTP {resp.status}: {snippet}"
            if _looks_like_supervisor_error(text):
                snippet = _strip_ansi(text)[:120].replace("\n", " ")
                return None, f"Supervisor traceback in body: {snippet}"
            return _strip_ansi(text), ""
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


async def _fetch_log_core_error_log(
    session: aiohttp.ClientSession, errors: list[str]
) -> str | None:
    """HA Core REST API /api/error_log — in-memory handler, no disk file needed."""
    token = _supervisor_token()
    if not token:
        errors.append("core/api/error_log: SUPERVISOR_TOKEN not set")
        return None
    hdrs = {"Authorization": f"Bearer {token}"}
    text, err = await _get(session, f"{_SUPERVISOR_URL}/core/api/error_log", hdrs)
    if text is not None:
        _LOGGER.info("Fetched %d bytes from core/api/error_log", len(text))
        return text
    errors.append(f"core/api/error_log: {err}")
    return None


async def _fetch_log_core_logs_identifier(
    session: aiohttp.ClientSession, errors: list[str]
) -> str | None:
    """Supervisor /core/logs/identifiers/homeassistant (journald, HA-only entries)."""
    token = _supervisor_token()
    if not token:
        errors.append("core/logs/identifiers/homeassistant: SUPERVISOR_TOKEN not set")
        return None
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "text/plain"}
    text, err = await _get(
        session, f"{_SUPERVISOR_URL}/core/logs/identifiers/homeassistant", hdrs
    )
    if text is not None:
        # Output is syslog-format with homeassistant header; strip it to get bare HA log lines
        stripped, dbg = _filter_syslog_for_ha(text)
        result = stripped if stripped.strip() else text
        _LOGGER.info(
            "Fetched %d bytes from core/logs/identifiers/homeassistant (%d after syslog strip, %s)",
            len(text), len(result), dbg,
        )
        return result
    errors.append(f"core/logs/identifiers/homeassistant: {err}")
    return None


async def _fetch_log_host_journal(
    session: aiohttp.ClientSession, errors: list[str]
) -> str | None:
    """Supervisor /host/logs — try text/x-log then text/plain, filter for HA entries."""
    token = _supervisor_token()
    if not token:
        errors.append("host/logs: SUPERVISOR_TOKEN not set")
        return None

    url = f"{_SUPERVISOR_URL}/host/logs"
    auth = {"Authorization": f"Bearer {token}"}

    # Supervisor 2026.04 explicitly supports text/x-log and text/plain (not journal MIME)
    for accept in ("text/x-log", "text/plain"):
        hdrs = {**auth, "Accept": accept}
        text, err = await _get(session, url, hdrs)
        if text is not None:
            filtered, dbg = _filter_syslog_for_ha(text)
            if filtered.strip():
                _LOGGER.info(
                    "Extracted %d chars of HA entries from host/logs (%s, %d total, %s)",
                    len(filtered), accept, len(text), dbg,
                )
                return filtered
            err = f"no HA entries found ({dbg})"
        errors.append(f"host/logs ({accept}): {err}")

    return None


async def _fetch_log_core_logs(
    session: aiohttp.ClientSession, errors: list[str]
) -> str | None:
    """Supervisor /core/logs — primary container-log source for HA OS 2026.04+."""
    token = _supervisor_token()
    if not token:
        errors.append("core/logs: SUPERVISOR_TOKEN not set")
        return None
    for accept in ("text/x-log", "text/plain"):
        hdrs = {"Authorization": f"Bearer {token}", "Accept": accept}
        text, err = await _get(session, f"{_SUPERVISOR_URL}/core/logs", hdrs)
        if text is not None:
            # May be bare HA log format or syslog-wrapped; try syslog strip first
            stripped, dbg = _filter_syslog_for_ha(text)
            result = stripped if stripped.strip() else text
            _LOGGER.info(
                "Fetched %d bytes from core/logs (%s, %d usable, %s)",
                len(text), accept, len(result), dbg,
            )
            return result
        errors.append(f"core/logs ({accept}): {err}")
    return None


async def api_models(request: web.Request) -> web.Response:
    opts = _load_options()
    api_key = opts.get("api_key", "").strip()
    base_url = opts.get("base_url", _DEFAULTS["base_url"])

    if not api_key:
        return web.json_response({"models": []})

    url = base_url.rstrip("/") + "/models"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return web.json_response({"models": []})
                data = await resp.json(content_type=None)
    except Exception:
        return web.json_response({"models": []})

    raw = data.get("data", [])
    models = sorted(
        [{"id": m["id"], "name": m.get("name", m["id"])} for m in raw if "id" in m],
        key=lambda m: m["id"],
    )
    return web.json_response({"models": models})


async def api_config(request: web.Request) -> web.Response:
    opts = _load_options()
    return web.json_response({
        "model": opts.get("model", _DEFAULTS["model"]),
        "base_url": opts.get("base_url", _DEFAULTS["base_url"]),
        "default_lines": opts.get("default_lines", _DEFAULTS["default_lines"]),
        "default_levels": opts.get("default_levels", _DEFAULTS["default_levels"]),
        "redaction_style": opts.get("redaction_style", _DEFAULTS["redaction_style"]),
        "has_api_key": bool(opts.get("api_key", "").strip()),
    })


async def api_fetch_log(request: web.Request) -> web.Response:
    errors: list[str] = []

    async with aiohttp.ClientSession() as session:
        log_text = await _fetch_log_core_error_log(session, errors)

        if log_text is None:
            log_text = await _fetch_log_core_logs_identifier(session, errors)

        # /core/logs is the primary container-log source; try before host journal
        # (host/logs only contains host-level services, not HA Core container logs)
        if log_text is None:
            log_text = await _fetch_log_core_logs(session, errors)

        if log_text is None:
            log_text = await _fetch_log_host_journal(session, errors)

    # Filesystem fallback (non-HAOS or older installs)
    if log_text is None:
        log_path = _find_log_file()
        if log_path is not None:
            try:
                log_text = log_path.read_text(errors="replace")
                _LOGGER.info("Read %d bytes from %s", len(log_text), log_path)
            except OSError as exc:
                errors.append(f"file {log_path}: {exc}")
        else:
            errors.append(
                "filesystem: not found — checked "
                + ", ".join(str(p) for p in _LOG_CANDIDATES)
            )

    if log_text is None:
        detail = " | ".join(errors) if errors else "no sources attempted"
        return web.json_response(
            {"error": f"Could not retrieve logs. Details: {detail}"},
            status=503,
        )

    return web.json_response({"log_text": log_text})


async def api_analyze(request: web.Request) -> web.Response:
    opts = _load_options()

    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    log_text: str = body.get("log_text", "")
    if not log_text.strip():
        return web.json_response({"error": "No log text provided"}, status=400)

    lines = int(body.get("lines", opts.get("default_lines", _DEFAULTS["default_lines"])))
    levels: list[str] = (
        body.get("levels")
        or opts.get("default_levels", _DEFAULTS["default_levels"])
    )
    model: str = str(body.get("model") or opts.get("model", _DEFAULTS["model"]))

    api_key: str = opts.get("api_key", "").strip()
    if not api_key:
        return web.json_response(
            {"error": "No API key configured. Set it in the add-on configuration panel."},
            status=400,
        )

    entries = parse_text(log_text)
    filtered = filter_entries(entries, levels, lines)
    raw_text = to_text(filtered)

    if not raw_text.strip():
        found_levels = sorted({e.level for e in entries if e.level})
        total = len(entries)
        sample = repr("\n".join(log_text.splitlines()[:3]))
        if total == 0:
            detail = f"The log appears to be empty. Raw sample: {sample}"
        elif not found_levels:
            detail = (
                f"{total} lines received but none matched the expected log format. "
                f"Raw sample: {sample}"
            )
        else:
            detail = (
                f"{total} entries parsed; levels present: {', '.join(found_levels)}. "
                f"None matched the selected filter: {', '.join(levels)}."
            )
        return web.json_response({"error": detail}, status=400)

    detections = detect(raw_text)
    merged_detections = merge(detections)
    style: str = opts.get("redaction_style", _DEFAULTS["redaction_style"])
    redacted = redact_apply(raw_text, merged_detections, style)

    kinds: dict[str, int] = {}
    for det in merged_detections:
        kinds[det.kind] = kinds.get(det.kind, 0) + 1

    time_context = _log_time_context(filtered, datetime.now())

    base_url: str = opts.get("base_url", _DEFAULTS["base_url"])
    try:
        async with aiohttp.ClientSession() as session:
            result = await analyze(
                api_key=api_key,
                redacted_log=redacted,
                model=model,
                base_url=base_url,
                session=session,
                extra_instructions=time_context,
            )
    except AnalyzerError as exc:
        return web.json_response({"error": str(exc)}, status=502)

    analysis_html = md_lib.markdown(
        result.content,
        extensions=["fenced_code", "tables"],
    )

    return web.json_response({
        "analysis_html": analysis_html,
        "analysis_md": result.content,
        "redaction_count": len(merged_detections),
        "redaction_kinds": kinds,
        "entries_analyzed": len(filtered),
        "total_entries": len(entries),
        "model": result.model,
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
    })


async def _index(request: web.Request) -> web.Response:
    ingress_path = request.headers.get("X-Ingress-Path", "")
    base_href = ingress_path.rstrip("/") + "/" if ingress_path else "/"
    html = (_STATIC_DIR / "index.html").read_text()
    html = html.replace("__BASE_HREF__", base_href)
    return web.Response(text=html, content_type="text/html")


def _create_app() -> web.Application:
    app = web.Application(client_max_size=50 * 1024 * 1024)
    app.router.add_get("/api/config", api_config)
    app.router.add_get("/api/models", api_models)
    app.router.add_get("/api/log", api_fetch_log)
    app.router.add_post("/api/analyze", api_analyze)
    app.router.add_static("/static", _STATIC_DIR, name="static")
    app.router.add_get("/", _index)
    return app


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    port = int(os.environ.get("INGRESS_PORT", 8099))
    _LOGGER.info("Starting HA Log Analyzer on :%d", port)
    web.run_app(_create_app(), host="0.0.0.0", port=port)
