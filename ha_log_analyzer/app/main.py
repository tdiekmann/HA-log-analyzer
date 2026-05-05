"""HA Log Analyzer add-on web server."""
from __future__ import annotations

import json
import logging
import os
import re
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


def _supervisor_token() -> str:
    return os.environ.get("SUPERVISOR_TOKEN", "")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


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


def _looks_like_traceback(text: str) -> bool:
    """Return True if the response body looks like a Supervisor internal error."""
    stripped = _strip_ansi(text)
    return "Traceback (most recent call last)" in stripped or "AttributeError:" in stripped


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


async def _fetch_log_supervisor(session: aiohttp.ClientSession) -> str | None:
    """Try HA Core REST API error_log endpoint (in-memory log handler, no file needed)."""
    token = _supervisor_token()
    if not token:
        return None
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{_SUPERVISOR_URL}/core/api/error_log"
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                _LOGGER.warning("core/api/error_log returned HTTP %d", resp.status)
                return None
            text = await resp.text()
            if _looks_like_traceback(text):
                _LOGGER.warning("core/api/error_log body looks like a Supervisor traceback, skipping")
                return None
            _LOGGER.info("Fetched %d bytes from core/api/error_log", len(text))
            return _strip_ansi(text)
    except Exception as exc:
        _LOGGER.warning("core/api/error_log failed: %s", exc)
        return None


async def _fetch_log_host_journal(session: aiohttp.ClientSession) -> str | None:
    """Try host journal endpoint, parse journald export format for HA entries."""
    token = _supervisor_token()
    if not token:
        return None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.fdo.journal",
    }
    url = f"{_SUPERVISOR_URL}/host/logs"
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                _LOGGER.warning("host/logs returned HTTP %d", resp.status)
                return None
            text = await resp.text()
            if _looks_like_traceback(text):
                _LOGGER.warning("host/logs body looks like a Supervisor traceback, skipping")
                return None
            parsed = _parse_journald_export(_strip_ansi(text))
            if parsed.strip():
                _LOGGER.info("Extracted %d chars from host/logs journal", len(parsed))
                return parsed
            _LOGGER.warning("host/logs: no HA entries found after journald parse")
            return None
    except Exception as exc:
        _LOGGER.warning("host/logs failed: %s", exc)
        return None


async def _fetch_log_core_logs(session: aiohttp.ClientSession) -> str | None:
    """Try Supervisor /core/logs (plain text). Broken in some Supervisor versions."""
    token = _supervisor_token()
    if not token:
        return None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/plain",
    }
    url = f"{_SUPERVISOR_URL}/core/logs"
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                _LOGGER.warning("core/logs returned HTTP %d", resp.status)
                return None
            text = await resp.text()
            if _looks_like_traceback(text):
                _LOGGER.warning("core/logs body looks like a Supervisor traceback, skipping")
                return None
            _LOGGER.info("Fetched %d bytes from core/logs", len(text))
            return _strip_ansi(text)
    except Exception as exc:
        _LOGGER.warning("core/logs failed: %s", exc)
        return None


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
    async with aiohttp.ClientSession() as session:
        # 1. HA Core REST API in-memory log (works even when no log file is written)
        log_text = await _fetch_log_supervisor(session)

        # 2. Host journal (journald export format, filter for homeassistant entries)
        if log_text is None:
            log_text = await _fetch_log_host_journal(session)

        # 3. Supervisor native /core/logs (broken in some versions but worth trying)
        if log_text is None:
            log_text = await _fetch_log_core_logs(session)

    # 4. Filesystem fallback (works on non-HAOS or older installs)
    if log_text is None:
        log_path = _find_log_file()
        if log_path is not None:
            try:
                log_text = log_path.read_text(errors="replace")
                _LOGGER.info("Read %d bytes from %s", len(log_text), log_path)
            except OSError as exc:
                log_text = None
                _LOGGER.warning("Could not read %s: %s", log_path, exc)

    if log_text is None:
        return web.json_response(
            {
                "error": (
                    "Could not retrieve logs. Tried: Supervisor /core/api/error_log, "
                    "/host/logs (journald), /core/logs, and filesystem paths "
                    + ", ".join(str(p) for p in _LOG_CANDIDATES)
                    + ". Check add-on logs for details."
                )
            },
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

    base_url: str = opts.get("base_url", _DEFAULTS["base_url"])
    try:
        async with aiohttp.ClientSession() as session:
            result = await analyze(
                api_key=api_key,
                redacted_log=redacted,
                model=model,
                base_url=base_url,
                session=session,
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
