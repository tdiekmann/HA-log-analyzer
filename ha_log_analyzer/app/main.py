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
_SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")

_DEFAULTS = {
    "model": "anthropic/claude-haiku-4-5",
    "base_url": "https://openrouter.ai/api/v1",
    "default_lines": 500,
    "default_levels": ["WARNING", "ERROR", "CRITICAL"],
    "redaction_style": "typed",
}

# Docker log timestamp prefix: 2026-05-04T15:51:51.879054321Z<space>
_DOCKER_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+")
# Journald export format: KEY=value blocks separated by blank lines
_JOURNALD_KEY_RE = re.compile(r"^[A-Z_]+=")


def _normalise_supervisor_log(raw: str) -> str:
    """Convert whatever format the Supervisor returns into plain HA log text.

    Handles:
    - Standard HA log text (no-op)
    - Docker log timestamps prefixed to each line
    - systemd journal export format (KEY=VALUE blocks, extract MESSAGE=)
    """
    lines = raw.splitlines()
    if not lines:
        return raw

    first = lines[0]
    _LOGGER.info("Log format sample (first line): %r", first[:120])

    # Docker timestamp prefix
    if _DOCKER_TS_RE.match(first):
        _LOGGER.info("Detected Docker timestamp prefix — stripping")
        return "\n".join(_DOCKER_TS_RE.sub("", l) for l in lines)

    # systemd journal export: majority of lines are KEY=VALUE
    kv_count = sum(1 for l in lines[:20] if _JOURNALD_KEY_RE.match(l))
    if kv_count >= 3:
        _LOGGER.info("Detected journald export format — extracting MESSAGE fields")
        extracted: list[str] = []
        for line in lines:
            if line.startswith("MESSAGE="):
                extracted.append(line[len("MESSAGE="):])
        return "\n".join(extracted)

    return raw


def _load_options() -> dict:
    try:
        return json.loads(_OPTIONS_FILE.read_text())
    except Exception:
        return {}


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
    if not _SUPERVISOR_TOKEN:
        return web.json_response(
            {"error": "SUPERVISOR_TOKEN not set — is the add-on running inside Home Assistant?"},
            status=503,
        )
    headers = {
        "Authorization": f"Bearer {_SUPERVISOR_TOKEN}",
        "Accept": "text/plain",
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "http://supervisor/core/logs",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    return web.json_response(
                        {"error": f"Supervisor returned HTTP {resp.status}: {body[:200]}"},
                        status=502,
                    )
                log_text = await resp.text()
    except aiohttp.ClientError as exc:
        return web.json_response({"error": f"Could not reach Supervisor: {exc}"}, status=502)

    log_text = _normalise_supervisor_log(log_text)
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
