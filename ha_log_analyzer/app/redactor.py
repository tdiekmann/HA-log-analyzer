"""Pure-Python, regex-only redactor for Home Assistant logs.

This module has zero third-party dependencies so it can run in-process inside
Home Assistant without pulling spaCy/Presidio/etc.

The standalone FastAPI server in ``app/`` re-uses the same patterns and adds
Microsoft Presidio on top for broader PII coverage. Inside HA we keep things
lightweight and deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


@dataclass(frozen=True)
class Detection:
    start: int
    end: int
    kind: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class _Pattern:
    kind: str
    regex: re.Pattern[str]
    confidence: float
    reason: str
    capture_group: int = 0


def _compile(pattern: str, flags: int = re.MULTILINE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# Patterns are ordered roughly from most-specific to most-generic so that the
# overlap-merging step prefers high-confidence matches when ranges collide.
_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        kind="PRIVATE_KEY",
        regex=_compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        confidence=1.0,
        reason="PEM-encoded private key block",
    ),
    _Pattern(
        kind="HA_LONG_LIVED_TOKEN",
        # HA long-lived access tokens are JWT-style: three base64url segments.
        regex=_compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        confidence=0.99,
        reason="JWT-shaped token (likely HA long-lived access token)",
    ),
    _Pattern(
        kind="API_KEY",
        regex=_compile(r"\bAKIA[0-9A-Z]{16}\b"),
        confidence=0.99,
        reason="AWS access key id",
    ),
    _Pattern(
        kind="API_KEY",
        regex=_compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9]{20,}\b"),
        confidence=0.95,
        reason="OpenAI/Stripe-style key prefix",
    ),
    _Pattern(
        kind="API_KEY",
        regex=_compile(r"\bsk-or-(?:v\d+-)?[A-Za-z0-9_\-]{20,}\b"),
        confidence=0.99,
        reason="OpenRouter API key",
    ),
    _Pattern(
        kind="API_KEY",
        regex=_compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        confidence=0.99,
        reason="GitHub token",
    ),
    _Pattern(
        kind="PASSWORD",
        regex=_compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*([^\s,;]+)"),
        confidence=0.99,
        reason="credential assignment pattern",
        capture_group=1,
    ),
    _Pattern(
        kind="TOKEN",
        regex=_compile(
            r"(?i)\b(?:access[_-]?token|refresh[_-]?token|api[_-]?token|bearer)"
            r"\b\s*[:=]?\s*([A-Za-z0-9._\-]{12,})"
        ),
        confidence=0.95,
        reason="token-like assignment",
        capture_group=1,
    ),
    _Pattern(
        kind="TOKEN",
        regex=_compile(r"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9._\-]{8,})"),
        confidence=0.99,
        reason="Authorization Bearer header",
        capture_group=1,
    ),
    _Pattern(
        kind="GENERIC_SECRET",
        regex=_compile(
            r"(?i)\b(?:secret|client[_-]?secret|db[_-]?password|webhook[_-]?id|api[_-]?key)"
            r"\b\s*[:=]\s*([^\s,;]+)"
        ),
        confidence=0.92,
        reason="generic secret field name",
        capture_group=1,
    ),
    _Pattern(
        kind="URL_CREDENTIALS",
        regex=_compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/@:]+:([^\s/@]+)@[^\s/]+"),
        confidence=0.99,
        reason="credentials embedded in URL",
        capture_group=1,
    ),
    _Pattern(
        kind="EMAIL",
        regex=_compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        confidence=0.95,
        reason="email address",
    ),
    _Pattern(
        kind="MAC_ADDRESS",
        regex=_compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"),
        confidence=0.97,
        reason="MAC address",
    ),
    _Pattern(
        kind="IP_ADDRESS",
        # Public-ish IPv4. Matches RFC1918 too — those are arguably safe but
        # we let the policy decide on the consumer side; treat them as PII for now.
        regex=_compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        confidence=0.90,
        reason="IPv4 address",
    ),
    _Pattern(
        kind="IP_ADDRESS",
        # Full IPv6 form (8 groups, 7 colons). Require ≥4 colons so we don't
        # match HH:MM:SS timestamps. MAC addresses also match this shape but
        # are caught by the MAC pattern first at higher confidence and win
        # the overlap-merge.
        regex=_compile(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b"),
        confidence=0.85,
        reason="IPv6 address (full form)",
    ),
    _Pattern(
        kind="IP_ADDRESS",
        # IPv6 compressed form — must contain ``::`` so this can't collide
        # with timestamps or MAC addresses.
        regex=_compile(
            r"(?<![:\w])(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{0,4}"
            r"(?::[0-9a-fA-F]{1,4}){0,6}(?![:\w])"
        ),
        confidence=0.85,
        reason="IPv6 address (:: shorthand)",
    ),
    _Pattern(
        kind="LATLON",
        regex=_compile(
            r"(?i)\b(?:latitude|longitude|lat|lon|lng)\b\s*[:=]\s*"
            r"(-?\d{1,3}\.\d{2,})"
        ),
        confidence=0.95,
        reason="geographic coordinate",
        capture_group=1,
    ),
    _Pattern(
        kind="HA_USER_ID",
        # HA user_id / device_id / entry_id are 32-char hex.
        regex=_compile(r"(?i)\b(?:user_id|device_id|entry_id|webhook_id)\s*[:=]\s*([a-f0-9]{32})\b"),
        confidence=0.95,
        reason="HA 32-char hex id",
        capture_group=1,
    ),
    _Pattern(
        kind="UUID",
        regex=_compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        confidence=0.80,
        reason="UUID",
    ),
    _Pattern(
        kind="SSID",
        regex=_compile(r"(?i)\bssid\b\s*[:=]\s*([^\s,;]+)"),
        confidence=0.90,
        reason="Wi-Fi SSID",
        capture_group=1,
    ),
    _Pattern(
        kind="CREDIT_CARD",
        regex=_compile(r"\b(?:\d[ \-]?){13,19}\b"),
        confidence=0.60,
        reason="credit-card-shaped digit run",
    ),
)


def detect(text: str) -> list[Detection]:
    """Run every pattern over ``text`` and return raw, possibly-overlapping hits."""
    found: list[Detection] = []
    for pat in _PATTERNS:
        for match in pat.regex.finditer(text):
            if pat.capture_group and match.lastindex and match.lastindex >= pat.capture_group:
                start, end = match.span(pat.capture_group)
            else:
                start, end = match.span()
            if start == end:
                continue
            found.append(
                Detection(
                    start=start,
                    end=end,
                    kind=pat.kind,
                    confidence=pat.confidence,
                    reason=pat.reason,
                )
            )
    return found


def merge(detections: Iterable[Detection]) -> list[Detection]:
    """Collapse overlapping detections, preferring higher confidence."""
    ordered = sorted(detections, key=lambda d: (d.start, -d.confidence, d.end))
    merged: list[Detection] = []
    for item in ordered:
        if not merged or item.start >= merged[-1].end:
            merged.append(item)
            continue
        prev = merged[-1]
        if item.confidence > prev.confidence:
            merged[-1] = Detection(
                start=prev.start,
                end=max(prev.end, item.end),
                kind=item.kind,
                confidence=item.confidence,
                reason=item.reason,
            )
        else:
            merged[-1] = Detection(
                start=prev.start,
                end=max(prev.end, item.end),
                kind=prev.kind,
                confidence=prev.confidence,
                reason=prev.reason,
            )
    return merged


def apply(text: str, detections: Iterable[Detection], style: str = "typed",
          fixed: str = "[REDACTED]") -> str:
    """Replace each detected span with a placeholder. Operates right-to-left
    so offsets in earlier spans remain valid as we splice."""
    result = text
    for det in sorted(detections, key=lambda d: d.start, reverse=True):
        replacement = f"[{det.kind}]" if style == "typed" else fixed
        result = result[: det.start] + replacement + result[det.end :]
    return result


def redact(text: str, style: str = "typed",
           fixed: str = "[REDACTED]") -> tuple[str, list[Detection]]:
    """Convenience: detect + merge + apply in one call."""
    findings = merge(detect(text))
    return apply(text, findings, style=style, fixed=fixed), findings
