"""Parser for Home Assistant log files.

HA's default format is::

    2024-01-15 10:30:45.123 ERROR (MainThread) [homeassistant.components.foo] message

Tracebacks and other multi-line content follow the header line and do *not*
themselves start with a timestamp, so we group continuation lines into the
preceding entry. The parser is tolerant: anything we cannot fit into the
schema is returned as a raw entry with ``level=None``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Iterable, Iterator


# Tolerate ' ' or 'T' between date and time, optional milliseconds, and either
# bracketed or non-bracketed thread.
_HEADER_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL)\s+"
    r"\((?P<thread>[^)]+)\)\s+"
    r"\[(?P<logger>[^\]]+)\]\s?"
    r"(?P<message>.*)$"
)


@dataclass
class LogEntry:
    timestamp: str | None
    level: str | None
    thread: str | None
    logger: str | None
    message: str
    extra_lines: list[str] = field(default_factory=list)

    @property
    def full_text(self) -> str:
        head_parts = []
        if self.timestamp:
            head_parts.append(self.timestamp)
        if self.level:
            head_parts.append(self.level)
        if self.thread:
            head_parts.append(f"({self.thread})")
        if self.logger:
            head_parts.append(f"[{self.logger}]")
        head = " ".join(head_parts)
        head = f"{head} {self.message}".strip() if head else self.message
        if self.extra_lines:
            return head + "\n" + "\n".join(self.extra_lines)
        return head


def parse(lines: Iterable[str]) -> list[LogEntry]:
    """Parse an iterable of raw log lines into structured ``LogEntry`` objects."""
    entries: list[LogEntry] = []
    current: LogEntry | None = None
    for raw in lines:
        line = raw.rstrip("\n").rstrip("\r")
        if not line:
            if current is not None:
                current.extra_lines.append("")
            continue
        match = _HEADER_RE.match(line)
        if match:
            if current is not None:
                entries.append(current)
            current = LogEntry(
                timestamp=match.group("ts"),
                level=match.group("level").upper(),
                thread=match.group("thread"),
                logger=match.group("logger"),
                message=match.group("message"),
            )
        elif current is not None:
            current.extra_lines.append(line)
        else:
            entries.append(
                LogEntry(timestamp=None, level=None, thread=None, logger=None, message=line)
            )
    if current is not None:
        entries.append(current)
    return entries


def parse_text(text: str) -> list[LogEntry]:
    return parse(text.splitlines())


def filter_entries(
    entries: Iterable[LogEntry],
    levels: Iterable[str] | None = None,
    last_n: int | None = None,
) -> list[LogEntry]:
    """Filter by level and/or keep only the last ``last_n`` matching entries."""
    items = list(entries)
    if levels:
        wanted = {lvl.upper() for lvl in levels}
        items = [e for e in items if e.level and e.level in wanted]
    if last_n is not None and last_n > 0:
        items = items[-last_n:]
    return items


def to_text(entries: Iterable[LogEntry]) -> str:
    return "\n".join(e.full_text for e in entries)


def iter_entries(text: str) -> Iterator[LogEntry]:
    yield from parse_text(text)
