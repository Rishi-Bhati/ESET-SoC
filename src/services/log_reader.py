"""
Incremental reader + query engine behind the dashboard's Logs view.

The dashboard polls the log every few seconds, and the file only ever grows
(it is opened in append mode by src/utils/logging.py), so re-reading and
re-parsing the whole thing on every poll would be wasted work. Instead the
parsed entries are cached per file and only the bytes appended since the last
call are parsed. A rotated, truncated or rewritten file (different inode,
smaller size, or same size with a new mtime) resets the cache.

Each entry gets two derived keys that the UI relies on:
  _id      byte offset of the line in the file — unique and stable across
           polls, so an expanded row stays expanded when new lines arrive.
  _source  "http" for uvicorn access lines, "app" for everything else. Access
           lines are most of the file (the dashboard's own polling is logged
           too), so being able to hide them is the single most useful filter.

Entries are redacted once at parse time, before they are cached, so neither
the rendered output nor the search filter can ever surface a credential from
an older file written before write-time redaction existed.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from src.utils.logging import redact_secrets

# How far back the view can reach. Anything older than this many bytes from
# the end of the file is not loaded (the response says so via window.truncated).
MAX_WINDOW_BYTES = 64_000_000
# Hard cap on cached entries, independent of byte size (many tiny lines).
MAX_ENTRIES = 250_000

LEVELS = ("debug", "info", "warning", "error", "critical")
SOURCES = ("app", "http")

# `127.0.0.1:52758 - "GET /health HTTP/1.1" 200`
# `127.0.0.1:37434 - "WebSocket /dashboard/api/ws" [accepted]`
_ACCESS_RE = re.compile(
    r'^(?P<client>\S+) - "(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" (?P<status>\d{3}|\[[a-z]+\])'
)


@dataclass
class _Entry:
    data: dict[str, Any]
    level: str
    source: str
    event: str
    ts: str
    haystack: str  # lower-cased JSON for the free-text filter


@dataclass
class _Cache:
    path: str = ""
    inode: int = -1
    offset: int = 0
    mtime: float = 0.0
    truncated: bool = False
    entries: list[_Entry] = field(default_factory=list)


_cache = _Cache()


def _parse_line(text: str, offset: int) -> _Entry | None:
    text = text.strip()
    if not text:
        return None
    try:
        raw = json.loads(text)
    except Exception:
        return None  # non-JSON console output
    if not isinstance(raw, dict):
        return None
    data = redact_secrets(raw)
    event = str(data.get("event") or "")
    # Pre-level-processor files wrote uvicorn lines with no level at all.
    level = str(data.get("level") or "info").lower()
    source = "app"
    m = _ACCESS_RE.match(event)
    if m:
        source = "http"
        data.setdefault("http_method", m.group("method"))
        data.setdefault("http_path", m.group("path"))
        data.setdefault("http_status", m.group("status").strip("[]"))
        data.setdefault("client", m.group("client"))
    data["_id"] = offset
    data["_source"] = source
    return _Entry(
        data=data, level=level, source=source, event=event,
        ts=str(data.get("timestamp") or ""),
        haystack=json.dumps(data, ensure_ascii=False, default=str).lower(),
    )


def _refresh(path: str) -> _Cache:
    """Brings the cache for `path` up to date with the file on disk."""
    global _cache
    st = os.stat(path)
    c = _cache
    stale = (
        c.path != path
        or c.inode != st.st_ino
        or st.st_size < c.offset
        or (st.st_size == c.offset and st.st_mtime != c.mtime)
    )
    if stale:
        c = _cache = _Cache(path=path, inode=st.st_ino)
        start = max(0, st.st_size - MAX_WINDOW_BYTES)
        c.truncated = start > 0
    else:
        start = c.offset
    if st.st_size == start:
        c.mtime = st.st_mtime
        return c

    with open(path, "rb") as f:
        f.seek(start)
        chunk = f.read(st.st_size - start)
    if stale and start > 0:
        # Began mid-file: drop the partial first line.
        nl = chunk.find(b"\n")
        skip = nl + 1 if nl >= 0 else len(chunk)
        chunk, start = chunk[skip:], start + skip
    # Only consume complete lines; a line still being written is picked up
    # on the next poll.
    end = chunk.rfind(b"\n")
    if end < 0:
        c.mtime = st.st_mtime
        c.offset = start
        return c
    complete = chunk[: end + 1]

    pos = start
    for raw_line in complete.split(b"\n")[:-1]:
        entry = _parse_line(raw_line.decode("utf-8", errors="replace"), pos)
        if entry is not None:
            c.entries.append(entry)
        pos += len(raw_line) + 1
    if len(c.entries) > MAX_ENTRIES:
        del c.entries[: len(c.entries) - MAX_ENTRIES]
        c.truncated = True
    c.offset = start + len(complete)
    c.mtime = st.st_mtime
    return c


def reset_cache() -> None:
    global _cache
    _cache = _Cache()


def _since_cutoff(since_minutes: int | None) -> str | None:
    if not since_minutes or since_minutes <= 0:
        return None
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    # Same shape structlog's TimeStamper(fmt="iso") writes, so a plain string
    # comparison orders correctly.
    return cutoff.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def query(
    path: str,
    *,
    page: int = 1,
    page_size: int = 100,
    levels: set[str] | None = None,
    sources: set[str] | None = None,
    event: str | None = None,
    q: str | None = None,
    since_minutes: int | None = None,
    sort: str = "desc",
    top_events: int = 30,
) -> dict[str, Any]:
    cache = _refresh(path)
    cutoff = _since_cutoff(since_minutes)
    needle = (q or "").strip().lower() or None
    levels = {lv for lv in (levels or set()) if lv} or None
    sources = {s for s in (sources or set()) if s} or None

    level_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    event_counts: Counter[str] = Counter()
    matched: list[_Entry] = []

    for e in cache.entries:
        # Time and text are "base" filters; the other three are facets, and
        # each facet's counts ignore that facet's own selection so its other
        # options still show how many entries picking them would give.
        if cutoff and (not e.ts or e.ts < cutoff):
            continue
        if needle and needle not in e.haystack:
            continue
        ok_level = levels is None or e.level in levels
        ok_source = sources is None or e.source in sources
        ok_event = event is None or e.event == event
        if ok_source and ok_event:
            level_counts[e.level] += 1
        if ok_level and ok_event:
            source_counts[e.source] += 1
        if ok_level and ok_source:
            event_counts[e.event] += 1
        if ok_level and ok_source and ok_event:
            matched.append(e)

    total = len(matched)
    pages = max(1, -(-total // page_size))
    page = min(max(1, page), pages)
    if sort == "asc":
        lo = (page - 1) * page_size
        window = matched[lo: lo + page_size]
    else:
        hi = total - (page - 1) * page_size
        window = matched[max(0, hi - page_size): hi][::-1]

    return {
        "lines": [e.data for e in window],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "sort": "asc" if sort == "asc" else "desc",
        "facets": {
            "levels": dict(level_counts),
            "sources": dict(source_counts),
            "events": event_counts.most_common(top_events),
        },
        "window": {
            "entries": len(cache.entries),
            "oldest": cache.entries[0].ts if cache.entries else None,
            "newest": cache.entries[-1].ts if cache.entries else None,
            "truncated": cache.truncated,
        },
    }
