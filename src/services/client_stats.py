"""
Shapes the client portal's Home statistics from alert_index_store.window_aggregates().
Pure functions (no I/O), so the bucketing, ranking and name tidying are unit-tested
directly (tests/unit/test_client_stats.py).

Periods are JST calendar days, both ends inclusive, ending today: a 30-day period is
today and the 29 days before it, the same window the portal's "Last 30 days" list
filter uses. Up to DAILY_MAX_DAYS the chart has one bucket per day; longer periods
are cut into 7-day buckets counted back from today, so only the oldest bucket can be
shorter (a 90-day period: twelve full weeks and one 6-day bucket).
"""
from datetime import date, timedelta
from typing import Any, Mapping

RISKS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
DAILY_MAX_DAYS = 31
TOP_N = 5
# What the normalizer stores when the alert did not say; shown to the client as "not reported".
_MISSING_NAMES = {"", "UNKNOWN", "NONE", "NULL", "N/A"}


def period_days(today: date, days: int) -> tuple[date, date]:
    """(first, last) JST day of the `days`-day period ending `today`, both inclusive."""
    return today - timedelta(days=days - 1), today


def previous_period(first: date, days: int) -> tuple[date, date]:
    """The `days`-day period immediately before the one starting on `first`."""
    return first - timedelta(days=days), first - timedelta(days=1)


def clean_name(name: Any) -> str | None:
    """A device/threat name as shown to the client, or None when the alert did not carry one."""
    if name is None:
        return None
    text = str(name).strip()
    return None if text.upper() in _MISSING_NAMES else text


def empty_counts() -> dict[str, int]:
    return {level: 0 for level in RISKS}


def buckets(by_day: Mapping[tuple[str, str], int], first: date, last: date) -> tuple[list[dict[str, Any]], int]:
    """Zero-filled chart buckets covering first..last, oldest first, and the bucket size
    in days (1 or 7). Each bucket: {"from", "to" (YYYY-MM-DD, inclusive), "counts"}."""
    days = (last - first).days + 1
    size = 1 if days <= DAILY_MAX_DAYS else 7
    out: list[dict[str, Any]] = []
    end = last
    while end >= first:
        start = max(first, end - timedelta(days=size - 1))
        counts = empty_counts()
        d = start
        while d <= end:
            key = d.isoformat()
            for level in RISKS:
                counts[level] += int(by_day.get((key, level), 0))
            d += timedelta(days=1)
        out.append({"from": start.isoformat(), "to": end.isoformat(), "counts": counts})
        end = start - timedelta(days=1)
    out.reverse()
    return out, size


def totals(by_day: Mapping[tuple[str, str], int]) -> dict[str, int]:
    counts = empty_counts()
    for (_, level), n in by_day.items():
        if level in counts:
            counts[level] += int(n)
    return counts


def merge_names(raw: Mapping[Any, int]) -> dict[str | None, int]:
    """Counts keyed by clean_name(): blank and 'UNKNOWN' collapse into one None entry."""
    merged: dict[str | None, int] = {}
    for name, n in raw.items():
        key = clean_name(name)
        merged[key] = merged.get(key, 0) + int(n)
    return merged


def ranked(raw: Mapping[Any, int], top_n: int = TOP_N) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The top_n names by count (ties: alphabetical, 'not reported' last) and what is left:
    {"names": how many other names, "alerts": their alert count}."""
    merged = merge_names(raw)
    order = sorted(((k, n) for k, n in merged.items() if n > 0), key=lambda kv: (-kv[1], kv[0] is None, kv[0] or ""))
    top = [{"name": name, "count": n} for name, n in order[:top_n]]
    rest = order[top_n:]
    return top, {"names": len(rest), "alerts": sum(n for _, n in rest)}


def distinct_named(raw: Mapping[Any, int]) -> int:
    """How many distinct named entries (not-reported excluded) have at least one alert."""
    return sum(1 for name, n in merge_names(raw).items() if name is not None and n > 0)
