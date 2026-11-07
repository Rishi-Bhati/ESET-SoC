"""Pure helpers behind GET /client/api/stats (src/services/client_stats.py)."""
from datetime import date

import pytest

from src.services import client_stats as cs


def test_period_days_ends_today_inclusive():
    assert cs.period_days(date(2026, 11, 9), 7) == (date(2026, 11, 3), date(2026, 11, 9))
    assert cs.period_days(date(2026, 11, 9), 1) == (date(2026, 11, 9), date(2026, 11, 9))
    assert cs.period_days(date(2026, 3, 1), 30) == (date(2026, 1, 31), date(2026, 3, 1))


def test_previous_period_is_the_same_length_and_adjacent():
    first, _ = cs.period_days(date(2026, 11, 9), 30)
    assert cs.previous_period(first, 30) == (date(2026, 9, 11), date(2026, 10, 10))
    prev_first, prev_last = cs.previous_period(date(2026, 11, 3), 7)
    assert (prev_last - prev_first).days + 1 == 7 and (date(2026, 11, 3) - prev_last).days == 1


def test_daily_buckets_are_zero_filled_and_ordered():
    by_day = {("2026-11-05", "LOW"): 2, ("2026-11-05", "HIGH"): 1, ("2026-11-09", "CRITICAL"): 1,
              ("2026-11-02", "LOW"): 9}                        # outside the period: ignored
    out, size = cs.buckets(by_day, date(2026, 11, 3), date(2026, 11, 9))
    assert size == 1
    assert [b["from"] for b in out] == ["2026-11-03", "2026-11-04", "2026-11-05", "2026-11-06",
                                        "2026-11-07", "2026-11-08", "2026-11-09"]
    assert out[2]["counts"] == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 2}
    assert out[0]["counts"] == cs.empty_counts()
    assert out[-1]["counts"]["CRITICAL"] == 1


@pytest.mark.parametrize("days,size", [(7, 1), (30, 1), (31, 1), (32, 7), (90, 7)])
def test_bucket_size_switches_to_weeks_past_a_month(days, size):
    first, last = cs.period_days(date(2026, 11, 9), days)
    out, got = cs.buckets({}, first, last)
    assert got == size
    assert out[0]["from"] == first.isoformat() and out[-1]["to"] == last.isoformat()
    covered = sum((date.fromisoformat(b["to"]) - date.fromisoformat(b["from"])).days + 1 for b in out)
    assert covered == days                                     # no gaps, no overlaps


def test_weekly_buckets_count_back_from_today_so_only_the_oldest_is_short():
    first, last = cs.period_days(date(2026, 11, 9), 90)
    by_day = {("2026-11-03", "LOW"): 1, ("2026-11-09", "LOW"): 1, ("2026-11-02", "HIGH"): 4}
    out, _ = cs.buckets(by_day, first, last)
    assert len(out) == 13
    lengths = [(date.fromisoformat(b["to"]) - date.fromisoformat(b["from"])).days + 1 for b in out]
    assert lengths == [6] + [7] * 12
    assert out[-1] == {"from": "2026-11-03", "to": "2026-11-09", "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 2}}
    assert out[-2]["counts"]["HIGH"] == 4


def test_totals_ignore_unknown_levels():
    assert cs.totals({("2026-11-03", "LOW"): 2, ("2026-11-04", "LOW"): 1, ("2026-11-04", "WEIRD"): 5}) == {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 3}


@pytest.mark.parametrize("raw,clean", [
    (None, None), ("", None), ("   ", None), ("UNKNOWN", None), ("unknown", None), ("N/A", None),
    ("PC-1", "PC-1"), ("  PC-1 ", "PC-1"), ("Unknown-Host-7", "Unknown-Host-7"),
])
def test_clean_name(raw, clean):
    assert cs.clean_name(raw) == clean


def test_ranked_orders_by_count_then_name_with_not_recorded_last_on_ties():
    raw = {"b-host": 3, "a-host": 3, None: 3, "UNKNOWN": 0, "c-host": 5, "": 0}
    top, rest = cs.ranked(raw, top_n=5)
    assert top == [{"name": "c-host", "count": 5}, {"name": "a-host", "count": 3},
                   {"name": "b-host", "count": 3}, {"name": None, "count": 3}]
    assert rest == {"names": 0, "alerts": 0}


def test_ranked_merges_missing_names_and_reports_the_rest():
    raw = {"UNKNOWN": 2, None: 1, "": 1, "h1": 9, "h2": 8, "h3": 7, "h4": 6, "h5": 5, "h6": 1}
    top, rest = cs.ranked(raw, top_n=3)
    assert [t["name"] for t in top] == ["h1", "h2", "h3"]
    assert rest == {"names": 4, "alerts": 6 + 5 + 4 + 1}       # h4, h5, not-recorded (2+1+1), h6


def test_distinct_named_skips_not_recorded():
    assert cs.distinct_named({"UNKNOWN": 3, None: 1, "PC-1": 2, "PC-2": 1, " PC-1": 1}) == 2
    assert cs.distinct_named({}) == 0
