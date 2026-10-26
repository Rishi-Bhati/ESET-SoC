"""
Alert timestamps shown in email: converted to JST only when the source says
which instant it is, never guessed (src/utils/jst_time.py).
"""
import pytest
from src.utils.jst_time import (
    CONVERTED, MISSING, NO_TIMEZONE, UNPARSEABLE, parse_alert_time,
)


@pytest.mark.parametrize("value", [
    "2026-09-20T03:05:00Z",
    "2026-09-20T03:05:00.123456Z",
    "2026-09-20T03:05:00+00:00",
    "2026-09-20 03:05:00Z",
    "2026-09-20T12:05:00+09:00",           # already JST
    "2026-09-20T08:35:00+05:30",           # IST
    "2026-09-19T23:05:00-04:00",           # crosses midnight
    "2026-09-20 03:05:00 UTC",
    "2026-09-20 03:05:00 gmt",
    "2026-09-20 12:05:00 JST",
    "Sun, 20 Sep 2026 03:05:00 +0000",     # RFC 2822
])
def test_values_with_a_zone_are_converted_to_jst(value):
    t = parse_alert_time(value)
    assert t.status == CONVERTED
    assert t.en == "2026-09-20 12:05:00 JST"
    assert t.ja == "2026年09月20日 12:05:00 JST"


def test_conversion_rolls_over_the_date_and_year():
    assert parse_alert_time("2026-12-31T20:00:00Z").en == "2027-01-01 05:00:00 JST"


@pytest.mark.parametrize("value", ["1789873500", "1789873500000", 1789873500, "1789873500.25"])
def test_unix_epochs_are_utc_and_converted(value):
    # 1789873500 = 2026-09-20T03:05:00Z
    assert parse_alert_time(value).en == "2026-09-20 12:05:00 JST"


@pytest.mark.parametrize("value", [
    "2026-09-20T03:05:00",
    "2026-09-20 03:05:00",
    "2026/09/20 03:05:00",
    "20-Sep-2026 03:05:00",                # ESET PROTECT syslog "occured"
    "Sun, 20 Sep 2026 03:05:00 -0000",     # RFC 2822's "zone unknown"
])
def test_values_without_a_zone_are_never_assumed_utc(value):
    t = parse_alert_time(value)
    assert t.status == NO_TIMEZONE and t.jst is None
    assert t.en.startswith(value) and "not converted to JST" in t.en
    assert t.ja.startswith(value) and "JST未換算" in t.ja
    assert "12:05" not in t.en, "must not shift a time whose zone is unknown"


@pytest.mark.parametrize("value", ["yesterday", "2026-13-45T00:00:00Z", "99999999999999999",
                                   "2026-09-20T03:05:00+05:30 UTC"])
def test_unreadable_or_contradictory_values_are_shown_as_received(value):
    t = parse_alert_time(value)
    assert t.status == UNPARSEABLE
    assert t.en == f"{value} (unrecognized time format; not converted to JST)"


@pytest.mark.parametrize("value", [None, "", "  ", "UNKNOWN", "unknown"])
def test_missing_values(value):
    t = parse_alert_time(value)
    assert t.status == MISSING and t.en == "UNKNOWN" and t.ja == "不明"


def test_an_overlong_raw_value_is_capped():
    t = parse_alert_time("x" * 500)
    assert len(t.en) < 150 and "…" in t.en
