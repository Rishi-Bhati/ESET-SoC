"""Weekly report period math: due slot, period, ISO-week keys, JST vs a UTC server clock."""
from datetime import datetime, timedelta, timezone
import pytest
from src.services import weekly_report as wr
from src.utils.jst_time import JST


def jst(*args) -> datetime:
    return datetime(*args, tzinfo=JST)


def test_due_slot_is_most_recent_weekday_time_at_or_before_now():
    assert wr.due_slot(jst(2026, 11, 9, 9, 0), "MON", "09:00") == jst(2026, 11, 9, 9, 0)
    assert wr.due_slot(jst(2026, 11, 9, 8, 59), "MON", "09:00") == jst(2026, 11, 2, 9, 0)
    assert wr.due_slot(jst(2026, 11, 12, 15, 0), "MON", "09:00") == jst(2026, 11, 9, 9, 0)
    assert wr.due_slot(jst(2026, 11, 12, 15, 0), "fri", "18:30") == jst(2026, 11, 6, 18, 30)


def test_sunday_2359_vs_monday_0000_jst():
    # Sunday 23:59 JST: the Monday 00:00 slot of the coming week is not due yet.
    before = wr.due_slot(jst(2026, 11, 8, 23, 59), "MON", "00:00")
    at = wr.due_slot(jst(2026, 11, 9, 0, 0), "MON", "00:00")
    assert wr.period_for_slot(before).key == "2026-W44"
    assert wr.period_for_slot(at).key == "2026-W45"
    p = wr.period_for_slot(at)
    assert (p.start, p.end) == (jst(2026, 11, 2), jst(2026, 11, 9))
    assert p.end_epoch - p.start_epoch == 7 * 86400


def test_utc_server_clock_is_converted_to_jst():
    # 2026-11-09 00:30 JST == 2026-11-08 15:30 UTC (still Sunday in UTC)
    utc_now = datetime(2026, 11, 8, 15, 30, tzinfo=timezone.utc)
    assert wr.due_slot(utc_now, "MON", "00:00") == jst(2026, 11, 9, 0, 0)
    naive_utc = datetime(2026, 11, 8, 15, 30)          # naive = UTC
    assert wr.due_slot(naive_utc, "MON", "00:00") == jst(2026, 11, 9, 0, 0)
    # 08:59 JST Monday is 23:59 UTC Sunday -> the 09:00 slot is not due yet
    assert wr.due_slot(datetime(2026, 11, 8, 23, 59, tzinfo=timezone.utc), "MON", "09:00") \
        == jst(2026, 11, 2, 9, 0)
    assert wr.due_slot(datetime(2026, 11, 9, 0, 0, tzinfo=timezone.utc), "MON", "09:00") \
        == jst(2026, 11, 9, 9, 0)


def test_year_boundary_iso_weeks():
    # Period starting Mon 2025-12-29 is ISO 2026-W01; the one after 2026-12-28 is 2026-W53.
    assert wr.period_for_slot(jst(2026, 1, 5, 9)).key == "2026-W01"
    assert wr.period_for_slot(jst(2026, 1, 5, 9)).start == jst(2025, 12, 29)
    assert wr.period_for_slot(jst(2027, 1, 4, 9)).key == "2026-W53"
    assert wr.period_for_slot(jst(2027, 1, 11, 9)).key == "2027-W01"
    assert wr.period_from_key("2026-W53").start == jst(2026, 12, 28)
    with pytest.raises(ValueError):
        wr.period_from_key("2025-W53")                  # 2025 has 52 ISO weeks


def test_weekday_and_time_changes_keep_the_same_period_within_a_week():
    now = jst(2026, 11, 13, 20, 0)   # Friday
    keys = {wr.period_for_slot(wr.due_slot(now, day, hhmm)).key
            for day, hhmm in (("MON", "09:00"), ("TUE", "00:00"), ("FRI", "19:59"))}
    assert keys == {"2026-W45"}
    # a slot later on Friday is not due yet -> still last week's slot, previous period
    assert wr.period_for_slot(wr.due_slot(now, "FRI", "20:01")).key == "2026-W44"


def test_next_slot_is_strictly_after_now():
    assert wr.next_slot(jst(2026, 11, 9, 9, 0), "MON", "09:00") == jst(2026, 11, 16, 9, 0)
    assert wr.next_slot(jst(2026, 11, 9, 8, 0), "MON", "09:00") == jst(2026, 11, 9, 9, 0)


def test_period_tuple_unpacks_and_round_trips():
    key, start, end = wr.period_for_slot(jst(2026, 11, 9, 9))
    assert wr.period_from_key(key) == (key, start, end)
    assert wr.period_from_key("2026-W45-r2").key == "2026-W45"
    assert end - start == timedelta(days=7)


@pytest.mark.parametrize("bad", ["", "2026-45", "2026-W5", "2026-W00", "2026-W54", "../2026-W45",
                                 "2026-W45/../x", "2026-W45.xlsx", "2026-W45-r", None, 202645])
def test_invalid_period_keys_rejected(bad):
    with pytest.raises(ValueError):
        wr.validate_period_key(bad)
    with pytest.raises(ValueError):
        wr.report_path(bad)


def test_report_path_built_from_key_only():
    path = wr.report_path("2026-W45-r3")
    assert path.endswith("/weekly/2026-W45.xlsx")


@pytest.mark.parametrize("bad_time", ["24:00", "9am", "09:60"])
def test_invalid_schedule_rejected(bad_time):
    with pytest.raises(ValueError):
        wr.due_slot(jst(2026, 11, 9), "MON", bad_time)
    with pytest.raises(ValueError):
        wr.due_slot(jst(2026, 11, 9), "FUNDAY", "09:00")
