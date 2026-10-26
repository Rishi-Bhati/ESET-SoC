"""
Alert timestamps for outgoing email, shown in Japan Standard Time.

Every notification states the detection time in JST, labelled as such. The
source value (`occurred_at`) arrives as whatever string the sender used, so
it is parsed here, once, and every email type — the AI-written ones via the
prompt, the composed and fallback ones directly — uses the same result.

A value is converted only when it says which instant it is: an ISO 8601 offset
or "Z", an RFC 2822 zone, a trailing UTC/GMT/JST, or a Unix epoch (UTC by
definition). A wall-clock time with no zone is NOT assumed to be UTC or JST:
guessing wrong shifts the stated detection time by up to nine hours, so it is
shown exactly as received and marked as not converted.

JST is a fixed UTC+9 with no daylight saving, so a fixed offset is exact and
needs no tz database (Windows Python ships without one).

Only for display: internal timestamps, stored records and the mail-signing
X-Timestamp stay in UTC / epoch seconds.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

JST = timezone(timedelta(hours=9), "JST")

CONVERTED = "converted_to_jst"
NO_TIMEZONE = "timezone_not_stated"
UNPARSEABLE = "unrecognized_format"
MISSING = "missing"

# A raw value is echoed into the email only when it could not be converted;
# it is sender-controlled, so it is capped like a header value would be.
_RAW_MAX_CHARS = 64

_EPOCH_SECONDS_RE = re.compile(r"\d{9,10}(?:\.\d+)?")
_EPOCH_MILLIS_RE = re.compile(r"\d{12,13}")
_ZONE_SUFFIX_RE = re.compile(r"^(?P<rest>.+?)\s*(?P<zone>UTC|GMT|JST)$", re.IGNORECASE)
_ZONE_OFFSETS = {"UTC": timedelta(0), "GMT": timedelta(0), "JST": timedelta(hours=9)}

# Formats seen from ESET consoles and syslog relays that fromisoformat() does
# not read. None of them carries a zone, so they only ever yield NO_TIMEZONE.
_NAIVE_FORMATS = (
    "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M",
    "%d-%b-%Y %H:%M:%S",            # ESET PROTECT syslog "occured", e.g. 20-Sep-2026 03:05:00
    "%d.%m.%Y %H:%M:%S",
)


@dataclass(frozen=True)
class AlertTime:
    status: str                    # CONVERTED / NO_TIMEZONE / UNPARSEABLE / MISSING
    raw: str
    jst: datetime | None = None    # set only when status == CONVERTED

    @property
    def _raw_shown(self) -> str:
        return self.raw if len(self.raw) <= _RAW_MAX_CHARS else self.raw[:_RAW_MAX_CHARS] + "…"

    @property
    def en(self) -> str:
        if self.status == CONVERTED:
            return f"{self.jst:%Y-%m-%d %H:%M:%S} JST"
        if self.status == NO_TIMEZONE:
            return f"{self._raw_shown} (time zone not stated by the source; not converted to JST)"
        if self.status == UNPARSEABLE:
            return f"{self._raw_shown} (unrecognized time format; not converted to JST)"
        return "UNKNOWN"

    @property
    def ja(self) -> str:
        if self.status == CONVERTED:
            # Built from fields, not strftime: non-ASCII format strings are
            # locale-dependent on some platforms.
            t = self.jst
            return f"{t.year}年{t.month:02d}月{t.day:02d}日 {t:%H:%M:%S} JST"
        if self.status == NO_TIMEZONE:
            return f"{self._raw_shown}（送信元にタイムゾーン情報なし・JST未換算）"
        if self.status == UNPARSEABLE:
            return f"{self._raw_shown}（日時形式不明・JST未換算）"
        return "不明"


def _parse(text: str) -> datetime | None:
    """The datetime the text denotes, naive when it carries no zone; None if unreadable."""
    if _EPOCH_SECONDS_RE.fullmatch(text):
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    if _EPOCH_MILLIS_RE.fullmatch(text):
        return datetime.fromtimestamp(int(text) / 1000, tz=timezone.utc)

    suffix = _ZONE_SUFFIX_RE.match(text)
    if suffix:
        parsed = _parse(suffix["rest"])
        if parsed is None:
            return None
        zone = timezone(_ZONE_OFFSETS[suffix["zone"].upper()])
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=zone)
        # "…+00:00 UTC" agrees with itself; "…+05:30 UTC" contradicts itself.
        return parsed if parsed.utcoffset() == zone.utcoffset(None) else None

    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(text)   # naive for "-0000", per RFC 2822
    except (TypeError, ValueError, IndexError):
        pass
    for fmt in _NAIVE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_alert_time(value: object) -> AlertTime:
    text = "" if value is None else str(value).strip()
    if not text or text.upper() == "UNKNOWN":
        return AlertTime(MISSING, text)
    try:
        parsed = _parse(text)
    except (OverflowError, OSError, ValueError):   # epoch out of the platform's range
        parsed = None
    if parsed is None:
        return AlertTime(UNPARSEABLE, text)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return AlertTime(NO_TIMEZONE, text)
    return AlertTime(CONVERTED, text, parsed.astimezone(JST))
