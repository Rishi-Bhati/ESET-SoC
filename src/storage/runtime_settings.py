"""
Dashboard-editable runtime settings for the client portal, weekly report and
email attachments.

Every setting here has an env default (src/config.py / .env) and an optional
override stored in the `app_settings` table under the key prefix "rt." — the same
DB-over-env pattern as the notification recipients in settings_store.py, so an
engineer can change any of it from the dashboard without editing .env or
restarting. Code MUST read these through get() (never through
`src.config.settings`) so a change applies on the very next read.

    await runtime_settings.get("weekly_report_weekday")   # -> "MON"
    await runtime_settings.set("client_session_idle_minutes", 30)  # ValueError if invalid
    await runtime_settings.reset("client_session_idle_minutes")    # back to env default
    await runtime_settings.get_all()  # for the dashboard settings page

Recipient lists (recommendation_notification_emails, weekly_report_emails) are NOT
here; they live with the other recipients in settings_store.py.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Any
import structlog
from src.config import settings
from src.storage import settings_store

logger = structlog.get_logger(__name__)

DB_PREFIX = "rt."

WEEKDAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}
_HHMM_RE = re.compile(r"^(\d{1,2}):(\d{2})$")


@dataclass(frozen=True)
class SettingSpec:
    key: str
    type: str  # bool | int | str | enum | time_hhmm | list
    config_attr: str  # attribute of src.config.settings holding the env default
    fallback: Any  # used only if the env default itself is invalid
    description: str = ""
    min: int | None = None  # int bounds (inclusive)
    max: int | None = None
    choices: tuple[str, ...] | None = None  # enum values
    max_length: int | None = None  # str length cap
    url: bool = False  # str must be blank or http(s)://
    secret: bool = False  # value is masked by get_all()
    group: str = ""

    def constraints(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.min is not None:
            out["min"] = self.min
        if self.max is not None:
            out["max"] = self.max
        if self.choices:
            out["choices"] = list(self.choices)
        if self.max_length is not None:
            out["max_length"] = self.max_length
        if self.url:
            out["format"] = "http(s) URL or blank"
        if self.type == "time_hhmm":
            out["format"] = "HH:MM, 24-hour, JST"
        return out


def _spec(key: str, type_: str, **kw: Any) -> SettingSpec:
    kw.setdefault("config_attr", key)
    return SettingSpec(key=key, type=type_, **kw)


REGISTRY: dict[str, SettingSpec] = {s.key: s for s in [
    # --- client portal ---
    _spec("client_portal_enabled", "bool", fallback=False, group="portal",
          description="Master switch: when off, the client portal login and API are closed."),
    _spec("client_portal_url", "str", fallback="", max_length=500, url=True, group="portal",
          description="Public base URL of the portal, used for links in emails (blank = no link)."),
    _spec("client_session_idle_minutes", "int", fallback=60, min=1, max=1440, group="portal",
          description="A client session expires after this many minutes without activity."),
    _spec("client_session_max_hours", "int", fallback=12, min=1, max=168, group="portal",
          description="A client session expires this many hours after login, however active."),
    _spec("client_login_max_failures", "int", fallback=10, min=1, max=1000, group="portal",
          description="Consecutive wrong passwords before the account is temporarily locked."),
    _spec("client_login_lockout_minutes", "int", fallback=15, min=1, max=1440, group="portal",
          description="How long a locked account stays locked."),
    _spec("client_export_max_alerts", "int", fallback=5000, min=1, max=100000, group="portal",
          description="Most alerts one client spreadsheet export may contain."),
    _spec("client_immediate_min_risk", "enum", fallback="LOW", choices=RISK_LEVELS, group="portal",
          description="Minimum risk level that triggers an immediate client notification."),
    # --- weekly report ---
    _spec("weekly_report_enabled", "bool", fallback=False, group="weekly_report",
          description="Send the weekly report automatically."),
    _spec("weekly_report_weekday", "enum", fallback="MON", choices=WEEKDAYS, group="weekly_report",
          description="Day of the week the report is sent (JST)."),
    _spec("weekly_report_time", "time_hhmm", fallback="09:00", group="weekly_report",
          description="Time of day the report is sent, HH:MM 24-hour JST."),
    _spec("weekly_report_check_interval_seconds", "int", fallback=60, min=1, max=3600,
          group="weekly_report",
          description="How often the scheduler checks whether a report is due."),
    _spec("weekly_report_max_findings_listed", "int", fallback=50, min=1, max=1000,
          group="weekly_report",
          description="Most individual findings listed in the report email body."),
    # No env variable: settings has no such attribute, so the default is `fallback`.
    _spec("weekly_report_email_enabled", "bool", fallback=False, group="weekly_report",
          description="Email the weekly report to the recipients"),
    # --- email attachments ---
    _spec("email_attachments_enabled", "bool", fallback=False, group="email",
          description="Attach files (e.g. the weekly workbook) to emails."),
    _spec("email_attachment_max_bytes", "int", fallback=1_000_000, min=1024, max=25_000_000,
          group="email",
          description="Largest attachment that will be sent; bigger files are left out."),
]}


def keys() -> list[str]:
    return list(REGISTRY)


def _spec_for(key: str) -> SettingSpec:
    try:
        return REGISTRY[key]
    except KeyError:
        raise ValueError(f"Unknown setting: {key!r}") from None


def validate(key: str, value: Any) -> Any:
    """
    Coerces and validates `value` for `key`, returning the normalised typed value
    (enum upper-cased, time zero-padded, URL stripped of a trailing slash...).
    Pure and synchronous. Raises ValueError with a message safe to show in the UI.
    """
    spec = _spec_for(key)
    t = spec.type

    if t == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in _TRUE:
            return True
        if isinstance(value, str) and value.strip().lower() in _FALSE:
            return False
        raise ValueError(f"{key}: must be true or false")

    if t == "int":
        if isinstance(value, bool):
            raise ValueError(f"{key}: must be a whole number")
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        if isinstance(value, str):
            text = value.strip()
            if not re.fullmatch(r"-?\d+", text):
                raise ValueError(f"{key}: must be a whole number")
            value = int(text)
        if not isinstance(value, int):
            raise ValueError(f"{key}: must be a whole number")
        if spec.min is not None and value < spec.min:
            raise ValueError(f"{key}: must be at least {spec.min}")
        if spec.max is not None and value > spec.max:
            raise ValueError(f"{key}: must be at most {spec.max}")
        return value

    if t == "str":
        if not isinstance(value, str):
            raise ValueError(f"{key}: must be text")
        text = value.strip()
        if spec.max_length is not None and len(text) > spec.max_length:
            raise ValueError(f"{key}: must be at most {spec.max_length} characters")
        if spec.url and text:
            if not re.match(r"^https?://[^\s/?#]+", text, re.IGNORECASE) or re.search(r"\s", text):
                raise ValueError(f"{key}: must be blank or start with http:// or https://")
            text = text.rstrip("/")
        return text

    if t == "enum":
        if not isinstance(value, str):
            raise ValueError(f"{key}: must be one of {', '.join(spec.choices or ())}")
        text = value.strip().upper()
        if text not in (spec.choices or ()):
            raise ValueError(f"{key}: must be one of {', '.join(spec.choices or ())}")
        return text

    if t == "time_hhmm":
        if not isinstance(value, str):
            raise ValueError(f"{key}: must be HH:MM (24-hour)")
        m = _HHMM_RE.match(value.strip())
        if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
            raise ValueError(f"{key}: must be HH:MM (24-hour)")
        return f"{int(m.group(1)):02d}:{m.group(2)}"

    if t == "list":
        if isinstance(value, str):
            value = [part for part in value.split(",")]
        if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"{key}: must be a list of text values")
        return [v.strip() for v in value if v.strip()]

    raise ValueError(f"{key}: unsupported type {t!r}")  # pragma: no cover


def _serialise(spec: SettingSpec, value: Any) -> str:
    if spec.type == "bool":
        return "true" if value else "false"
    if spec.type == "list":
        return json.dumps(value)
    return str(value)


def _deserialise(spec: SettingSpec, stored: str) -> Any:
    if spec.type == "list":
        return validate(spec.key, json.loads(stored))
    return validate(spec.key, stored)


def default(key: str) -> Any:
    """The env default for `key` (typed). Read at call time; an invalid env value
    falls back to the built-in default with a warning rather than failing."""
    spec = _spec_for(key)
    raw = getattr(settings, spec.config_attr, spec.fallback)
    try:
        return validate(key, raw)
    except ValueError:
        logger.warning("runtime_setting_invalid_env_default", key=key, value=str(raw))
        return spec.fallback


def _resolve(spec: SettingSpec, stored: str | None) -> tuple[Any, str]:
    if stored is not None:
        try:
            return _deserialise(spec, stored), "db"
        except (ValueError, json.JSONDecodeError):
            logger.warning("runtime_setting_invalid_stored_value", key=spec.key)
    return default(spec.key), "env"


async def get(key: str) -> Any:
    """Typed effective value: the dashboard override if one is saved and valid,
    else the env default."""
    spec = _spec_for(key)
    stored = await settings_store.get_setting(DB_PREFIX + key)
    return _resolve(spec, stored)[0]


async def source(key: str) -> str:
    """"db" if a dashboard override is in effect, else "env"."""
    spec = _spec_for(key)
    stored = await settings_store.get_setting(DB_PREFIX + key)
    return _resolve(spec, stored)[1]


async def get_all() -> dict[str, dict[str, Any]]:
    """Every setting as {key: {value, default, source, type, constraints, ...}} for
    the dashboard settings page. Secret settings (none today) are masked."""
    stored = await settings_store.get_settings_with_prefix(DB_PREFIX)
    out: dict[str, dict[str, Any]] = {}
    for spec in REGISTRY.values():
        value, src = _resolve(spec, stored.get(DB_PREFIX + spec.key))
        default_value = default(spec.key)
        if spec.secret:
            value = "********" if value else ""
            default_value = "********" if default_value else ""
        out[spec.key] = {
            "value": value,
            "default": default_value,
            "source": src,
            "type": spec.type,
            "constraints": spec.constraints(),
            "group": spec.group,
            "description": spec.description,
            "secret": spec.secret,
        }
    return out


async def set(key: str, value: Any) -> Any:  # noqa: A001 - public API name
    """Validates and saves a dashboard override. Returns the normalised value.
    Raises ValueError (unknown key or invalid value) without writing anything."""
    spec = _spec_for(key)
    clean = validate(key, value)
    await settings_store.set_setting(DB_PREFIX + key, _serialise(spec, clean))
    return clean


async def reset(key: str) -> bool:
    """Removes the dashboard override so the env default applies again.
    Returns True if an override existed. Raises ValueError for an unknown key."""
    _spec_for(key)
    return await settings_store.delete_setting(DB_PREFIX + key)
