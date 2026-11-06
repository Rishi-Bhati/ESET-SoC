"""
The catalogue of columns/fields a client can pick for a spreadsheet export or that the
weekly report includes. One FieldSpec per field; extractors work on an AlertBundle
(src/services/alert_catalog.py) and must return plain text/number/None, never raise.

Client-facing labels exist in Japanese and English (the portal is bilingual).

SECURITY: this registry is an ALLOWLIST and the only path by which alert data reaches
a client spreadsheet. Each extractor reads exactly the one value it names. Never add a
field that exposes internal material: the internal/C-three/engineer AI texts
(internal_summary_ja, backlog_comment_ja, engineer_summary_en,
recommended_initial_actions_en, unknown_items), the AI run/trace record, risk
factors/rationale, threat-intel lookups, staged notifications, email deliveries,
job errors, retracted recommendations or any file-system path.
tests/unit/test_client_fields.py pins the exact key set and checks for leaks.
"""
import json
from dataclasses import dataclass
from typing import Any, Callable

import structlog

from src.services.alert_catalog import AlertBundle
from src.services.xlsx_writer import epoch_jst, jst_text, recommendations_text
from src.utils.jst_time import CONVERTED, MISSING, parse_alert_time

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class FieldSpec:
    key: str
    label_ja: str
    label_en: str
    group: str                    # UI grouping, e.g. "basic", "risk", "endpoint", "ai", "recommendation"
    default_selected: bool
    extractor: Callable[[AlertBundle], Any]


# UI group key -> (label_ja, label_en), in display order.
GROUP_LABELS: dict[str, tuple[str, str]] = {
    "id": ("ID", "IDs"),
    "time": ("日時", "Times"),
    "alert": ("アラート詳細", "Alert details"),
    "ai": ("AI 初期分析", "AI initial findings"),
    "recommendation": ("エンジニア推奨対策", "Engineer recommendations"),
}

# Legacy result files (older pipeline versions) wrote "UNKNOWN" for fields the
# alert did not carry; the client sees an empty cell instead.
_PLACEHOLDERS = {"UNKNOWN"}

# Older result files stored client_notification_ja as an object with these parts.
_LEGACY_CLIENT_NOTIFICATION_PARTS = ("summary", "current_status", "required_confirmation")


# ---------------------------------------------------------------- accessors

def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _job(bundle: AlertBundle) -> dict[str, Any]:
    return _dict(getattr(bundle, "job", None))


def _result(bundle: AlertBundle) -> dict[str, Any]:
    return _dict(getattr(bundle, "result", None))


def _alert(bundle: AlertBundle) -> dict[str, Any]:
    return _dict(_result(bundle).get("normalized_alert"))


def _ai(bundle: AlertBundle) -> dict[str, Any]:
    return _dict(_result(bundle).get("ai_output"))


def _text(value: Any) -> str:
    """A scalar as text; anything else (missing, dict, list, placeholder) as ''."""
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    return "" if text.strip() in _PLACEHOLDERS else text


def _lines(value: Any) -> str:
    """A list of strings as one numbered line each."""
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return ""
    items = [_text(v) for v in value]
    return "\n".join(f"{i}. {item}" for i, item in enumerate((x for x in items if x), start=1))


def _alert_field(name: str) -> Callable[[AlertBundle], str]:
    return lambda bundle: _text(_alert(bundle).get(name))


def _ai_text(name: str) -> Callable[[AlertBundle], str]:
    return lambda bundle: _text(_ai(bundle).get(name))


def _ai_list(name: str) -> Callable[[AlertBundle], str]:
    return lambda bundle: _lines(_ai(bundle).get(name))


# --------------------------------------------------------------- extractors

def _alert_id(bundle: AlertBundle) -> str:
    return _text(_job(bundle).get("correlation_id") or _result(bundle).get("correlation_id"))


def _received_at(bundle: AlertBundle) -> str:
    when = epoch_jst(_job(bundle).get("created_at"))
    if when is None:                      # no job row: the result file's own receipt time
        parsed = parse_alert_time(_result(bundle).get("received_at"))
        when = parsed.jst.replace(tzinfo=None) if parsed.status == CONVERTED else None
    return jst_text(when)


def _occurred_at(bundle: AlertBundle) -> str:
    raw = _alert(bundle).get("occurred_at")
    parsed = parse_alert_time(raw if isinstance(raw, (str, int, float)) else None)
    if parsed.status == MISSING:
        return ""
    if parsed.status == CONVERTED:
        return jst_text(parsed.jst.replace(tzinfo=None))
    # A time with no stated zone is never guessed at: shown as sent, marked.
    return f"{parsed.raw} (JST未換算 / not converted to JST)"


def _client_notification(bundle: AlertBundle) -> str:
    value = _ai(bundle).get("client_notification_ja")
    if isinstance(value, dict):           # legacy result-file shape
        return "\n".join(t for t in (_text(value.get(k)) for k in _LEGACY_CLIENT_NOTIFICATION_PARTS) if t)
    return _text(value)


def _raw_alert_json(bundle: AlertBundle) -> str:
    """The original submitted JSON (the alert as ESET sent it), as the dashboard's
    Raw view shows it — see alert_export.original_request."""
    outer = _job(bundle).get("raw_payload")
    if isinstance(outer, dict) and outer:
        inner = outer.get("raw_payload")
        payload = inner if isinstance(inner, dict) and inner else outer
    else:
        payload = _alert(bundle).get("raw_payload")
    if not isinstance(payload, dict) or not payload:
        return ""
    return json.dumps(payload, ensure_ascii=False, default=str)


def _engineer_recommendations(bundle: AlertBundle) -> str:
    # The bundle carries active recommendations only; retracted ones are filtered
    # again here so a wrongly-built bundle still cannot leak them.
    recs = getattr(bundle, "recommendations", None)
    return recommendations_text(recs if isinstance(recs, list) else [], active_only=True)


# ------------------------------------------------------------------ registry

def _safe(key: str, extractor: Callable[[AlertBundle], Any]) -> Callable[[AlertBundle], Any]:
    def run(bundle: AlertBundle) -> Any:
        try:
            return extractor(bundle)
        except Exception as e:            # malformed data must not break an export
            logger.warning("client_field_extract_failed", field=key, error=type(e).__name__)
            return ""
    run.__name__ = f"extract_{key}"
    return run


def _spec(key: str, label_ja: str, label_en: str, group: str, default: bool,
          extractor: Callable[[AlertBundle], Any]) -> FieldSpec:
    return FieldSpec(key, label_ja, label_en, group, default, _safe(key, extractor))


_SPECS: list[FieldSpec] = [
    # IDs
    _spec("alert_id", "アラートID", "Alert ID", "id", True, _alert_id),
    _spec("eset_alert_id", "ESET アラートID", "ESET alert ID", "id", True, _alert_field("alert_id")),
    # Times (JST)
    _spec("received_at_jst", "受信日時 (JST)", "Received at (JST)", "time", True, _received_at),
    _spec("occurred_at_jst", "検知日時 (JST)", "Detected at (JST)", "time", True, _occurred_at),
    # Alert details
    _spec("risk_level", "リスクレベル", "Risk level", "alert", True,
          lambda b: _text(_result(b).get("risk_level"))),
    _spec("eset_severity", "ESET 重大度", "ESET severity", "alert", False, _alert_field("severity")),
    _spec("detection_name", "検知名", "Detection name", "alert", True, _alert_field("detection_name")),
    _spec("endpoint_name", "端末名", "Endpoint name", "alert", True, _alert_field("endpoint_name")),
    _spec("endpoint_type", "端末種別", "Endpoint type", "alert", False, _alert_field("endpoint_type")),
    _spec("os_name", "OS", "OS", "alert", False, _alert_field("os_name")),
    _spec("user_name", "ユーザー名", "User name", "alert", False, _alert_field("user_name")),
    _spec("action_taken", "実行された処置", "Action taken", "alert", True, _alert_field("action_taken")),
    _spec("threat_handled", "脅威対処済み", "Threat handled", "alert", True, _alert_field("threat_handled")),
    _spec("isolation_status", "隔離状態", "Isolation status", "alert", False, _alert_field("isolation_status")),
    _spec("object_type", "オブジェクト種別", "Object type", "alert", False, _alert_field("object_type")),
    _spec("object_uri", "オブジェクトURI", "Object URI", "alert", False, _alert_field("object_uri")),
    _spec("file_hash", "ファイルハッシュ", "File hash", "alert", False, _alert_field("file_hash")),
    _spec("url", "URL", "URL", "alert", False, _alert_field("url")),
    _spec("ip_address", "IPアドレス", "IP address", "alert", False, _alert_field("ip_address")),
    _spec("domain", "ドメイン", "Domain", "alert", False, _alert_field("domain")),
    _spec("raw_subject", "元の件名", "Original subject", "alert", False, _alert_field("raw_subject")),
    _spec("raw_content", "元の本文", "Original content", "alert", False, _alert_field("raw_content")),
    _spec("raw_alert_json", "元のアラート (JSON)", "Original alert (JSON)", "alert", False, _raw_alert_json),
    # AI initial findings (client-facing texts only)
    _spec("ai_alert_summary_ja", "AI アラート概要", "AI alert summary (Japanese)", "ai", True,
          _ai_text("alert_summary_ja")),
    _spec("ai_risk_reason_ja", "AI リスク判定理由", "AI risk reason (Japanese)", "ai", True,
          _ai_text("risk_reason_ja")),
    _spec("ai_client_notification_ja", "AI お客様向け通知", "AI client notification (Japanese)", "ai", False,
          _client_notification),
    _spec("ai_recommended_actions_ja", "AI 推奨初動対応", "AI recommended initial actions (Japanese)", "ai",
          False, _ai_list("recommended_initial_actions_ja")),
    _spec("ai_confirmation_items_ja", "AI 追加確認事項", "AI items to confirm (Japanese)", "ai", False,
          _ai_list("additional_confirmation_items_ja")),
    # Engineer recommendations (active only)
    _spec("engineer_recommendations", "エンジニア推奨対策", "Engineer recommendations", "recommendation",
          True, _engineer_recommendations),
]

# key -> FieldSpec, in display order (insertion-ordered).
REGISTRY: dict[str, FieldSpec] = {spec.key: spec for spec in _SPECS}

# Keys (in column order) used by the weekly report workbook; every key must be in REGISTRY.
# The client asked for ONLY: ID, alert details, initial AI findings, engineer countermeasures.
WEEKLY_FIELDS: list[str] = [
    "alert_id", "eset_alert_id", "received_at_jst", "occurred_at_jst", "risk_level",
    "detection_name", "endpoint_name", "action_taken", "threat_handled",
    "ai_alert_summary_ja", "ai_risk_reason_ja", "engineer_recommendations",
]

DEFAULT_FIELDS: list[str] = [spec.key for spec in _SPECS if spec.default_selected]

assert len(REGISTRY) == len(_SPECS), "duplicate client field key"
assert all(k in REGISTRY for k in WEEKLY_FIELDS), "WEEKLY_FIELDS must be registry keys"


def get_fields(keys: list[str]) -> list[FieldSpec]:
    """FieldSpecs for `keys`, in the order given. Raises ValueError naming any unknown key."""
    if isinstance(keys, str):
        raise ValueError("field keys must be a list of keys, not a string")
    unknown = [str(k) for k in keys if not isinstance(k, str) or k not in REGISTRY]
    if unknown:
        raise ValueError(f"Unknown field(s): {', '.join(unknown)}")
    return [REGISTRY[k] for k in keys]


def field_catalog() -> list[dict[str, Any]]:
    """The registry for the portal UI, in display order (no extractors)."""
    return [
        {"key": s.key, "label_ja": s.label_ja, "label_en": s.label_en,
         "group": s.group, "default_selected": s.default_selected}
        for s in REGISTRY.values()
    ]
