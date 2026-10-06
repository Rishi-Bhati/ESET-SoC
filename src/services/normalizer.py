from typing import Any
import structlog
from src.models.raw_payload import EsetRawPayload
from src.models.normalized_alert import NormalizedAlert

logger = structlog.get_logger(__name__)

# Alternate key names normalize() will look for in the ORIGINAL submitted JSON
# (raw.raw_payload) when the primary EsetRawPayload field is empty.
#
# Why this exists: the ingest routes accept any JSON object (src/api/webhook.py has
# no required fields, EsetRawPayload has extra="allow") — this platform does not
# require a sender to match ESET's exact field names. Without this table, a payload
# shaped like {"threat":"...", "host":"...", "sev":"high"} normalized to a wall of
# absent fields, the deterministic risk engine fell back to its MEDIUM safety default
# for every such alert, and the dashboard table showed nothing useful — even though
# the sender's JSON plainly contained the information.
#
# This is a best-effort heuristic, not a schema requirement: it is only ever a
# fallback (the exact EsetRawPayload field always wins when present — which covers
# real ESET webhook/syslog payloads and anything already mapped by
# src/ingestion/syslog_handler.py), and when nothing matches, the field stays
# absent (None) — it is never filled with a placeholder. The model still sees the complete, unmodified original payload
# (see src/services/ai/base.py) and can extract from whatever shape it
# actually is — that is the layer that makes an arbitrary JSON shape produce a real
# alert summary that this alias table cannot.
_ALIASES: dict[str, tuple[str, ...]] = {
    "event_type": ("event_type", "log_type", "event", "type"),
    "alert_id": ("alert_id", "id", "event_id"),
    "detection_uuid": ("detection_uuid", "uuid", "detection_id"),
    "target_uuid": ("target_uuid", "computer_uuid", "endpoint_id", "device_id"),
    "occurred_at": ("occurred_at", "occurred", "time", "timestamp", "event_time", "date"),
    "severity": ("severity", "risk", "risk_level", "level", "priority", "sev"),
    "detection_name": ("detection_name", "threat_name", "name", "signature", "rule", "title", "alert_name"),
    "endpoint_name": ("endpoint_name", "computer_name", "hostname", "host", "device_name", "machine"),
    "endpoint_type": ("endpoint_type", "device_type", "machine_type"),
    "user_name": ("user_name", "username", "user", "account"),
    "os_name": ("os_name", "os", "operating_system", "platform"),
    "action_taken": ("action_taken", "action", "response"),
    "threat_handled": ("threat_handled", "handled", "resolved", "remediated"),
    "isolation_status": ("isolation_status", "isolated", "quarantined"),
    "object_type": ("object_type", "object_kind", "artifact_type"),
    "object_uri": ("object_uri", "object", "path", "file_path", "process_path"),
    "file_hash": ("file_hash", "hash", "sha256", "sha1", "md5"),
    "url": ("url", "uri", "link"),
    "ip_address": ("ip_address", "ip", "ipv4", "source_ip", "src_ip"),
    "domain": ("domain", "fqdn"),
    "raw_subject": ("raw_subject", "subject"),
    "raw_content": ("raw_content", "content", "description", "message", "details"),
}


def _find_alias(raw_payload: Any, field: str) -> Any:
    """Case-insensitive lookup of `field`'s alternate key names in the original
    submitted JSON. Only looks at top-level keys — arbitrarily nested nested
    structures are for the model to read from the full raw payload, not for this
    heuristic to chase."""
    if not isinstance(raw_payload, dict) or field not in _ALIASES:
        return None
    lower_map = {str(k).lower(): v for k, v in raw_payload.items()}
    for candidate in _ALIASES[field]:
        value = lower_map.get(candidate)
        if not _is_blank(value):
            return value
    return None


def _is_blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _str_field(raw: EsetRawPayload, field: str) -> str | None:
    """The exact EsetRawPayload field if set, else the best alias match from the
    original payload, else None (the sender did not report it)."""
    value = getattr(raw, field, None)
    if _is_blank(value):
        value = _find_alias(raw.raw_payload, field)
    return None if _is_blank(value) else str(value)


def _bool_like_field(raw: EsetRawPayload, field: str) -> str | None:
    """threat_handled / isolation_status: bool or string from the exact field, else
    the same from an alias match, standardized to 'true'/'false' (or the sender's
    own lowercased wording). None when not reported — a missing value is NOT
    'false'."""
    value = getattr(raw, field, None)
    if _is_blank(value):
        value = _find_alias(raw.raw_payload, field)

    if isinstance(value, bool):
        return "true" if value else "false"
    if _is_blank(value):
        return None
    return str(value).strip().lower()


def normalize(raw: EsetRawPayload, source: str) -> NormalizedAlert:
    """
    Normalizes an EsetRawPayload into a strict NormalizedAlert.
    Only fields present in the submitted alert are set; anything the sender did
    not report stays None (and is omitted from every serialized form of the
    alert). Boolean-like properties are standardized.
    """
    logger.debug("normalizer_start", raw_source=raw.source, input_source=source)

    data: dict[str, Any] = {"source": source or raw.source}

    for field in (
        "event_type", "alert_id", "detection_uuid", "target_uuid", "occurred_at",
        "severity", "detection_name", "endpoint_name", "endpoint_type", "user_name",
        "os_name", "action_taken", "object_type", "object_uri", "file_hash", "url",
        "ip_address", "domain", "raw_subject", "raw_content",
    ):
        data[field] = _str_field(raw, field)

    data["threat_handled"] = _bool_like_field(raw, "threat_handled")
    data["isolation_status"] = _bool_like_field(raw, "isolation_status")

    # Preserve full raw structure for debugging/auditing, and as the source the AI
    # prompt reads from directly for anything the field mapping above did not
    # recognize (see src/services/ai/base.py).
    data["raw_payload"] = raw.raw_payload or {}

    alert = NormalizedAlert(**data)
    logger.debug("normalizer_fields_present", fields=list(alert.present_fields()))
    return alert
