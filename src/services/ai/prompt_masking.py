"""
Pre-AI data minimization for the AI provider prompt (OpenAI, Azure OpenAI, Gemini).

Implements the masking policy proposed in docs/SOC_LITE_AUDIT.md §9 (Data
Masking / Privacy Audit). That policy is an engineering proposal pending
client sign-off — see the audit's Client/ESET Action Items — so this module
is deliberately conservative and documents its reasoning per field:

  - user_name    : masked. PII, and the audit's own assessment is that it is
                   "not needed for risk/triage reasoning" by the model.
  - object_uri   : the username segment of a Windows user-profile path
                   (...\\Users\\<name>\\...) is masked; the rest (process/file
                   name, which is the actually useful triage signal) is kept.
  - email addresses : masked wherever they appear in any string field (the
                   client's integration requirement #9). The domain is kept —
                   it can matter for triage (phishing, a partner domain); the
                   mailbox is personal data.
  - DOMAIN\\user account references inside free text : user part masked.
  - detection_uuid, target_uuid, alert_id : internal identifiers. Replaced
                   with "[INTERNAL_ID]" — the model has no use for them, and
                   keeping them out means an AI-side log never holds an ID
                   that can be joined back to the client's ESET tenant.
  - endpoint_name, ip_address, url, domain, file_hash : left unmasked. The
    audit's own conclusion is that these are needed for triage/threat-intel
    reasoning, and endpoint_name in particular already appears unmasked in
    every outbound notification (client/C-Three/internal/engineer) regardless
    of what is sent to the AI, so masking it here would add no protection.

This never touches the caller's NormalizedAlert — risk scoring, email
composition, and the persisted PipelineResult must all see the real values.
Only the copy built for the AI prompt is masked.
"""
from __future__ import annotations

import re
from typing import Any

# Fields fully masked before they reach the prompt (see module docstring).
_MASKED_FIELDS = ("user_name",)
# Internal identifiers replaced outright (see module docstring).
_INTERNAL_ID_FIELDS = ("detection_uuid", "target_uuid", "alert_id")
INTERNAL_ID_PLACEHOLDER = "[INTERNAL_ID]"

_USER_PROFILE_SEGMENT_RE = re.compile(r"(?i)(\\Users\\)([^\\]+)")
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
# DOMAIN\user or domain.local\user in free text (not a path: no drive letter before it).
_DOMAIN_ACCOUNT_RE = re.compile(r"(?<![A-Za-z]:)(?<![\\/\w])([A-Za-z][A-Za-z0-9.\-]{0,62})\\([A-Za-z0-9._\-$]{2,64})\b(?![\\/])")


def _mask_free_text(value: str) -> str:
    """Emails and DOMAIN\\user references anywhere inside a string."""
    value = _EMAIL_RE.sub(lambda m: f"{_mask_identifier(m.group(1))}@{m.group(2)}", value)
    return _DOMAIN_ACCOUNT_RE.sub(lambda m: f"{m.group(1)}\\{_mask_identifier(m.group(2))}", value)


def _mask_identifier(value: str) -> str:
    """First+last character kept, everything between replaced with asterisks."""
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"


def _mask_object_uri(value: str) -> str:
    """Masks only the username segment of a Windows user-profile path, if present."""
    return _USER_PROFILE_SEGMENT_RE.sub(
        lambda m: f"{m.group(1)}{_mask_identifier(m.group(2))}", value
    )


def mask_alert_for_prompt(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """
    Returns (masked_copy, masked_field_names) for a normalized-alert dict
    (as produced by NormalizedAlert.model_dump()). Does not mutate `data`.
    """
    masked = dict(data)
    changed: list[str] = []

    for field in _MASKED_FIELDS:
        value = masked.get(field)
        if isinstance(value, str) and value and value != "UNKNOWN":
            masked[field] = _mask_identifier(value)
            changed.append(field)

    for field in _INTERNAL_ID_FIELDS:
        value = masked.get(field)
        if isinstance(value, str) and value and value != "UNKNOWN":
            masked[field] = INTERNAL_ID_PLACEHOLDER
            changed.append(field)

    object_uri = masked.get("object_uri")
    if isinstance(object_uri, str) and object_uri and object_uri != "UNKNOWN":
        new_value = _mask_object_uri(object_uri)
        if new_value != object_uri:
            masked["object_uri"] = new_value
            changed.append("object_uri")

    for field, value in list(masked.items()):
        if field in _MASKED_FIELDS or field in _INTERNAL_ID_FIELDS or not isinstance(value, str):
            continue
        new_value = _mask_free_text(value)
        if new_value != value:
            masked[field] = new_value
            if field not in changed:
                changed.append(field)

    return masked, changed


# Key names masked wherever they appear in the ORIGINAL submitted payload (see
# mask_raw_payload_for_prompt below) — a superset of _MASKED_FIELDS's single
# "user_name", because the raw payload is not ESET-shaped by requirement: a sender
# may call the same concept "username", "user", "owner", or "account". Matched
# case-insensitively against the key, not the field name the platform itself uses.
_RAW_MASKED_KEY_NAMES = frozenset({
    "user_name", "username", "user", "owner", "account", "email", "e_mail", "mail",
    "user_email", "email_address", "logged_user", "logon_user", "account_name",
})
# Internal identifiers in the raw payload, replaced with INTERNAL_ID_PLACEHOLDER.
_RAW_INTERNAL_ID_KEY_NAMES = frozenset({
    "detection_uuid", "target_uuid", "computer_uuid", "device_uuid", "uuid", "alert_id",
    "event_id", "id", "detection_id", "endpoint_id", "device_id", "tenant_id", "customer_id",
})


def mask_raw_payload_for_prompt(value: Any, _path: str = "") -> tuple[Any, list[str]]:
    """
    Recursively masks values under any key matching _RAW_MASKED_KEY_NAMES, anywhere
    in the arbitrarily-shaped original submitted payload (src/api/webhook.py accepts
    any JSON object — this does not assume ESET's or any other specific schema).

    Unlike mask_alert_for_prompt (which knows the exact NormalizedAlert field list),
    this walks a structure of unknown shape, so it masks by key name at every
    nesting level rather than at a fixed set of top-level fields. Does not mutate
    the input.
    """
    changed: list[str] = []

    def walk(node: Any, path: str) -> Any:
        if isinstance(node, dict):
            out = {}
            for key, item in node.items():
                key_path = f"{path}.{key}" if path else str(key)
                lowered = str(key).lower()
                if lowered in _RAW_MASKED_KEY_NAMES and isinstance(item, str) and item:
                    out[key] = _mask_identifier(item)
                    changed.append(key_path)
                elif lowered in _RAW_INTERNAL_ID_KEY_NAMES and isinstance(item, (str, int)) and item != "":
                    out[key] = INTERNAL_ID_PLACEHOLDER
                    changed.append(key_path)
                else:
                    out[key] = walk(item, key_path)
            return out
        if isinstance(node, list):
            return [walk(item, f"{path}[{i}]") for i, item in enumerate(node)]
        if isinstance(node, str):
            masked_text = _mask_free_text(node)
            if masked_text != node:
                changed.append(path)
            return masked_text
        return node

    return walk(value, _path), changed
