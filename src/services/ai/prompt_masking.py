"""
Pre-AI data minimization for the Gemini prompt.

Implements the masking policy proposed in docs/SOC_LITE_AUDIT.md §9 (Data
Masking / Privacy Audit). That policy is an engineering proposal pending
client sign-off — see the audit's Client/ESET Action Items — so this module
is deliberately conservative and documents its reasoning per field:

  - user_name    : masked. PII, and the audit's own assessment is that it is
                   "not needed for risk/triage reasoning" by the model.
  - object_uri   : the username segment of a Windows user-profile path
                   (...\\Users\\<name>\\...) is masked; the rest (process/file
                   name, which is the actually useful triage signal) is kept.
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

_USER_PROFILE_SEGMENT_RE = re.compile(r"(?i)(\\Users\\)([^\\]+)")


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

    object_uri = masked.get("object_uri")
    if isinstance(object_uri, str) and object_uri and object_uri != "UNKNOWN":
        new_value = _mask_object_uri(object_uri)
        if new_value != object_uri:
            masked["object_uri"] = new_value
            changed.append("object_uri")

    return masked, changed


# Key names masked wherever they appear in the ORIGINAL submitted payload (see
# mask_raw_payload_for_prompt below) — a superset of _MASKED_FIELDS's single
# "user_name", because the raw payload is not ESET-shaped by requirement: a sender
# may call the same concept "username", "user", "owner", or "account". Matched
# case-insensitively against the key, not the field name the platform itself uses.
_RAW_MASKED_KEY_NAMES = frozenset({"user_name", "username", "user", "owner", "account"})


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
                if str(key).lower() in _RAW_MASKED_KEY_NAMES and isinstance(item, str) and item:
                    out[key] = _mask_identifier(item)
                    changed.append(key_path)
                else:
                    out[key] = walk(item, key_path)
            return out
        if isinstance(node, list):
            return [walk(item, f"{path}[{i}]") for i, item in enumerate(node)]
        return node

    return walk(value, _path), changed
