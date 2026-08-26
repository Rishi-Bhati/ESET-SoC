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
