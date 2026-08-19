"""
Sensitive-data detection and redaction for AI observability data.

This module exists so the AI Visibility feature (src/services/ai/trace_recorder.py,
src/api/ai_visibility.py) never persists a raw secret. It is applied at the CAPTURE
layer: every string that becomes part of a stored AITrace is passed through
redact_value() before it is written anywhere, so the dashboard frontend is never the
only thing standing between a captured payload and an exposed credential.

This is a pattern-based, best-effort scanner, not a guarantee — it catches the
categories of secret that show up in well-known, recognizable formats (API keys,
private keys, connection strings, bearer tokens, generic `key: value` secret
assignments, JWTs, credit-card-shaped numbers, email addresses). It deliberately
over-redacts for the categories that matter most: private keys, passwords, connection
strings and generic secret assignments are always fully replaced; identifier-shaped
secrets (API keys, tokens) keep a short recognizable prefix/suffix so an operator can
still tell traces apart without ever seeing the secret itself.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class Finding:
    category: str
    matched_text: str
    masked: str


def _mask_full(category: str) -> Callable[["re.Match[str]"], str]:
    def _mask(_m: "re.Match[str]") -> str:
        return f"[REDACTED: {category}]"
    return _mask


def _mask_partial(category: str) -> Callable[["re.Match[str]"], str]:
    def _mask(m: "re.Match[str]") -> str:
        text = m.group(0)
        if len(text) <= 8:
            return f"[REDACTED: {category}]"
        head, tail = text[:3], text[-2:]
        return f"{head}{'*' * max(4, len(text) - len(head) - len(tail))}{tail}"
    return _mask


def _mask_secret_assignment(m: "re.Match[str]") -> str:
    # Keeps the key name (e.g. "api_key", "password") visible — only the value is secret.
    key = m.group(1)
    return f"{key}: [REDACTED: SECRET]"


def _mask_bearer(_m: "re.Match[str]") -> str:
    return "Bearer [REDACTED: TOKEN]"


def _mask_email(m: "re.Match[str]") -> str:
    text = m.group(0)
    local, _, domain = text.partition("@")
    head = local[:1] or "*"
    return f"{head}{'*' * max(3, len(local) - 1)}@{domain}"


# Ordered: more specific / higher-severity patterns first, so a private key or
# connection string is never partially matched by a looser rule first.
_RULES: list[tuple[str, "re.Pattern[str]", Callable[["re.Match[str]"], str]]] = [
    ("PRIVATE_KEY", re.compile(
        r"-----BEGIN(?: RSA| EC| OPENSSH| DSA)? PRIVATE KEY-----[\s\S]*?"
        r"-----END(?: RSA| EC| OPENSSH| DSA)? PRIVATE KEY-----"
    ), _mask_full("PRIVATE_KEY")),
    ("JWT", re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     _mask_full("JWT")),
    ("CONNECTION_STRING", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s]+:[^@\s]+@\S+"
    ), _mask_full("CONNECTION_STRING")),
    ("AUTH_HEADER", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{8,}=*"), _mask_bearer),
    ("GENERIC_SECRET_ASSIGNMENT", re.compile(
        r"(?i)\b(api[_-]?key|api[_-]?secret|secret|password|passwd|pwd|"
        r"access[_-]?key|private[_-]?key|auth[_-]?token)\s*[:=]\s*['\"]?([^\s'\"]{4,})"
    ), _mask_secret_assignment),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), _mask_partial("AWS_ACCESS_KEY")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), _mask_partial("GOOGLE_API_KEY")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), _mask_partial("GITHUB_TOKEN")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), _mask_partial("SLACK_TOKEN")),
    ("GENERIC_API_KEY", re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), _mask_partial("GENERIC_API_KEY")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,16}\b"), _mask_full("CREDIT_CARD")),
    ("EMAIL_PII", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), _mask_email),
]


def scan_text(text: str) -> tuple[str, list[Finding]]:
    """Scans and redacts a single string. Returns (redacted_text, findings)."""
    if not text:
        return text, []

    findings: list[Finding] = []
    redacted = text
    for category, pattern, mask_fn in _RULES:
        def _sub(m: "re.Match[str]", category: str = category, mask_fn: Callable = mask_fn) -> str:
            matched = m.group(0)
            masked = mask_fn(m)
            findings.append(Finding(category=category, matched_text=matched, masked=masked))
            return masked
        redacted = pattern.sub(_sub, redacted)
    return redacted, findings


def redact_value(value: Any, path: str = "") -> tuple[Any, list[tuple[str, Finding]]]:
    """
    Recursively redacts every string inside `value` (dict / list / str / anything
    else passes through unchanged), mirroring the recursive-scan pattern already
    used by src/services/ai/lint_checker.py.

    Returns (redacted_value, [(field_path, Finding), ...]) — safe to store directly.
    """
    findings: list[tuple[str, Finding]] = []

    if isinstance(value, str):
        redacted, found = scan_text(value)
        for f in found:
            findings.append((path, f))
        return redacted, findings

    if isinstance(value, list):
        out = []
        for i, item in enumerate(value):
            r, f = redact_value(item, f"{path}[{i}]")
            out.append(r)
            findings.extend(f)
        return out, findings

    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            child_path = f"{path}.{k}" if path else str(k)
            r, f = redact_value(v, child_path)
            out[k] = r
            findings.extend(f)
        return out, findings

    return value, findings
