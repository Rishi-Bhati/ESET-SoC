"""
Runtime secret resolution: AWS Secrets Manager first, environment second.

Every credential this platform holds can come from one of two places:

  * an AWS Secrets Manager secret, named by a `*_SECRET_ID` setting — fetched
    at runtime with the instance/task IAM role, cached in memory for
    SECRET_CACHE_TTL_SECONDS, and never written to disk, logs or the dashboard;
  * a plain environment variable — for local development, or for a platform
    (ECS `secrets:`, Railway variables) that injects the value into the
    environment itself.

When both are set the secret ID wins: pointing a deployment at Secrets Manager
is an explicit decision, and silently preferring a leftover env value would
defeat it.

A secret's SecretString may be the bare value, or a JSON object. For JSON, the
value is taken from the key named like the env variable (e.g. "OPENAI_API_KEY"),
else "api_key", else the object's only value — so both a one-value secret and a
shared "app credentials" secret work without extra configuration.

Nothing in this module logs or returns a secret value except `resolve_secret()`
itself. Errors name the secret ID and the failure class, never the value.
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

import structlog

from src.config import settings

logger = structlog.get_logger(__name__)


class SecretUnavailableError(RuntimeError):
    """A required secret is not configured, or could not be fetched."""


@dataclass(frozen=True)
class SecretSource:
    """Where a credential comes from, for status displays. Never holds the value."""
    kind: str          # "aws_secrets_manager" | "environment" | "missing"
    reference: str     # secret name (not the value) or env variable name


_cache: dict[str, tuple[str, float]] = {}
_lock = threading.Lock()
_client: Any = None
_client_region: str | None = None


def describe_source(env_name: str, env_value: str, secret_id: str) -> SecretSource:
    if secret_id:
        # The ARN's trailing name is enough to identify it; the account ID and
        # random suffix add nothing an operator needs on a dashboard.
        name = secret_id.split(":secret:", 1)[-1] if ":secret:" in secret_id else secret_id
        return SecretSource("aws_secrets_manager", name)
    if env_value:
        return SecretSource("environment", env_name)
    return SecretSource("missing", env_name)


def _region_for(secret_id: str) -> str | None:
    # arn:aws:secretsmanager:<region>:<account>:secret:<name>
    if secret_id.startswith("arn:"):
        parts = secret_id.split(":")
        if len(parts) > 3 and parts[3]:
            return parts[3]
    return settings.aws_region or None


def _get_client(region: str | None) -> Any:
    global _client, _client_region
    if _client is None or _client_region != region:
        try:
            import boto3  # imported lazily: only deployments using Secrets Manager need it
        except ImportError as exc:  # pragma: no cover - boto3 is in requirements.txt
            raise SecretUnavailableError("boto3 is not installed; cannot read AWS Secrets Manager") from exc
        _client = boto3.client("secretsmanager", region_name=region) if region else boto3.client("secretsmanager")
        _client_region = region
    return _client


def _extract(secret_string: str, env_name: str) -> str:
    text = secret_string.strip()
    if not text.startswith("{"):
        return text
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    if not isinstance(data, dict):
        return text
    for key in (env_name, env_name.lower(), "api_key", "value"):
        if isinstance(data.get(key), str) and data[key]:
            return data[key]
    if len(data) == 1:
        (only,) = data.values()
        if isinstance(only, str):
            return only
    raise SecretUnavailableError(
        f"Secret is a JSON object without a '{env_name}' or 'api_key' key"
    )


def fetch_secret_string(secret_id: str) -> str:
    """Raw SecretString from AWS Secrets Manager (blocking). Not cached."""
    try:
        response = _get_client(_region_for(secret_id)).get_secret_value(SecretId=secret_id)
    except SecretUnavailableError:
        raise
    except Exception as exc:
        # botocore errors carry the secret ID and an error code, never the value;
        # still, only the class and code are surfaced.
        response = getattr(exc, "response", None)
        code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
        raise SecretUnavailableError(
            f"Could not read secret '{secret_id}' from AWS Secrets Manager "
            f"({type(exc).__name__}{': ' + code if code else ''})"
        ) from None
    value = response.get("SecretString")
    if not value:
        raise SecretUnavailableError(f"Secret '{secret_id}' has no SecretString value")
    return value


def _resolve_blocking(env_name: str, env_value: str, secret_id: str) -> str:
    if not secret_id:
        if env_value:
            return env_value
        raise SecretUnavailableError(f"{env_name} is not configured (set it, or {env_name}_SECRET_ID)")

    now = time.monotonic()
    with _lock:
        cached = _cache.get(secret_id)
        if cached and (settings.secret_cache_ttl_seconds == 0 or now - cached[1] < settings.secret_cache_ttl_seconds):
            return cached[0]

    value = _extract(fetch_secret_string(secret_id), env_name)
    with _lock:
        _cache[secret_id] = (value, now)
    logger.info("secret_loaded", secret=describe_source(env_name, "", secret_id).reference)
    return value


async def resolve_secret(env_name: str, env_value: str, secret_id: str) -> str:
    """
    The credential for `env_name`, from Secrets Manager (`secret_id`) or the
    environment (`env_value`). Raises SecretUnavailableError if neither yields one.
    """
    if not secret_id:
        return _resolve_blocking(env_name, env_value, secret_id)
    return await asyncio.to_thread(_resolve_blocking, env_name, env_value, secret_id)


def invalidate(secret_id: str) -> bool:
    """Drops a cached secret so the next call re-reads it (e.g. after a 401 from
    the provider, which is what a rotated key looks like). Returns whether the
    secret is Secrets-Manager-backed, i.e. whether re-reading can help."""
    if not secret_id:
        return False
    with _lock:
        _cache.pop(secret_id, None)
    return True


def clear_cache() -> None:
    with _lock:
        _cache.clear()


# Settings that may be supplied by the APP_SECRETS_SECRET_ID JSON secret.
# Deliberately an allowlist: the secret can carry credentials, not arbitrary
# configuration, so it cannot quietly flip e.g. APP_ENV or AI_MASKING_ENABLED.
APP_SECRET_KEYS = {
    "ESET_WEBHOOK_AUTH_TOKEN": "eset_webhook_auth_token",
    "DASHBOARD_ACCESS_KEY": "dashboard_access_key",
    "EMAIL_API_KEY": "email_api_key",
    "EMAIL_API_SECRET": "email_api_secret",
    "OPENAI_API_KEY": "openai_api_key",
    "AZURE_OPENAI_API_KEY": "azure_openai_api_key",
    "GEMINI_API_KEY": "gemini_api_key",
}


# Credentials read straight from os.environ by their integrations
# (src/services/threat_intel/*.py), so the overlay sets them there.
APP_SECRET_ENV_KEYS = ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")


def apply_app_secrets() -> list[str]:
    """
    Startup-only: overlays platform credentials from the APP_SECRETS_SECRET_ID
    JSON secret onto `settings`. Returns the setting names applied (never values).
    A configured-but-unreadable secret raises, so a deployment never starts with
    half its credentials silently missing.
    """
    secret_id = settings.app_secrets_secret_id
    if not secret_id:
        return []
    raw = fetch_secret_string(secret_id)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise SecretUnavailableError(f"APP_SECRETS_SECRET_ID '{secret_id}' is not a JSON object") from None
    if not isinstance(data, dict):
        raise SecretUnavailableError(f"APP_SECRETS_SECRET_ID '{secret_id}' is not a JSON object")

    applied = []
    for env_name, attr in APP_SECRET_KEYS.items():
        value = data.get(env_name)
        if isinstance(value, str) and value:
            setattr(settings, attr, value)
            applied.append(env_name)
    for env_name in APP_SECRET_ENV_KEYS:
        value = data.get(env_name)
        if isinstance(value, str) and value:
            os.environ[env_name] = value
            applied.append(env_name)
    ignored = sorted(k for k in data if k not in APP_SECRET_KEYS and k not in APP_SECRET_ENV_KEYS)
    logger.info("app_secrets_applied", secret=secret_id.split(":secret:", 1)[-1],
                applied=applied, ignored_keys=ignored)
    return applied
