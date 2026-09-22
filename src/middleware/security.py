"""
HTTP hardening that applies across routes rather than to any one of them:

  * SecurityHeadersMiddleware  — CSP, framing, sniffing, referrer, HSTS.
  * same-origin enforcement for state-changing dashboard calls (CSRF defence
    in depth; the access-key header already stops CSRF when a key is set, but
    a blank key on a trusted bind would otherwise leave POST .../retry and
    friends reachable from any page the operator visits).
  * AuthFailureLimiter         — slows down guessing of the webhook token and
    the dashboard key, per client address.

Written as a pure ASGI middleware (not BaseHTTPMiddleware) so it never
buffers streaming bodies and leaves WebSocket traffic untouched.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from collections import deque
from typing import Any

import structlog

from src.config import settings

logger = structlog.get_logger(__name__)

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def inline_script_hashes(html: str) -> list[str]:
    """CSP hashes for every inline <script> in the dashboard page, so the page
    can keep its pre-paint theme snippet without allowing 'unsafe-inline'."""
    hashes = []
    for body in re.findall(r"<script>(.*?)</script>", html, flags=re.S):
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        hashes.append(f"'sha256-{base64.b64encode(digest).decode()}'")
    return hashes


def build_csp(script_hashes: list[str]) -> str:
    return "; ".join([
        "default-src 'self'",
        "script-src 'self' " + " ".join(script_hashes),
        # Inline style attributes are used throughout the markup and by the
        # chart library; styles cannot execute code, so this is the usual trade.
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self' data:",
        # 'self' covers same-origin ws:/wss: in current browsers.
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ])


class AuthFailureLimiter:
    """
    Sliding-window count of failed credential checks per client address.
    After `max_failures` inside `window_seconds` the address gets 429 on every
    authenticated route until the window drains. Only WRONG credentials count —
    a request with no credential at all (the dashboard's own first probe before
    login) is not a guess and is not counted.
    """

    def __init__(self, max_failures: int, window_seconds: int, max_tracked: int = 10_000) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self.max_tracked = max_tracked
        self._failures: dict[str, deque[float]] = {}

    def _prune(self, key: str, now: float) -> deque[float] | None:
        q = self._failures.get(key)
        if q is None:
            return None
        while q and q[0] <= now - self.window:
            q.popleft()
        if not q:
            del self._failures[key]
            return None
        return q

    def retry_after(self, key: str) -> int:
        """Seconds until `key` may try again; 0 when not blocked."""
        if self.max_failures <= 0:
            return 0
        now = time.monotonic()
        q = self._prune(key, now)
        if q is None or len(q) < self.max_failures:
            return 0
        return max(1, int(q[0] + self.window - now) + 1)

    def record_failure(self, key: str) -> None:
        if self.max_failures <= 0:
            return
        now = time.monotonic()
        if key not in self._failures and len(self._failures) >= self.max_tracked:
            # Bounded memory under a spray from many addresses: drop the
            # stalest entry rather than growing without limit.
            oldest = min(self._failures, key=lambda k: self._failures[k][-1])
            del self._failures[oldest]
        q = self._failures.setdefault(key, deque())
        q.append(now)
        if len(q) == self.max_failures:
            logger.warning("auth_lockout_started", client_ip=key, window_seconds=self.window)

    def reset(self) -> None:
        self._failures.clear()


auth_limiter = AuthFailureLimiter(
    settings.auth_max_failures, settings.auth_failure_window_seconds,
)


def client_key(scope_or_request: Any) -> str:
    client = getattr(scope_or_request, "client", None)
    if client is None and isinstance(scope_or_request, dict):
        client = scope_or_request.get("client")
    if not client:
        return "unknown"
    return client[0] if isinstance(client, (tuple, list)) else getattr(client, "host", "unknown")


def _header(scope: dict, name: bytes) -> str | None:
    for k, v in scope.get("headers", []):
        if k == name:
            return v.decode("latin-1")
    return None


class SecurityHeadersMiddleware:
    def __init__(self, app, csp: str) -> None:
        self.app = app
        self.csp = csp

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        method: str = scope.get("method", "GET")

        if method in _UNSAFE_METHODS and path.startswith("/dashboard/api/"):
            origin = _header(scope, b"origin")
            host = _header(scope, b"host") or ""
            if origin is not None and origin.split("://", 1)[-1] != host:
                logger.warning("dashboard_cross_origin_rejected", origin=origin, path=path)
                await _json_response(send, 403, {"detail": "Cross-origin request rejected"})
                return

        is_https = scope.get("scheme") == "https"

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}

                def add(name: str, value: str) -> None:
                    if name.encode() not in present:
                        headers.append((name.encode(), value.encode()))

                add("x-content-type-options", "nosniff")
                add("x-frame-options", "DENY")
                add("referrer-policy", "no-referrer")
                add("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()")
                add("cross-origin-opener-policy", "same-origin")
                add("content-security-policy", self.csp)
                if is_https:
                    add("strict-transport-security", "max-age=31536000; includeSubDomains")
                if path.startswith(("/dashboard/api/", "/status/", "/webhook/")):
                    # API responses carry alert data; never let a shared cache keep them.
                    add("cache-control", "no-store")
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


async def _json_response(send, status: int, body: dict, extra_headers: list | None = None) -> None:
    payload = json.dumps(body).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]
    headers += extra_headers or []
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})
