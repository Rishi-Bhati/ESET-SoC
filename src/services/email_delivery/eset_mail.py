"""
ESET Mail delivery provider — the Cloudflare Worker documented in
email-api-docs.pdf (POST /api/send).

Security modes, matching the worker's SECURITY_MODE:

  api-key-only  X-API-Key
  signed        + X-Timestamp, X-Signature   (nonce is an empty string)
  full          + X-Nonce                    (replay protection)

Signature (signed / full):

    body_hash         = SHA256(raw_request_body)            -> hex
    canonical_message = timestamp + "\\n" + nonce + "\\n" + body_hash
    X-Signature       = HMAC_SHA256(API_SECRET, canonical_message) -> hex

The hash covers the **exact bytes transmitted**, so the body is serialised once
as compact JSON and those same bytes are both hashed and sent. Re-serialising
(or letting the HTTP client re-encode) would change the hash and the worker
would reject the request with "Invalid signature".
"""
import hashlib
import hmac
import json
import time
import uuid
import httpx
import structlog
from src.config import settings
from src.models.email_message import EmailMessage
from src.services.email_delivery.base import DeliveryResult, EmailDeliveryProvider

logger = structlog.get_logger(__name__)

# Worker rejects a timestamp more than ±3 minutes from its own clock.
CLOCK_SKEW_TOLERANCE_SECONDS = 180


class EsetMailProvider(EmailDeliveryProvider):
    name = "eset_mail"

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        api_secret: str | None = None,
        security_mode: str | None = None,
        timeout: int | None = None,
    ) -> None:
        self.url = (url if url is not None else settings.email_api_url).strip()
        self.api_key = (api_key if api_key is not None else settings.email_api_key).strip()
        self.api_secret = (api_secret if api_secret is not None else settings.email_api_secret).strip()
        self.security_mode = (security_mode or settings.email_security_mode).strip().lower()
        self.timeout = timeout or settings.email_timeout_seconds

    # ------------------------------------------------------------------ config

    def is_configured(self) -> tuple[bool, str]:
        if not self.url:
            return False, "EMAIL_API_URL is not set"
        if not self.api_key:
            return False, "EMAIL_API_KEY is not set"
        if self.security_mode in ("signed", "full") and not self.api_secret:
            return False, f"EMAIL_API_SECRET is required for security mode '{self.security_mode}'"
        if self.security_mode not in ("api-key-only", "signed", "full"):
            return False, f"Unknown EMAIL_SECURITY_MODE '{self.security_mode}'"
        return True, "ready"

    # ------------------------------------------------------------------ signing

    @staticmethod
    def _canonical_message(timestamp: str, nonce: str, body_bytes: bytes) -> str:
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        return f"{timestamp}\n{nonce}\n{body_hash}"

    def _sign(self, timestamp: str, nonce: str, body_bytes: bytes) -> str:
        canonical = self._canonical_message(timestamp, nonce, body_bytes)
        return hmac.new(
            self.api_secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def build_request(self, payload: dict) -> tuple[bytes, dict[str, str]]:
        """
        Returns the exact body bytes to transmit and their matching headers.
        Split out from send() so the signing scheme is directly testable.
        """
        # Compact separators: whitespace would change the hash the worker recomputes.
        body_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }

        if self.security_mode in ("signed", "full"):
            timestamp = str(int(time.time()))          # UTC unix seconds
            nonce = str(uuid.uuid4()) if self.security_mode == "full" else ""
            headers["X-Timestamp"] = timestamp
            headers["X-Signature"] = self._sign(timestamp, nonce, body_bytes)
            if self.security_mode == "full":
                headers["X-Nonce"] = nonce

        return body_bytes, headers

    # ------------------------------------------------------------------ send

    async def send(self, message: EmailMessage) -> DeliveryResult:
        ready, reason = self.is_configured()
        if not ready:
            return DeliveryResult.fail(f"Provider not configured: {reason}", retryable=False)

        payload: dict = {
            "to": message.to,
            "subject": message.subject,
            "body": message.body,
            # Idempotency key for the worker: when a timeout makes the outcome
            # ambiguous, the worker can reject a repeat of the same email_id
            # instead of enqueuing a duplicate again.
            "email_id": message.email_id,
        }

        body_bytes, headers = self.build_request(payload)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # content= (not json=) so the transmitted bytes are the signed bytes
                response = await client.post(self.url, content=body_bytes, headers=headers)
        except httpx.TimeoutException as e:
            return DeliveryResult.fail(f"Timeout contacting mail service: {e}")
        except Exception as e:
            return DeliveryResult.fail(f"Transport error: {e}")

        return self._interpret(response, message)

    def _interpret(self, response: httpx.Response, message: EmailMessage) -> DeliveryResult:
        try:
            data = response.json()
        except Exception:
            data = {}

        if response.status_code in (200, 202) and data.get("success"):
            # 202 means the worker has persisted it in its own queue; delivery
            # (and any retrying) is its responsibility from this point on.
            remote_id = str(data.get("id")) if data.get("id") is not None else None
            logger.info(
                "email_handoff_accepted",
                email_id=message.email_id, remote_id=remote_id,
                status_code=response.status_code,
            )
            return DeliveryResult.ok(remote_id, response.status_code)

        detail = data.get("reason") or data.get("error") or data.get("message") or response.text[:300]

        # 401/400 mean the request itself is wrong — retrying identical input
        # will fail identically, so don't burn attempts on it. A fresh nonce is
        # generated per attempt, so a genuine replay rejection is still retryable.
        retryable = True
        if response.status_code == 400:
            retryable = False
        elif response.status_code == 401 and "nonce" not in str(detail).lower():
            retryable = False

        logger.error(
            "email_handoff_rejected",
            email_id=message.email_id, status_code=response.status_code,
            detail=str(detail)[:300], retryable=retryable,
        )
        return DeliveryResult.fail(str(detail), response.status_code, retryable)

    async def fetch_service_status(self) -> dict:
        """
        Reads the mail service's own queue counters (GET /api/status) so the
        dashboard can show what happened *after* handoff — the part of the
        lifecycle this platform does not own.
        """
        ready, reason = self.is_configured()
        if not ready:
            return {"available": False, "error": reason}

        status_url = self.url.rsplit("/api/send", 1)[0] + "/api/status"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(status_url, headers={"X-API-Key": self.api_key})
            if response.status_code != 200:
                return {"available": False, "error": f"HTTP {response.status_code}", "url": status_url}
            return {"available": True, "url": status_url, "queue": response.json()}
        except Exception as e:
            return {"available": False, "error": str(e), "url": status_url}
