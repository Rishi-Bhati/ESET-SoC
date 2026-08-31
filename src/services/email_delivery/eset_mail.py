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

When a sender is routed via headers (see `routing_via_headers`), the worker
binds those headers into the canonical string so they cannot be injected onto
an otherwise-valid signature:

    canonical_message = timestamp + "\\n" + nonce + "\\n" + qualifier + "\\n" + body_hash
    qualifier         = "provider:<id>"  if X-Provider-Id is sent
                        "email:<addr>"   otherwise (X-Sender-Email)

The hash covers the **exact bytes transmitted**, so the body is serialised once
as compact JSON and those same bytes are both hashed and sent. Re-serialising
(or letting the HTTP client re-encode) would change the hash and the worker
would reject the request with "Invalid signature".

Sender routing
--------------
The mail service holds several configured providers and chooses one per email,
falling over to the next by priority when a send fails. This platform can either
say nothing (the service applies its own default/priority order) or pin a
specific sender. A pinned sender must be active on the service, or it answers
400 "Unauthorized Sender/Provider" — which is a permanent, non-retryable error.
"""
import hashlib
import hmac
import json
import re
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

# The worker validates the nonce against ^[a-zA-Z0-9_-]{8,128}$ and rejects
# anything else outright, so the nonce must be generated to fit it.
NONCE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{8,128}$")

# The worker validates X-Provider-Id against ^[a-zA-Z0-9_-]{1,64}$.
PROVIDER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# The worker strips CR/LF/NUL from the subject and truncates it at 1000 chars
# (header-injection defence). Applying the same rule here keeps the bytes this
# platform signs and records identical to what the worker stores and sends.
SUBJECT_MAX_CHARS = 1000

_CRLF = re.compile(r"[\r\n\x00]+")


class EsetMailProvider(EmailDeliveryProvider):
    name = "eset_mail"

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        api_secret: str | None = None,
        security_mode: str | None = None,
        timeout: int | None = None,
        sender_email: str | None = None,
        sender_name: str | None = None,
        provider_id: str | None = None,
        routing_via_headers: bool | None = None,
    ) -> None:
        self.url = (url if url is not None else settings.email_api_url).strip()
        self.api_key = (api_key if api_key is not None else settings.email_api_key).strip()
        self.api_secret = (api_secret if api_secret is not None else settings.email_api_secret).strip()
        self.security_mode = (security_mode or settings.email_security_mode).strip().lower()
        self.timeout = timeout or settings.email_timeout_seconds
        self.sender_email = (
            sender_email if sender_email is not None else settings.email_sender_email
        ).strip()
        self.sender_name = (
            sender_name if sender_name is not None else settings.email_sender_name
        ).strip()
        self.provider_id = (
            provider_id if provider_id is not None else settings.email_provider_id
        ).strip()
        self.routing_via_headers = (
            settings.email_routing_via_headers
            if routing_via_headers is None
            else routing_via_headers
        )

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
        # Catch a malformed pin here rather than as a 400 on every send.
        if self.provider_id and not PROVIDER_ID_PATTERN.match(self.provider_id):
            return False, (
                f"EMAIL_PROVIDER_ID '{self.provider_id}' is not accepted by the mail "
                "service (must be 1-64 chars of a-z, A-Z, 0-9, '-' or '_')"
            )
        if self.sender_email and _CRLF.search(self.sender_email):
            return False, "EMAIL_SENDER_EMAIL must not contain line breaks"
        return True, "ready"

    def sender_routing(self) -> dict[str, str]:
        """The pinned sender, if any — surfaced in the dashboard's delivery status."""
        routing: dict[str, str] = {}
        if self.provider_id:
            routing["provider_id"] = self.provider_id
        if self.sender_email:
            routing["sender_email"] = self.sender_email
        if self.sender_name:
            routing["sender_name"] = self.sender_name
        if routing:
            routing["transport"] = "headers" if self.routing_via_headers else "body"
        return routing

    # ------------------------------------------------------------------ signing

    @classmethod
    def _sanitize_header_value(cls, value: str, max_chars: int) -> str:
        """Mirrors the worker's CRLF stripping so signed bytes match stored bytes."""
        return cls._encodable(_CRLF.sub(" ", value)).strip()[:max_chars]

    def _signing_qualifier(self) -> str | None:
        """
        The extra canonical line the worker inserts when routing headers are sent.
        None when no routing header goes out, in which case the standard
        three-part canonical string applies.
        """
        if not self.routing_via_headers:
            return None
        # Matches the worker: X-Provider-Id wins when both headers are present.
        if self.provider_id:
            return f"provider:{self.provider_id}"
        if self.sender_email:
            return f"email:{self.sender_email}"
        return None

    @staticmethod
    def _canonical_message(
        timestamp: str, nonce: str, body_bytes: bytes, qualifier: str | None = None
    ) -> str:
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        if qualifier:
            return f"{timestamp}\n{nonce}\n{qualifier}\n{body_hash}"
        return f"{timestamp}\n{nonce}\n{body_hash}"

    def _sign(
        self, timestamp: str, nonce: str, body_bytes: bytes, qualifier: str | None = None
    ) -> str:
        canonical = self._canonical_message(timestamp, nonce, body_bytes, qualifier)
        return hmac.new(
            self.api_secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _new_nonce() -> str:
        # uuid4().hex is 32 hex chars — inside the worker's ^[a-zA-Z0-9_-]{8,128}$
        # window with no dependence on how uuid formats separators.
        return uuid.uuid4().hex

    @staticmethod
    def _encodable(value: str) -> str:
        """
        Drops anything that cannot be encoded as UTF-8.

        `json.loads` accepts lone surrogates (`"\\ud800"`), so an alert field
        derived from an attacker-chosen file or process name can carry one all
        the way here. Serialising that with ensure_ascii=False raises
        UnicodeEncodeError, and because the outbox entry is already durable the
        same message would fail identically on every later sweep — wedging the
        queue behind it. Substituting the unencodable code points keeps the
        alert deliverable and legible.
        """
        return value.encode("utf-8", "replace").decode("utf-8")

    def build_payload(self, message: EmailMessage) -> dict:
        """
        The JSON the worker receives. Split out from send() so the wire contract
        is directly testable.
        """
        recipients = [
            cleaned
            for cleaned in (
                self._encodable(_CRLF.sub("", addr or "")).strip() for addr in message.to
            )
            if cleaned
        ]

        payload: dict = {
            "to": recipients,
            "subject": self._sanitize_header_value(message.subject, SUBJECT_MAX_CHARS),
            # `body`, deliberately not `html`: every composer body in
            # src/services/email_composer.py is PLAIN TEXT with \n\n paragraph
            # breaks. The worker decides the MIME type by sniffing this string
            # (providers.ts: isHtml), so sending the same plain text under an
            # `html` key would be a false claim about its format the moment a
            # worker version trusts the field name over the sniff.
            "body": self._encodable(message.body),
            # Carried for cross-referencing this platform's record with the
            # worker's log. The worker does not deduplicate on it — see the
            # duplicate-on-timeout note in send().
            "email_id": message.email_id,
        }

        # Sender routing. `from_name` always travels in the body: the worker
        # reads it from the body in both routing modes (there is no sender-name
        # header), so gating it on the transport would silently drop the
        # configured display name in header mode.
        if self.sender_name:
            payload["from_name"] = self._sanitize_header_value(self.sender_name, 200)

        # The address and provider pin travel in the body only when they are not
        # being sent as headers — the body form is already covered by the body
        # hash, so it is as tamper-proof without changing the canonical string.
        if not self.routing_via_headers:
            if self.sender_email:
                payload["from_email"] = self.sender_email
            if self.provider_id:
                payload["provider_id"] = self.provider_id

        return payload

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

        # Routing headers go out in every mode; in signed/full they are bound
        # into the signature below.
        if self.routing_via_headers:
            if self.provider_id:
                headers["X-Provider-Id"] = self.provider_id
            if self.sender_email:
                headers["X-Sender-Email"] = self.sender_email

        if self.security_mode in ("signed", "full"):
            timestamp = str(int(time.time()))          # UTC unix seconds
            nonce = self._new_nonce() if self.security_mode == "full" else ""
            headers["X-Timestamp"] = timestamp
            headers["X-Signature"] = self._sign(
                timestamp, nonce, body_bytes, self._signing_qualifier()
            )
            if self.security_mode == "full":
                headers["X-Nonce"] = nonce

        return body_bytes, headers

    # ------------------------------------------------------------------ send

    async def send(self, message: EmailMessage) -> DeliveryResult:
        ready, reason = self.is_configured()
        if not ready:
            return DeliveryResult.fail(f"Provider not configured: {reason}", retryable=False)

        # Serialising is inside the guard deliberately: base.EmailDeliveryProvider
        # requires send() never to raise, and an exception escaping here would
        # abort the dispatcher's whole sweep (see email_dispatcher.dispatch_pending)
        # while leaving the offending entry in the outbox to do it again forever.
        try:
            payload = self.build_payload(message)
            if not payload["to"]:
                # The worker answers 400 for an empty recipient list; failing here
                # keeps a malformed message from consuming handoff attempts.
                return DeliveryResult.fail(
                    "No valid recipient addresses on the message", retryable=False
                )
            body_bytes, headers = self.build_request(payload)
        except Exception as e:
            logger.error(
                "email_payload_unserialisable",
                email_id=message.email_id, error=str(e),
            )
            return DeliveryResult.fail(
                f"Could not serialise message for handoff: {e}", retryable=False
            )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # content= (not json=) so the transmitted bytes are the signed bytes
                response = await client.post(self.url, content=body_bytes, headers=headers)
        except httpx.TimeoutException as e:
            # The outcome is genuinely ambiguous: the worker may already have
            # queued this email. It does not deduplicate on `email_id`, so the
            # retry the dispatcher schedules can produce a second copy. That is
            # the deliberate trade — a duplicate notification is preferable to a
            # silently dropped one. EMAIL_TIMEOUT_SECONDS is set generously to
            # keep this window rare.
            logger.warning(
                "email_handoff_timeout_ambiguous",
                email_id=message.email_id, timeout_seconds=self.timeout,
            )
            return DeliveryResult.fail(f"Timeout contacting mail service: {e}")
        except Exception as e:
            return DeliveryResult.fail(f"Transport error: {e}")

        return self._interpret(response, message)

    @staticmethod
    def _is_permanent_rejection(detail: str) -> bool:
        """
        Whether a 400 is a complaint about *this message* rather than a failure
        inside the mail service.

        The service wraps its whole /api/send handler in one try/catch that
        answers **400** for any internal throw — a D1 outage included
        (`index.ts`: `throw new Error('Failed to insert email into D1 database')`).
        Treating every 400 as permanent therefore meant a Cloudflare incident
        deleted every SOC notification raised during it, because a permanent
        verdict drops the message from the outbox (email_dispatcher._hand_off).

        So only the service's own validation messages count as permanent; an
        unrecognised 400 is assumed to be the service failing and is retried.
        """
        lowered = detail.lower()
        return any(
            marker in lowered
            for marker in (
                "unauthorized sender",       # sender/provider not configured
                "missing recipient",
                "no valid recipient",
                'missing "subject"',
                "invalid or empty \"subject\"",
                'missing "html"',
                "invalid json body",
                "invalid recipient format",
                "invalid type",
            )
        )

    @staticmethod
    def _is_retryable_auth_failure(detail: str) -> bool:
        """
        Which of the mail service's 401s are worth another attempt.

        Only two are. Everything else it answers 401 for — a wrong API key, a
        wrong secret, a missing signature, a missing or malformed nonce — is a
        misconfiguration that the next identical attempt reproduces exactly.

          * replay      the nonce was already used. A fresh nonce is generated
                        per attempt, so the retry is a genuinely different
                        request and can succeed.
          * clock skew  the timestamp fell outside the service's ±3 minute
                        window. Each attempt carries a fresh timestamp, so a
                        drifting clock that is being corrected recovers on its own.

        Note the trap this replaces: matching on the substring "nonce" also
        caught "Missing X-Nonce header (required in full security mode)", which
        is what the service answers when EMAIL_SECURITY_MODE is set lower than
        its own SECURITY_MODE. That is permanent, and retrying it spent every
        attempt on an email that could never be accepted.
        """
        lowered = detail.lower()
        return (
            "already used" in lowered
            or "replay" in lowered
            or "out of range" in lowered          # clock skew, fresh timestamp per attempt
            or "server misconfiguration" in lowered  # service's own API_SECRET unset
        )

    def _interpret(self, response: httpx.Response, message: EmailMessage) -> DeliveryResult:
        try:
            data = response.json()
        except Exception:
            data = {}

        if response.status_code in (200, 202) and data.get("success"):
            # 202 means the worker has persisted it in its own queue; delivery
            # (and any retrying/failover across its providers) is its
            # responsibility from this point on.
            remote_id = str(data.get("id")) if data.get("id") is not None else None
            logger.info(
                "email_handoff_accepted",
                email_id=message.email_id, remote_id=remote_id,
                status_code=response.status_code,
                target_provider=data.get("targetProvider"),
            )
            return DeliveryResult.ok(remote_id, response.status_code)

        detail = data.get("reason") or data.get("error") or data.get("message") or response.text[:300]

        # 401/400 mean the request itself is wrong — retrying identical input
        # will fail identically, so don't burn attempts on it.
        # The service splits its rejection across `error` (the category) and
        # `reason` (the specifics); classify on both rather than on whichever
        # one happened to win the `detail` fallback above.
        classify_on = " ".join(
            str(data.get(field, "")) for field in ("error", "reason", "message")
        ) or str(detail)

        retryable = True
        if response.status_code == 400:
            retryable = not self._is_permanent_rejection(classify_on)
        elif response.status_code == 401:
            retryable = self._is_retryable_auth_failure(classify_on)

        logger.error(
            "email_handoff_rejected",
            email_id=message.email_id, status_code=response.status_code,
            detail=str(detail)[:300], retryable=retryable,
        )
        return DeliveryResult.fail(str(detail), response.status_code, retryable)

    # ------------------------------------------------------------------ status

    def _service_base_url(self) -> str:
        """The worker's origin, derived from the configured /api/send endpoint."""
        return self.url.rsplit("/api/send", 1)[0].rstrip("/")

    async def fetch_service_status(self) -> dict:
        """
        Reads the mail service's own queue counters (GET /api/status) and its
        configured senders (GET /api/providers) so the dashboard can show what
        happened *after* handoff — the part of the lifecycle this platform does
        not own.
        """
        ready, reason = self.is_configured()
        if not ready:
            return {"available": False, "error": reason}

        base = self._service_base_url()
        status_url = f"{base}/api/status"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(status_url, headers={"X-API-Key": self.api_key})
                if response.status_code != 200:
                    return {
                        "available": False,
                        "error": f"HTTP {response.status_code}",
                        "url": status_url,
                    }
                result = {"available": True, "url": status_url, "queue": response.json()}

                # Which senders the service will actually use. Older worker
                # deployments have no /api/providers, so its absence is not an error.
                try:
                    providers_response = await client.get(
                        f"{base}/api/providers", headers={"X-API-Key": self.api_key}
                    )
                    if providers_response.status_code == 200:
                        body = providers_response.json()
                        result["providers"] = [
                            {
                                "id": p.get("id"),
                                "name": p.get("name"),
                                "type": p.get("type"),
                                "from_email": p.get("from_email"),
                                "priority": p.get("priority"),
                                "is_default": bool(p.get("is_default")),
                                "is_active": bool(p.get("is_active")),
                                "daily_limit": p.get("daily_limit"),
                                "daily_sent_count": p.get("daily_sent_count"),
                            }
                            for p in (body.get("providers") or [])
                        ]
                except Exception as e:
                    logger.debug("mail_service_providers_unavailable", error=str(e))

                return result
        except Exception as e:
            return {"available": False, "error": str(e), "url": status_url}
