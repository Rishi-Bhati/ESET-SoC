"""
Contract tests for the ESET Mail handoff.

`verify_like_worker()` below is an independent re-implementation of the mail
service's own verifier (`src/auth.ts: verifyRequest` in the Serverless Email
Queue Service). The provider is checked against *that*, not against itself, so a
drift between the two signing schemes fails here instead of at runtime as an
opaque "Invalid signature (request headers or body may have been tampered with)".
"""
import hashlib
import hmac
import json
import re
import time
import httpx
import pytest
from src.models.email_message import EmailMessage
from src.services.email_delivery.base import DeliveryResult
from src.services.email_delivery.eset_mail import (
    NONCE_PATTERN,
    PROVIDER_ID_PATTERN,
    EsetMailProvider,
)

API_KEY = "test-api-key"
API_SECRET = "test-api-secret-value"


def make_message(**overrides) -> EmailMessage:
    fields = dict(
        email_id="em-0001",
        correlation_id="corr-0001",
        notification_type="ENGINEER_EN",
        to=["soc@example.com"],
        subject="Malware detected on WKS-01",
        body="<p>A detection was recorded.</p>",
        risk_level="HIGH",
        endpoint_name="WKS-01",
        detection_name="Win32/Agent.ABC",
        created_at="2026-08-30T00:00:00Z",
    )
    fields.update(overrides)
    return EmailMessage(**fields)


def make_provider(**overrides) -> EsetMailProvider:
    fields = dict(
        url="https://mail.example.workers.dev/api/send",
        api_key=API_KEY,
        api_secret=API_SECRET,
        security_mode="full",
        timeout=5,
        sender_email="",
        sender_name="",
        provider_id="",
        routing_via_headers=False,
    )
    fields.update(overrides)
    return EsetMailProvider(**fields)


# --------------------------------------------------------------------------
# The mail service's verifier, re-implemented from src/auth.ts
# --------------------------------------------------------------------------

# The worker records every accepted nonce in D1 and refuses a repeat.
_USED_NONCES: set[str] = set()


def verify_like_worker(
    body_bytes: bytes,
    headers: dict[str, str],
    secret: str = API_SECRET,
    mode: str = "full",
    now: int | None = None,
) -> tuple[bool, str]:
    """Returns (ok, reason), mirroring the worker's checks in the same order."""
    if headers.get("X-API-Key") != API_KEY:
        return False, "Invalid API key"
    if mode == "api-key-only":
        return True, ""

    header_sender = headers.get("X-Sender-Email", "")
    header_provider = headers.get("X-Provider-Id", "")

    timestamp = headers.get("X-Timestamp", "")
    if not re.fullmatch(r"\d+", timestamp.strip()):
        return False, "Invalid or missing X-Timestamp header"
    # auth.ts:152-155 — |now - timestamp| must be within 180 seconds.
    reference = int(time.time()) if now is None else now
    if abs(reference - int(timestamp.strip())) > 180:
        return False, "Timestamp out of range (must be within \u00b13 minutes of server time in UTC)"

    raw_nonce = headers.get("X-Nonce", "")
    if mode == "full" and not raw_nonce:
        return False, "Missing X-Nonce header"
    if raw_nonce and not re.fullmatch(r"[a-zA-Z0-9_-]{8,128}", raw_nonce.strip()):
        return False, "Invalid X-Nonce format"
    nonce = raw_nonce.strip()

    if header_provider and not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", header_provider):
        return False, "Invalid X-Provider-Id header format"
    if header_sender and re.search(r"[\r\n\x00]", header_sender):
        return False, "Invalid X-Sender-Email header format"

    signature = headers.get("X-Signature", "")
    if not signature:
        return False, "Missing X-Signature header"
    raw_sig = signature[7:] if signature.startswith("sha256=") else signature
    normalized = raw_sig.lower().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", normalized):
        return False, "Invalid signature format"

    body_hash = hashlib.sha256(body_bytes).hexdigest()

    def hmac_hex(message: str) -> str:
        return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    if header_sender or header_provider:
        qualifier = (
            f"provider:{header_provider}" if header_provider else f"email:{header_sender}"
        )
        expected = hmac_hex(f"{timestamp.strip()}\n{nonce}\n{qualifier}\n{body_hash}")
        valid = hmac.compare_digest(normalized, expected)
        if not valid:
            legacy_qualifier = header_sender or header_provider
            expected_legacy = hmac_hex(
                f"{timestamp.strip()}\n{nonce}\n{legacy_qualifier}\n{body_hash}"
            )
            valid = hmac.compare_digest(normalized, expected_legacy)
    else:
        expected = hmac_hex(f"{timestamp.strip()}\n{nonce}\n{body_hash}")
        valid = hmac.compare_digest(normalized, expected)

    if not valid:
        return False, "Invalid signature"

    # auth.ts:237-268 — atomic INSERT into used_nonces rejects a replay.
    if mode == "full":
        if nonce in _USED_NONCES:
            return False, "Nonce already used (replay attack detected)"
        _USED_NONCES.add(nonce)

    return True, ""


# --------------------------------------------------------------------------
# Signing — the worker accepts what the provider produces
# --------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["full", "signed", "api-key-only"])
def test_worker_accepts_request_in_every_security_mode(mode):
    provider = make_provider(security_mode=mode)
    body_bytes, headers = provider.build_request(provider.build_payload(make_message()))

    ok, reason = verify_like_worker(body_bytes, headers, mode=mode)
    assert ok, reason


def test_signed_mode_uses_empty_nonce_and_sends_no_nonce_header():
    provider = make_provider(security_mode="signed")
    _, headers = provider.build_request(provider.build_payload(make_message()))
    assert "X-Nonce" not in headers
    assert "X-Signature" in headers


def test_api_key_only_mode_sends_no_signature():
    provider = make_provider(security_mode="api-key-only")
    _, headers = provider.build_request(provider.build_payload(make_message()))
    assert "X-Signature" not in headers
    assert "X-Timestamp" not in headers


def test_nonce_matches_the_format_the_worker_enforces():
    provider = make_provider(security_mode="full")
    seen = set()
    for _ in range(50):
        _, headers = provider.build_request(provider.build_payload(make_message()))
        nonce = headers["X-Nonce"]
        assert NONCE_PATTERN.match(nonce), f"worker would reject nonce {nonce!r}"
        seen.add(nonce)
    assert len(seen) == 50, "nonces must be unique or the worker rejects the replay"


def test_signature_is_lowercase_hex_of_the_expected_length():
    provider = make_provider()
    _, headers = provider.build_request(provider.build_payload(make_message()))
    assert re.fullmatch(r"[a-f0-9]{64}", headers["X-Signature"])


def test_transmitted_bytes_are_the_signed_bytes():
    """
    The worker hashes the raw body it receives. Re-serialising the payload
    anywhere between signing and sending would change that hash.
    """
    provider = make_provider()
    payload = provider.build_payload(make_message(subject="非ASCII 件名 — ünïcode"))
    body_bytes, headers = provider.build_request(payload)

    assert json.loads(body_bytes.decode("utf-8")) == payload
    # Compact separators, no ASCII escaping — exactly what was hashed.
    assert b", " not in body_bytes
    ok, reason = verify_like_worker(body_bytes, headers)
    assert ok, reason


def test_tampered_body_is_rejected_by_the_worker():
    provider = make_provider()
    body_bytes, headers = provider.build_request(provider.build_payload(make_message()))
    tampered = body_bytes.replace(b"soc@example.com", b"attacker@evil.com")
    assert tampered != body_bytes

    ok, reason = verify_like_worker(tampered, headers)
    assert not ok and reason == "Invalid signature"


# --------------------------------------------------------------------------
# Sender routing
# --------------------------------------------------------------------------

def test_no_routing_configured_sends_no_routing_fields():
    provider = make_provider()
    payload = provider.build_payload(make_message())
    _, headers = provider.build_request(payload)

    assert "from_email" not in payload
    assert "provider_id" not in payload
    assert "X-Sender-Email" not in headers
    assert "X-Provider-Id" not in headers
    assert provider.sender_routing() == {}


def test_body_routing_puts_sender_in_the_signed_payload():
    provider = make_provider(
        sender_email="soc-alerts@example.com",
        sender_name="ESET SOC Lite",
        provider_id="resend_primary",
        routing_via_headers=False,
    )
    payload = provider.build_payload(make_message())
    body_bytes, headers = provider.build_request(payload)

    assert payload["from_email"] == "soc-alerts@example.com"
    assert payload["from_name"] == "ESET SOC Lite"
    assert payload["provider_id"] == "resend_primary"
    # Body routing must not add routing headers — that would change the
    # canonical string the worker builds.
    assert "X-Sender-Email" not in headers
    assert "X-Provider-Id" not in headers

    ok, reason = verify_like_worker(body_bytes, headers)
    assert ok, reason


def test_header_routing_binds_provider_id_into_the_signature():
    provider = make_provider(
        sender_email="soc-alerts@example.com",
        provider_id="resend_primary",
        routing_via_headers=True,
    )
    payload = provider.build_payload(make_message())
    body_bytes, headers = provider.build_request(payload)

    assert headers["X-Provider-Id"] == "resend_primary"
    assert headers["X-Sender-Email"] == "soc-alerts@example.com"
    assert "provider_id" not in payload

    ok, reason = verify_like_worker(body_bytes, headers)
    assert ok, reason


def test_header_routing_by_sender_email_alone_uses_the_email_qualifier():
    provider = make_provider(
        sender_email="soc-alerts@example.com", routing_via_headers=True
    )
    body_bytes, headers = provider.build_request(
        provider.build_payload(make_message())
    )

    assert headers["X-Sender-Email"] == "soc-alerts@example.com"
    assert "X-Provider-Id" not in headers

    ok, reason = verify_like_worker(body_bytes, headers)
    assert ok, reason


def test_injecting_a_routing_header_invalidates_a_body_routed_signature():
    """
    The worker binds routing headers into the canonical string precisely so a
    man-in-the-middle cannot bolt them onto a validly-signed request.
    """
    provider = make_provider(routing_via_headers=False)
    body_bytes, headers = provider.build_request(
        provider.build_payload(make_message())
    )
    ok, _ = verify_like_worker(body_bytes, headers)
    assert ok

    headers["X-Provider-Id"] = "attacker_provider"
    ok, reason = verify_like_worker(body_bytes, headers)
    assert not ok and reason == "Invalid signature"


def test_sender_routing_reports_the_configured_pin():
    provider = make_provider(provider_id="smtp_backup", routing_via_headers=True)
    assert provider.sender_routing() == {
        "provider_id": "smtp_backup",
        "transport": "headers",
    }


# --------------------------------------------------------------------------
# Payload shape
# --------------------------------------------------------------------------

def test_payload_sends_plain_text_under_body_not_html():
    """
    Every composer body is plain text. The worker sniffs this string to choose
    the MIME type, so claiming it is `html` would be a false format claim as
    soon as a worker version trusts the field name over the sniff.
    """
    provider = make_provider()
    payload = provider.build_payload(make_message(body="Alert Summary: x\n\nAssessment: y"))
    assert payload["body"] == "Alert Summary: x\n\nAssessment: y"
    assert "html" not in payload


def test_subject_is_stripped_of_crlf_and_capped_like_the_worker():
    provider = make_provider()
    payload = provider.build_payload(
        make_message(subject="Alert\r\nBcc: attacker@evil.com" + "x" * 2000)
    )
    subject = payload["subject"]
    assert "\r" not in subject and "\n" not in subject
    assert len(subject) == 1000


def test_recipients_are_cleaned_of_crlf_and_blanks():
    provider = make_provider()
    payload = provider.build_payload(
        make_message(to=["  soc@example.com  ", "", "bad\r\n@example.com"])
    )
    assert payload["to"] == ["soc@example.com", "bad@example.com"]


def test_email_id_is_carried_for_cross_referencing():
    provider = make_provider()
    payload = provider.build_payload(make_message(email_id="em-42"))
    assert payload["email_id"] == "em-42"


# --------------------------------------------------------------------------
# Configuration validation
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "overrides, fragment",
    [
        ({"url": ""}, "EMAIL_API_URL"),
        ({"api_key": ""}, "EMAIL_API_KEY"),
        ({"api_secret": "", "security_mode": "full"}, "EMAIL_API_SECRET"),
        ({"security_mode": "sorta-signed"}, "Unknown EMAIL_SECURITY_MODE"),
        ({"provider_id": "not a valid id!"}, "EMAIL_PROVIDER_ID"),
        ({"sender_email": "a@b.com\r\nBcc: c@d.com"}, "line breaks"),
    ],
)
def test_misconfiguration_is_reported_before_any_send(overrides, fragment):
    provider = make_provider(**overrides)
    ready, reason = provider.is_configured()
    assert not ready
    assert fragment in reason


def test_valid_provider_id_passes_the_worker_pattern():
    assert PROVIDER_ID_PATTERN.match("resend_primary-01")
    assert not PROVIDER_ID_PATTERN.match("resend primary")


@pytest.mark.asyncio
async def test_send_refuses_a_message_with_no_usable_recipients():
    provider = make_provider()
    result = await provider.send(make_message(to=["", "   "]))
    assert not result.success
    assert not result.retryable
    assert "recipient" in result.error.lower()


# --------------------------------------------------------------------------
# Response interpretation
# --------------------------------------------------------------------------

def _response(status_code: int, payload: dict | None = None, text: str = "") -> httpx.Response:
    if payload is not None:
        return httpx.Response(status_code, json=payload)
    return httpx.Response(status_code, text=text)


def test_202_accepted_is_recorded_with_the_remote_id():
    provider = make_provider()
    result = provider._interpret(
        _response(202, {"success": True, "id": 4321, "targetProvider": "Resend"}),
        make_message(),
    )
    assert result.success
    assert result.remote_id == "4321"
    assert result.status_code == 202


def test_400_rejecting_this_message_is_permanent():
    provider = make_provider()
    result = provider._interpret(
        _response(400, {
            "error": "Unauthorized Sender/Provider",
            "reason": 'Unauthorized sender or provider. No providers matching "x@y.z" are configured.',
        }),
        make_message(),
    )
    assert not result.success
    assert not result.retryable


# The service wraps its whole /api/send handler in one try/catch that answers
# 400 for any internal throw, so an unrecognised 400 is the SERVICE failing,
# not this message being invalid. Retrying is the only safe reading — a
# permanent verdict drops the notification.
@pytest.mark.parametrize("payload", [
    {"error": "Failed to insert email into D1 database"},
    {"error": "D1_ERROR: network connection lost"},
    {"error": "Internal error"},
])
def test_400_from_a_service_failure_is_retried(payload):
    provider = make_provider()
    result = provider._interpret(_response(400, payload), make_message())
    assert not result.success
    assert result.retryable, "a D1 outage must not delete the notification"


@pytest.mark.parametrize("reason", [
    "Missing recipient \"to\" field",
    'Missing "subject" field',
    'Missing "html" (or "body") field',
    "Invalid JSON body",
    "No valid recipient addresses provided",
])
def test_400_validation_errors_are_permanent(reason):
    provider = make_provider()
    result = provider._interpret(_response(400, {"error": reason}), make_message())
    assert not result.retryable, reason


# The exact reason strings the mail service returns with 401 (src/auth.ts).
# Each attempt carries a fresh nonce and timestamp, so only replay and clock
# skew can succeed on a retry; the rest are permanent misconfiguration.
WORKER_401_REASONS = [
    ("Nonce already used (replay attack detected)", True),
    ("Timestamp out of range (must be within \u00b13 minutes of server time in UTC)", True),
    ("Missing X-Nonce header (required in full security mode)", False),
    ("Invalid X-Nonce format (must be 8-128 alphanumeric characters, dashes, or underscores)", False),
    ("Invalid API key", False),
    ("Missing X-API-Key header", False),
    ("Missing X-Signature header", False),
    ("Invalid signature (request headers or body may have been tampered with)", False),
    ("Invalid signature format (must be SHA-256 hex string)", False),
    ("Invalid or missing X-Timestamp header (must be Unix epoch seconds)", False),
    ("Invalid X-Provider-Id header format", False),
]


@pytest.mark.parametrize("reason, expected_retryable", WORKER_401_REASONS)
def test_401_reasons_are_classified_by_whether_a_retry_could_differ(reason, expected_retryable):
    provider = make_provider()
    result = provider._interpret(_response(401, {"error": reason}), make_message())
    assert not result.success
    assert result.retryable is expected_retryable, reason


def test_mode_mismatch_is_permanent_not_retried_forever():
    """
    Regression: EMAIL_SECURITY_MODE below the service's SECURITY_MODE gets
    401 "Missing X-Nonce header". Matching on the substring "nonce" made that
    look retryable and spent every attempt on an email that could never be
    accepted.
    """
    provider = make_provider()
    result = provider._interpret(
        _response(401, {"error": "Missing X-Nonce header (required in full security mode)"}),
        make_message(),
    )
    assert not result.retryable


def test_5xx_is_retryable():
    provider = make_provider()
    result = provider._interpret(_response(503, text="upstream unavailable"), make_message())
    assert not result.success
    assert result.retryable


def test_success_flag_is_required_not_just_a_2xx_status():
    provider = make_provider()
    result = provider._interpret(_response(200, {"error": "something odd"}), make_message())
    assert not result.success


# --------------------------------------------------------------------------
# Service status
# --------------------------------------------------------------------------

def test_service_base_url_is_derived_from_the_send_endpoint():
    assert (
        make_provider(url="https://mail.example.workers.dev/api/send")._service_base_url()
        == "https://mail.example.workers.dev"
    )
    assert (
        make_provider(url="https://mail.example.dev/base/api/send")._service_base_url()
        == "https://mail.example.dev/base"
    )


@pytest.mark.asyncio
async def test_fetch_service_status_reports_queue_and_providers(monkeypatch):
    provider = make_provider()

    async def fake_get(self, url, **kwargs):
        if url.endswith("/api/status"):
            return _response(200, {"queued": 2, "sending": 0, "sent": 9, "failed": 1})
        if url.endswith("/api/providers"):
            return _response(200, {
                "providers": [
                    {
                        "id": "resend_primary", "name": "Resend", "type": "resend",
                        "from_email": "soc@example.com", "priority": 1,
                        "is_default": 1, "is_active": 1,
                        "daily_limit": 100, "daily_sent_count": 9,
                    }
                ],
                "count": 1,
            })
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    status = await provider.fetch_service_status()

    assert status["available"] is True
    assert status["queue"]["sent"] == 9
    assert status["providers"][0]["id"] == "resend_primary"
    assert status["providers"][0]["is_default"] is True


@pytest.mark.asyncio
async def test_fetch_service_status_survives_a_worker_without_providers(monkeypatch):
    """An older worker deployment has no /api/providers — that is not an error."""
    provider = make_provider()

    async def fake_get(self, url, **kwargs):
        if url.endswith("/api/status"):
            return _response(200, {"queued": 0, "sending": 0, "sent": 0, "failed": 0})
        return _response(404, {"error": "Not Found"})

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    status = await provider.fetch_service_status()

    assert status["available"] is True
    assert "providers" not in status


@pytest.mark.asyncio
async def test_fetch_service_status_reports_misconfiguration_without_calling_out():
    provider = make_provider(url="")
    status = await provider.fetch_service_status()
    assert status["available"] is False
    assert "EMAIL_API_URL" in status["error"]


# --------------------------------------------------------------------------
# Unencodable content must not wedge the queue
# --------------------------------------------------------------------------

# json.loads accepts a lone surrogate, so an alert field derived from an
# attacker-chosen file or process name can carry one all the way to handoff.
LONE_SURROGATE = "Win32/\ud800Agent"


def test_lone_surrogate_does_not_break_serialisation():
    provider = make_provider()
    payload = provider.build_payload(
        make_message(subject=f"[HIGH] {LONE_SURROGATE}", body=f"Detection: {LONE_SURROGATE}")
    )
    body_bytes, headers = provider.build_request(payload)
    ok, reason = verify_like_worker(body_bytes, headers)
    assert ok, reason


@pytest.mark.asyncio
async def test_send_never_raises_on_unserialisable_content():
    """
    base.EmailDeliveryProvider requires send() to return a failed result rather
    than raise. An exception here would abort the dispatcher's entire sweep and
    leave the offending entry in the outbox to do it again on every later run.
    """
    provider = make_provider()
    result = await provider.send(
        make_message(subject=LONE_SURROGATE, body=LONE_SURROGATE, to=["a@b.test"])
    )
    # Either it serialised cleanly and failed on transport, or it was refused —
    # what matters is that it returned a DeliveryResult instead of raising.
    assert isinstance(result, DeliveryResult)


@pytest.mark.asyncio
async def test_send_returns_permanent_failure_if_serialisation_fails(monkeypatch):
    provider = make_provider()
    monkeypatch.setattr(
        EsetMailProvider, "build_request",
        lambda self, payload: (_ for _ in ()).throw(UnicodeEncodeError("utf-8", "", 0, 1, "boom")),
    )
    result = await provider.send(make_message())
    assert not result.success
    assert not result.retryable
    assert "serialise" in result.error.lower()


# --------------------------------------------------------------------------
# Client mode and worker mode are set independently
# --------------------------------------------------------------------------

@pytest.mark.parametrize("client_mode, worker_mode, should_verify", [
    ("full", "full", True),
    ("signed", "signed", True),
    ("api-key-only", "api-key-only", True),
    # A client below the worker's mode is the common misconfiguration.
    ("signed", "full", False),
    ("api-key-only", "full", False),
    ("api-key-only", "signed", False),
    # A client above the worker's mode still verifies — extra headers are ignored.
    ("full", "signed", True),
    ("full", "api-key-only", True),
])
def test_client_mode_against_worker_mode(client_mode, worker_mode, should_verify):
    provider = make_provider(security_mode=client_mode)
    body_bytes, headers = provider.build_request(provider.build_payload(make_message()))
    ok, _ = verify_like_worker(body_bytes, headers, mode=worker_mode)
    assert ok is should_verify


def test_worker_rejects_a_replayed_nonce():
    provider = make_provider(security_mode="full")
    body_bytes, headers = provider.build_request(provider.build_payload(make_message()))
    first_ok, _ = verify_like_worker(body_bytes, headers)
    second_ok, reason = verify_like_worker(body_bytes, headers)
    assert first_ok
    assert not second_ok and "already used" in reason


def test_worker_rejects_a_stale_timestamp():
    provider = make_provider()
    body_bytes, headers = provider.build_request(provider.build_payload(make_message()))
    ok, reason = verify_like_worker(
        body_bytes, headers, now=int(headers["X-Timestamp"]) + 400
    )
    assert not ok and "out of range" in reason


def test_clock_skew_rejection_is_retryable_not_alert_loss():
    """Each attempt carries a fresh timestamp, so a correcting clock recovers."""
    provider = make_provider()
    result = provider._interpret(
        _response(401, {"error": "Timestamp out of range (must be within ±3 minutes of server time in UTC)"}),
        make_message(),
    )
    assert result.retryable
