"""
Attachments, idempotency keys, retry policy and structured-error handling for
the ESET Mail handoff (Email Service README 1.1.0-1.2.1).

Nothing here touches the network: `httpx.AsyncClient.post` is replaced by a
FakeWorker that re-implements the parts of POST /api/send the platform depends
on — signature verification (reusing verify_like_worker from the provider
contract tests), attachment validation, the idempotency store and the
`{ error, code, reason }` error shape.
"""
import base64
import hashlib
import json
import re

import httpx
import pytest
import structlog

from src.models.email_message import EmailAttachment
from src.services import email_dispatcher, email_outbox
from src.services.email_delivery import limits
from src.services.email_delivery.base import DeliveryResult
from src.services.email_delivery.eset_mail import EsetMailProvider
from src.storage import delivery_store

from test_eset_mail_provider import (  # tests/unit is on sys.path (no package)
    API_KEY, make_message, make_provider, verify_like_worker,
)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def attachment(name="weekly_report_2026-W44.xlsx", data=b"PK\x03\x04 workbook bytes",
               content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"):
    return EmailAttachment(filename=name, content_type=content_type,
                           content_base64=b64(data), size_bytes=len(data))


def error(status, code, message="Error", reason=None):
    body = {"error": message, "code": code}
    if reason:
        body["reason"] = reason
    return httpx.Response(status, json=body)


class FakeWorker:
    """POST /api/send as documented. `script` items (Response | Exception) are
    consumed first, one per request, to simulate outages and canned replies."""

    def __init__(self, mode="full", script=None):
        self.mode = mode
        self.script = list(script or [])
        self.requests: list[tuple[dict, dict]] = []   # (parsed body, headers)
        self.raw: list[bytes] = []
        self.by_key: dict[str, tuple[int, str]] = {}  # key -> (id, body-hash)
        self.queued: list[dict] = []

    async def post(self, _client, url, content=None, headers=None, **_):
        body = json.loads(content)
        self.requests.append((body, dict(headers)))
        self.raw.append(content)
        ok, why = verify_like_worker(content, headers, mode=self.mode)
        if not ok:
            return error(401, "invalid_signature", "Unauthorized", why)
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return self.handle(body)

    def handle(self, body):
        for i, att in enumerate(body.get("attachments") or []):
            if "content_type" in att or "content_base64" in att:
                return error(400, "validation_error", f"attachments[{i}] uses platform field names")
            if not att.get("filename") or not att.get("content"):
                return error(400, "validation_error", f"attachments[{i}] incomplete")
        key = body.get("idempotency_key")
        digest = hashlib.sha256(json.dumps(
            [body.get("to"), body.get("subject"), body.get("html"), body.get("body"),
             body.get("attachments")], sort_keys=True).encode()).hexdigest()
        if key and key in self.by_key:
            remote_id, old = self.by_key[key]
            if old != digest:
                return error(409, "idempotency_key_conflict",
                             "Idempotency key was already used for a different email")
            return httpx.Response(200, json={
                "success": True, "id": remote_id, "idempotent_replay": True,
                "idempotency_key": key, "status": "queued"},
                headers={"Idempotent-Replayed": "true"})
        remote_id = len(self.queued) + 1
        self.queued.append(body)
        if key:
            self.by_key[key] = (remote_id, digest)
        return httpx.Response(202, json={
            "success": True, "id": remote_id, "status": "queued",
            "idempotency_key": key, "idempotent_replay": False})


@pytest.fixture
def worker(monkeypatch):
    w = FakeWorker()

    async def post(client, url, **kwargs):
        return await w.post(client, url, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    return w


def provider(**kw):
    kw.setdefault("send_attempts", 3)
    kw.setdefault("retry_backoff_seconds", 0)
    kw.setdefault("retry_budget_seconds", 60)
    return make_provider(**kw)


# ---------------------------------------------------------------- attachments

def test_attachment_wire_shape_uses_the_workers_field_names():
    att = attachment()
    payload = provider().build_payload(make_message(attachments=[att]))
    assert payload["attachments"] == [{
        "filename": att.filename,
        "content": att.content_base64,
        "mimeType": att.content_type,
    }]


def test_no_attachments_key_when_there_are_none():
    assert "attachments" not in provider().build_payload(make_message())


def test_attachment_filename_is_flattened_and_stripped_of_control_characters():
    wire = limits.prepare_attachments([attachment(name="  ../a\r\nb\\c.xlsx\x00 ")])
    assert wire[0]["filename"] == ".._ab_c.xlsx"


def test_mime_type_with_whitespace_is_normalised_and_garbage_is_dropped():
    assert limits.prepare_attachments([attachment(content_type=" application / pdf ")])[0]["mimeType"] \
        == "application/pdf"
    assert "mimeType" not in limits.prepare_attachments([attachment(content_type="not a mime")])[0]
    assert "mimeType" not in limits.prepare_attachments([attachment(content_type="")])[0]


def test_line_wrapped_base64_is_normalised_like_the_worker_does():
    data = b"x" * 200
    wrapped = "\n".join(b64(data)[i:i + 76] for i in range(0, len(b64(data)), 76))
    att = EmailAttachment(filename="a.bin", content_type="", content_base64=wrapped, size_bytes=200)
    assert limits.prepare_attachments([att])[0]["content"] == b64(data)


@pytest.mark.parametrize("att, fragment", [
    (EmailAttachment(filename="", content_type="a/b", content_base64=b64(b"x"), size_bytes=1), "filename"),
    (EmailAttachment(filename="a" * 256, content_type="a/b", content_base64=b64(b"x"), size_bytes=1), "255"),
    (EmailAttachment(filename="a.bin", content_type="a/b", content_base64="", size_bytes=0), "empty"),
    (EmailAttachment(filename="a.bin", content_type="a/b", content_base64="abc", size_bytes=3), "base64"),
    (EmailAttachment(filename="a.bin", content_type="a/b", content_base64="ab!d", size_bytes=3), "base64"),
])
def test_malformed_attachments_are_refused_before_sending(att, fragment):
    with pytest.raises(limits.MailLimitError, match=fragment):
        limits.prepare_attachments([att])


def test_more_than_20_attachments_is_refused():
    limits.prepare_attachments([attachment() for _ in range(20)])
    with pytest.raises(limits.MailLimitError, match="Too many"):
        limits.prepare_attachments([attachment() for _ in range(21)])


def test_stored_size_limit_matches_the_workers_1_9mb_budget():
    # ~1.4 MB raw is the documented ceiling once base64 + JSON overhead count.
    fits = limits.prepare_attachments([attachment(data=b"\0" * 1_390_000)])
    limits.check_sizes("<p>hi</p>", fits)
    too_big = limits.prepare_attachments([attachment(data=b"\0" * 1_450_000)])
    with pytest.raises(limits.MailLimitError, match="too large"):
        limits.check_sizes("<p>hi</p>", too_big)


def test_body_over_900k_chars_is_refused():
    with pytest.raises(limits.MailLimitError, match="body is too large"):
        limits.check_sizes("x" * 900_001, [])


def test_request_body_over_3mib_is_refused():
    with pytest.raises(limits.MailLimitError, match="Request body"):
        limits.check_sizes("x", [], request_bytes=3 * 1024 * 1024 + 1)


async def test_send_with_attachment_reaches_the_worker_signed(worker):
    result = await provider().send(make_message(attachments=[attachment()]))
    assert result.success and result.status_code == 202
    [(body, _)] = worker.requests
    assert body["attachments"][0]["mimeType"].endswith("spreadsheetml.sheet")
    assert worker.queued[0]["attachments"][0]["filename"] == "weekly_report_2026-W44.xlsx"


async def test_oversized_attachment_is_a_permanent_failure_and_never_sent(worker):
    big = attachment(data=b"\0" * 1_600_000)
    result = await provider().send(make_message(attachments=[big]))
    assert not result.success and not result.retryable
    assert result.code == "client_limit_exceeded"
    assert worker.requests == []


# ------------------------------------------------------------- idempotency key

def test_idempotency_key_is_in_the_signed_body_in_every_mode():
    for mode in ("full", "signed", "api-key-only"):
        p = provider(security_mode=mode)
        payload = p.build_payload(make_message())
        body_bytes, headers = p.build_request(payload)
        assert json.loads(body_bytes)["idempotency_key"]
        assert "Idempotency-Key" not in headers   # header is outside the HMAC
        ok, why = verify_like_worker(body_bytes, headers, mode=mode)
        assert ok, why


def test_idempotency_key_is_stable_and_valid():
    p = provider()
    a = p.build_payload(make_message())["idempotency_key"]
    b = p.build_payload(make_message())["idempotency_key"]
    assert a == b
    assert re.fullmatch(r"[\x21-\x7e]{1,255}", a)


def test_idempotency_key_ignores_recipient_order_and_case():
    p = provider()
    k1 = p.idempotency_key_for(make_message(to=["a@x.jp", "B@x.jp"]))
    k2 = p.idempotency_key_for(make_message(to=["b@X.jp", "a@x.jp"]))
    assert k1 == k2


def test_idempotency_key_differs_per_email_and_per_recipient_set():
    p = provider()
    base = p.idempotency_key_for(make_message(email_id="c1-CLIENT_JA"))
    assert base != p.idempotency_key_for(make_message(email_id="c1-CTHREE_JA"))
    assert base != p.idempotency_key_for(make_message(email_id="c2-CLIENT_JA"))
    assert base != p.idempotency_key_for(make_message(email_id="c1-CLIENT_JA", to=["other@x.jp"]))


def test_idempotency_key_survives_awkward_and_long_email_ids():
    p = provider()
    for email_id in ("has space and 日本語", "x" * 400):
        key = p.idempotency_key_for(make_message(email_id=email_id))
        assert re.fullmatch(r"[\x21-\x7e]{1,255}", key), key


def test_explicit_idempotency_key_wins_and_is_validated():
    p = provider()
    assert p.idempotency_key_for(make_message(idempotency_key="order-1:receipt")) == "order-1:receipt"
    with pytest.raises(limits.MailLimitError):
        p.idempotency_key_for(make_message(idempotency_key="has space"))


def test_unsupported_fields_are_never_sent():
    payload = provider().build_payload(make_message(attachments=[attachment()]))
    assert not {"reply_to", "metadata", "email_id"} & payload.keys()


async def test_resending_the_same_email_does_not_double_send(worker):
    p = provider()
    first = await p.send(make_message())
    second = await p.send(make_message())     # e.g. pipeline re-queued the same alert
    assert first.success and not first.idempotent_replay
    assert second.success and second.idempotent_replay
    assert second.remote_id == first.remote_id
    assert len(worker.queued) == 1


async def test_same_key_with_different_content_is_a_permanent_conflict(worker):
    p = provider()
    await p.send(make_message())
    result = await p.send(make_message(body="<p>re-generated text</p>"))
    assert not result.success and not result.retryable
    assert result.status_code == 409 and result.code == "idempotency_key_conflict"
    assert len(worker.queued) == 1


# ---------------------------------------------------------------- retry policy

async def test_network_error_is_retried_with_same_key_and_fresh_signature(worker):
    worker.script = [httpx.ConnectError("boom")]
    result = await provider().send(make_message())
    assert result.success and result.request_attempts == 2
    (b1, h1), (b2, h2) = worker.requests
    assert b1["idempotency_key"] == b2["idempotency_key"]
    assert worker.raw[0] == worker.raw[1]                         # identical body
    assert h1["X-Nonce"] != h2["X-Nonce"]
    assert h1["X-Signature"] != h2["X-Signature"]
    # the fake worker verified (and recorded the nonce of) every attempt


async def test_timeout_after_the_worker_accepted_does_not_duplicate(worker):
    """The response is lost but the email was queued: the retry gets the replay."""
    real_handle = worker.handle
    state = {"first": True}

    def lossy(body):
        response = real_handle(body)
        if state.pop("first", None):
            raise httpx.ReadTimeout("response lost")
        return response

    worker.handle = lossy
    result = await provider().send(make_message())
    assert result.success and result.idempotent_replay and result.request_attempts == 2
    assert len(worker.queued) == 1


async def test_5xx_is_retried_then_succeeds(worker):
    worker.script = [error(500, "internal_error", "Internal server error"),
                     error(503, "internal_error", "unavailable")]
    result = await provider().send(make_message())
    assert result.success and result.request_attempts == 3
    keys = {b["idempotency_key"] for b, _ in worker.requests}
    assert len(keys) == 1
    nonces = {h["X-Nonce"] for _, h in worker.requests}
    assert len(nonces) == 3


async def test_persistent_5xx_stops_at_the_attempt_limit_and_stays_retryable(worker):
    worker.script = [error(500, "internal_error")] * 5
    result = await provider(send_attempts=3).send(make_message())
    assert not result.success and result.retryable
    assert result.request_attempts == 3 and len(worker.requests) == 3
    assert result.code == "internal_error"


async def test_non_json_edge_error_page_is_retried(worker):
    worker.script = [httpx.Response(502, text="<html>Bad gateway</html>")]
    result = await provider().send(make_message())
    assert result.success and result.request_attempts == 2


@pytest.mark.parametrize("status, code", [
    (400, "validation_error"), (400, "unauthorized_sender"), (400, "invalid_idempotency_key"),
    (401, "invalid_api_key"), (401, "invalid_signature"), (403, "forbidden"),
    (404, "not_found"), (409, "idempotency_key_conflict"), (413, "payload_too_large"),
])
async def test_4xx_is_never_retried_and_is_permanent(worker, status, code):
    worker.script = [error(status, code, "Rejected", "details")]
    result = await provider().send(make_message())
    assert not result.success and not result.retryable
    assert result.code == code and result.reason == "details"
    assert len(worker.requests) == 1


@pytest.mark.parametrize("code", ["timestamp_skew", "nonce_reused"])
async def test_transient_auth_codes_are_not_retried_in_call_but_stay_queued(worker, code):
    worker.script = [error(401, code, "Unauthorized")]
    result = await provider().send(make_message())
    assert not result.success and result.retryable        # a later sweep retries
    assert len(worker.requests) == 1                      # not hammered in-call


async def test_retry_budget_stops_further_attempts(worker):
    worker.script = [error(500, "internal_error")] * 5
    p = provider(send_attempts=5, retry_backoff_seconds=10, retry_budget_seconds=5)
    result = await p.send(make_message())
    assert not result.success and len(worker.requests) == 1


async def test_backoff_doubles(monkeypatch, worker):
    delays = []

    async def fake_sleep(d):
        delays.append(d)

    monkeypatch.setattr("src.services.email_delivery.eset_mail.asyncio.sleep", fake_sleep)
    monkeypatch.setattr("src.services.email_delivery.eset_mail.random.uniform", lambda a, b: 1.0)
    worker.script = [error(500, "internal_error")] * 3
    await provider(send_attempts=4, retry_backoff_seconds=2).send(make_message())
    assert delays == [2, 4, 8]


# ------------------------------------------------------------ structured errors

@pytest.mark.parametrize("status, code, retryable", [
    (400, "validation_error", False), (400, "invalid_json", False),
    (400, "invalid_idempotency_key", False), (400, "unauthorized_sender", False),
    (400, "bad_request", False),
    (401, "invalid_api_key", False), (401, "invalid_header", False),
    (401, "invalid_nonce", False), (401, "missing_signature", False),
    (401, "invalid_signature", False), (401, "unauthorized", False),
    (401, "timestamp_skew", True), (401, "nonce_reused", True),
    (403, "forbidden", False), (404, "not_found", False),
    (409, "idempotency_key_conflict", False), (413, "payload_too_large", False),
    (500, "internal_error", True), (500, "server_misconfigured", True),
])
def test_every_documented_code_is_classified(status, code, retryable):
    result = provider()._interpret(error(status, code, "Msg", "why"), make_message())
    assert result.retryable is retryable
    assert result.code == code and result.reason == "why" and result.status_code == status
    assert f"[{code}]" in result.error and "why" in result.error


def test_400_with_a_code_is_permanent_even_when_the_text_looks_like_an_outage():
    # Since worker 1.1.0 internal failures are 500; a coded 400 is the message's fault.
    result = provider()._interpret(
        error(400, "bad_request", "Failed to insert email into D1 database"), make_message())
    assert not result.retryable


def test_codeless_responses_fall_back_to_the_legacy_heuristics():
    p = provider()
    assert p._interpret(httpx.Response(400, json={"error": "D1 hiccup"}), make_message()).retryable
    assert not p._interpret(httpx.Response(400, json={"error": "Invalid JSON body"}),
                            make_message()).retryable
    assert p._interpret(httpx.Response(503, text="x"), make_message()).retryable


def test_error_code_and_reason_are_logged():
    with structlog.testing.capture_logs() as logs:
        provider()._interpret(
            error(401, "invalid_signature", "Unauthorized", "Invalid signature (tampered)"),
            make_message())
    [entry] = [e for e in logs if e["event"] == "email_handoff_rejected"]
    assert entry["code"] == "invalid_signature"
    assert entry["reason"] == "Invalid signature (tampered)"
    assert entry["retryable"] is False and entry["status_code"] == 401


def test_idempotent_replay_is_recognised_from_body_or_header():
    p = provider()
    by_body = p._interpret(
        httpx.Response(200, json={"success": True, "id": 7, "idempotent_replay": True}),
        make_message())
    by_header = p._interpret(
        httpx.Response(200, json={"success": True, "id": 7},
                       headers={"Idempotent-Replayed": "true"}), make_message())
    assert by_body.success and by_body.idempotent_replay and by_body.remote_id == "7"
    assert by_header.idempotent_replay


# ------------------------------------------------------------------ dispatcher

class _StubProvider:
    name = "stub"

    def __init__(self, result: DeliveryResult):
        self.result = result

    async def send(self, message):
        return self.result


async def _queue(message):
    await email_outbox.add_emails([message])


async def test_dispatcher_drops_a_conflicting_duplicate_without_flipping_accepted():
    message = make_message(email_id="dup-1")
    await _queue(message)
    await delivery_store.record_attempt("dup-1", delivery_store.ACCEPTED, remote_id="55")
    conflict = DeliveryResult.fail("[idempotency_key_conflict] differs", 409, retryable=False,
                                   code="idempotency_key_conflict")
    outcome = await email_dispatcher._hand_off(_StubProvider(conflict), message)
    assert outcome == "duplicate"
    assert (await delivery_store.get_delivery("dup-1"))["status"] == delivery_store.ACCEPTED
    assert await email_outbox.list_emails() == []
    assert await email_outbox.list_dead_letters() == []


async def test_dispatcher_records_a_replay_as_accepted():
    message = make_message(email_id="rep-1")
    await _queue(message)
    replay = DeliveryResult.ok("9", 200, idempotent_replay=True)
    assert await email_dispatcher._hand_off(_StubProvider(replay), message) == "accepted"
    row = await delivery_store.get_delivery("rep-1")
    assert row["status"] == delivery_store.ACCEPTED and row["remote_id"] == "9"
    assert await email_outbox.list_emails() == []


async def test_dispatcher_dead_letters_a_permanent_coded_failure_with_the_reason():
    message = make_message(email_id="perm-1")
    await _queue(message)
    bad = DeliveryResult.fail("[validation_error] Missing subject", 400, retryable=False,
                              code="validation_error", reason="Missing subject")
    assert await email_dispatcher._hand_off(_StubProvider(bad), message) == "failed"
    row = await delivery_store.get_delivery("perm-1")
    assert row["status"] == delivery_store.FAILED and "validation_error" in row["error"]
    assert [d["email_id"] for d in await email_outbox.list_dead_letters()] == ["perm-1"]


async def test_dispatcher_keeps_a_retryable_failure_queued():
    message = make_message(email_id="ret-1")
    await _queue(message)
    flaky = DeliveryResult.fail("[internal_error] boom", 500, retryable=True, code="internal_error")
    assert await email_dispatcher._hand_off(_StubProvider(flaky), message) == "retry"
    assert [e["email_id"] for e in await email_outbox.list_emails()] == ["ret-1"]
    assert (await delivery_store.get_delivery("ret-1"))["status"] == delivery_store.PENDING


async def test_attachment_survives_the_outbox_round_trip_and_reaches_the_worker(worker):
    message = make_message(email_id="att-1", attachments=[attachment()])
    await _queue(message)
    [raw] = await email_outbox.list_emails()
    from src.models.email_message import EmailMessage
    result = await provider().send(EmailMessage(**raw))
    assert result.success
    assert worker.queued[0]["attachments"][0]["content"] == attachment().content_base64
