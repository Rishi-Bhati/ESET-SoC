"""
Malformed ingest bodies must be answered as client errors.

Regression: a webhook payload containing an invalid JSON escape (e.g. an
unescaped Windows path like C:\\Users\\...) crashed request.json() and surfaced
as a 500 with a full stack trace, leaking internal file paths. A bad frame from
a sender is a 400, and it must never create a job.
"""
import sys

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from src.api import webhook
from src.config import settings

AUTH = {"Authorization": "Bearer test_token"}
JSON_HEADERS = {**AUTH, "Content-Type": "application/json"}

ROUTES = ["/webhook/eset", "/webhook/syslog"]

MALFORMED_BODIES = [
    pytest.param(rb'{"alert_id": "a", "object_uri": "C:\Users\bob\x.exe"}', id="invalid-escape"),
    pytest.param(b'{"alert_id": "a", "severity": ', id="truncated"),
    pytest.param(b"", id="empty"),
    pytest.param(b"not json at all", id="not-json"),
    pytest.param(b'{"alert_id": "a",}', id="trailing-comma"),
    pytest.param(b"\xff\xfe\x00bad", id="invalid-utf8"),
]

NON_OBJECT_BODIES = [
    pytest.param(b"[1, 2, 3]", id="array"),
    pytest.param(b'"just a string"', id="string"),
    pytest.param(b"42", id="number"),
    pytest.param(b"null", id="null"),
]


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("body", MALFORMED_BODIES)
def test_malformed_json_is_rejected_as_400(client: TestClient, route: str, body: bytes):
    res = client.post(route, headers=JSON_HEADERS, content=body)
    assert res.status_code == 400, res.text
    assert "not valid JSON" in res.json()["detail"]


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("body", NON_OBJECT_BODIES)
def test_non_object_json_is_rejected_as_400(client: TestClient, route: str, body: bytes):
    res = client.post(route, headers=JSON_HEADERS, content=body)
    assert res.status_code == 400, res.text
    assert "must be a JSON object" in res.json()["detail"]


def test_malformed_body_leaks_no_internals(client: TestClient):
    res = client.post("/webhook/eset", headers=JSON_HEADERS, content=rb'{"a": "C:\Users"}')
    assert res.status_code == 400
    assert "Traceback" not in res.text
    assert "/src/api" not in res.text
    assert "site-packages" not in res.text


def test_malformed_body_creates_no_job(client: TestClient):
    before = client.get("/dashboard/api/jobs?limit=300").json()["jobs"]
    client.post("/webhook/eset", headers=JSON_HEADERS, content=rb'{"a": "C:\Users"}')
    after = client.get("/dashboard/api/jobs?limit=300").json()["jobs"]
    assert len(after) == len(before)


@pytest.mark.parametrize("route", ROUTES)
def test_auth_is_checked_before_body_parsing(client: TestClient, route: str):
    """An unauthenticated caller gets 401, not a parse error revealing the route works."""
    res = client.post(route, headers={"Content-Type": "application/json"}, content=rb'{"a": "C:\U"}')
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_stream_limit_without_content_length_rejects_before_copying_chunk(monkeypatch):
    monkeypatch.setattr(settings, "max_ingest_body_bytes", 16)
    copied = []

    class RecordingBuffer(bytearray):
        def extend(self, data):
            copied.append(len(data))
            super().extend(data)

    monkeypatch.setattr(webhook, "bytearray", RecordingBuffer, raising=False)
    chunks = iter((b'{"a":', b'"' + b'x' * 128 + b'"}'))

    async def receive():
        return {"type": "http.request", "body": next(chunks), "more_body": True}

    request = Request({"type": "http", "headers": []}, receive)
    assert webhook._reject_oversized_body(request) == 0
    with pytest.raises(HTTPException) as error:
        await webhook.read_json_body(request)
    assert error.value.status_code == 413
    assert copied == [5]


@pytest.mark.parametrize("route", ROUTES)
def test_deeply_nested_json_is_client_error(client, route):
    depth = sys.getrecursionlimit() + 100
    body = b'{"nested":' + b'[' * depth + b'0' + b']' * depth + b'}'
    assert len(body) < settings.max_ingest_body_bytes
    response = client.post(route, headers=JSON_HEADERS, content=body)
    assert response.status_code == 400
    assert response.json()["detail"] == "Request body JSON is nested too deeply"


def test_scrubbing_recursion_is_client_error(client, monkeypatch):
    def too_deep(_value):
        raise RecursionError

    monkeypatch.setattr(webhook, "scrub_unencodable", too_deep)
    response = client.post(ROUTES[0], headers=JSON_HEADERS, content=b'{"nested": []}')
    assert response.status_code == 400


# --------------------------- rejected-request visibility ---------------------------
# A request dropped before a job exists (malformed, non-object, duplicate, over
# capacity) leaves no job row, no result file, and no Alert Timeline entry — the
# log is the only place its content is ever recorded.
#
# These assert directly on the logger.warning/info() call args rather than
# round-tripping through GET /dashboard/api/logs: that endpoint reads the real
# logs/app.log file, which conftest.py never points at a temp path and the test
# app's lifespan never runs src.utils.logging.setup_logging() for (structlog
# falls back to its default stdout-only configuration under pytest) — so the
# file that endpoint reads is whatever a REAL run of the server most recently
# wrote, not anything from this test. Capturing the call directly is what
# actually verifies this feature works; the endpoint itself is covered
# separately (test_dashboard_controls.py) against real production logging.

def _capture_warnings(monkeypatch):
    calls = []
    original = webhook.logger.warning

    def spy(event, **kwargs):
        calls.append({"event": event, **kwargs})
        return original(event, **kwargs)

    monkeypatch.setattr(webhook.logger, "warning", spy)
    return calls


def _capture_info(monkeypatch):
    calls = []
    original = webhook.logger.info

    def spy(event, **kwargs):
        calls.append({"event": event, **kwargs})
        return original(event, **kwargs)

    monkeypatch.setattr(webhook.logger, "info", spy)
    return calls


def test_malformed_body_preview_is_logged(client: TestClient, monkeypatch):
    calls = _capture_warnings(monkeypatch)
    client.post(ROUTES[0], headers=JSON_HEADERS, content=rb'{"marker_xyz_malformed": true,')
    entry = next(c for c in calls if c["event"] == "ingest_malformed_json")
    assert "marker_xyz_malformed" in entry["body_preview"]


def test_non_object_body_preview_is_logged(client: TestClient, monkeypatch):
    calls = _capture_warnings(monkeypatch)
    client.post(ROUTES[0], headers=JSON_HEADERS, content=b'"marker_xyz_string_body"')
    entry = next(c for c in calls if c["event"] == "ingest_non_object_body")
    assert entry["body_preview"] == "marker_xyz_string_body"


def test_duplicate_drop_body_preview_is_logged(client: TestClient, monkeypatch):
    payload = {
        "alert_id": "marker-xyz-dup-alert", "occurred_at": "2026-01-01T00:00:00Z",
        "detection_name": "marker_xyz_dup_detection",
    }
    client.post(ROUTES[0], headers=JSON_HEADERS, json=payload)
    calls = _capture_info(monkeypatch)
    client.post(ROUTES[0], headers=JSON_HEADERS, json=payload)  # second is the duplicate

    entry = next(c for c in calls if c["event"] == "ingest_duplicate_dropped")
    assert entry["body_preview"]["detection_name"] == "marker_xyz_dup_detection"


@pytest.mark.asyncio
async def test_oversized_stream_body_preview_is_logged(monkeypatch):
    # Goes through read_json_body() directly with no content-length header (a
    # TestClient .post(content=...) sets one automatically, which would trip
    # _reject_oversized_body's header check instead of the streaming path this
    # test targets — see test_stream_limit_without_content_length_... above).
    calls = _capture_warnings(monkeypatch)
    monkeypatch.setattr(settings, "max_ingest_body_bytes", 16)

    async def receive():
        return {"type": "http.request", "body": b'{"marker_xyz_oversized": "' + b"x" * 64 + b'"}'}

    request = Request({"type": "http", "headers": []}, receive)
    with pytest.raises(HTTPException):
        await webhook.read_json_body(request)

    entry = next(c for c in calls if c["event"] == "ingest_payload_too_large_stream")
    assert "marker_xyz_oversized" in entry["body_preview"]


def test_body_preview_is_capped_and_truncated():
    huge = {"field": "x" * 10_000}
    preview = webhook._body_preview(huge)
    assert isinstance(preview, str)
    assert preview.endswith("…[truncated]")
    assert len(preview) <= webhook._LOG_BODY_PREVIEW_LIMIT + len("…[truncated]")


def test_body_preview_passes_through_small_dict_unchanged():
    small = {"detection_name": "X", "endpoint_name": "Y"}
    assert webhook._body_preview(small) == small
