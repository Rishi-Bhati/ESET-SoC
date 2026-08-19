"""
Malformed ingest bodies must be answered as client errors.

Regression: a webhook payload containing an invalid JSON escape (e.g. an
unescaped Windows path like C:\\Users\\...) crashed request.json() and surfaced
as a 500 with a full stack trace, leaking internal file paths. A bad frame from
a sender is a 400, and it must never create a job.
"""
import pytest
from fastapi.testclient import TestClient

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
