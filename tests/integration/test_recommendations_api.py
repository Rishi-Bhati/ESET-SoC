"""Engineer recommendations API: create / list / retract / counts, validation and auth."""
import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.storage import job_store

BASE = "/dashboard/api"


async def _make_alert(cid: str) -> str:
    """The API treats an alert as existing when it has a jobs row."""
    await job_store.create_job(cid, "WEBHOOK", {"alert_id": cid})
    return cid


@pytest.mark.asyncio
async def test_create_list_retract_and_counts(client: TestClient):
    cid = await _make_alert("rec-alert-1")

    res = client.post(f"{BASE}/alerts/{cid}/recommendations",
                      json={"body": "Isolate the host", "author": "alice"})
    assert res.status_code == 201
    body = res.json()
    rec = body["recommendation"]
    assert rec["id"].startswith("rec_")
    assert rec["body"] == "Isolate the host"
    assert rec["retracted_at"] is None
    assert body["notification"] == {
        "queued": False, "email_id": None, "reason": "recommendation_email_disabled"}

    listing = client.get(f"{BASE}/alerts/{cid}/recommendations").json()
    assert [r["id"] for r in listing["recommendations"]] == [rec["id"]]
    assert client.get(f"{BASE}/recommendations/counts",
                      params={"cids": cid}).json()["counts"] == {cid: 1}

    retracted = client.post(f"{BASE}/recommendations/{rec['id']}/retract",
                            json={"author": "bob", "reason": "wrong host"})
    assert retracted.status_code == 200
    assert retracted.json()["recommendation"]["retracted_by"] == "bob"
    assert retracted.json()["recommendation"]["retract_reason"] == "wrong host"

    # Still listed for the engineer (including retracted), but no longer counted.
    assert len(client.get(f"{BASE}/alerts/{cid}/recommendations").json()["recommendations"]) == 1
    assert client.get(f"{BASE}/recommendations/counts",
                      params={"cids": cid}).json()["counts"] == {cid: 0}


@pytest.mark.asyncio
async def test_counts_multiple_and_empty(client: TestClient):
    a = await _make_alert("rec-count-a")
    b = await _make_alert("rec-count-b")
    client.post(f"{BASE}/alerts/{a}/recommendations", json={"body": "x", "author": "a"})
    client.post(f"{BASE}/alerts/{a}/recommendations", json={"body": "y", "author": "a"})
    client.post(f"{BASE}/alerts/{b}/recommendations", json={"body": "z", "author": "a"})

    counts = client.get(f"{BASE}/recommendations/counts",
                        params={"cids": f"{a},{b},rec-count-c"}).json()["counts"]
    assert counts == {a: 2, b: 1, "rec-count-c": 0}
    assert client.get(f"{BASE}/recommendations/counts", params={"cids": ""}).json()["counts"] == {}


@pytest.mark.asyncio
async def test_control_characters_are_stripped_but_tabs_and_newlines_kept(client: TestClient):
    cid = await _make_alert("rec-ctrl-1")
    rec = client.post(f"{BASE}/alerts/{cid}/recommendations", json={
        "body": "line1\nline2\tend\x00\x07", "author": "a\x00l",
    }).json()["recommendation"]
    assert rec["body"] == "line1\nline2\tend"
    assert rec["author"] == "al"


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"body": "", "author": "a"},
    {"body": "   ", "author": "a"},
    {"body": "x" * 4001, "author": "a"},
    {"body": "ok", "author": ""},
    {"body": "ok", "author": "a" * 101},
    {"body": "ok"},
    {"author": "a"},
])
async def test_create_validation_errors(client: TestClient, payload: dict):
    cid = await _make_alert("rec-val-1")
    assert client.post(f"{BASE}/alerts/{cid}/recommendations", json=payload).status_code == 422
    assert client.get(f"{BASE}/alerts/{cid}/recommendations").json()["recommendations"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"reason": ""},
    {"author": "", "reason": ""},
    {"author": "a" * 101, "reason": ""},
    {"author": "bob", "reason": "x" * 501},
])
async def test_retract_validation_errors(client: TestClient, payload: dict):
    cid = await _make_alert("rec-retract-val")
    rec = client.post(f"{BASE}/alerts/{cid}/recommendations",
                      json={"body": "x", "author": "a"}).json()["recommendation"]
    res = client.post(f"{BASE}/recommendations/{rec['id']}/retract", json=payload)
    assert res.status_code == 422
    # Validation failure must not have retracted it.
    assert client.get(f"{BASE}/recommendations/counts",
                      params={"cids": cid}).json()["counts"] == {cid: 1}


def test_unknown_alert_and_recommendation_are_404(client: TestClient):
    assert client.get(f"{BASE}/alerts/does-not-exist/recommendations").status_code == 404
    assert client.post(f"{BASE}/alerts/does-not-exist/recommendations",
                       json={"body": "x", "author": "a"}).status_code == 404
    assert client.post(f"{BASE}/recommendations/rec_missing/retract",
                       json={"author": "bob", "reason": ""}).status_code == 404


def test_invalid_ids_are_rejected(client: TestClient):
    assert client.get(f"{BASE}/alerts/bad%20id/recommendations").status_code == 400
    assert client.post(f"{BASE}/alerts/bad%20id/recommendations",
                       json={"body": "x", "author": "a"}).status_code == 400
    assert client.get(f"{BASE}/recommendations/counts",
                      params={"cids": "ok, bad id"}).status_code == 400
    too_many = ",".join(f"c{i}" for i in range(501))
    assert client.get(f"{BASE}/recommendations/counts",
                      params={"cids": too_many}).status_code == 400


def test_all_endpoints_require_the_dashboard_key(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", "s3cret-key")
    routes = [
        ("get", f"{BASE}/alerts/x/recommendations", None),
        ("post", f"{BASE}/alerts/x/recommendations", {"body": "x", "author": "a"}),
        ("post", f"{BASE}/recommendations/rec_x/retract", {"author": "a", "reason": ""}),
        ("get", f"{BASE}/recommendations/counts?cids=x", None),
    ]
    for method, url, payload in routes:
        call = getattr(client, method)
        assert call(url).status_code == 401, url
        assert call(url, headers={"X-Dashboard-Key": "wrong"}).status_code == 401, url
        assert call(url, headers={"X-Dashboard-Key": "s3cret-key"},
                    **({"json": payload} if payload else {})).status_code != 401, url
