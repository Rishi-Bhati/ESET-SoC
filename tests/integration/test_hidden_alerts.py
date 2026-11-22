"""
Hidden alerts (storage/hidden_store.py): a hidden alert keeps all its data but is
left out of every dashboard view, the client portal, exports and the weekly /
on-demand reports; unhiding brings it back everywhere.
"""
import io
import os
import time

import aiosqlite
import openpyxl
import pytest
from fastapi.testclient import TestClient

from client_auth_helpers import ENGINEER, enable_portal, make_client_session, session_header
from src.config import settings
from src.services import weekly_report
from src.storage import hidden_store, job_store
from test_client_api import seed  # same seeding as the portal API tests

NOW = time.time()
REAL, TEST = "real-alert-1", "test-alert-1"
HIDE = "/dashboard/api/alerts/hide"
UNHIDE = "/dashboard/api/alerts/unhide"


@pytest.fixture
async def alerts():
    await seed(REAL, NOW - 3600, risk="MEDIUM")
    await seed(TEST, NOW - 1800, risk="MEDIUM")


@pytest.fixture
def auth(client: TestClient, monkeypatch) -> dict[str, str]:
    enable_portal(monkeypatch)
    return session_header(make_client_session(client))


def _visible_everywhere(client: TestClient, auth: dict[str, str]) -> dict[str, set[str]]:
    """Alert ids each surface shows."""
    seen: dict[str, set[str]] = {}
    r = client.get("/client/api/alerts", headers=auth)
    assert r.status_code == 200, r.text
    seen["portal list"] = {i["alert_id"] for i in r.json()["items"]}
    seen["portal detail"] = {cid for cid in (REAL, TEST)
                             if client.get(f"/client/api/alerts/{cid}", headers=auth).status_code == 200}
    seen["dashboard alerts"] = {a["correlation_id"] for a in
                                client.get("/dashboard/api/alerts", headers=ENGINEER).json()["alerts"]}
    seen["dashboard jobs"] = {j["correlation_id"] for j in
                              client.get("/dashboard/api/jobs", headers=ENGINEER).json()["jobs"]}
    seen["dashboard ai content"] = {i["correlation_id"] for i in
                                    client.get("/dashboard/api/ai-content", headers=ENGINEER).json()["items"]}
    r = client.get("/dashboard/api/alerts/export", headers=ENGINEER)
    assert r.status_code == 200, r.text
    cells = {c for row in openpyxl.load_workbook(io.BytesIO(r.content)).active.iter_rows(values_only=True)
             for c in row}
    seen["dashboard export"] = {cid for cid in (REAL, TEST) if cid in cells}
    return seen


async def test_hidden_alert_disappears_everywhere_and_comes_back(client, auth, alerts):
    before = _visible_everywhere(client, auth)
    assert all(ids == {REAL, TEST} for ids in before.values()), before

    r = client.post(HIDE, headers=ENGINEER, json={"correlation_ids": [TEST], "reason": "test alert"})
    assert r.status_code == 200, r.text
    assert r.json()["hidden"] == 1

    after = _visible_everywhere(client, auth)
    assert all(ids == {REAL} for ids in after.values()), after

    # Nothing was deleted: the job row and the result file are still there.
    assert await job_store.get_job(TEST) is not None
    assert os.path.exists(os.path.join(settings.output_dir, f"{TEST}.json"))
    # ... and the engineer can still open it by id.
    assert client.get(f"/dashboard/api/jobs/{TEST}", headers=ENGINEER).status_code == 200

    hidden = client.get("/dashboard/api/alerts/hidden", headers=ENGINEER).json()
    assert [h["correlation_id"] for h in hidden["hidden"]] == [TEST]
    assert hidden["hidden"][0]["reason"] == "test alert"

    r = client.post(UNHIDE, headers=ENGINEER, json={"correlation_ids": [TEST]})
    assert r.status_code == 200 and r.json()["unhidden"] == 1
    assert all(ids == {REAL, TEST} for ids in _visible_everywhere(client, auth).values())


async def test_portal_stats_and_reports_leave_hidden_alerts_out(client, auth, alerts):
    await hidden_store.hide([TEST])

    stats = client.get("/client/api/stats?days=7", headers=auth)
    assert stats.status_code == 200, stats.text
    body = stats.json()
    assert body["total"] == 1
    assert f"PC-{TEST}" not in str(body["top_devices"]) and f"PC-{REAL}" in str(body["top_devices"])

    period = weekly_report.current_period()
    content = await weekly_report.build_content(period, always_build_file=True)
    assert content.counts["MEDIUM"] == 1
    cells = {c for row in openpyxl.load_workbook(io.BytesIO(content.xlsx)).active.iter_rows(values_only=True)
             for c in row}
    assert REAL in cells and TEST not in cells

    on_demand = await weekly_report.build_on_demand(period, include_high_risk=True, header_lang="ja", max_rows=100)
    assert on_demand.counts["MEDIUM"] == 1 and on_demand.rows == 1
    cells = {c for ws in openpyxl.load_workbook(io.BytesIO(on_demand.content)).worksheets
             for row in ws.iter_rows(values_only=True) for c in row}
    assert REAL in cells and TEST not in cells


def test_hide_requires_the_dashboard_key(client, auth):
    assert client.post(HIDE, json={"correlation_ids": [TEST]}).status_code == 401
    assert client.get("/dashboard/api/alerts/hidden", headers=auth).status_code == 401


@pytest.mark.parametrize("bad", ["../etc/passwd", "a/b", "..", ""])
def test_hide_rejects_invalid_ids(client, auth, bad):
    assert client.post(HIDE, headers=ENGINEER, json={"correlation_ids": [bad]}).status_code == 422


async def test_hiding_twice_is_harmless(alerts):
    assert await hidden_store.hide([TEST, TEST]) == 1
    assert await hidden_store.hide([TEST]) == 0
    assert await hidden_store.hidden_ids() == {TEST}
    assert await hidden_store.unhide([TEST, "never-hidden"]) == 1
