"""
Client portal data API: /client/api/alerts (list, detail), /export/fields and the
spreadsheet export. Real app + temp DB; alerts are seeded as result file + jobs row +
alert_index row with a chosen receipt time.
"""
import asyncio
import io
import threading
import zipfile

import aiosqlite
import openpyxl
import pytest
from fastapi.testclient import TestClient

from client_auth_helpers import ENGINEER, LogRecorder, enable_portal, make_client_session, session_header
from src.api import client as client_api
from src.config import settings
from src.models.ai_output import AIOutput
from src.models.normalized_alert import NormalizedAlert
from src.models.pipeline_result import PipelineResult
from src.services import output_writer
from src.services.client_fields import DEFAULT_FIELDS, GROUP_LABELS, REGISTRY, WEEKLY_FIELDS
from src.storage import alert_index_store, job_store, recommendation_store, runtime_settings
from src.utils.jst_time import jst_day_start_epoch

BASE = "/client/api"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
DAY = jst_day_start_epoch("2026-11-03")          # 00:00 JST on the test day


# ------------------------------------------------------------------ helpers

@pytest.fixture
def auth(client: TestClient, monkeypatch) -> dict[str, str]:
    enable_portal(monkeypatch)
    return session_header(make_client_session(client))


def _ai(summary: str = "AI要約", **over) -> AIOutput:
    data = dict(
        risk_level="HIGH", alert_summary_ja=summary, risk_reason_ja="理由",
        client_notification_ja="お客様通知", internal_summary_ja="internal", engineer_summary_en="eng",
        recommended_initial_actions_ja=["対応1", "対応2"], recommended_initial_actions_en=["act1"],
        additional_confirmation_items_ja=["確認1"], unknown_items=["u: Needs confirmation"],
        backlog_comment_ja="backlog", email_subject_ja="subj", email_body_ja="body")
    data.update(over)
    return AIOutput(**data)


async def seed(cid: str, received_at: float, risk: str = "HIGH", status: str = "SUCCESS",
               ai: AIOutput | None = None, job_error: str | None = None, **result_over) -> None:
    result = PipelineResult(
        correlation_id=cid, source="WEBHOOK",
        received_at="2026-11-03T00:00:00+00:00", processed_at="2026-11-03T00:00:05+00:00",
        pipeline_status=status,
        normalized_alert=NormalizedAlert(severity="Warning", alert_id=f"E-{cid}", detection_name=f"Det-{cid}",
                                         endpoint_name=f"PC-{cid}", action_taken="Cleaned"),
        risk_level=risk, risk_rationale="rationale", ai_output=ai or _ai(f"summary of {cid}"), **result_over)
    await job_store.create_job(cid, "WEBHOOK", {"alert_id": f"E-{cid}"})
    await output_writer.write_result(result)
    await alert_index_store.upsert_from_result(result, received_at)
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("UPDATE jobs SET created_at = ? WHERE correlation_id = ?", (received_at, cid))
        await conn.commit()
    if job_error:
        await job_store.update_job_status(cid, "FAILED", job_error)


def ids(res) -> list[str]:
    assert res.status_code == 200, res.text
    return [i["alert_id"] for i in res.json()["items"]]


def sheet_rows(content: bytes) -> list[tuple]:
    wb = openpyxl.load_workbook(io.BytesIO(content))
    return list(wb.active.iter_rows(values_only=True))


def export(client, auth, **body):
    body.setdefault("fields", ["alert_id", "risk_level"])
    return client.post(f"{BASE}/alerts/export", json=body, headers=auth)


# --------------------------------------------------------------------- auth

ROUTES = [
    ("GET", f"{BASE}/alerts", None),
    ("GET", f"{BASE}/alerts/some-id", None),
    ("GET", f"{BASE}/export/fields", None),
    ("POST", f"{BASE}/alerts/export", {"fields": ["alert_id"]}),
    ("GET", f"{BASE}/stats", None),
]


@pytest.mark.parametrize("method,path,body", ROUTES)
async def test_every_route_rejects_missing_wrong_and_engineer_credentials(client, monkeypatch, method, path, body):
    enable_portal(monkeypatch)
    await seed("some-id", DAY + 100)
    for headers in ({}, {"X-Client-Session": "not-a-session"}, ENGINEER):
        res = client.request(method, path, json=body, headers=headers)
        assert res.status_code == 401, (headers, res.text)
        assert "some-id" not in res.text


# --------------------------------------------------------------------- list

async def test_list_filters_by_risk(client, auth):
    for cid, risk in (("a-low", "LOW"), ("a-med", "MEDIUM"), ("a-high", "HIGH"), ("a-crit", "CRITICAL")):
        await seed(cid, DAY + 100 + len(cid), risk)
    assert sorted(ids(client.get(f"{BASE}/alerts", headers=auth))) == ["a-crit", "a-high", "a-low", "a-med"]
    assert sorted(ids(client.get(f"{BASE}/alerts", params={"risk": "high,critical"}, headers=auth))) == [
        "a-crit", "a-high"]
    assert ids(client.get(f"{BASE}/alerts", params={"risk": "LOW"}, headers=auth)) == ["a-low"]


async def test_list_only_shows_finished_alerts(client, auth):
    await seed("ok", DAY + 10)
    await seed("part", DAY + 20, status="PARTIAL")
    await seed("bad", DAY + 30, status="FAILED")
    assert sorted(ids(client.get(f"{BASE}/alerts", headers=auth))) == ["ok", "part"]


async def test_list_date_range_uses_jst_day_boundaries(client, auth):
    await seed("before", DAY - 1)             # 23:59:59 JST the day before
    await seed("start", DAY)                  # 00:00:00 JST, first second of the day
    await seed("last", DAY + 86399)           # 23:59:59 JST on the `to` date
    await seed("next", DAY + 86400)           # 00:00:00 JST next day
    got = ids(client.get(f"{BASE}/alerts", params={"from": "2026-11-03", "to": "2026-11-03"}, headers=auth))
    assert sorted(got) == ["last", "start"]
    assert sorted(ids(client.get(f"{BASE}/alerts", params={"from": "2026-11-03"}, headers=auth))) == [
        "last", "next", "start"]
    assert sorted(ids(client.get(f"{BASE}/alerts", params={"to": "2026-11-03"}, headers=auth))) == [
        "before", "last", "start"]
    # a 23:59 JST alert is the previous UTC day's 14:59 - UTC day logic would put it elsewhere
    assert ids(client.get(f"{BASE}/alerts", params={"from": "2026-11-04", "to": "2026-11-04"},
                          headers=auth)) == ["next"]


async def test_list_pagination_sorting_and_counts_ignore_the_risk_filter(client, auth):
    for i in range(5):
        await seed(f"p{i}", DAY + 100 * (i + 1), "HIGH" if i < 3 else "LOW")
    await seed("out", DAY + 5 * 86400, "CRITICAL")           # outside the date range
    params = {"from": "2026-11-03", "to": "2026-11-03", "page_size": 2, "risk": "HIGH"}
    first = client.get(f"{BASE}/alerts", params=params, headers=auth).json()
    assert [i["alert_id"] for i in first["items"]] == ["p2", "p1"]            # newest first
    assert (first["total"], first["page"], first["pages"]) == (3, 1, 2)
    assert first["counts_by_risk"] == {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 0, "LOW": 2}
    second = client.get(f"{BASE}/alerts", params={**params, "page": 2}, headers=auth).json()
    assert [i["alert_id"] for i in second["items"]] == ["p0"] and second["page"] == 2
    asc = client.get(f"{BASE}/alerts", params={**params, "sort": "asc"}, headers=auth).json()
    assert [i["alert_id"] for i in asc["items"]] == ["p0", "p1"]
    empty = client.get(f"{BASE}/alerts", params={"risk": "MEDIUM"}, headers=auth).json()
    assert empty["items"] == [] and empty["total"] == 0 and empty["pages"] == 1


async def test_list_item_shape_and_excerpt(client, auth):
    await seed("long", DAY + 50, ai=_ai("あ" * 500))
    await seed("rec", DAY + 60)
    first = await recommendation_store.create("rec", "first advice", "eng.a")
    await recommendation_store.create("rec", "second advice", "eng.b")
    gone = await recommendation_store.create("rec", "oops", "eng.c")
    await recommendation_store.retract(gone["id"], "eng.c", "wrong")
    items = {i["alert_id"]: i for i in client.get(f"{BASE}/alerts", headers=auth).json()["items"]}
    assert set(items["long"]) == {
        "alert_id", "eset_alert_id", "received_at", "risk_level", "eset_severity", "detection_name",
        "endpoint_name", "ai_summary_excerpt", "recommendation_count", "latest_recommendation_at"}
    assert items["long"]["ai_summary_excerpt"] == "あ" * 200
    assert items["long"]["received_at"] == DAY + 50
    assert items["long"]["recommendation_count"] == 0 and items["long"]["latest_recommendation_at"] is None
    assert items["long"]["eset_alert_id"] == "E-long" and items["long"]["eset_severity"] == "Warning"
    assert items["long"]["detection_name"] == "Det-long" and items["long"]["endpoint_name"] == "PC-long"
    assert items["rec"]["recommendation_count"] == 2
    assert items["rec"]["latest_recommendation_at"] >= first["created_at"]


@pytest.mark.parametrize("params", [
    {"risk": "SEVERE"}, {"risk": "HIGH,bogus"}, {"from": "2026-13-01"}, {"to": "yesterday"},
    {"from": "2026-11-05", "to": "2026-11-04"}, {"sort": "sideways"}, {"from": "2026-02-30"},
])
async def test_list_rejects_bad_parameters_with_400(client, auth, params):
    assert client.get(f"{BASE}/alerts", params=params, headers=auth).status_code == 400


@pytest.mark.parametrize("params", [{"page": 0}, {"page_size": 0}, {"page_size": 101}])
async def test_list_rejects_out_of_range_paging(client, auth, params):
    assert client.get(f"{BASE}/alerts", params=params, headers=auth).status_code == 422


# ------------------------------------------------------------------- detail

async def test_detail_returns_grouped_registry_fields_and_only_active_recommendations(client, auth):
    await seed("d1", DAY + 10)
    keep = await recommendation_store.create("d1", "Isolate host", "eng.a")
    gone = await recommendation_store.create("d1", "RETRACTED-BODY", "eng.b")
    await recommendation_store.set_notification_email_id(keep["id"], "email-123")
    await recommendation_store.retract(gone["id"], "eng.b", "wrong")

    res = client.get(f"{BASE}/alerts/d1", headers=auth)
    assert res.status_code == 200
    data = res.json()
    assert set(data) == {"alert", "groups", "recommendations"}
    flat = {k: v for group in data["alert"].values() for k, v in group.items()}
    assert set(flat) == set(REGISTRY)                       # every registry field, nothing else
    for key, spec in REGISTRY.items():
        assert key in data["alert"][spec.group]
    assert list(data["alert"]) == [g for g in GROUP_LABELS if g in data["alert"]]
    assert data["groups"]["ai"] == {"ja": GROUP_LABELS["ai"][0], "en": GROUP_LABELS["ai"][1]}
    assert flat["alert_id"] == "d1" and flat["risk_level"] == "HIGH"
    assert flat["detection_name"] == "Det-d1" and flat["ai_alert_summary_ja"] == "summary of d1"
    assert data["recommendations"] == [
        {"id": keep["id"], "body": "Isolate host", "author": "eng.a", "created_at": keep["created_at"]}]
    assert "RETRACTED-BODY" not in res.text and "email-123" not in res.text and "retract" not in res.text


@pytest.mark.parametrize("bad", ["a b", "a%24b", "a;b", "x" * 129])
async def test_detail_rejects_invalid_ids_with_400(client, auth, bad):
    assert client.get(f"{BASE}/alerts/{bad}", headers=auth).status_code == 400


async def test_detail_404_for_unknown_or_unreadable_alert(client, auth):
    assert client.get(f"{BASE}/alerts/nope", headers=auth).status_code == 404
    await job_store.create_job("no-result", "WEBHOOK", {})
    assert client.get(f"{BASE}/alerts/no-result", headers=auth).status_code == 404
    assert client.get(f"{BASE}/alerts/..", headers=auth).status_code in (400, 404)


# ------------------------------------------------------------------- fields

async def test_export_fields_catalogue(client, auth, monkeypatch):
    data = client.get(f"{BASE}/export/fields", headers=auth).json()
    assert [f["key"] for f in data["fields"]] == list(REGISTRY)
    assert set(data["fields"][0]) == {"key", "label_ja", "label_en", "group", "default_selected"}
    assert data["groups"] == {g: {"ja": ja, "en": en} for g, (ja, en) in GROUP_LABELS.items()}
    assert data["default_fields"] == DEFAULT_FIELDS and data["weekly_fields"] == WEEKLY_FIELDS
    assert data["max_alerts"] == await runtime_settings.get("client_export_max_alerts")
    await runtime_settings.set("client_export_max_alerts", 7)
    assert client.get(f"{BASE}/export/fields", headers=auth).json()["max_alerts"] == 7


# ------------------------------------------------------------------- export

async def test_export_returns_requested_columns_in_order(client, auth):
    await seed("x1", DAY + 10, "HIGH")
    await seed("x2", DAY + 20, "LOW")
    keys = ["risk_level", "alert_id", "detection_name"]
    res = export(client, auth, fields=keys, header_lang="en")
    assert res.status_code == 200
    assert res.headers["content-type"] == XLSX
    assert res.headers["x-alert-count"] == "2"
    assert res.headers["cache-control"] == "no-store"
    disp = res.headers["content-disposition"]
    assert disp.startswith('attachment; filename="soc-lite-client-alerts-') and disp.endswith('.xlsx"')
    rows = sheet_rows(res.content)
    assert rows[0] == tuple(REGISTRY[k].label_en for k in keys)
    assert rows[1:] == [("LOW", "x2", "Det-x2"), ("HIGH", "x1", "Det-x1")]          # newest first
    ja = sheet_rows(export(client, auth, fields=keys, header_lang="ja", sort="asc").content)
    assert ja[0] == tuple(REGISTRY[k].label_ja for k in keys)
    assert [r[1] for r in ja[1:]] == ["x1", "x2"]


async def test_export_filters_like_the_list_and_respects_limit(client, auth):
    for i in range(6):
        await seed(f"e{i}", DAY + 100 * (i + 1), "HIGH" if i % 2 == 0 else "LOW")
    await seed("far", DAY + 3 * 86400, "HIGH")
    res = export(client, auth, risk=["HIGH"], **{"from": "2026-11-03", "to": "2026-11-03"})
    assert [r[0] for r in sheet_rows(res.content)[1:]] == ["e4", "e2", "e0"] and res.headers["x-alert-count"] == "3"
    res = export(client, auth, limit=2, fields=["alert_id"])
    assert res.headers["x-alert-count"] == "2" and len(sheet_rows(res.content)) == 3
    assert [r[0] for r in sheet_rows(res.content)[1:]] == ["far", "e5"]


async def test_export_pages_through_large_limits(client, auth, monkeypatch):
    monkeypatch.setattr(client_api, "EXPORT_CHUNK", 2)
    for i in range(5):
        await seed(f"c{i}", DAY + 10 * (i + 1))
    res = export(client, auth, fields=["alert_id"], sort="asc")
    assert [r[0] for r in sheet_rows(res.content)[1:]] == [f"c{i}" for i in range(5)]
    res = export(client, auth, fields=["alert_id"], sort="asc", limit=3)
    assert [r[0] for r in sheet_rows(res.content)[1:]] == ["c0", "c1", "c2"]


async def test_export_with_no_matches_is_a_valid_header_only_workbook(client, auth):
    res = export(client, auth, fields=["alert_id", "risk_level"], risk=["CRITICAL"], include_info_sheet=True)
    assert res.status_code == 200 and res.headers["x-alert-count"] == "0"
    wb = openpyxl.load_workbook(io.BytesIO(res.content))
    assert len(wb.sheetnames) == 2
    assert [c.value for c in wb.worksheets[0][1]] == [REGISTRY["alert_id"].label_ja, REGISTRY["risk_level"].label_ja]
    assert wb.worksheets[0].max_row == 1


@pytest.mark.parametrize("body", [
    {"fields": ["alert_id", "internal_summary_ja"]},
    {"fields": ["ai_run"]},
    {"fields": ["alert_id", "alert_id"]},
    {"fields": ["alert_id"], "header_lang": "fr"},
    {"fields": ["alert_id"], "risk": ["SEVERE"]},
    {"fields": ["alert_id"], "from": "nope"},
    {"fields": ["alert_id"], "from": "2026-11-05", "to": "2026-11-01"},
    {"fields": ["alert_id"], "sort": "up"},
    {"fields": ["alert_id"], "limit": 100001},
])
async def test_export_rejects_bad_requests_with_400(client, auth, body):
    res = client.post(f"{BASE}/alerts/export", json=body, headers=auth)
    assert res.status_code == 400, res.text
    assert "traceback" not in res.text.lower()


@pytest.mark.parametrize("body", [
    {"fields": []}, {}, {"fields": ["alert_id"] * 51}, {"fields": ["alert_id"], "limit": 0},
    {"fields": ["alert_id"], "risk": ["LOW", "MEDIUM", "HIGH", "CRITICAL", "LOW"]},
    {"fields": ["alert_id"], "unexpected": 1},
])
async def test_export_rejects_malformed_bodies_with_422(client, auth, body):
    assert client.post(f"{BASE}/alerts/export", json=body, headers=auth).status_code == 422


@pytest.mark.parametrize("content", [b"{not json", b"", b'{"fields": 7}', b"[]"])
def test_export_checks_the_session_before_the_body(client, monkeypatch, content):
    """Regression: the export body was decoded before require_client ran, so a
    caller with no (or a foreign) credential got 422 instead of 401."""
    enable_portal(monkeypatch)
    for headers in ({}, {"X-Client-Session": "not-a-session"}, ENGINEER,
                    {"Authorization": "Bearer test_token"}):
        res = client.post(f"{BASE}/alerts/export", content=content,
                          headers={**headers, "Content-Type": "application/json"})
        assert res.status_code == 401, (headers, content, res.text)


def test_export_malformed_json_with_a_session_is_422(client, auth):
    res = client.post(f"{BASE}/alerts/export", content=b"{not json",
                      headers={**auth, "Content-Type": "application/json"})
    assert res.status_code == 422 and res.json()["detail"][0]["type"] == "json_invalid"
    res = client.post(f"{BASE}/alerts/export", json={"fields": "alert_id"}, headers=auth)
    assert res.status_code == 422 and res.json()["detail"][0]["loc"][:2] == ["body", "fields"]


async def test_export_limit_above_the_configured_maximum_is_rejected(client, auth):
    await runtime_settings.set("client_export_max_alerts", 2)
    for i in range(4):
        await seed(f"m{i}", DAY + i + 1)
    assert export(client, auth, limit=3).status_code == 400
    res = export(client, auth)                                       # default = the maximum
    assert res.status_code == 200 and res.headers["x-alert-count"] == "2"


async def test_export_audit_log_has_metadata_but_no_data(client, auth, monkeypatch):
    log = LogRecorder()
    monkeypatch.setattr(client_api, "logger", log)
    await seed("audit-1", DAY + 10)
    export(client, auth, fields=["alert_id", "detection_name"], risk=["HIGH"])
    (entry,) = log.find("client_export")
    assert entry["account"] == "probe.user" and entry["count"] == 1
    assert entry["fields"] == ["alert_id", "detection_name"] and entry["filter"]["risk"] == ["HIGH"]
    assert "Det-audit-1" not in log.dump()


async def test_only_one_export_per_user_at_a_time(client, auth, monkeypatch):
    await seed("slow-1", DAY + 10)
    entered, release = threading.Event(), threading.Event()
    real = client_api.build_workbook

    async def slow_build(*args, **kwargs):
        entered.set()
        while not release.is_set():
            await asyncio.sleep(0.02)
        return await real(*args, **kwargs)

    monkeypatch.setattr(client_api, "build_workbook", slow_build)
    first = asyncio.create_task(asyncio.to_thread(export, client, auth))
    assert await asyncio.to_thread(entered.wait, 10)
    second = await asyncio.to_thread(export, client, auth)
    assert second.status_code == 429 and "Retry-After" in second.headers
    release.set()
    assert (await first).status_code == 200
    assert export(client, auth).status_code == 200                          # slot released afterwards


async def test_export_slot_is_released_after_a_failed_export(client, auth):
    assert export(client, auth, fields=["nope"]).status_code == 400
    assert export(client, auth).status_code == 200
    assert client_api._active_exports == set()


# --------------------------------------------------------------------- leaks

async def test_internal_material_never_reaches_json_or_spreadsheet(client, auth):
    mark = {n: f"LEAK_{n.upper()}_9c1e" for n in (
        "internal", "backlog", "eng_en", "actions_en", "unknown", "risk_factor", "intel", "job_error",
        "email_subject", "email_body", "rationale", "provider", "extra_top", "notification", "path")}
    ai = _ai("visible summary", internal_summary_ja=mark["internal"], backlog_comment_ja=mark["backlog"],
             engineer_summary_en=mark["eng_en"], recommended_initial_actions_en=[mark["actions_en"]],
             unknown_items=[mark["unknown"]], email_subject_ja=mark["email_subject"],
             email_body_ja=mark["email_body"])
    await seed("leak-1", DAY + 10, ai=ai, job_error=mark["job_error"],
               risk_factors=[{"rule": mark["risk_factor"], "effect": "UP", "detail": mark["risk_factor"]}],
               threat_intel={"virustotal": {"status": "MALICIOUS", "permalink": mark["intel"]}},
               notifications=[{"email_id": mark["notification"], "recipients": [mark["notification"]]}],
               ai_run={"provider": mark["provider"], "model": "m", "prompt_version": "v"},
               error=mark["job_error"])
    # a hand-edited result file may also carry stray top-level keys
    import json, os
    path = os.path.join(settings.output_dir, "leak-1.json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    data["result_path"] = mark["path"]
    data["extra"] = mark["extra_top"]
    data["risk_rationale"] = mark["rationale"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    rec = await recommendation_store.create("leak-1", "advice for the client", "eng.a")
    await recommendation_store.set_notification_email_id(rec["id"], mark["notification"])

    bodies = [
        client.get(f"{BASE}/alerts", headers=auth).text,
        client.get(f"{BASE}/alerts/leak-1", headers=auth).text,
        client.get(f"{BASE}/export/fields", headers=auth).text,
    ]
    assert "visible summary" in bodies[0] and "advice for the client" in bodies[1]
    res = export(client, auth, fields=list(REGISTRY), include_info_sheet=True, header_lang="en")
    assert res.status_code == 200
    with zipfile.ZipFile(io.BytesIO(res.content)) as z:
        bodies.append("\n".join(z.read(n).decode("utf-8", "replace") for n in z.namelist()))
    cells = [str(c) for row in sheet_rows(res.content) for c in row if c is not None]
    assert any("advice for the client" in c for c in cells)
    bodies.append("\n".join(cells))
    for text in bodies:
        for name, value in mark.items():
            assert value not in text, f"{name} leaked"
        assert "internal_summary" not in text and "backlog_comment" not in text
        assert settings.output_dir not in text


# -------------------------------------------------------------------- stats
# GET /client/api/stats feeds the Home charts. Counts only; same rows as the list.

STATS_KEYS = {"days", "from", "to", "bucket_days", "buckets", "totals", "total", "devices_affected",
              "with_advice", "latest_advice_at", "top_devices", "other_devices", "top_threats",
              "other_threats", "previous"}


@pytest.fixture
def today(monkeypatch):
    """Pins the portal's 'today' to 9 Nov 2026 JST, so a 7-day period is 3-9 Nov."""
    from datetime import date
    monkeypatch.setattr(client_api, "_today_jst", lambda: date(2026, 11, 9))


async def name_alert(cid: str, endpoint: str | None, detection: str | None) -> None:
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("UPDATE alert_index SET endpoint_name = ?, detection_name = ? WHERE correlation_id = ?",
                           (endpoint, detection, cid))
        await conn.commit()


def stats(client, auth, days=7):
    res = client.get(f"{BASE}/stats", params={"days": days}, headers=auth)
    assert res.status_code == 200, res.text
    return res.json()


async def test_stats_counts_per_day_and_compares_with_the_previous_period(client, auth, today):
    await seed("s-first", DAY, "HIGH")                       # 00:00 JST 3 Nov: first second of the period
    await seed("s-mid", DAY + 2 * 86400 + 50, "LOW")          # 5 Nov
    await seed("s-mid2", DAY + 2 * 86400 + 60, "LOW")
    await seed("s-last", DAY + 7 * 86400 - 1, "CRITICAL")     # 23:59:59 JST 9 Nov (today)
    await seed("s-prev", DAY - 1, "MEDIUM")                   # 23:59:59 JST 2 Nov: previous period
    await seed("s-old", DAY - 7 * 86400 - 1, "HIGH")          # before the previous period
    await seed("s-future", DAY + 7 * 86400, "HIGH")           # 10 Nov: after today
    await seed("s-failed", DAY + 100, "HIGH", status="FAILED")
    body = stats(client, auth)
    assert set(body) == STATS_KEYS
    assert (body["days"], body["from"], body["to"], body["bucket_days"]) == (7, "2026-11-03", "2026-11-09", 1)
    assert [b["from"] for b in body["buckets"]] == [f"2026-11-0{d}" for d in range(3, 10)]
    assert all(b["from"] == b["to"] for b in body["buckets"])
    by_day = {b["from"]: b["counts"] for b in body["buckets"]}
    assert by_day["2026-11-03"] == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert by_day["2026-11-05"]["LOW"] == 2
    assert by_day["2026-11-09"]["CRITICAL"] == 1
    assert sum(sum(c.values()) for c in by_day.values()) == 4
    assert body["totals"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 2} and body["total"] == 4
    prev = body["previous"]
    assert (prev["from"], prev["to"]) == ("2026-10-27", "2026-11-02")
    assert prev["totals"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0} and prev["total"] == 1


async def test_stats_totals_match_the_alert_list_for_the_same_window(client, auth, today):
    for i, risk in enumerate(["LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL", "LOW"]):
        await seed(f"m-{i}", DAY - 20 * 86400 + i * 5 * 86400, risk)
    await seed("m-partial", DAY + 10, "MEDIUM", status="PARTIAL")
    await seed("m-failed", DAY + 20, "MEDIUM", status="FAILED")
    body = stats(client, auth, days=30)
    listed = client.get(f"{BASE}/alerts", params={"from": body["from"], "to": body["to"]}, headers=auth).json()
    assert body["totals"] == listed["counts_by_risk"]
    assert body["total"] == listed["total"]


async def test_stats_ranks_devices_and_threats_and_groups_missing_names(client, auth, today):
    names = [("PC-A", "Trojan.X"), ("PC-A", "Trojan.X"), ("PC-A", "Adware.Y"), ("PC-B", "Adware.Y"),
             ("PC-B", "Trojan.X"), ("UNKNOWN", "UNKNOWN"), ("", None), (None, "Worm.Z")]
    for i, (endpoint, detection) in enumerate(names):
        await seed(f"r-{i}", DAY + 100 + i, "LOW")
        await name_alert(f"r-{i}", endpoint, detection)
    body = stats(client, auth)
    assert body["top_devices"] == [{"name": "PC-A", "count": 3}, {"name": None, "count": 3},
                                   {"name": "PC-B", "count": 2}]
    assert body["devices_affected"] == 2                       # "not recorded" is not a device
    assert body["top_threats"] == [{"name": "Trojan.X", "count": 3}, {"name": "Adware.Y", "count": 2},
                                   {"name": None, "count": 2}, {"name": "Worm.Z", "count": 1}]
    assert body["other_devices"] == {"names": 0, "alerts": 0}


async def test_stats_keeps_the_top_five_and_counts_the_rest(client, auth, today):
    for i in range(8):
        for k in range(8 - i):
            cid = f"t-{i}-{k}"
            await seed(cid, DAY + 1000 + i * 10 + k, "LOW")
            await name_alert(cid, f"HOST-{i}", "Same.Threat")
    body = stats(client, auth)
    assert [d["name"] for d in body["top_devices"]] == [f"HOST-{i}" for i in range(5)]
    assert body["other_devices"] == {"names": 3, "alerts": 3 + 2 + 1}
    assert body["top_threats"] == [{"name": "Same.Threat", "count": 36}]
    assert body["devices_affected"] == 8


async def test_stats_counts_alerts_with_active_advice_only(client, auth, today):
    await seed("adv-1", DAY + 100, "HIGH")
    await seed("adv-2", DAY + 200, "HIGH")
    await seed("adv-old", DAY - 86400, "HIGH")                # previous period
    await recommendation_store.create("adv-1", "first", "eng.a")
    latest = await recommendation_store.create("adv-1", "second", "eng.a")
    gone = await recommendation_store.create("adv-2", "oops", "eng.a")
    await recommendation_store.retract(gone["id"], "eng.a", "wrong")
    await recommendation_store.create("adv-old", "outside", "eng.a")
    body = stats(client, auth)
    assert body["with_advice"] == 1
    assert body["latest_advice_at"] == pytest.approx(latest["created_at"])


async def test_stats_uses_weekly_buckets_counted_back_from_today_for_90_days(client, auth, today):
    await seed("w-oldest", jst_day_start_epoch("2026-08-12"), "LOW")      # first day of the 90
    await seed("w-today", jst_day_start_epoch("2026-11-09") + 3600, "HIGH")
    await seed("w-before", jst_day_start_epoch("2026-08-11") + 3600, "LOW")  # day 91: previous period
    body = stats(client, auth, days=90)
    assert (body["from"], body["to"], body["bucket_days"]) == ("2026-08-12", "2026-11-09", 7)
    chunks = body["buckets"]
    assert len(chunks) == 13
    assert (chunks[0]["from"], chunks[0]["to"]) == ("2026-08-12", "2026-08-17")   # the one short bucket: 6 days
    assert (chunks[-1]["from"], chunks[-1]["to"]) == ("2026-11-03", "2026-11-09")
    assert chunks[0]["counts"]["LOW"] == 1 and chunks[-1]["counts"]["HIGH"] == 1
    assert sum(sum(b["counts"].values()) for b in chunks) == body["total"] == 2
    assert body["previous"]["total"] == 1


async def test_stats_with_no_alerts_is_zero_filled(client, auth, today):
    body = stats(client, auth, days=30)
    assert len(body["buckets"]) == 30 and body["total"] == 0
    assert all(sum(b["counts"].values()) == 0 for b in body["buckets"])
    assert body["top_devices"] == [] and body["top_threats"] == [] and body["devices_affected"] == 0
    assert body["with_advice"] == 0 and body["latest_advice_at"] is None


@pytest.mark.parametrize("days", ["0", "367", "-7", "abc", "7.5"])
def test_stats_rejects_out_of_range_days(client, auth, days):
    assert client.get(f"{BASE}/stats", params={"days": days}, headers=auth).status_code == 422


async def test_stats_returns_counts_and_names_but_no_alert_material(client, auth, today):
    await seed("secret-cid-123", DAY + 100, "HIGH", ai=_ai("SECRET SUMMARY TEXT"))
    text = client.get(f"{BASE}/stats", headers=auth).text
    for leaked in ('"secret-cid-123"', "SECRET SUMMARY TEXT", "E-secret-cid-123", "raw_payload", "Cleaned",
                   "alert_id", "correlation_id"):
        assert leaked not in text
    assert "PC-secret-cid-123" in text and "Det-secret-cid-123" in text   # what the list already shows


async def test_stats_scope_is_the_same_for_every_client_account(client, monkeypatch, today):
    """Data scoping matches /alerts: a deployment serves one client organisation, so every
    client account sees the same finished alerts and no account sees more than the list."""
    enable_portal(monkeypatch)
    await seed("scope-1", DAY + 100, "HIGH")
    await seed("scope-2", DAY + 200, "LOW", status="FAILED")
    first = session_header(make_client_session(client, "first.user"))
    second = session_header(make_client_session(client, "second.user"))
    a, b = stats(client, first), stats(client, second)
    assert a == b and a["total"] == 1
    listed = client.get(f"{BASE}/alerts", params={"from": a["from"]}, headers=second).json()
    assert a["total"] == listed["total"]
