"""
Weekly report: scheduler tick (baseline, idempotency, concurrency, stale claims),
report content (LOW/MEDIUM workbook only, HIGH/CRITICAL counted + listed), the
optional email, and the engineer / client APIs.

Time is frozen by passing `now` explicitly. Period under test: 2026-W45 =
Mon 2026-11-02 00:00 JST .. Mon 2026-11-09 00:00 JST (exclusive).
"""
import asyncio
import base64
import io
import os
import time
from datetime import datetime, timedelta
import aiosqlite
import pytest
from fastapi.testclient import TestClient
from openpyxl import load_workbook
from ai_fakes import sample_output
from src.config import settings
from src.main import app
from src.models.email_message import EmailMessage
from src.models.normalized_alert import NormalizedAlert
from src.models.pipeline_result import PipelineResult
from src.services import email_dispatcher, email_outbox, output_writer
from src.services import weekly_report as wr
from src.services.client_fields import REGISTRY, WEEKLY_FIELDS
from src.storage import (job_store, recommendation_store, runtime_settings, settings_store,
                         weekly_report_store as store)
from src.utils.jst_time import JST

ENGINEER_KEY = "engineer-key-0123456789abcdef"
NOW = datetime(2026, 11, 9, 9, 30, tzinfo=JST)          # due slot Mon 09:00 -> period 2026-W45
KEY = "2026-W45"
IN_PERIOD = datetime(2026, 11, 4, 12, 0, tzinfo=JST)


@pytest.fixture(autouse=True)
async def clean_deliveries(monkeypatch):
    """conftest does not wipe email_deliveries (the queue guard keys on it), and the
    env defaults below must not leak in from a developer's .env."""
    for attr, value in (("weekly_report_enabled", False), ("weekly_report_weekday", "MON"),
                        ("weekly_report_time", "09:00"), ("weekly_report_emails", ""),
                        ("client_notification_emails", ""), ("client_portal_url", ""),
                        ("email_attachments_enabled", False), ("client_portal_enabled", False),
                        ("weekly_report_max_findings_listed", 50)):
        monkeypatch.setattr(settings, attr, value)
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("DELETE FROM email_deliveries")
        await conn.commit()
    yield


async def add_alert(cid: str, risk: str, received: datetime, *, summary: str | None = None,
                    detection: str = "Win32/Test", endpoint: str = "PC-01") -> None:
    if await job_store.get_job(cid) is None:
        await job_store.create_job(cid, "WEBHOOK", {"k": cid})
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("UPDATE jobs SET created_at = ? WHERE correlation_id = ?",
                           (received.timestamp(), cid))
        await conn.commit()
    overrides = {"alert_summary_ja": summary} if summary is not None else {}
    await output_writer.write_result(PipelineResult(
        correlation_id=cid, source="WEBHOOK",
        received_at=received.isoformat(), processed_at=received.isoformat(),
        pipeline_status="SUCCESS",
        normalized_alert=NormalizedAlert(detection_name=detection, endpoint_name=endpoint),
        risk_level=risk, risk_rationale="r",
        ai_output=sample_output(risk, detection, **overrides),
    ))


async def enable(email: bool = False) -> None:
    await runtime_settings.set("weekly_report_enabled", True)
    if email:
        await runtime_settings.set("weekly_report_email_enabled", True)


async def past_baseline() -> None:
    """Makes the table non-empty so the first-enable baseline does not apply."""
    p = wr.period_from_key("2026-W40")
    await store.record_skipped(p.key, p.start_epoch, p.end_epoch, "baseline", "test")


def read_xlsx(path_or_bytes) -> list[list[str]]:
    src = io.BytesIO(path_or_bytes) if isinstance(path_or_bytes, bytes) else path_or_bytes
    ws = load_workbook(src).worksheets[0]
    return [[c if c is not None else "" for c in row] for row in ws.iter_rows(values_only=True)]


# ------------------------------------------------------------------ scheduler

async def test_tick_does_nothing_while_disabled():
    assert (await wr.tick(NOW))["action"] == "disabled"
    assert await store.count() == 0


async def test_first_enable_records_baseline_then_reports_next_week():
    await enable()
    await add_alert("low1", "LOW", IN_PERIOD)
    res = await wr.tick(NOW)
    assert res["action"] == "baseline" and res["period_key"] == KEY
    row = await store.get(KEY)
    assert row["status"] == store.SKIPPED and row["trigger"] == "baseline"
    assert not os.path.exists(wr.report_path(KEY))
    assert (await wr.tick(NOW))["action"] == "none"
    # next Monday 09:00 the following week is reported
    await add_alert("low2", "LOW", IN_PERIOD + timedelta(days=7))
    res = await wr.tick(NOW + timedelta(days=7))
    assert res["action"] == "generated" and res["period_key"] == "2026-W46"
    assert os.path.isfile(wr.report_path("2026-W46"))


async def test_sequential_ticks_generate_once():
    await enable()
    await past_baseline()
    await add_alert("low1", "LOW", IN_PERIOD)
    first = await wr.tick(NOW)
    assert first["due"] and first["action"] == "generated" and first["status"] == store.GENERATED
    second = await wr.tick(NOW + timedelta(minutes=1))
    assert second["action"] == "none" and second["status"] == store.GENERATED
    row = await store.get(KEY)
    assert row["attempts"] == 1 and row["trigger"] == "scheduled"
    # not due before the slot: Monday 08:59 JST still points at the previous period
    assert (await wr.tick(datetime(2026, 11, 9, 8, 59, tzinfo=JST)))["period_key"] == "2026-W44"


async def test_concurrent_ticks_produce_one_report_and_one_email():
    await enable(email=True)
    await settings_store.update_recipients({"weekly_report_emails": "w@example.jp"})
    await past_baseline()
    await add_alert("low1", "LOW", IN_PERIOD)
    results = await asyncio.gather(wr.tick(NOW), wr.tick(NOW), wr.tick(NOW))
    assert sorted(r["action"] for r in results) == ["none", "none", "queued"]
    outbox = await email_outbox.list_emails()
    assert [e["email_id"] for e in outbox] == [f"weekly-report-{KEY}"]
    assert os.listdir(os.path.dirname(wr.report_path(KEY))) == [f"{KEY}.xlsx"]
    assert len(await store.list_reports()) == 2   # baseline + this one


async def test_concurrent_ticks_on_first_enable_record_one_baseline():
    await enable()
    results = await asyncio.gather(wr.tick(NOW), wr.tick(NOW))
    assert sorted(r["action"] for r in results) == ["baseline", "none"]
    assert await store.count() == 1


async def test_stale_claim_is_recovered_but_a_fresh_one_is_left_alone():
    await enable()
    await past_baseline()
    await add_alert("low1", "LOW", IN_PERIOD)
    p = wr.period_from_key(KEY)
    assert await store.claim(KEY, p.start_epoch, p.end_epoch, "scheduled")
    assert not await store.claim(KEY, p.start_epoch, p.end_epoch, "scheduled")
    assert (await wr.tick(NOW))["action"] == "none"          # someone is working on it
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("UPDATE weekly_reports SET claimed_at = ? WHERE period_key = ?",
                           (time.time() - store.STALE_CLAIM_SECONDS - 5, KEY))
        await conn.commit()
    res = await wr.tick(NOW)
    assert res["action"] == "generated"
    assert (await store.get(KEY))["attempts"] == 2


async def test_failed_run_is_recorded_and_retried_a_bounded_number_of_times(monkeypatch):
    await enable()
    await past_baseline()

    async def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(wr, "build_content", boom)
    for attempt in range(1, wr.MAX_AUTO_ATTEMPTS + 1):
        res = await wr.tick(NOW)
        assert res["action"] == "failed" and "disk on fire" in res["error"]
        row = await store.get(KEY)
        assert row["status"] == store.FAILED and row["attempts"] == attempt
    assert (await wr.tick(NOW))["action"] == "none"            # gave up
    monkeypatch.undo()
    # a manual run still can
    assert (await wr.generate_report(KEY, trigger="manual"))["action"] == "generated"


# ------------------------------------------------------------------ content

async def test_zero_alert_week_is_recorded_without_a_file():
    await enable()
    await past_baseline()
    await add_alert("hi1", "HIGH", IN_PERIOD)
    res = await wr.tick(NOW)
    assert res["action"] == "generated" and res["has_file"] is False
    row = await store.get(KEY)
    assert row["status"] == store.GENERATED and row["file_path"] is None
    assert row["counts"]["low_medium"] == 0 and row["counts"]["HIGH"] == 1
    assert row["counts"]["file_omitted_reason"] == wr.FILE_OMITTED_NO_ALERTS
    assert not os.path.exists(wr.report_path(KEY))


async def test_completely_empty_week_counts_zero():
    res = await wr.generate_report(KEY, trigger="manual")
    assert res["counts"]["total"] == 0 and res["has_file"] is False
    assert (await store.get(KEY))["findings"] == []


async def test_high_critical_counted_and_listed_but_not_in_workbook():
    await enable()
    await past_baseline()
    p = wr.period_from_key(KEY)
    await add_alert("low1", "LOW", IN_PERIOD)
    await add_alert("med1", "MEDIUM", IN_PERIOD + timedelta(hours=1))
    await add_alert("hi1", "HIGH", IN_PERIOD + timedelta(hours=2), detection="Trojan.X",
                    summary="あ" * 500)
    await add_alert("crit1", "CRITICAL", IN_PERIOD + timedelta(hours=3), detection="Ransom.Y")
    await recommendation_store.create("hi1", "isolate the PC", "eng")
    await recommendation_store.create("low1", "update signatures", "eng")
    # boundaries: start inclusive, end exclusive, previous week excluded
    await add_alert("edge_start", "LOW", p.start)
    await add_alert("edge_end", "LOW", p.end)
    await add_alert("prev_week", "MEDIUM", p.start - timedelta(seconds=1))

    res = await wr.tick(NOW)
    assert res["action"] == "generated"
    row = await store.get(KEY)
    c = row["counts"]
    assert (c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"]) == (1, 1, 1, 2)
    assert c["high_risk"] == 2 and c["low_medium"] == 3 and c["rows_in_file"] == 3
    assert row["file_sha256"] and len(row["file_sha256"]) == 64

    findings = row["findings"]
    assert [f["alert_id"] for f in findings] == ["crit1", "hi1"]           # CRITICAL first
    hi = findings[1]
    assert hi["risk_level"] == "HIGH" and hi["detection_name"] == "Trojan.X"
    assert hi["endpoint_name"] == "PC-01" and hi["recommendation_count"] == 1
    assert len(hi["ai_summary"]) <= 200 and hi["ai_summary"].endswith("…")
    assert hi["received_at_jst"] == "2026-11-04 14:00 JST"

    rows = read_xlsx(wr.report_path(KEY))
    assert rows[0] == [REGISTRY[k].label_ja for k in WEEKLY_FIELDS]       # only WEEKLY_FIELDS
    ids = [r[WEEKLY_FIELDS.index("alert_id")] for r in rows[1:]]
    assert ids == ["edge_start", "low1", "med1"]
    assert not {"hi1", "crit1", "edge_end", "prev_week"} & set(ids)
    recs = rows[1 + ids.index("low1")][WEEKLY_FIELDS.index("engineer_recommendations")]
    assert "update signatures" in recs


async def test_retried_alert_is_counted_once():
    await add_alert("retry1", "LOW", IN_PERIOD)
    await add_alert("retry1", "MEDIUM", IN_PERIOD)   # pipeline retry overwrites the index row
    res = await wr.generate_report(KEY)
    assert res["counts"]["total"] == 1 and res["counts"]["MEDIUM"] == 1
    assert len(read_xlsx(wr.report_path(KEY))) == 2   # header + one row


async def test_findings_listed_are_capped_but_all_counted():
    await runtime_settings.set("weekly_report_max_findings_listed", 1)
    await add_alert("h1", "HIGH", IN_PERIOD)
    await add_alert("h2", "HIGH", IN_PERIOD + timedelta(hours=1))
    await add_alert("c1", "CRITICAL", IN_PERIOD + timedelta(hours=2))
    res = await wr.generate_report(KEY)
    row = await store.get(KEY)
    assert [f["alert_id"] for f in row["findings"]] == ["c1"]
    assert res["counts"]["findings_total"] == 3 and res["counts"]["findings_listed"] == 1


async def test_low_medium_alerts_are_paged_without_a_cap(monkeypatch):
    monkeypatch.setattr(wr, "PAGE_SIZE", 2)
    for i in range(5):
        await add_alert(f"l{i}", "LOW", IN_PERIOD + timedelta(minutes=i))
    res = await wr.generate_report(KEY)
    assert res["counts"]["rows_in_file"] == 5
    assert len(read_xlsx(wr.report_path(KEY))) == 6


# ------------------------------------------------------------------ email

async def test_email_is_off_by_default():
    await enable()
    await past_baseline()
    await settings_store.update_recipients({"client_notification_emails": "c@example.jp"})
    await add_alert("low1", "LOW", IN_PERIOD)
    res = await wr.tick(NOW)
    assert res["action"] == "generated" and res["email_id"] is None
    assert await email_outbox.list_emails() == []
    row = await store.get(KEY)
    assert row["status"] == store.GENERATED and row["email_id"] is None


async def test_email_on_queues_one_message_with_summary_and_no_attachment_by_default():
    await enable(email=True)
    await past_baseline()
    await settings_store.update_recipients({"client_notification_emails": "c1@example.jp, c2@example.jp"})
    await runtime_settings.set("client_portal_url", "https://portal.example.jp/")
    await add_alert("low1", "LOW", IN_PERIOD)
    await add_alert("crit1", "CRITICAL", IN_PERIOD, detection="Ransom.Y", endpoint="SRV-9")
    res = await wr.tick(NOW)
    assert res["action"] == "queued" and res["email_id"] == f"weekly-report-{KEY}"
    [mail] = await email_outbox.list_emails()
    msg = EmailMessage(**mail)
    assert msg.to == ["c1@example.jp", "c2@example.jp"]       # falls back to client recipients
    assert msg.notification_type == wr.NOTIFICATION_TYPE
    assert msg.correlation_id == msg.email_id == f"weekly-report-{KEY}"
    assert KEY in msg.subject and "週次" in msg.subject
    assert "2026年11月02日" in msg.body and "2026年11月08日" in msg.body
    assert "weekly ESET SOC Lite alert report" in msg.body
    assert "Ransom.Y" in msg.body and "SRV-9" in msg.body and "crit1" in msg.body
    assert "https://portal.example.jp" in msg.body and "ダウンロード" in msg.body
    assert msg.attachments == []                               # attachments off by default
    assert msg.html and "Ransom.Y" in msg.html
    row = await store.get(KEY)
    assert row["status"] == store.QUEUED and row["recipients"] == ["c1@example.jp", "c2@example.jp"]
    assert row["attachment_included"] is False


async def test_weekly_recipients_override_client_recipients():
    await enable(email=True)
    await settings_store.update_recipients({"client_notification_emails": "c@example.jp",
                                            "weekly_report_emails": "w@example.jp"})
    await wr.generate_report(KEY)
    [mail] = await email_outbox.list_emails()
    assert mail["to"] == ["w@example.jp"]


@pytest.mark.parametrize("max_bytes, attached", [(25_000_000, True), (1024, False)])
async def test_attachment_gated_by_runtime_settings_and_size(max_bytes, attached):
    await enable(email=True)
    await settings_store.update_recipients({"weekly_report_emails": "w@example.jp"})
    await runtime_settings.set("email_attachments_enabled", True)
    await runtime_settings.set("email_attachment_max_bytes", max_bytes)
    await add_alert("low1", "LOW", IN_PERIOD)
    await wr.generate_report(KEY)
    [mail] = await email_outbox.list_emails()
    msg = EmailMessage(**mail)
    if attached:
        [att] = msg.attachments
        data = base64.b64decode(att.content_base64)
        with open(wr.report_path(KEY), "rb") as f:
            assert data == f.read()
        assert att.size_bytes == len(data) and att.filename == f"weekly_report_{KEY}.xlsx"
        assert "添付" in msg.body
    else:
        assert msg.attachments == [] and "ファイルサイズが大きいため" in msg.body
    assert (await store.get(KEY))["attachment_included"] is attached


async def test_attachment_over_the_mail_service_limits_falls_back_to_the_portal(monkeypatch):
    """
    email_attachment_max_bytes is operator-set (up to 25 MB) but the mail service
    rejects a stored email over ~1.9 MB. The report must still go out, without
    the file, instead of being dead-lettered at handoff.
    """
    from src.services.email_delivery import limits
    monkeypatch.setattr(limits, "MAX_STORED_EMAIL_BYTES", 5_000)   # smaller than any workbook
    await enable(email=True)
    await settings_store.update_recipients({"weekly_report_emails": "w@example.jp"})
    await runtime_settings.set("email_attachments_enabled", True)
    await runtime_settings.set("email_attachment_max_bytes", 25_000_000)
    await add_alert("low1", "LOW", IN_PERIOD)
    await wr.generate_report(KEY)
    [mail] = await email_outbox.list_emails()
    msg = EmailMessage(**mail)
    assert msg.attachments == [] and "ファイルサイズが大きいため" in msg.body
    assert (await store.get(KEY))["attachment_included"] is False


async def test_no_recipients_marks_the_run_and_queues_nothing():
    await enable(email=True)
    await settings_store.update_recipients({"weekly_report_emails": "", "client_notification_emails": ""})
    await add_alert("low1", "LOW", IN_PERIOD)
    res = await wr.generate_report(KEY)
    assert res["action"] == "no_recipients"
    row = await store.get(KEY)
    assert row["status"] == store.NO_RECIPIENTS and "no recipients" in row["error"]
    assert os.path.isfile(wr.report_path(KEY))                 # the archive still exists
    assert await email_outbox.list_emails() == []


async def test_regenerate_overwrites_archive_and_requeues_with_suffix():
    await enable(email=True)
    await settings_store.update_recipients({"weekly_report_emails": "w@example.jp"})
    await add_alert("low1", "LOW", IN_PERIOD)
    assert (await wr.generate_report(KEY))["action"] == "queued"
    assert (await wr.generate_report(KEY))["action"] == "none"            # idempotent
    await add_alert("low2", "LOW", IN_PERIOD + timedelta(hours=1))
    res = await wr.generate_report(KEY, regenerate=True)
    assert res["action"] == "queued" and res["email_id"] == f"weekly-report-{KEY}-r1"
    assert [e["email_id"] for e in await email_outbox.list_emails()] == \
        [f"weekly-report-{KEY}", f"weekly-report-{KEY}-r1"]
    assert len(read_xlsx(wr.report_path(KEY))) == 3
    assert (await store.get(KEY))["resend_count"] == 1


async def test_regenerate_without_email_queues_nothing():
    await add_alert("low1", "LOW", IN_PERIOD)
    await wr.generate_report(KEY)
    res = await wr.generate_report(KEY, regenerate=True)
    assert res["action"] == "generated" and await email_outbox.list_emails() == []
    assert (await store.get(KEY))["resend_count"] == 0


async def test_dispatcher_reports_no_pipeline_stage_for_weekly_report(monkeypatch):
    stages = []

    async def record_stage(cid, stage, state, detail=None, **extra):
        stages.append((cid, stage, state))

    class OkProvider:
        async def send(self, message):
            class R:
                success, remote_id, retryable, error = True, "r1", False, None
            return R()

    monkeypatch.setattr(email_dispatcher.events, "emit_stage", record_stage)
    common = dict(to=["a@example.jp"], subject="s", body="b", risk_level="LOW", created_at="x")
    weekly = EmailMessage(email_id="weekly-report-2026-W45", correlation_id="weekly-report-2026-W45",
                          notification_type="WEEKLY_REPORT_JA", **common)
    alert = EmailMessage(email_id="c1-CLIENT_JA", correlation_id="c1",
                         notification_type="CLIENT_JA", **common)
    await email_outbox.add_emails([weekly, alert])
    assert await email_dispatcher._hand_off(OkProvider(), weekly) == "accepted"
    assert await email_dispatcher._hand_off(OkProvider(), alert) == "accepted"
    assert stages == [("c1", "SEND", "ok")]


# ------------------------------------------------------------------ engineer API

@pytest.fixture
def engineer(monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", ENGINEER_KEY)
    # The run endpoint refuses weeks that have not ended; freeze its clock at NOW
    # (after 2026-W45) so these tests do not depend on the real date.
    from src.api import reports as reports_api
    monkeypatch.setattr(reports_api, "_now", lambda: NOW.timestamp())
    return {"X-Dashboard-Key": ENGINEER_KEY}


async def test_engineer_run_refuses_a_week_that_has_not_ended(engineer, monkeypatch):
    """Regression: a manual run of the current (or a future) week archived a partial
    report and recorded the period as done, so the scheduler never produced the
    complete one when it fell due."""
    from src.api import reports as reports_api
    client = TestClient(app)
    await add_alert("low1", "LOW", IN_PERIOD)
    monkeypatch.setattr(reports_api, "_now", lambda: IN_PERIOD.timestamp())   # inside 2026-W45
    for key in (KEY, "2027-W10"):
        res = client.post("/dashboard/api/reports/weekly/run", json={"period_key": key}, headers=engineer)
        assert res.status_code == 400 and "has not ended" in res.json()["detail"], res.text
        res = client.post("/dashboard/api/reports/weekly/run",
                          json={"period_key": key, "regenerate": True}, headers=engineer)
        assert res.status_code == 400
    assert await store.count() == 0 and not os.path.exists(wr.report_path(KEY))
    # preview of the unfinished week is still allowed (nothing is stored)
    assert client.get(f"/dashboard/api/reports/weekly/preview?period_key={KEY}",
                      headers=engineer).status_code == 200
    # once the week is over the scheduler produces it normally
    await enable()
    await past_baseline()
    res = await wr.tick(NOW)
    assert res["action"] == "generated" and res["period_key"] == KEY and res["counts"]["LOW"] == 1


@pytest.mark.parametrize("method, path", [
    ("GET", "/dashboard/api/reports/weekly"),
    ("GET", "/dashboard/api/reports/weekly/preview"),
    ("POST", "/dashboard/api/reports/weekly/run"),
    ("GET", f"/dashboard/api/reports/weekly/{KEY}/download"),
])
async def test_engineer_routes_require_the_dashboard_key(engineer, method, path):
    client = TestClient(app)
    assert client.request(method, path).status_code == 401
    assert client.request(method, path, headers={"X-Dashboard-Key": "wrong"}).status_code == 401
    assert await store.count() == 0


async def test_engineer_api_overview_run_download_preview(engineer):
    client = TestClient(app)
    await add_alert("low1", "LOW", IN_PERIOD)
    await add_alert("hi1", "HIGH", IN_PERIOD)

    body = client.get("/dashboard/api/reports/weekly", headers=engineer).json()
    assert body["enabled"] is False and body["email_enabled"] is False
    assert body["schedule"] == {"weekday": "MON", "time": "09:00", "timezone": "JST"}
    assert body["next_run_at"].endswith("+09:00") and "period_key" in body["next_period"]
    assert body["reports"] == []

    # preview: a workbook, nothing stored
    res = client.get(f"/dashboard/api/reports/weekly/preview?period_key={KEY}", headers=engineer)
    assert res.status_code == 200 and res.headers["x-report-rows"] == "1"
    assert len(read_xlsx(res.content)) == 2
    assert await store.count() == 0 and not os.path.exists(wr.report_path(KEY))
    assert client.get("/dashboard/api/reports/weekly/preview?period_key=../x",
                      headers=engineer).status_code == 400

    res = client.post("/dashboard/api/reports/weekly/run", json={"period_key": KEY}, headers=engineer)
    assert res.status_code == 200, res.text
    out = res.json()
    assert out["action"] == "generated" and out["report"]["status"] == store.GENERATED
    assert out["report"]["has_file"] is True and out["report"]["counts"]["HIGH"] == 1
    assert [f["alert_id"] for f in out["report"]["findings"]] == ["hi1"]
    assert "file_path" not in out["report"]
    again = client.post("/dashboard/api/reports/weekly/run", json={"period_key": KEY}, headers=engineer)
    assert again.json()["action"] == "none"

    hist = client.get("/dashboard/api/reports/weekly", headers=engineer).json()["reports"]
    assert [r["period_key"] for r in hist] == [KEY]
    assert hist[0]["period_start"] == "2026-11-02T00:00:00+09:00"

    dl = client.get(f"/dashboard/api/reports/weekly/{KEY}/download", headers=engineer)
    assert dl.status_code == 200 and dl.headers["cache-control"] == "no-store"
    assert "attachment" in dl.headers["content-disposition"]
    assert len(read_xlsx(dl.content)) == 2
    assert client.get("/dashboard/api/reports/weekly/2026-W44/download",
                      headers=engineer).status_code == 404
    assert client.get("/dashboard/api/reports/weekly/..%2Fsecret/download",
                      headers=engineer).status_code in (400, 404)
    assert client.post("/dashboard/api/reports/weekly/run", json={"period_key": "nope"},
                       headers=engineer).status_code == 400


async def test_engineer_run_without_body_uses_latest_due_period(engineer):
    client = TestClient(app)
    res = client.post("/dashboard/api/reports/weekly/run", headers=engineer)
    assert res.status_code == 200, res.text
    expected = (await wr.latest_due_period()).key
    assert res.json()["period_key"] == expected


# ------------------------------------------------------------------ client API

@pytest.fixture
def portal(monkeypatch, engineer):
    monkeypatch.setattr(settings, "client_portal_enabled", True)


async def _client_session() -> dict[str, str]:
    from src.storage import user_store
    user = await user_store.create_user("weekly.client", "correct horse battery")
    token, _ = await user_store.create_session(user["id"], "testclient")
    return {"X-Client-Session": token}


@pytest.mark.parametrize("path", ["/client/api/reports", f"/client/api/reports/{KEY}/download"])
async def test_client_routes_require_a_session(portal, engineer, path):
    client = TestClient(app)
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"X-Client-Session": "bogus"}).status_code == 401
    assert client.get(path, headers=engineer).status_code == 401       # dashboard key is not a session


async def test_client_lists_and_downloads_generated_reports(portal):
    client = TestClient(app)
    headers = await _client_session()
    await past_baseline()                                    # SKIPPED: not shown to the client
    await add_alert("low1", "LOW", IN_PERIOD)
    await wr.generate_report(KEY)
    await wr.generate_report("2026-W44")                       # empty week: listed, no file

    body = client.get("/client/api/reports", headers=headers).json()
    assert [r["period_key"] for r in body["reports"]] == [KEY, "2026-W44"]
    r = body["reports"][0]
    assert r["has_file"] is True and r["counts"]["LOW"] == 1
    assert r["period_start"] == "2026-11-02T00:00:00+09:00" and r["period_end"] == "2026-11-09T00:00:00+09:00"
    assert set(r) == {"period_key", "period_start", "period_end", "last_day", "timezone",
                      "generated_at", "counts", "has_file"}
    assert body["reports"][1]["has_file"] is False

    dl = client.get(f"/client/api/reports/{KEY}/download", headers=headers)
    assert dl.status_code == 200 and dl.headers["cache-control"] == "no-store"
    assert dl.headers["content-disposition"].startswith("attachment")
    assert len(read_xlsx(dl.content)) == 2
    for bad in ("2026-W44", "2026-W40", "2026-W45-r1x", "..%2F..%2Fetc", "2099-W01"):
        assert client.get(f"/client/api/reports/{bad}/download", headers=headers).status_code == 404
