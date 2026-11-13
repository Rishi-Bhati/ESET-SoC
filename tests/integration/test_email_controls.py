"""
Email sending controls (dashboard "Email sending" panel, runtime_settings group
"email") and the client recommendation emails.

  * the master switch (email_delivery_enabled) is a dashboard override of
    EMAIL_DELIVERY_ENABLED: off keeps emails in the outbox, on hands them off;
    it cannot be switched on without a configured mail service (409);
  * per-alert switches for the four audiences, and client_immediate_min_risk
    for the client notification and its C-Three copy;
  * recommendation emails: off by default, then one email per added
    recommendation and a withdrawal email when an emailed one is retracted;
  * the weekly report history reports what became of its email.
"""
import aiosqlite
import pytest
from fastapi.testclient import TestClient

from ai_fakes import sample_output
from src.config import settings
from src.main import app
from src.models.normalized_alert import NormalizedAlert
from src.models.pipeline_result import PipelineResult
from src.services import email_composer, email_dispatcher, email_outbox, output_writer
from src.services.email_delivery.base import DeliveryResult
from src.storage import delivery_store, job_store, runtime_settings, settings_store

KEY = "engineer-key-0123456789abcdef"
H = {"X-Dashboard-Key": KEY}


@pytest.fixture(autouse=True)
async def setup(monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", KEY)
    for attr, value in (("client_notification_emails", "client@example.com"),
                        ("cthree_notification_emails", "cthree@example.com"),
                        ("internal_notification_emails", "internal@example.com"),
                        ("engineer_notification_emails", "eng@example.com"),
                        ("recommendation_notification_emails", ""), ("client_portal_url", ""),
                        ("client_immediate_min_risk", "LOW")):
        monkeypatch.setattr(settings, attr, value)
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("DELETE FROM email_deliveries")
        await conn.commit()
    # Never schedule a real handoff from the API calls in these tests.
    from src.services import recommendation_notifier
    monkeypatch.setattr(recommendation_notifier, "dispatch_soon", lambda: None)
    yield


def _result(risk: str, cid: str = "cid-1", ai: bool = True) -> PipelineResult:
    return PipelineResult(
        correlation_id=cid, source="WEBHOOK", received_at="2026-11-01T00:00:00Z",
        processed_at="2026-11-01T00:00:05Z", pipeline_status="SUCCESS",
        normalized_alert=NormalizedAlert(detection_name="Win32/Test.A", endpoint_name="PC-01", severity=risk),
        risk_level=risk, risk_rationale="r",
        ai_output=sample_output(risk, "Win32/Test.A") if ai else None,
    )


def _types(emails) -> list[str]:
    return [e.notification_type for e in emails]


# ------------------------------------------------------------------ alert email switches

async def test_every_alert_email_is_on_by_default():
    assert _types(await email_composer.compose_emails(_result("LOW"))) == [
        "CLIENT_JA", "CTHREE_JA", "INTERNAL_JA", "ENGINEER_EN"]


@pytest.mark.parametrize("switch, missing", [
    ("alert_email_client_enabled", "CLIENT_JA"), ("alert_email_cthree_enabled", "CTHREE_JA"),
    ("alert_email_internal_enabled", "INTERNAL_JA"), ("alert_email_engineer_enabled", "ENGINEER_EN"),
])
async def test_each_audience_can_be_switched_off(switch, missing):
    await runtime_settings.set(switch, False)
    types = _types(await email_composer.compose_emails(_result("HIGH")))
    assert missing not in types and len(types) == 3


async def test_team_switches_also_cover_the_ai_failure_notices():
    await runtime_settings.set("alert_email_engineer_enabled", False)
    assert _types(await email_composer.compose_fallback_emails(_result("HIGH", ai=False))) == ["INTERNAL_JA"]


@pytest.mark.parametrize("risk, client_sent", [("LOW", False), ("MEDIUM", False), ("HIGH", True), ("CRITICAL", True)])
async def test_client_minimum_risk_gates_client_and_cthree_only(risk, client_sent):
    await runtime_settings.set("client_immediate_min_risk", "HIGH")
    types = _types(await email_composer.compose_emails(_result(risk)))
    assert ("CLIENT_JA" in types) is client_sent and ("CTHREE_JA" in types) is client_sent
    assert "INTERNAL_JA" in types and "ENGINEER_EN" in types


# ------------------------------------------------------------------ master switch

class _OkProvider:
    name = "fake"
    sent: list = []

    def is_configured(self):
        return True, "ready"

    async def send(self, message):
        _OkProvider.sent.append(message.email_id)
        return DeliveryResult.ok("remote-1", 202)


async def test_master_switch_override_holds_and_releases_the_outbox(monkeypatch):
    monkeypatch.setattr(settings, "email_delivery_enabled", True)       # env says on
    monkeypatch.setattr(email_dispatcher, "get_provider", lambda: _OkProvider())
    _OkProvider.sent = []
    await email_outbox.add_emails(await email_composer.compose_emails(_result("HIGH")))

    await runtime_settings.set("email_delivery_enabled", False)        # dashboard says off
    assert (await email_dispatcher.dispatch_pending())["skipped"] == "delivery disabled"
    assert len(await email_outbox.list_emails()) == 4 and _OkProvider.sent == []
    assert (await email_dispatcher.delivery_status())["enabled"] is False

    await runtime_settings.set("email_delivery_enabled", True)
    assert (await email_dispatcher.dispatch_pending())["accepted"] == 4
    assert await email_outbox.list_emails() == [] and len(_OkProvider.sent) == 4


def test_master_switch_cannot_be_turned_on_without_a_mail_service(monkeypatch):
    monkeypatch.setattr(settings, "email_api_url", "")
    client = TestClient(app)
    res = client.put("/dashboard/api/portal-settings/email_delivery_enabled", json={"value": True}, headers=H)
    assert res.status_code == 409 and "EMAIL_API_URL" in res.json()["detail"]
    # switching off is always allowed
    assert client.put("/dashboard/api/portal-settings/email_delivery_enabled",
                      json={"value": False}, headers=H).status_code == 200


def test_email_switches_are_listed_for_the_dashboard():
    settings_list = TestClient(app).get("/dashboard/api/portal-settings", headers=H).json()["settings"]
    for key in ("email_delivery_enabled", "alert_email_client_enabled", "alert_email_cthree_enabled",
                "alert_email_internal_enabled", "alert_email_engineer_enabled", "client_immediate_min_risk",
                "recommendation_email_enabled", "email_attachments_enabled"):
        assert settings_list[key]["group"] == "email", key
    assert settings_list["recommendation_email_enabled"]["value"] is False


# ------------------------------------------------------------------ recommendation emails

async def _alert(cid: str = "alert-1", risk: str = "HIGH") -> str:
    await job_store.create_job(cid, "WEBHOOK", {"alert_id": cid})
    await output_writer.write_result(_result(risk, cid))
    return cid


def _add(client, cid, body="端末をネットワークから切り離してください。", author="engineer-a"):
    res = client.post(f"/dashboard/api/alerts/{cid}/recommendations", json={"body": body, "author": author}, headers=H)
    assert res.status_code == 201, res.text
    return res.json()


async def test_recommendation_email_is_off_by_default():
    client = TestClient(app)
    out = _add(client, await _alert())
    assert out["notification"] == {"queued": False, "email_id": None, "reason": "recommendation_email_disabled"}
    assert await email_outbox.list_emails() == []


async def test_recommendation_email_content_and_recipients():
    client = TestClient(app)
    cid = await _alert()
    await runtime_settings.set("recommendation_email_enabled", True)
    await runtime_settings.set("client_portal_url", "https://soc.example.com/client")
    out = _add(client, cid)
    rec = out["recommendation"]
    assert out["notification"] == {"queued": True, "email_id": f"rec-{rec['id']}", "reason": None}
    assert rec["notification_email_id"] == f"rec-{rec['id']}"

    [mail] = await email_outbox.list_emails()
    assert mail["notification_type"] == "RECOMMENDATION_JA" and mail["correlation_id"] == cid
    assert mail["to"] == ["client@example.com"], "blank recommendation list falls back to the client list"
    assert mail["subject"] == "【推奨対策】[HIGH] Win32/Test.A — PC-01"
    for text in ("端末をネットワークから切り離してください。", "engineer-a", "PC-01", cid,
                 f"https://soc.example.com/client/#/alerts/{cid}"):
        assert text in mail["body"] and text in mail["html"], text
    # The HTML escapes engineer-written text.
    assert (await delivery_store.get_delivery(mail["email_id"]))["status"] == "PENDING"

    # the dedicated list wins when set
    await settings_store.set_setting("recommendation_notification_emails", "advice@example.com")
    _add(client, cid, body="パスワードを変更してください。")
    assert (await email_outbox.list_emails())[1]["to"] == ["advice@example.com"]


async def test_recommendation_html_is_escaped():
    client = TestClient(app)
    cid = await _alert()
    await runtime_settings.set("recommendation_email_enabled", True)
    _add(client, cid, body="<script>alert(1)</script> & check")
    [mail] = await email_outbox.list_emails()
    assert "<script>" not in mail["html"] and "&lt;script&gt;" in mail["html"]


async def test_no_recipients_means_no_email():
    client = TestClient(app)
    cid = await _alert()
    await runtime_settings.set("recommendation_email_enabled", True)
    await settings_store.set_setting("client_notification_emails", "")
    out = _add(client, cid)
    assert out["notification"]["reason"] == "no_recipients" and await email_outbox.list_emails() == []


async def test_retracting_an_emailed_recommendation_sends_a_withdrawal_once():
    client = TestClient(app)
    cid = await _alert()
    await runtime_settings.set("recommendation_email_enabled", True)
    rec = _add(client, cid)["recommendation"]
    res = client.post(f"/dashboard/api/recommendations/{rec['id']}/retract",
                      json={"author": "engineer-b", "reason": "社内メモ: 誤った端末"}, headers=H)
    assert res.status_code == 200
    assert res.json()["notification"] == {"queued": True, "email_id": f"rec-{rec['id']}-retracted", "reason": None}
    mails = await email_outbox.list_emails()
    withdrawn = mails[1]
    assert withdrawn["notification_type"] == "RECOMMENDATION_RETRACTED_JA"
    assert withdrawn["subject"].startswith("【推奨対策の取り下げ】")
    assert "社内メモ" not in withdrawn["body"], "the retraction reason is internal"
    again = client.post(f"/dashboard/api/recommendations/{rec['id']}/retract",
                        json={"author": "engineer-b"}, headers=H)
    assert again.json()["notification"]["reason"] == "already_retracted"
    assert len(await email_outbox.list_emails()) == 2


async def test_retracting_a_recommendation_that_was_never_emailed_sends_nothing():
    client = TestClient(app)
    cid = await _alert()
    rec = _add(client, cid)["recommendation"]                 # emails were off
    await runtime_settings.set("recommendation_email_enabled", True)
    res = client.post(f"/dashboard/api/recommendations/{rec['id']}/retract", json={"author": "b"}, headers=H)
    assert res.json()["notification"]["reason"] == "never_emailed" and await email_outbox.list_emails() == []


async def test_recommendation_emails_hand_off_without_a_pipeline_stage(monkeypatch):
    stages = []

    async def fake_stage(*args, **kwargs):
        stages.append(args)
    monkeypatch.setattr(settings, "email_delivery_enabled", True)
    monkeypatch.setattr(email_dispatcher, "get_provider", lambda: _OkProvider())
    client = TestClient(app)
    cid = await _alert()
    monkeypatch.setattr(email_dispatcher.events, "emit_stage", fake_stage)
    await runtime_settings.set("recommendation_email_enabled", True)
    rec = _add(client, cid)["recommendation"]
    assert (await email_dispatcher.dispatch_pending())["accepted"] == 1
    assert (await delivery_store.get_delivery(f"rec-{rec['id']}"))["status"] == "ACCEPTED"
    assert stages == [], "an old alert's pipeline lane is not reopened"


# ------------------------------------------------------------------ weekly history delivery status

async def test_weekly_history_shows_what_became_of_the_email(monkeypatch):
    from datetime import datetime
    from src.api import reports as reports_api
    from src.services import weekly_report as wr
    from src.utils.jst_time import JST
    monkeypatch.setattr(reports_api, "_now", lambda: datetime(2026, 11, 9, 10, tzinfo=JST).timestamp())
    monkeypatch.setattr(settings, "email_delivery_enabled", True)
    monkeypatch.setattr(email_dispatcher, "get_provider", lambda: _OkProvider())
    await runtime_settings.set("weekly_report_email_enabled", True)
    client = TestClient(app)
    run = client.post("/dashboard/api/reports/weekly/run", json={"period_key": "2026-W45"}, headers=H).json()
    assert run["report"]["status"] == "QUEUED" and run["report"]["delivery_status"] == "PENDING"
    await email_dispatcher.dispatch_pending()
    row = client.get("/dashboard/api/reports/weekly", headers=H).json()["reports"][0]
    assert row["status"] == "QUEUED" and row["delivery_status"] == "ACCEPTED"
