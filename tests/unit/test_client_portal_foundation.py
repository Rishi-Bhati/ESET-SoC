"""Foundation for the client portal: schema, runtime settings, recommendation store,
recipient settings, EmailMessage compatibility, and the (empty) new routers."""
import json
import os
import aiosqlite
import pytest
from fastapi.testclient import TestClient

from src.config import settings, reports_dir
from src.models.email_message import EmailAttachment, EmailMessage
from src.storage import recommendation_store, runtime_settings, settings_store
from src.storage.database import init_db


# ------------------------------ schema ------------------------------

NEW_TABLES = {"client_users", "client_sessions", "alert_index", "alert_recommendations", "weekly_reports"}


async def _tables() -> set[str]:
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            return {r[0] async for r in cur}


async def test_init_db_is_idempotent_and_keeps_data():
    await init_db()
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("INSERT INTO app_settings (key, value) VALUES ('keep', 'me')")
        await conn.commit()
    await init_db()
    await init_db()
    assert NEW_TABLES <= await _tables()
    assert await settings_store.get_setting("keep") == "me"


async def test_client_user_constraints_and_session_cascade():
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute(
            "INSERT INTO client_users (id, username, password_hash, created_at) VALUES ('u1', 'Alice', 'h', 1)")
        with pytest.raises(aiosqlite.IntegrityError):  # username unique, case-insensitive
            await conn.execute(
                "INSERT INTO client_users (id, username, password_hash, created_at) VALUES ('u2', 'ALICE', 'h', 1)")
        with pytest.raises(aiosqlite.IntegrityError):  # role fixed to 'client'
            await conn.execute(
                "INSERT INTO client_users (id, username, role, password_hash, created_at) "
                "VALUES ('u3', 'bob', 'admin', 'h', 1)")
        await conn.execute("INSERT INTO client_sessions (token_hash, user_id) VALUES ('t', 'u1')")
        await conn.execute("DELETE FROM client_users WHERE id = 'u1'")
        async with conn.execute("SELECT COUNT(*) FROM client_sessions") as cur:
            assert (await cur.fetchone())[0] == 0
        await conn.rollback()


# ------------------------------ config ------------------------------

def test_reports_dir_is_computed_at_call_time(monkeypatch):
    monkeypatch.setattr(settings, "output_dir", "/srv/data/alerts")
    assert reports_dir() == "/srv/data/reports"
    monkeypatch.setattr(settings, "output_dir", "/other/alerts")
    assert reports_dir() == "/other/reports"


def test_reports_dir_is_in_the_test_temp_tree():
    assert os.path.dirname(reports_dir()) == os.path.dirname(settings.output_dir)
    assert os.path.isdir(reports_dir())


# -------------------------- runtime settings --------------------------

async def test_runtime_defaults_come_from_config():
    assert await runtime_settings.get("client_portal_enabled") is False
    assert await runtime_settings.get("client_session_idle_minutes") == 60
    assert await runtime_settings.get("weekly_report_weekday") == "MON"
    assert await runtime_settings.get("weekly_report_time") == "09:00"
    assert await runtime_settings.get("client_immediate_min_risk") == "LOW"
    assert await runtime_settings.get("email_attachment_max_bytes") == 1_000_000


async def test_runtime_db_overrides_env_and_reset_restores(monkeypatch):
    monkeypatch.setattr(settings, "client_session_idle_minutes", 45)
    assert await runtime_settings.get("client_session_idle_minutes") == 45
    await runtime_settings.set("client_session_idle_minutes", 10)
    assert await runtime_settings.get("client_session_idle_minutes") == 10
    # a live env change does not beat the dashboard override
    monkeypatch.setattr(settings, "client_session_idle_minutes", 99)
    assert await runtime_settings.get("client_session_idle_minutes") == 10
    assert await runtime_settings.reset("client_session_idle_minutes") is True
    assert await runtime_settings.get("client_session_idle_minutes") == 99
    assert await runtime_settings.reset("client_session_idle_minutes") is False


async def test_runtime_get_all_reports_source_and_constraints():
    await runtime_settings.set("weekly_report_enabled", True)
    allv = await runtime_settings.get_all()
    assert set(allv) == set(runtime_settings.REGISTRY)
    entry = allv["weekly_report_enabled"]
    assert entry["value"] is True and entry["default"] is False and entry["source"] == "db"
    assert entry["type"] == "bool"
    assert allv["client_session_idle_minutes"]["source"] == "env"
    assert allv["client_session_idle_minutes"]["constraints"] == {"min": 1, "max": 1440}
    assert allv["weekly_report_weekday"]["constraints"]["choices"][0] == "MON"


async def test_runtime_normalises_values():
    assert await runtime_settings.set("weekly_report_weekday", "fri") == "FRI"
    assert await runtime_settings.set("weekly_report_time", "9:05") == "09:05"
    assert await runtime_settings.set("client_immediate_min_risk", "high") == "HIGH"
    assert await runtime_settings.set("client_session_max_hours", "8") == 8
    assert await runtime_settings.set("email_attachments_enabled", "true") is True
    assert await runtime_settings.set("client_portal_url", " https://portal.example.jp/ ") == "https://portal.example.jp"
    assert await runtime_settings.get("weekly_report_time") == "09:05"


@pytest.mark.parametrize("key,value", [
    ("nope", 1),
    ("client_session_idle_minutes", 0),
    ("client_session_idle_minutes", "abc"),
    ("client_session_idle_minutes", True),
    ("client_session_idle_minutes", 1441),
    ("client_session_idle_minutes", 1.5),
    ("client_portal_enabled", "maybe"),
    ("client_portal_enabled", 1),
    ("weekly_report_weekday", "FUNDAY"),
    ("weekly_report_time", "24:00"),
    ("weekly_report_time", "9am"),
    ("weekly_report_time", "09:60"),
    ("client_immediate_min_risk", "SEVERE"),
    ("client_portal_url", "ftp://x"),
    ("client_portal_url", "javascript:alert(1)"),
    ("email_attachment_max_bytes", 10),
])
async def test_runtime_rejects_invalid_values_without_writing(key, value):
    with pytest.raises(ValueError):
        await runtime_settings.set(key, value)
    if key in runtime_settings.REGISTRY:
        assert await settings_store.get_setting("rt." + key) is None


async def test_runtime_reset_unknown_key_raises():
    with pytest.raises(ValueError):
        await runtime_settings.reset("nope")


async def test_runtime_bad_stored_or_env_value_falls_back(monkeypatch):
    await settings_store.set_setting("rt.client_session_idle_minutes", "garbage")
    assert await runtime_settings.get("client_session_idle_minutes") == 60
    assert (await runtime_settings.get_all())["client_session_idle_minutes"]["source"] == "env"
    monkeypatch.setattr(settings, "weekly_report_weekday", "someday")
    assert await runtime_settings.get("weekly_report_weekday") == "MON"


async def test_runtime_keys_do_not_collide_with_recipients():
    await runtime_settings.set("client_portal_url", "https://a.example")
    cfg = await settings_store.get_recipient_config()
    assert "rt.client_portal_url" not in cfg and "client_portal_url" not in cfg


def test_runtime_registry_covers_required_keys():
    assert set(runtime_settings.REGISTRY) == {
        "client_portal_enabled", "client_portal_url", "client_session_idle_minutes",
        "client_session_max_hours", "client_login_max_failures", "client_login_lockout_minutes",
        "client_login_account_max_failures", "client_login_account_decay_hours",
        "client_login_backstop_max_failures", "client_login_backstop_max_lock_hours",
        "client_export_max_alerts", "weekly_report_enabled", "weekly_report_weekday",
        "weekly_report_time", "weekly_report_check_interval_seconds",
        "weekly_report_max_findings_listed", "weekly_report_email_enabled",
        "email_attachments_enabled", "email_attachment_max_bytes", "client_immediate_min_risk",
    }


# ------------------------ recommendation store ------------------------

async def test_recommendation_create_get_list_and_counts():
    a = await recommendation_store.create("c1", "  Isolate the host  ", "alice")
    b = await recommendation_store.create("c1", "Reset credentials", "bob")
    c = await recommendation_store.create("c2", "Monitor", "alice")
    assert a["id"].startswith("rec_") and len(a["id"]) <= 24 and a["id"] != b["id"]
    assert a["body"] == "Isolate the host" and a["retracted_at"] is None
    assert await recommendation_store.get(a["id"]) == a
    assert await recommendation_store.get("missing") is None
    assert [r["id"] for r in await recommendation_store.list_for_alert("c1")] == [a["id"], b["id"]]
    assert await recommendation_store.counts(["c1", "c2", "c3"]) == {"c1": 2, "c2": 1, "c3": 0}
    grouped = await recommendation_store.list_for_alerts(["c1", "c2", "c3"])
    assert [r["id"] for r in grouped["c1"]] == [a["id"], b["id"]]
    assert [r["id"] for r in grouped["c2"]] == [c["id"]] and grouped["c3"] == []
    assert await recommendation_store.counts([]) == {}


async def test_recommendation_retract_hides_from_active_but_keeps_record():
    a = await recommendation_store.create("c1", "Do X", "alice")
    await recommendation_store.create("c1", "Do Y", "alice")
    done = await recommendation_store.retract(a["id"], "bob", "Wrong host")
    assert done["retracted_by"] == "bob" and done["retract_reason"] == "Wrong host" and done["retracted_at"]
    assert len(await recommendation_store.list_for_alert("c1")) == 1
    assert len(await recommendation_store.list_for_alert("c1", include_retracted=True)) == 2
    assert await recommendation_store.counts(["c1"]) == {"c1": 1}
    assert (await recommendation_store.list_for_alerts(["c1"]))["c1"][0]["body"] == "Do Y"
    # idempotent: the first retraction is kept
    again = await recommendation_store.retract(a["id"], "carol", "other")
    assert again["retracted_by"] == "bob"
    assert await recommendation_store.retract("missing", "bob", "") is None


async def test_recommendation_set_notification_email_id():
    a = await recommendation_store.create("c1", "Do X", "alice")
    await recommendation_store.set_notification_email_id(a["id"], "email-1")
    assert (await recommendation_store.get(a["id"]))["notification_email_id"] == "email-1"


@pytest.mark.parametrize("args", [("c1", "   ", "a"), ("c1", "x", " "), ("", "x", "a"),
                                  ("c1", "x" * 4001, "a")])
async def test_recommendation_create_validates(args):
    with pytest.raises(ValueError):
        await recommendation_store.create(*args)


async def test_recommendation_many_ids_chunked():
    ids = [f"c{i}" for i in range(1200)]
    await recommendation_store.create("c1199", "x", "a")
    counts = await recommendation_store.counts(ids)
    assert len(counts) == 1200 and counts["c1199"] == 1 and counts["c0"] == 0


# ------------------------------ recipients ------------------------------

def test_new_recipient_keys_round_trip(client: TestClient):
    body = client.get("/dashboard/api/settings").json()["recipients"]
    assert body["recommendation_notification_emails"] == {"value": "", "source": "env"}
    assert body["weekly_report_emails"]["source"] == "env"
    res = client.put("/dashboard/api/settings/recipients", json={
        "recommendation_notification_emails": "a@example.jp, b@example.jp",
        "weekly_report_emails": "weekly@example.jp",
    })
    assert res.status_code == 200
    body = client.get("/dashboard/api/settings").json()["recipients"]
    assert body["recommendation_notification_emails"] == {
        "value": "a@example.jp, b@example.jp", "source": "dashboard"}
    assert body["weekly_report_emails"] == {"value": "weekly@example.jp", "source": "dashboard"}
    assert client.put("/dashboard/api/settings/recipients",
                      json={"weekly_report_emails": "not-an-address"}).status_code == 422


def test_existing_recipient_updates_still_work_without_new_fields(client: TestClient):
    res = client.put("/dashboard/api/settings/recipients", json={"client_notification_emails": "c@example.jp"})
    assert res.status_code == 200


async def test_effective_with_fallback():
    await settings_store.update_recipients({"client_notification_emails": "client@example.jp"})
    assert await settings_store.get_effective_with_fallback(
        "weekly_report_emails", "client_notification_emails") == "client@example.jp"
    await settings_store.update_recipients({"weekly_report_emails": "w@example.jp"})
    assert await settings_store.get_effective_with_fallback(
        "weekly_report_emails", "client_notification_emails") == "w@example.jp"
    await settings_store.update_recipients({"weekly_report_emails": "   "})  # blank -> fallback again
    assert await settings_store.get_effective_with_fallback(
        "weekly_report_emails", "client_notification_emails") == "client@example.jp"


# ------------------------------ email model ------------------------------

_OLD_OUTBOX_ITEM = {
    "email_id": "e1", "correlation_id": "c1", "notification_type": "CLIENT_JA",
    "to": ["a@example.jp"], "subject": "s", "body": "b", "risk_level": "HIGH",
    "created_at": "2026-01-01T00:00:00Z", "status": "PENDING",
}


def test_email_message_without_attachments_field_still_loads():
    msg = EmailMessage(**_OLD_OUTBOX_ITEM)
    assert msg.attachments == []
    assert "attachments" in json.loads(msg.model_dump_json())


def test_email_message_attachment_round_trip():
    att = EmailAttachment(filename="r.xlsx", content_type="application/vnd.ms-excel",
                          content_base64="AAEC", size_bytes=3)
    msg = EmailMessage(**_OLD_OUTBOX_ITEM, attachments=[att])
    again = EmailMessage(**json.loads(msg.model_dump_json()))
    assert again.attachments == [att]
    assert EmailMessage(**_OLD_OUTBOX_ITEM).attachments is not EmailMessage(**_OLD_OUTBOX_ITEM).attachments


# ------------------------------ routers ------------------------------

def test_new_routers_have_their_prefixes_and_are_registered():
    from src.api import client, client_auth, client_reports, portal_admin, recommendations, reports
    expected = {
        client_auth: "/client/api/auth", client: "/client/api", client_reports: "/client/api/reports",
        recommendations: "/dashboard/api", reports: "/dashboard/api/reports",
        portal_admin: "/dashboard/api/portal",
    }
    for module, prefix in expected.items():
        assert module.router.prefix == prefix


async def test_weekly_scheduler_is_a_noop_while_disabled(monkeypatch):
    import asyncio
    from src.services import weekly_report
    calls = []

    async def fake_tick(now=None):
        calls.append(now)
        return {}

    monkeypatch.setattr(weekly_report, "tick", fake_tick)
    await runtime_settings.set("weekly_report_check_interval_seconds", 1)
    task = asyncio.create_task(weekly_report.run_scheduler_loop())
    await asyncio.sleep(0.2)
    assert calls == []
    await runtime_settings.set("weekly_report_enabled", True)  # picked up live, next iteration
    await asyncio.sleep(1.3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(calls) >= 1
