"""Engineer API for dashboard-editable portal settings (src/api/portal_settings.py)."""
import sys
import types

import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.storage import runtime_settings

BASE = "/dashboard/api/portal-settings"
KEY = "test-dashboard-key-0001"


# ------------------------------ listing ------------------------------

def test_get_lists_every_registry_key(client: TestClient):
    body = client.get(BASE).json()
    assert set(body["settings"]) == set(runtime_settings.REGISTRY)

    entry = body["settings"]["weekly_report_time"]
    assert entry["value"] == entry["default"]
    assert entry["source"] == "env"
    assert entry["type"] == "time_hhmm"
    assert entry["group"] == "weekly_report"
    assert entry["description"]
    assert entry["constraints"]["format"].startswith("HH:MM")
    assert entry["secret"] is False

    idle = body["settings"]["client_session_idle_minutes"]
    assert idle["type"] == "int"
    assert idle["constraints"] == {"min": 1, "max": 1440}
    assert body["settings"]["weekly_report_weekday"]["constraints"]["choices"][0] == "MON"


def test_put_then_get_reports_db_source_and_new_value(client: TestClient):
    res = client.put(f"{BASE}/weekly_report_enabled", json={"value": True})
    assert res.status_code == 200
    assert res.json() == {"key": "weekly_report_enabled", "value": True, "source": "db"}

    settings_body = client.get(BASE).json()["settings"]
    assert settings_body["weekly_report_enabled"]["value"] is True
    assert settings_body["weekly_report_enabled"]["default"] is False
    assert settings_body["weekly_report_enabled"]["source"] == "db"
    # an untouched key still reports its env default
    assert settings_body["client_portal_enabled"]["source"] == "env"


async def test_saved_value_is_what_the_app_reads(client: TestClient):
    client.put(f"{BASE}/client_session_idle_minutes", json={"value": 30})
    assert await runtime_settings.get("client_session_idle_minutes") == 30


def test_delete_resets_to_env(client: TestClient):
    before = client.get(BASE).json()["settings"]["weekly_report_weekday"]
    client.put(f"{BASE}/weekly_report_weekday", json={"value": "TUE"})
    assert client.get(BASE).json()["settings"]["weekly_report_weekday"]["source"] == "db"

    res = client.delete(f"{BASE}/weekly_report_weekday")
    assert res.status_code == 200
    assert res.json() == {"key": "weekly_report_weekday", "value": before["default"], "source": "env"}
    entry = client.get(BASE).json()["settings"]["weekly_report_weekday"]
    assert entry["value"] == before["default"] and entry["source"] == "env"
    # deleting again is harmless
    assert client.delete(f"{BASE}/weekly_report_weekday").status_code == 200


# ------------------------------ errors ------------------------------

def test_unknown_key_is_404(client: TestClient):
    assert client.put(f"{BASE}/not_a_setting", json={"value": 1}).status_code == 404
    assert client.delete(f"{BASE}/not_a_setting").status_code == 404


@pytest.mark.parametrize("key,value", [
    ("client_session_idle_minutes", 0),
    ("client_session_idle_minutes", "abc"),
    ("client_session_idle_minutes", 1.5),
    ("client_session_idle_minutes", True),
    ("client_portal_enabled", "maybe"),
    ("weekly_report_time", "9:5"),
    ("weekly_report_time", "24:00"),
    ("weekly_report_weekday", "FUNDAY"),
    ("client_immediate_min_risk", "SEVERE"),
    ("client_portal_url", "javascript:alert(1)"),
])
def test_invalid_value_is_422_with_store_message(client: TestClient, key, value):
    res = client.put(f"{BASE}/{key}", json={"value": value})
    assert res.status_code == 422
    detail = res.json()["detail"]
    assert isinstance(detail, str) and key in detail
    assert client.get(BASE).json()["settings"][key]["source"] == "env"


def test_missing_or_wrong_dashboard_key_is_401(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", KEY)

    assert client.get(BASE).status_code == 401
    assert client.get(BASE, headers={"X-Dashboard-Key": "wrong"}).status_code == 401
    assert client.put(f"{BASE}/weekly_report_enabled", json={"value": True}).status_code == 401
    assert client.delete(f"{BASE}/weekly_report_weekday").status_code == 401
    # nothing was written by the rejected calls
    assert client.get(BASE, headers={"X-Dashboard-Key": KEY}).json()[
        "settings"]["weekly_report_enabled"]["source"] == "env"

    ok = client.get(BASE, headers={"X-Dashboard-Key": KEY})
    assert ok.status_code == 200
    saved = client.put(f"{BASE}/weekly_report_enabled", json={"value": True},
                       headers={"X-Dashboard-Key": KEY})
    assert saved.status_code == 200


# ---------------------------- validation ----------------------------

def test_valid_values_are_normalised(client: TestClient):
    def put(key, value):
        res = client.put(f"{BASE}/{key}", json={"value": value})
        assert res.status_code == 200, res.text
        return res.json()["value"]

    assert put("weekly_report_time", "09:30") == "09:30"
    assert put("weekly_report_time", "9:05") == "09:05"
    assert put("weekly_report_weekday", "TUE") == "TUE"
    assert put("weekly_report_weekday", "fri") == "FRI"
    assert put("client_session_idle_minutes", "45") == 45
    assert put("client_session_idle_minutes", 45.0) == 45
    assert put("email_attachments_enabled", "true") is True
    assert put("client_immediate_min_risk", "high") == "HIGH"
    assert put("client_portal_url", " https://portal.example.jp/ ") == "https://portal.example.jp"


# --------------------------- portal guard ---------------------------

def _install_guard(monkeypatch, ok: bool, reason: str = "") -> None:
    module = types.ModuleType("src.services.portal_guard")
    module.portal_prerequisites_ok = lambda: (ok, reason)
    monkeypatch.setitem(sys.modules, "src.services.portal_guard", module)


def test_enabling_portal_is_blocked_when_prerequisites_fail(client: TestClient, monkeypatch):
    _install_guard(monkeypatch, False, "No client users exist yet")
    res = client.put(f"{BASE}/client_portal_enabled", json={"value": True})
    assert res.status_code == 409
    assert res.json()["detail"] == "No client users exist yet"
    assert client.get(BASE).json()["settings"]["client_portal_enabled"]["source"] == "env"


def test_enabling_portal_succeeds_when_prerequisites_pass(client: TestClient, monkeypatch):
    _install_guard(monkeypatch, True)
    res = client.put(f"{BASE}/client_portal_enabled", json={"value": True})
    assert res.status_code == 200 and res.json()["value"] is True


def test_enabling_portal_is_allowed_when_the_guard_module_is_absent(client: TestClient, monkeypatch):
    monkeypatch.setitem(sys.modules, "src.services.portal_guard", None)
    res = client.put(f"{BASE}/client_portal_enabled", json={"value": True})
    assert res.status_code == 200 and res.json()["value"] is True


def test_disabling_portal_does_not_consult_the_guard(client: TestClient, monkeypatch):
    _install_guard(monkeypatch, False, "must not be consulted")
    assert client.put(f"{BASE}/client_portal_enabled", json={"value": False}).status_code == 200


# ------------------------------ audit -------------------------------

def test_changes_are_audit_logged(client: TestClient):
    from structlog.testing import capture_logs

    with capture_logs() as logs:
        client.put(f"{BASE}/weekly_report_time", json={"value": "10:15"})
    entry = next(e for e in logs if e["event"] == "portal_setting_updated")
    assert entry["key"] == "weekly_report_time" and entry["value"] == "10:15"

    with capture_logs() as logs:
        client.delete(f"{BASE}/weekly_report_time")
    assert any(e["event"] == "portal_setting_reset" and e["key"] == "weekly_report_time" for e in logs)
