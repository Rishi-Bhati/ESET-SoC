"""scripts/purge_alerts.py against a database built by the application's own init_db."""
import importlib.util
import json
import os
import sqlite3
import time

import pytest

from src.config import settings

_spec = importlib.util.spec_from_file_location(
    "purge_alerts", os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "purge_alerts.py")
)
purge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(purge)

TEST_IDS = ["test-0001", "test-0002"]
KEEP_ID = "real-0001"
ALL_IDS = TEST_IDS + [KEEP_ID]


def _insert_alert(conn, cid, endpoint, now, eset_alert_id=None, raw_payload="{}", indexed=True):
    conn.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?)", (cid, "eset", "SUCCESS", raw_payload, now, now, None))
    if not indexed:
        return
    conn.execute(
        "INSERT INTO alert_index (correlation_id, source, received_at, risk_level, endpoint_name, "
        "detection_name, pipeline_status, eset_alert_id) VALUES (?,?,?,?,?,?,?,?)",
        (cid, "eset", now, "HIGH", endpoint, "EICAR", "SUCCESS", eset_alert_id),
    )
    conn.execute(
        "INSERT INTO ai_traces (trace_id, correlation_id, component, provider, model, status, risk, "
        "started_at, data_json) VALUES (?,?,?,?,?,?,?,?,?)",
        (f"tr-{cid}", cid, "summary", "openai", "m", "SUCCESS", "SAFE", now, "{}"),
    )
    conn.execute(
        "INSERT INTO email_deliveries (email_id, correlation_id, notification_type, recipients, subject, "
        "status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
        (f"em-{cid}", cid, "client", "[]", "s", "SENT", now, now),
    )
    conn.execute(
        "INSERT INTO alert_recommendations (id, correlation_id, body, author, created_at) VALUES (?,?,?,?,?)",
        (f"rec-{cid}", cid, "b", "eng", now),
    )
    conn.execute("INSERT INTO alert_observations VALUES (?,?,?,?)", (cid, "EICAR", endpoint, now))


@pytest.fixture
def data_dir(tmp_path):
    """A production-shaped data dir: soc_lite.db (app schema) + output/alerts + output/emails."""
    db = tmp_path / "soc_lite.db"
    src = sqlite3.connect(settings.sqlite_db_path)  # schema made by init_db in conftest
    dst = sqlite3.connect(db)
    src.backup(dst)
    src.close()
    now = time.time()
    with dst:
        for t in purge.ALERT_TABLES:
            dst.execute(f"DELETE FROM {t}")
        for cid in TEST_IDS:
            _insert_alert(dst, cid, "TEST-PC", now)
        _insert_alert(dst, KEEP_ID, "FINANCE-PC-09", now - 60)
    dst.close()

    alerts = tmp_path / "output" / "alerts"
    emails = tmp_path / "output" / "emails"
    alerts.mkdir(parents=True)
    emails.mkdir(parents=True)
    for cid in ALL_IDS:
        (alerts / f"{cid}.json").write_text(json.dumps({"correlation_id": cid}))
    (alerts / "index.json").write_text(json.dumps([{"correlation_id": c} for c in ALL_IDS]))
    (emails / "outbox.json").write_text(json.dumps([{"email_id": f"em-{c}", "correlation_id": c} for c in ALL_IDS]))
    return tmp_path


def _count(db, table, cid):
    with sqlite3.connect(db) as c:
        return c.execute(f"SELECT COUNT(*) FROM {table} WHERE correlation_id = ?", (cid,)).fetchone()[0]


def _run(data_dir, *args):
    return purge.main(["--data-dir", str(data_dir), *args])


def test_dry_run_changes_nothing(data_dir):
    assert _run(data_dir, "purge", "--endpoint", "TEST-PC") == 0
    for t in purge.ALERT_TABLES:
        assert _count(data_dir / "soc_lite.db", t, "test-0001") == 1
    assert (data_dir / "output" / "alerts" / "test-0001.json").exists()
    assert not list(data_dir.glob("purge-backup-*"))


def test_apply_requires_app_stopped_confirmation(data_dir):
    with pytest.raises(SystemExit):
        _run(data_dir, "purge", "--id", "test-0001", "--apply")
    assert _count(data_dir / "soc_lite.db", "jobs", "test-0001") == 1


def test_apply_removes_only_selected_alerts_and_backs_up(data_dir):
    backup = data_dir / "bk"
    assert _run(data_dir, "purge", "--endpoint", "TEST-PC", "--apply", "--confirm-app-stopped",
                "--backup-dir", str(backup)) == 0
    db = data_dir / "soc_lite.db"
    for t in purge.ALERT_TABLES:
        for cid in TEST_IDS:
            assert _count(db, t, cid) == 0, t
        assert _count(db, t, KEEP_ID) == 1, t

    alerts = data_dir / "output" / "alerts"
    assert sorted(p.name for p in alerts.glob("*-*.json")) == [f"{KEEP_ID}.json"]
    assert json.loads((alerts / "index.json").read_text()) == [{"correlation_id": KEEP_ID}]
    outbox = json.loads((data_dir / "output" / "emails" / "outbox.json").read_text())
    assert [r["correlation_id"] for r in outbox] == [KEEP_ID]

    # Backup holds the pre-purge database, the moved files and the removed records.
    assert _count(backup / "soc_lite.db", "jobs", "test-0001") == 1
    assert sorted(p.name for p in (backup / "alerts").iterdir()) == ["test-0001.json", "test-0002.json"]
    removed = json.loads((backup / "removed_records.json").read_text())
    assert removed["ids"] == TEST_IDS
    assert len(removed["index"]) == 2 and len(removed["outbox"]) == 2


def test_ids_file_accepts_list_csv(data_dir, tmp_path):
    csv_path = tmp_path / "alerts.csv"
    assert _run(data_dir, "list", "--csv", str(csv_path)) == 0
    lines = csv_path.read_text(encoding="utf-8-sig").splitlines()
    assert lines[0].startswith("correlation_id,")
    assert len(lines) == 4
    keep = [lines[0]] + [l for l in lines[1:] if l.startswith("test-0001,")]
    ids_file = tmp_path / "ids.csv"
    ids_file.write_text("\n".join(keep), encoding="utf-8")
    assert _run(data_dir, "purge", "--ids-file", str(ids_file), "--apply", "--confirm-app-stopped") == 0
    assert _count(data_dir / "soc_lite.db", "jobs", "test-0001") == 0
    assert _count(data_dir / "soc_lite.db", "jobs", "test-0002") == 1


@pytest.mark.parametrize("alert_id", [
    "test-alert-1763600000-4821", "syslog-sim-1763600000", "poc-high-0001-a1b2c3", "poc-critical-0002",
    "alert-0001", "syslog-0001", "high-alert-99999", "critical-multi-endpoint-88888",
    # hand-typed ids seen in our own development database
    "test-001", "dup-test-001", "live-repro-1787063544", "ai-content-repro-1787114741",
])
def test_tool_alert_ids_are_recognised(alert_id):
    assert purge.test_evidence({"eset_alert_id": alert_id}).startswith("test alert id")


@pytest.mark.parametrize("alert_id", [
    "8f14e45f-ceea-467a-9575-3a4b5c6d7e8f", "123456789", "alert-0002", "poc-high-0001-zzzzzz", "",
])
def test_real_looking_ids_are_not(alert_id):
    assert purge.test_evidence({"eset_alert_id": alert_id}) == ""


def test_known_test_ids_selects_only_tool_alerts(data_dir):
    db = data_dir / "soc_lite.db"
    now = time.time()
    with sqlite3.connect(db) as c:
        _insert_alert(c, "poc-run", "MAC-PC-031", now, eset_alert_id="poc-high-0001-a1b2c3")
        # Real-looking id on a host that shares a test host name: flagged for review, not selected.
        _insert_alert(c, "real-eset", "MAC-PC-031", now, eset_alert_id="8f14e45f-ceea-467a-9575-3a4b5c6d7e8f")
        # Never indexed (failed run): the id is read from the stored payload.
        _insert_alert(c, "job-only", "-", now, raw_payload='{"alert_id": "test-alert-1763600000-42"}', indexed=False)

    conn = purge.connect(str(db))
    by_id = {a["correlation_id"]: a for a in purge.list_alerts(conn)}
    conn.close()
    assert by_id["real-eset"]["test_evidence"] == "test host name MAC-PC-031 (check)"
    assert by_id["job-only"]["eset_alert_id"] == "test-alert-1763600000-42"

    assert _run(data_dir, "purge", "--known-tests", "--apply", "--confirm-app-stopped") == 0
    assert _count(db, "jobs", "poc-run") == 0
    assert _count(db, "jobs", "job-only") == 0
    for kept in ("real-eset", KEEP_ID, *TEST_IDS):  # TEST_IDS have no test alert id
        assert _count(db, "jobs", kept) == 1


# What ESET PROTECT's "test webhook" sends: an audit-log event, subject TEST.
ESET_TEST_PAYLOAD = {"subject": "TEST", "domain": "Test", "action": "Test", "result": "Success",
                     "user": "Administrator", "details": "Test webhook"}
ESET_AUDIT_PAYLOAD = {"subject": "Policy changed", "domain": "Policies", "action": "Modify",
                      "result": "Success", "user": "admin", "details": "..."}
ESET_DETECTION_PAYLOAD = {"event_type": "ウイルス対策検出", "subject": "Threat detected",
                          "detection_name": "Win32/Emotet.CS", "computer_name": "PC-123",
                          "user": "sato", "action": "cleaned", "result": "Success"}


def test_eset_test_webhook_recognised():
    assert purge.eset_test_evidence(ESET_TEST_PAYLOAD) == "ESET test webhook (subject TEST)"
    assert purge.eset_test_evidence({"data": {"Subject": " test "}}) == "ESET test webhook (subject TEST)"


def test_other_audit_events_only_flagged_for_checking():
    assert purge.eset_test_evidence(ESET_AUDIT_PAYLOAD).endswith("(check)")


def test_real_detection_is_not_flagged():
    # Has audit-like keys (user/action/result) but carries a detection: a real alert.
    assert purge.eset_test_evidence(ESET_DETECTION_PAYLOAD) == ""


def test_known_tests_removes_eset_test_webhooks_but_not_detections(data_dir):
    db = data_dir / "soc_lite.db"
    now = time.time()
    with sqlite3.connect(db) as c:
        _insert_alert(c, "eset-test", "UNKNOWN", now, raw_payload=json.dumps(ESET_TEST_PAYLOAD))
        _insert_alert(c, "eset-audit", "UNKNOWN", now, raw_payload=json.dumps(ESET_AUDIT_PAYLOAD))
        _insert_alert(c, "eset-real", "PC-123", now, raw_payload=json.dumps(ESET_DETECTION_PAYLOAD, ensure_ascii=False))

    conn = purge.connect(str(db))
    by_id = {a["correlation_id"]: a for a in purge.list_alerts(conn)}
    conn.close()
    assert by_id["eset-test"]["payload_subject"] == "TEST"
    assert by_id["eset-real"]["test_evidence"] == ""

    assert _run(data_dir, "purge", "--known-tests", "--apply", "--confirm-app-stopped") == 0
    assert _count(db, "jobs", "eset-test") == 0
    assert _count(db, "jobs", "eset-audit") == 1  # "(check)" only: never removed automatically
    assert _count(db, "jobs", "eset-real") == 1


@pytest.mark.parametrize("bad", ["../../etc/passwd", "a/b", ""])
def test_rejects_path_like_ids(data_dir, bad):
    with pytest.raises(SystemExit):
        _run(data_dir, "purge", "--id", bad)


def test_date_range_alone_is_refused(data_dir):
    with pytest.raises(SystemExit):
        _run(data_dir, "purge", "--received-from", "2026-01-01")


# ------------------------------------------------------------------ hide / unhide

def _hidden(db):
    with sqlite3.connect(db) as c:
        return {r[0] for r in c.execute("SELECT correlation_id FROM hidden_alerts")}


def test_hide_dry_run_then_apply_keeps_all_data(data_dir):
    db = data_dir / "soc_lite.db"
    assert _run(data_dir, "hide", "--endpoint", "TEST-PC") == 0
    assert _hidden(db) == set()                     # dry run: nothing written

    assert _run(data_dir, "hide", "--endpoint", "TEST-PC", "--apply") == 0
    assert _hidden(db) == set(TEST_IDS)
    for t in purge.ALERT_TABLES:                    # every row still there
        for cid in ALL_IDS:
            assert _count(db, t, cid) == 1, t
    assert sorted(p.name for p in (data_dir / "output" / "alerts").glob("*-*.json")) == \
        sorted(f"{c}.json" for c in ALL_IDS)

    assert _run(data_dir, "unhide", "--id", "test-0001", "--apply") == 0
    assert _hidden(db) == {"test-0002"}


def test_list_shows_hidden_column(data_dir, tmp_path):
    assert _run(data_dir, "hide", "--id", "test-0001", "--apply") == 0
    out = tmp_path / "l.csv"
    assert _run(data_dir, "list", "--csv", str(out)) == 0
    rows = {l.split(",")[0]: l.split(",")[2] for l in out.read_text(encoding="utf-8-sig").splitlines()[1:]}
    assert rows["test-0001"] == "yes" and rows["test-0002"] == ""


def test_hide_refuses_on_a_database_without_the_table(data_dir):
    with sqlite3.connect(data_dir / "soc_lite.db") as c:
        c.execute("DROP TABLE hidden_alerts")
    with pytest.raises(SystemExit):
        _run(data_dir, "hide", "--id", "test-0001", "--apply")
