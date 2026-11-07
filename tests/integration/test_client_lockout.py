"""
Client sign-in lock-out model (review finding: anonymous account lock-out) and
the "no typed username in the log" rule (review finding: password pasted into
the username box reached app.log).

Lock-out model under test (src/storage/user_store.py):
  - wrong passwords are counted per (account, client address); after
    client_login_max_failures only THAT address is locked out of the account,
    for client_login_lockout_minutes;
  - an account-wide backstop (client_login_account_max_failures within
    client_login_account_window_minutes) slows attempts down with a growing
    delay instead of hard-locking, and never for an address that signed in to
    the account recently;
  - every refusal is the same generic 401.
"""
import logging
import sqlite3
import time

import aiosqlite
import pytest
import structlog
from fastapi.testclient import TestClient

from client_auth_helpers import (
    ADMIN_USERS, ENGINEER, LOGIN_PATH, PASSWORD, LogRecorder, admin_create, enable_portal,
)
from src.config import settings
from src.main import app
from src.middleware import security
from src.storage import database, runtime_settings, user_store

ADDR_A = "198.51.100.7"    # the attacker's address
ADDR_B = "203.0.113.20"    # the real user's address
GENERIC_401 = {"detail": "Invalid username or password"}


@pytest.fixture(autouse=True)
def _fresh_address_limiter():
    # The per-address limiter is process-wide; start each test from zero.
    security.auth_limiter.reset()
    yield
    security.auth_limiter.reset()


def client_from(ip: str) -> TestClient:
    return TestClient(app, client=(ip, 50000))


def attempt(c: TestClient, username: str, password: str):
    return c.post(LOGIN_PATH, json={"username": username, "password": password})


async def _scalar(sql: str, params: tuple = ()):
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        async with conn.execute(sql, params) as cur:
            row = await cur.fetchone()
    return row[0] if row else None


async def _exec(sql: str, params: tuple = ()) -> None:
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute(sql, params)
        await conn.commit()


# ============================ (a) per-address lock ============================

def test_wrong_passwords_from_one_address_do_not_lock_out_another(monkeypatch):
    """The reported attack, with the default settings (10 failures, 15 minutes):
    BEFORE the fix the 10 wrong passwords from A locked the account for every
    address, so the real user's correct password from B got 401 for 15 minutes.
    NOW only the pair (account, A) is locked."""
    enable_portal(monkeypatch)
    admin = TestClient(app)
    uid = admin_create(admin, "victim")["user"]["id"]
    attacker, real_user = client_from(ADDR_A), client_from(ADDR_B)

    for _ in range(10):
        res = attempt(attacker, "victim", "guess guess guess")
        assert (res.status_code, res.json()) == (401, GENERIC_401)
    # A is locked out, even with the correct password, with the generic answer
    res = attempt(attacker, "victim", PASSWORD)
    assert (res.status_code, res.json()) == (401, GENERIC_401)
    # ...but the real user at B signs in normally, and again after that
    assert attempt(real_user, "victim", PASSWORD).status_code == 200
    assert attempt(real_user, "VICTIM", PASSWORD).status_code == 200

    # A stays locked for the lock period (client_login_lockout_minutes = 15)
    lock_end = sqlite3.connect(settings.sqlite_db_path).execute(
        "SELECT locked_until FROM client_login_failures WHERE user_id = ? AND client_ip = ?",
        (uid, ADDR_A)).fetchone()[0]
    assert lock_end == pytest.approx(time.time() + 15 * 60, abs=10)
    assert attempt(attacker, "victim", PASSWORD).status_code == 401
    # once the period has passed, A may try again
    conn = sqlite3.connect(settings.sqlite_db_path)
    conn.execute("UPDATE client_login_failures SET locked_until = ? WHERE client_ip = ?",
                 (time.time() - 1, ADDR_A))
    conn.commit()
    conn.close()
    assert attempt(attacker, "victim", PASSWORD).status_code == 200


async def test_ipv6_addresses_are_counted_per_64():
    assert user_store.address_key("2001:db8:1:2::5") == "2001:db8:1:2::/64"
    assert user_store.address_key("2001:db8:1:2:ffff::1") == "2001:db8:1:2::/64"
    assert user_store.address_key("::ffff:198.51.100.7") == "198.51.100.7"
    assert user_store.address_key("198.51.100.7") == "198.51.100.7"
    assert user_store.address_key("testclient") == "testclient"
    await runtime_settings.set("client_login_max_failures", 3)
    await user_store.create_user("six", PASSWORD)
    for i in range(3):  # rotating addresses inside one /64 does not reset the count
        await user_store.verify_credentials("six", "wrong-password!", f"2001:db8:1:2::{i + 1}")
    assert await user_store.verify_credentials("six", PASSWORD, "2001:db8:1:2::99") is None
    assert await user_store.verify_credentials("six", PASSWORD, "2001:db8:1:3::1")


async def test_unknown_usernames_create_no_lockout_rows():
    for i in range(5):
        assert await user_store.verify_credentials(f"ghost{i}", "wrong-password!", f"10.0.0.{i}") is None
    assert await _scalar("SELECT COUNT(*) FROM client_login_failures") == 0


# ============================ (b) account-wide backstop ============================

async def test_account_backstop_slows_down_at_its_threshold_with_growing_delay(monkeypatch):
    """BEFORE: a hard lock of the whole account at 10 failures. NOW: nothing
    account-wide happens until client_login_account_max_failures (default 100,
    set to 20 here), and then attempts are only spaced out (1 s, 2 s, 4 s ...
    capped), except from an address that recently signed in."""
    rec = LogRecorder()
    monkeypatch.setattr(user_store, "logger", rec)
    await runtime_settings.set("client_login_max_failures", 5)
    await runtime_settings.set("client_login_account_max_failures", 20)
    await runtime_settings.set("client_login_account_max_delay_seconds", 30)
    u = await user_store.create_user("target", PASSWORD)
    assert await user_store.verify_credentials("target", PASSWORD, "10.9.9.9")  # the user's usual address

    # 19 wrong passwords from 5 addresses (each below its own lock): no slow-down
    for i in range(19):
        await user_store.verify_credentials("target", "wrong-password!", f"10.0.0.{i % 5}")
    state = await user_store.get_by_id(u["id"])
    assert state["failed_attempts"] == 19 and not state["throttled"] and not state["locked"]
    assert await user_store.verify_credentials("target", PASSWORD, "10.1.1.1")  # fresh address: fine

    # the 20th engages the backstop: a 1 s slow-down, logged once
    await user_store.verify_credentials("target", "wrong-password!", "10.0.0.50")
    state = await user_store.get_by_id(u["id"])
    assert state["throttled"] and state["locked"] and state["locked_addresses"] == 0
    assert state["throttled_until"] - time.time() == pytest.approx(1, abs=0.5)
    assert len(rec.find("client_account_throttled")) == 1
    # during it, a new address is refused even with the right password...
    assert await user_store.verify_credentials("target", PASSWORD, "10.2.2.2") is None
    assert rec.find("client_login_rejected")[-1]["reason"] == "throttled"
    # ...but an address that signed in to the account recently is not
    assert await user_store.verify_credentials("target", PASSWORD, "10.9.9.9")
    assert await user_store.verify_credentials("target", PASSWORD, "10.1.1.1")

    # the delay grows with each further wrong password: 2 s, 4 s, ...
    for expected in (2, 4, 8):
        await _exec("UPDATE client_users SET locked_until = ? WHERE id = ?", (time.time() - 0.01, u["id"]))
        await user_store.verify_credentials("target", "wrong-password!", "10.0.0.60")
        until = (await user_store.get_by_id(u["id"]))["throttled_until"]
        assert until - time.time() == pytest.approx(expected, abs=0.5)
    # ...up to client_login_account_max_delay_seconds
    await _exec("UPDATE client_users SET locked_until = NULL, failed_attempts = 60 WHERE id = ?", (u["id"],))
    await user_store.verify_credentials("target", "wrong-password!", "10.0.0.70")
    until = (await user_store.get_by_id(u["id"]))["throttled_until"]
    assert until - time.time() == pytest.approx(30, abs=0.5)
    assert len(rec.find("client_account_throttled")) == 1

    # once the window (client_login_account_window_minutes) has passed, the count restarts
    await _exec("UPDATE client_users SET locked_until = NULL, failure_window_start = ? WHERE id = ?",
                (time.time() - 61 * 60, u["id"]))
    await user_store.verify_credentials("target", "wrong-password!", "10.0.0.80")
    state = await user_store.get_by_id(u["id"])
    assert state["failed_attempts"] == 1 and not state["throttled"]


async def test_backstop_default_threshold_is_far_above_the_address_limit():
    assert await runtime_settings.get("client_login_max_failures") == 10
    assert await runtime_settings.get("client_login_lockout_minutes") == 15
    assert await runtime_settings.get("client_login_account_max_failures") == 100
    assert await runtime_settings.get("client_login_account_window_minutes") == 60
    assert await runtime_settings.get("client_login_account_max_delay_seconds") == 60
    with pytest.raises(ValueError):  # cannot be set low enough to act as a hard lock again
        await runtime_settings.set("client_login_account_max_failures", 5)


# ============================ (c) one generic answer ============================

def test_every_refusal_is_the_same_401_and_runs_the_hash(monkeypatch):
    """Unknown user, wrong password, locked-out address, slowed-down account and
    disabled account: same status, same body, and the password hash is checked
    every time (so the timing does not tell them apart either)."""
    enable_portal(monkeypatch)
    monkeypatch.setattr(settings, "client_login_max_failures", 2)
    admin = TestClient(app)
    admin_create(admin, "known.user")
    slowed = admin_create(admin, "slowed.user")["user"]["id"]
    off = admin_create(admin, "off.user")["user"]["id"]
    admin.post(f"{ADMIN_USERS}/{off}/disable", headers=ENGINEER)
    conn = sqlite3.connect(settings.sqlite_db_path)
    conn.execute("UPDATE client_users SET locked_until = ? WHERE id = ?", (time.time() + 600, slowed))
    conn.commit()
    conn.close()
    a = client_from(ADDR_A)
    attempt(a, "known.user", "wrong wrong wrong")
    attempt(a, "known.user", "wrong wrong wrong")  # A is now locked out of known.user

    hashed = []
    real = user_store.check_password
    monkeypatch.setattr(user_store, "check_password", lambda p, s: hashed.append(s) or real(p, s))
    rec = LogRecorder()
    monkeypatch.setattr(user_store, "logger", rec)
    cases = [
        (client_from(ADDR_B), "no.such.user", PASSWORD, "unknown_user"),
        (client_from(ADDR_B), "known.user", "wrong wrong wrong", "bad_password"),
        (a, "known.user", PASSWORD, "address_locked"),
        (client_from(ADDR_B), "slowed.user", PASSWORD, "throttled"),
        (client_from(ADDR_B), "off.user", PASSWORD, "disabled"),
    ]
    for c, username, password, reason in cases:
        res = attempt(c, username, password)
        assert (res.status_code, res.json()) == (401, GENERIC_401), reason
        assert rec.find("client_login_rejected")[-1]["reason"] == reason
    assert len(hashed) == len(cases)


# ============================ (d) engineer unlock ============================

def test_engineer_sees_and_clears_address_locks_and_the_slowdown(monkeypatch):
    enable_portal(monkeypatch)
    monkeypatch.setattr(settings, "client_login_max_failures", 2)
    admin = TestClient(app)
    uid = admin_create(admin, "rita")["user"]["id"]
    b = client_from(ADDR_B)
    assert attempt(b, "rita", PASSWORD).status_code == 200   # B becomes a known address
    a = client_from(ADDR_A)
    for _ in range(2):
        attempt(a, "rita", "nope nope nope")
    conn = sqlite3.connect(settings.sqlite_db_path)
    conn.execute("UPDATE client_users SET locked_until = ? WHERE id = ?", (time.time() + 600, uid))
    conn.commit()
    conn.close()

    listed = admin.get(ADMIN_USERS, headers=ENGINEER).json()["users"][0]
    assert listed["locked"] is True and listed["locked_addresses"] == 1 and listed["throttled"] is True
    assert attempt(a, "rita", PASSWORD).status_code == 401
    assert attempt(client_from("192.0.2.1"), "rita", PASSWORD).status_code == 401  # slowed down

    user = admin.post(f"{ADMIN_USERS}/{uid}/unlock", headers=ENGINEER).json()["user"]
    assert user["locked"] is False and user["locked_addresses"] == 0 and user["throttled"] is False
    assert user["failed_attempts"] == 0
    assert attempt(a, "rita", PASSWORD).status_code == 200
    assert attempt(client_from("192.0.2.1"), "rita", PASSWORD).status_code == 200
    # unlock keeps the known addresses (they only ever exempt from the slow-down)
    known = sqlite3.connect(settings.sqlite_db_path).execute(
        "SELECT COUNT(*) FROM client_login_failures WHERE user_id = ? AND last_success_at IS NOT NULL",
        (uid,)).fetchone()[0]
    assert known == 3


# ============================ (e) no typed username in the log ============================

@pytest.fixture
def real_log_file(tmp_path, monkeypatch):
    """The app's real logging pipeline (setup_logging: structlog processors with
    redaction, JSON file handler) writing to a temp file; restored afterwards."""
    from src.api import client_auth, portal_admin
    from src.utils.logging import setup_logging
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    saved_config = structlog.get_config()
    path = tmp_path / "app.log"
    setup_logging("INFO", str(path))
    # Module loggers may be proxies cached against an earlier configuration.
    for module in (user_store, client_auth, portal_admin, security):
        monkeypatch.setattr(module, "logger", structlog.get_logger(module.__name__))
    yield path
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        handler.close()
    for handler in saved_handlers:
        root.addHandler(handler)
    root.setLevel(saved_level)
    structlog.configure(**saved_config)


async def test_password_typed_as_username_never_reaches_the_log(monkeypatch, real_log_file, caplog):
    """BEFORE: client_login_failed carried username=<what was typed> whenever it
    had a username's shape, which a generated password (and many human ones)
    has. NOW: failed logins and lock events carry no typed username at all."""
    enable_portal(monkeypatch)
    caplog.set_level(logging.INFO)
    pasted_password = user_store.generate_password()          # 24 chars of [A-Za-z0-9_-]
    assert user_store.USERNAME_RE.match(pasted_password)        # i.e. shaped like a username
    # An account whose own name looks like a password, locked out from A: the
    # lock events must not name it either (they carry the user id).
    secret_name = "Pw." + user_store.generate_password()
    await user_store.create_user(secret_name, PASSWORD)

    a, b = client_from(ADDR_A), client_from(ADDR_B)
    for _ in range(3):
        assert attempt(a, pasted_password, "irrelevant password").status_code == 401
    for _ in range(11):
        assert attempt(b, secret_name, "wrong wrong wrong").status_code == 401

    for handler in logging.getLogger().handlers:
        handler.flush()
    written = real_log_file.read_text()
    captured = caplog.text + "".join(str(r.msg) for r in caplog.records)
    for event in ("client_login_failed", "client_login_rejected", "client_account_locked"):
        assert event in written, event
    for text in (written, captured):
        assert pasted_password not in text and pasted_password.lower() not in text.lower()
        assert secret_name.lower() not in text.lower()
        assert '"username"' not in text


def test_redaction_backstop_covers_username_fields():
    from src.utils.logging import redact_secrets
    out = redact_secrets({"username": "typed", "user_name": "typed", "nested": {"login": "typed"},
                          "account": "kept", "event": "POST /x?username=typed&page=2"})
    assert "typed" not in repr(out)
    assert out["account"] == "kept" and "page=2" in out["event"]


# ============================ (f) migration of an older database ============================

# client_users / client_sessions exactly as created by the release before this change.
_OLD_SCHEMA = """
CREATE TABLE client_users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'client' CHECK(role = 'client'),
    password_hash TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    created_at REAL NOT NULL,
    password_changed_at REAL,
    last_login_at REAL
);
CREATE TABLE client_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES client_users(id) ON DELETE CASCADE,
    created_at REAL, last_seen_at REAL, expires_at REAL, client_ip TEXT
);
"""


async def test_init_db_migrates_an_older_database_idempotently(tmp_path, monkeypatch):
    old_db = tmp_path / "old.db"
    conn = sqlite3.connect(old_db)
    conn.executescript(_OLD_SCHEMA)
    now = time.time()
    # an account caught in the OLD account-wide lock at upgrade time
    conn.execute("INSERT INTO client_users (id, username, password_hash, failed_attempts, locked_until, "
                 "created_at) VALUES ('usr_old', 'old.client', ?, 10, ?, ?)",
                 (user_store.hash_password(PASSWORD), now + 900, now - 86400))
    conn.commit()
    conn.close()
    monkeypatch.setattr(settings, "sqlite_db_path", str(old_db))

    await database.init_db()
    cols = {r[1] for r in sqlite3.connect(old_db).execute("PRAGMA table_info(client_users)")}
    assert "failure_window_start" in cols
    assert sqlite3.connect(old_db).execute(
        "SELECT failed_attempts, locked_until FROM client_users").fetchone() == (0, None)
    user = await user_store.get_by_id("usr_old")
    assert user["locked"] is False and user["username"] == "old.client"
    assert await user_store.verify_credentials("old.client", "wrong-password!", ADDR_A) is None
    assert await user_store.verify_credentials("old.client", PASSWORD, ADDR_B)

    # running it again (every start-up) changes nothing and keeps the new state
    before = sqlite3.connect(old_db).execute(
        "SELECT failed_attempts, failure_window_start FROM client_users").fetchone()
    await database.init_db()
    await database.init_db()
    assert sqlite3.connect(old_db).execute(
        "SELECT failed_attempts, failure_window_start FROM client_users").fetchone() == before
    assert before[0] == 1
    assert await _scalar("SELECT COUNT(*) FROM client_login_failures") == 2


# ============================ pruning ============================

async def test_lockout_rows_are_pruned_and_capped(monkeypatch):
    u = await user_store.create_user("prune.me", PASSWORD)
    now = time.time()
    day = 86400
    rows = [  # (client_ip, last_failed_at, locked_until, last_success_at, kept?)
        ("1.0.0.1", now - 2 * day, None, None, False),            # stale failures
        ("1.0.0.2", now - 60, None, None, True),                  # recent failure
        ("1.0.0.3", now - 2 * day, now + 600, None, True),        # still locked
        ("1.0.0.4", None, None, now - 10 * day, True),            # known address
        ("1.0.0.5", None, None, now - 40 * day, False),           # no longer known
        ("1.0.0.6", now - 2 * day, now - 1, now - 40 * day, False),
    ]
    for ip, failed_at, lock, success, _ in rows:
        await _exec("INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at, "
                    "locked_until, last_success_at) VALUES (?, ?, 3, ?, ?, ?)",
                    (u["id"], ip, failed_at, lock, success))
    assert await user_store.purge_login_failures() == 3
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        async with conn.execute("SELECT client_ip FROM client_login_failures ORDER BY client_ip") as cur:
            left = [r[0] for r in await cur.fetchall()]
    assert left == [ip for ip, *_, kept in rows if kept]

    # hard cap: oldest activity goes first
    monkeypatch.setattr(user_store, "LOGIN_FAILURE_MAX_ROWS", 2)
    assert await user_store.purge_login_failures() == 1
    assert await _scalar("SELECT COUNT(*) FROM client_login_failures WHERE client_ip = '1.0.0.4'") == 0

    # and it runs by itself on the failure path (at most once per interval)
    await _exec("INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at) "
                "VALUES (?, '1.0.0.9', 1, ?)", (u["id"], now - 2 * day))
    monkeypatch.setattr(user_store, "LOGIN_FAILURE_MAX_ROWS", 50_000)
    monkeypatch.setattr(user_store, "_last_login_failure_prune", 0.0)
    await user_store.verify_credentials("prune.me", "wrong-password!", "1.0.0.10")
    assert await _scalar("SELECT COUNT(*) FROM client_login_failures WHERE client_ip = '1.0.0.9'") == 0
