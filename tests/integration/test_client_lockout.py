"""
Client sign-in lock-out model and the "no typed username in the log" rule.

Model under test (src/storage/user_store.py):
  - wrong passwords are counted per (account, address); after
    client_login_max_failures only THAT address is locked out of the account;
  - an account-wide score (draining, never reset at a boundary) switches on
    BACKSTOP mode, in which wrong passwords from addresses the account has not
    signed in from are also counted per network (IPv4 /24, IPv6 /48); a few of
    them lock that network out, with a doubling lock;
  - nothing refuses a correct password from an unrelated network;
  - every refusal is the same 401, and every attempt runs the same work.

The tests named after a review finding (F1..F6) each fail on 98fce4b.
"""
import ipaddress
import logging
import sqlite3
import time
from contextlib import asynccontextmanager

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

ADDR_A = "198.51.100.7"    # an attacker's address
ADDR_B = "203.0.113.20"    # the real user's address
GENERIC_401 = {"detail": "Invalid username or password"}
WRONG = "wrong-password!"


@pytest.fixture(autouse=True)
def _fresh_limiters(monkeypatch):
    # The per-address limiter is process-wide; start each test from zero. Keep
    # the opportunistic prune out of the way unless a test asks for it.
    security.auth_limiter.reset()
    monkeypatch.setattr(user_store, "_last_login_failure_prune", time.time())
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


def _sync_exec(sql: str, params: tuple = ()) -> None:
    conn = sqlite3.connect(settings.sqlite_db_path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


# ============================ per-address lock ============================

def test_wrong_passwords_from_one_address_do_not_lock_out_another(monkeypatch):
    """The originally reported attack, with the default settings (10 failures,
    15 minutes): only the pair (account, A) is locked."""
    enable_portal(monkeypatch)
    admin = TestClient(app)
    uid = admin_create(admin, "victim")["user"]["id"]
    attacker, real_user = client_from(ADDR_A), client_from(ADDR_B)

    for _ in range(10):
        res = attempt(attacker, "victim", "guess guess guess")
        assert (res.status_code, res.json()) == (401, GENERIC_401)
    res = attempt(attacker, "victim", PASSWORD)
    assert (res.status_code, res.json()) == (401, GENERIC_401)
    assert attempt(real_user, "victim", PASSWORD).status_code == 200
    assert attempt(real_user, "VICTIM", PASSWORD).status_code == 200

    lock_end = sqlite3.connect(settings.sqlite_db_path).execute(
        "SELECT locked_until FROM client_login_failures WHERE user_id = ? AND client_ip = ?",
        (uid, ADDR_A)).fetchone()[0]
    assert lock_end == pytest.approx(time.time() + 15 * 60, abs=10)
    assert attempt(attacker, "victim", PASSWORD).status_code == 401
    _sync_exec("UPDATE client_login_failures SET locked_until = ? WHERE client_ip = ?",
               (time.time() - 1, ADDR_A))
    assert attempt(attacker, "victim", PASSWORD).status_code == 200


def test_address_and_network_keys():
    assert user_store.address_key("2001:db8:1:2::5") == "2001:db8:1:2::/64"
    assert user_store.address_key("::ffff:198.51.100.7") == "198.51.100.7"
    assert user_store.address_key("testclient") == "testclient"
    assert user_store.network_key("198.51.100.7") == "net:198.51.100.0/24"
    assert user_store.network_key("::ffff:198.51.100.7") == "net:198.51.100.0/24"
    assert user_store.network_key("2001:db8:abcd:1f::9") == "net:2001:db8:abcd::/48"
    assert user_store.network_key("testclient") == "net:testclient"


async def test_ipv6_addresses_are_counted_per_64():
    await runtime_settings.set("client_login_max_failures", 3)
    await user_store.create_user("six", PASSWORD)
    for i in range(3):
        await user_store.verify_credentials("six", WRONG, f"2001:db8:1:2::{i + 1}")
    assert await user_store.verify_credentials("six", PASSWORD, "2001:db8:1:2::99") is None
    assert await user_store.verify_credentials("six", PASSWORD, "2001:db8:1:3::1")


async def test_unknown_usernames_create_no_lockout_rows():
    for i in range(5):
        assert await user_store.verify_credentials(f"ghost{i}", WRONG, f"10.0.0.{i}") is None
    assert await _scalar("SELECT COUNT(*) FROM client_login_failures") == 0


# ====== F1: an attacker's traffic never makes a correct password fail elsewhere ======

def _ipv4_in_one_24(i: int) -> str:
    return f"198.51.100.{i % 254 + 1}"


def _ipv4_across_24s(i: int) -> str:
    return f"198.18.{i % 40}.{i // 40 % 254 + 1}"


def _ipv6_in_one_60(i: int) -> str:
    # 16 different /64s inside 2001:db8:abcd:10::/60 (all in one /48)
    return str(ipaddress.IPv6Address(f"2001:db8:abcd:{0x10 + i % 16:x}::") + 1 + i // 16)


@pytest.mark.parametrize("attacker_ip,threshold", [
    (_ipv4_in_one_24, None),     # default settings (account limit 100)
    (_ipv4_across_24s, 20),
    (_ipv6_in_one_60, 20),
])
async def test_F1_attacker_on_many_addresses_cannot_make_a_correct_password_fail_elsewhere(
        monkeypatch, attacker_ip, threshold):
    """98fce4b: past the account-wide threshold every address that had not
    signed in before was refused, so ~100 wrong passwords from a handful of
    addresses locked out a client on a new device or network. Now the real user
    signs in with the correct password at every stage of the attack, from a
    network that has never signed in before."""
    rec = LogRecorder()
    monkeypatch.setattr(user_store, "logger", rec)
    if threshold:
        await runtime_settings.set("client_login_account_max_failures", threshold)
    limit = threshold or 100
    u = await user_store.create_user("victim", PASSWORD)
    fresh_networks = iter(["203.0.113.20", "192.0.2.30", "100.64.5.6", "2001:db8:ffff:1::5",
                           "100.100.1.1", "2001:db8:eeee::1"])

    async def real_user_signs_in() -> None:
        assert await user_store.verify_credentials("victim", PASSWORD, next(fresh_networks)), \
            rec.find("client_login_rejected")[-1:]

    sent = 0
    for stop in (limit - 1, limit + 5, limit + 40):
        while sent < stop:
            await user_store.verify_credentials("victim", f"guess-{sent:04d}-xyz", attacker_ip(sent))
            sent += 1
        await real_user_signs_in()
    assert (await user_store.get_by_id(u["id"]))["throttled"] is True
    # even mistyping twice first, in backstop mode, the real user still gets in
    for _ in range(2):
        assert await user_store.verify_credentials("victim", "typo typo typo", "100.100.1.1") is None
    assert await user_store.verify_credentials("victim", PASSWORD, "100.100.1.1")
    # the attacker's own network is what gets locked out: a few more guesses
    # from it and even the correct password is refused there
    for _ in range(3):
        await user_store.verify_credentials("victim", "more guessing!", attacker_ip(sent))
    assert await user_store.verify_credentials("victim", PASSWORD, attacker_ip(sent)) is None
    assert rec.find("client_login_rejected")[-1]["reason"] == "network_locked"
    # the engineer signal: logged once, and visible in the account list
    assert len(rec.find("client_account_throttled")) == 1
    listed = (await user_store.list_users())[0]
    assert listed["throttled"] and listed["locked_networks"] >= 1


async def test_backstop_network_lock_doubles_and_spares_known_addresses(monkeypatch):
    await runtime_settings.set("client_login_account_max_failures", 10)
    u = await user_store.create_user("target", PASSWORD)
    assert await user_store.verify_credentials("target", PASSWORD, "198.51.100.200")  # known, in the attacker /24
    for i in range(10):  # reach backstop from elsewhere
        await user_store.verify_credentials("target", WRONG, f"192.0.2.{i + 1}")
    assert (await user_store.get_by_id(u["id"]))["throttled"]

    def net_lock() -> float:
        return sqlite3.connect(settings.sqlite_db_path).execute(
            "SELECT locked_until FROM client_login_failures WHERE client_ip = 'net:198.51.100.0/24'"
        ).fetchone()[0]

    # three wrong passwords from the attacker /24 (allowance 3) -> 15-minute lock
    for i in range(3):
        await user_store.verify_credentials("target", WRONG, f"198.51.100.{i + 1}")
    assert net_lock() - time.time() == pytest.approx(15 * 60, abs=5)
    assert await user_store.verify_credentials("target", PASSWORD, "198.51.100.50") is None
    # the known address inside that /24 is not affected
    assert await user_store.verify_credentials("target", PASSWORD, "198.51.100.200")
    # each further wrong password after a lock ends doubles it: 30, 60, 120 min ...
    for expected_min in (30, 60, 120):
        await _exec("UPDATE client_login_failures SET locked_until = ? WHERE client_ip LIKE 'net:%'",
                    (time.time() - 1,))
        await user_store.verify_credentials("target", WRONG, "198.51.100.77")
        assert net_lock() - time.time() == pytest.approx(expected_min * 60, abs=5)
    # ... up to client_login_backstop_max_lock_hours (24)
    await _exec("UPDATE client_login_failures SET locked_until = ?, failed_attempts = 40 "
                "WHERE client_ip LIKE 'net:%'", (time.time() - 1,))
    await user_store.verify_credentials("target", WRONG, "198.51.100.78")
    assert net_lock() - time.time() == pytest.approx(24 * 3600, abs=5)


# ============ F2: no reset at a window boundary, and a guess-rate bound ============

async def test_F2_account_score_drains_slowly_instead_of_resetting():
    """98fce4b: the account-wide count reset completely when its 60-minute window
    ended. Now it is a score that drains by the limit (100) per 24 hours."""
    await runtime_settings.set("client_login_account_max_failures", 10)
    u = await user_store.create_user("target", PASSWORD)
    for i in range(14):  # from 14 different networks, so none is locked out
        await user_store.verify_credentials("target", WRONG, f"192.0.{i}.1")
    # an hour later (more than any old window), still in backstop mode
    await _exec("UPDATE client_users SET login_score_at = login_score_at - 3600 WHERE id = ?", (u["id"],))
    state = await user_store.get_by_id(u["id"])
    assert state["throttled"] and state["failed_attempts"] == 14  # drained 10/24 per hour
    # after enough time it has drained out
    await _exec("UPDATE client_users SET login_score_at = login_score_at - 2 * 86400 WHERE id = ?", (u["id"],))
    state = await user_store.get_by_id(u["id"])
    assert not state["throttled"] and state["failed_attempts"] == 0


class _Clock:
    def __init__(self) -> None:
        self.now = time.time()

    def time(self) -> float:
        return self.now


async def _simulate_attack(monkeypatch, networks: int, days: int, step_minutes: int = 15) -> list[int]:
    """An attacker with `networks` IPv4 /24s and a fresh address for every
    guess, guessing as fast as the lock-out lets it. Returns the number of
    guesses actually checked (not refused) on each simulated day."""
    clock = _Clock()
    monkeypatch.setattr(user_store, "time", clock)
    monkeypatch.setattr(user_store, "check_password", lambda password, stored: False)
    rec = LogRecorder()
    monkeypatch.setattr(user_store, "logger", rec)
    await user_store.create_user("target", PASSWORD)
    per_day, addr = [], 0
    for _ in range(days):
        before = len([f for f in rec.find("client_login_rejected") if f["reason"] == "bad_password"])
        for _ in range(24 * 60 // step_minutes):
            for n in range(networks):
                for _ in range(120):  # until this network is refused, at most 120 per step
                    addr += 1
                    await user_store.verify_credentials(
                        "target", "guess guess guess", f"198.19.{n}.{addr % 254 + 1}")
                    if rec.find("client_login_rejected")[-1]["reason"] != "bad_password":
                        break
            clock.now += step_minutes * 60
        checked = len([f for f in rec.find("client_login_rejected") if f["reason"] == "bad_password"])
        per_day.append(checked - before)
    return per_day


@pytest.mark.parametrize("networks", [1, 4])
async def test_F2_guesses_per_day_stay_within_the_documented_bound(monkeypatch, networks):
    """docs/CLIENT_PORTAL.md: with the defaults an attacker gets at most about
    199 + 9k checked guesses on the first day and 100 + k per day after, for k
    networks (IPv4 /24 or IPv6 /48). On 98fce4b the same attacker got ~4,000 a day."""
    day1, day2 = await _simulate_attack(monkeypatch, networks, days=2)
    assert day1 <= 199 + 9 * networks + 2, (day1, day2)
    assert day2 <= 100 + networks + 3, (day1, day2)
    assert day2 >= 50  # sanity: the simulation really was guessing at the limit
    print(f"networks={networks} checked guesses: day1={day1} day2={day2}")


# ============================ weak passwords (F2) ============================

@pytest.mark.parametrize("password", [
    "Welcome2026!!", "Password1234", "P@ssw0rd!2026", "qwertyuiop12", "1qaz2wsx3edc",
    "Summer2026Summer", "Tokyo2026Spring!", "iloveyou1234", "123456789012", "aaaaaaaaaaaa",
    "tanaka.a2026!!", "Admin@Eset2026", "abcdefgh1234",
])
async def test_F2_common_passwords_are_refused(password):
    """98fce4b accepted any 12+ characters, including these."""
    with pytest.raises(ValueError, match="too easy to guess"):
        await user_store.create_user("tanaka.a", password)


@pytest.mark.parametrize("password", [
    "correct horse battery", "a brand new passphrase", "Kq7vRz2mWp4x", "tanaka loves green tea",
])
async def test_strong_passwords_and_passphrases_are_accepted(password):
    assert await user_store.create_user("tanaka.a", password)


def test_generated_passwords_always_pass_the_check():
    from src.utils.password_strength import weak_password_reason
    assert not any(weak_password_reason(user_store.generate_password(), "someone") for _ in range(2000))


def test_dashboard_refuses_a_weak_password_with_400(monkeypatch):
    enable_portal(monkeypatch)
    admin = TestClient(app)
    res = admin.post(ADMIN_USERS, json={"username": "weak.one", "password": "Welcome2026!!"}, headers=ENGINEER)
    assert res.status_code == 400 and "too easy to guess" in res.json()["detail"]


# ============================ one generic answer ============================

def test_every_refusal_is_the_same_401_and_runs_the_hash(monkeypatch):
    enable_portal(monkeypatch)
    monkeypatch.setattr(settings, "client_login_max_failures", 2)
    admin = TestClient(app)
    admin_create(admin, "known.user")
    netlocked = admin_create(admin, "netlocked.user")["user"]["id"]
    off = admin_create(admin, "off.user")["user"]["id"]
    admin.post(f"{ADMIN_USERS}/{off}/disable", headers=ENGINEER)
    _sync_exec("INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at, "
               "locked_until) VALUES (?, ?, 3, ?, ?)",
               (netlocked, user_store.network_key(ADDR_B), time.time(), time.time() + 600))
    a = client_from(ADDR_A)
    attempt(a, "known.user", "wrong wrong wrong")
    attempt(a, "known.user", "wrong wrong wrong")

    hashed = []
    real = user_store.check_password
    monkeypatch.setattr(user_store, "check_password", lambda p, s: hashed.append(s) or real(p, s))
    rec = LogRecorder()
    monkeypatch.setattr(user_store, "logger", rec)
    cases = [
        (client_from(ADDR_B), "no.such.user", PASSWORD, "unknown_user"),
        (client_from(ADDR_B), "not a valid name!", PASSWORD, "unknown_user"),
        (client_from(ADDR_B), "known.user", "wrong wrong wrong", "bad_password"),
        (a, "known.user", PASSWORD, "address_locked"),
        (client_from(ADDR_B), "netlocked.user", PASSWORD, "network_locked"),
        (client_from(ADDR_B), "off.user", PASSWORD, "disabled"),
    ]
    for c, username, password, reason in cases:
        res = attempt(c, username, password)
        assert (res.status_code, res.json()) == (401, GENERIC_401), reason
        assert rec.find("client_login_rejected")[-1]["reason"] == reason
    assert len(hashed) == len(cases)


# ============ F5: unknown and real usernames do the same database work ============

class _RecordingConn:
    def __init__(self, conn, log: list[str]) -> None:
        self._conn, self._log = conn, log

    def execute(self, sql: str, params=()):
        verb = sql.split()[0].upper()
        self._log.append({"INSERT": "WRITE", "UPDATE": "WRITE", "DELETE": "WRITE"}.get(verb, verb))
        return self._conn.execute(sql, params)

    async def commit(self) -> None:
        self._log.append("COMMIT")
        await self._conn.commit()

    async def rollback(self) -> None:
        self._log.append("ROLLBACK")
        await self._conn.rollback()

    def __getattr__(self, name):
        return getattr(self._conn, name)


async def test_F5_unknown_and_real_usernames_run_the_same_statements(monkeypatch):
    """98fce4b: an unknown name did one SELECT and the dummy hash; a real
    account also read the policy, opened a second connection and committed a
    write transaction — measurably slower. Now every refusal runs the same
    sequence of statements, settings reads and hash checks."""
    await runtime_settings.set("client_login_account_max_failures", 10)
    await runtime_settings.set("client_login_max_failures", 2)
    await user_store.create_user("real.user", PASSWORD)
    backstopped = await user_store.create_user("backstop.user", PASSWORD)
    await _exec("UPDATE client_users SET login_score = 50, login_score_at = ? WHERE id = ?",
                (time.time(), backstopped["id"]))
    off = await user_store.create_user("off.user", PASSWORD)
    await user_store.set_disabled(off["id"], True)
    for _ in range(2):
        await user_store.verify_credentials("real.user", WRONG, "10.0.0.9")  # lock 10.0.0.9

    log: list[str] = []
    real_session = database.db_session

    @asynccontextmanager
    async def recording_session():
        async with real_session() as conn:
            log.append("OPEN")
            yield _RecordingConn(conn, log)

    gets, hashes = [], []
    real_get, real_check = runtime_settings.get, user_store.check_password
    monkeypatch.setattr(user_store, "db_session", recording_session)
    monkeypatch.setattr(runtime_settings, "get", lambda key: gets.append(key) or real_get(key))
    monkeypatch.setattr(user_store, "check_password", lambda p, s: hashes.append(1) or real_check(p, s))

    traces = {}
    for name, username, ip in [
        ("unknown", "no.such.user", "10.0.0.1"),
        ("malformed", "bad name!", "10.0.0.1"),
        ("wrong_password", "real.user", "10.0.0.2"),
        ("wrong_password_backstop", "backstop.user", "10.0.0.3"),
        ("address_locked", "real.user", "10.0.0.9"),
        ("disabled", "off.user", "10.0.0.4"),
    ]:
        log.clear(), gets.clear(), hashes.clear()
        assert await user_store.verify_credentials(username, WRONG, ip) is None
        traces[name] = (tuple(log), len(gets), len(hashes))
    expected = traces["unknown"]
    assert expected[0] == ("OPEN", "SELECT", "OPEN", "BEGIN", "SELECT", "SELECT", "SELECT",
                           "WRITE", "WRITE", "WRITE", "COMMIT")
    for name, trace in traces.items():
        assert trace == expected, (name, trace)


# ============================ engineer unlock ============================

def test_engineer_sees_and_clears_locks_and_backstop(monkeypatch):
    enable_portal(monkeypatch)
    monkeypatch.setattr(settings, "client_login_max_failures", 2)
    admin = TestClient(app)
    uid = admin_create(admin, "rita")["user"]["id"]
    b = client_from(ADDR_B)
    assert attempt(b, "rita", PASSWORD).status_code == 200   # B becomes a known address
    a = client_from(ADDR_A)
    for _ in range(2):
        attempt(a, "rita", "nope nope nope")
    _sync_exec("UPDATE client_users SET login_score = 500, login_score_at = ? WHERE id = ?", (time.time(), uid))
    _sync_exec("INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at, "
               "locked_until) VALUES (?, 'net:192.0.2.0/24', 9, ?, ?)", (uid, time.time(), time.time() + 3600))

    listed = admin.get(ADMIN_USERS, headers=ENGINEER).json()["users"][0]
    assert listed["locked"] is True and listed["locked_addresses"] == 1
    assert listed["locked_networks"] == 1 and listed["throttled"] is True
    assert attempt(a, "rita", PASSWORD).status_code == 401
    assert attempt(client_from("192.0.2.1"), "rita", PASSWORD).status_code == 401

    user = admin.post(f"{ADMIN_USERS}/{uid}/unlock", headers=ENGINEER).json()["user"]
    assert user["locked"] is False and user["locked_addresses"] == user["locked_networks"] == 0
    assert user["throttled"] is False and user["failed_attempts"] == 0
    assert attempt(a, "rita", PASSWORD).status_code == 200
    assert attempt(client_from("192.0.2.1"), "rita", PASSWORD).status_code == 200
    known = sqlite3.connect(settings.sqlite_db_path).execute(
        "SELECT COUNT(*) FROM client_login_failures WHERE user_id = ? AND last_success_at IS NOT NULL",
        (uid,)).fetchone()[0]
    assert known == 3


# ======================= no typed username in the log (F6) =======================

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
    enable_portal(monkeypatch)
    caplog.set_level(logging.INFO)
    pasted_password = user_store.generate_password()
    assert user_store.USERNAME_RE.match(pasted_password)
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


async def test_F6_unknown_username_is_logged_without_any_identifier(monkeypatch):
    """98fce4b logged attempt=<12 hex of HMAC(typed name)>: someone with log
    access could test a candidate name by submitting it and comparing. Now an
    unknown name leaves only the reason and the address."""
    rec = LogRecorder()
    monkeypatch.setattr(user_store, "logger", rec)
    await user_store.verify_credentials("Some.Name", WRONG, "10.1.2.3")
    await user_store.verify_credentials("some.name", WRONG, "10.1.2.3")
    assert rec.find("client_login_rejected") == [{"reason": "unknown_user", "client_ip": "10.1.2.3"}] * 2
    assert not hasattr(user_store, "attempt_fingerprint")


def test_redaction_backstop_covers_username_fields():
    from src.utils.logging import redact_secrets
    out = redact_secrets({"username": "typed", "user_name": "typed", "nested": {"login": "typed"},
                          "account": "kept", "event": "POST /x?username=typed&page=2"})
    assert "typed" not in repr(out)
    assert out["account"] == "kept" and "page=2" in out["event"]


# ============================ migration ============================

# client_users / client_sessions exactly as created before the lock-out rework.
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
# ... and what 98fce4b added on top.
_98FCE4B_ADDITIONS = """
ALTER TABLE client_users ADD COLUMN failure_window_start REAL;
CREATE TABLE client_login_failures (
    user_id TEXT NOT NULL REFERENCES client_users(id) ON DELETE CASCADE,
    client_ip TEXT NOT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at REAL, locked_until REAL, last_success_at REAL,
    PRIMARY KEY (user_id, client_ip)
);
"""


@pytest.mark.parametrize("starting_point", ["before_rework", "98fce4b"])
async def test_init_db_migrates_an_older_database_idempotently(tmp_path, monkeypatch, starting_point):
    old_db = tmp_path / "old.db"
    conn = sqlite3.connect(old_db)
    conn.executescript(_OLD_SCHEMA + (_98FCE4B_ADDITIONS if starting_point == "98fce4b" else ""))
    now = time.time()
    # an account caught in an account-wide lock / slow-down at upgrade time
    conn.execute("INSERT INTO client_users (id, username, password_hash, failed_attempts, locked_until, "
                 "created_at) VALUES ('usr_old', 'old.client', ?, 10, ?, ?)",
                 (user_store.hash_password(PASSWORD), now + 900, now - 86400))
    conn.commit()
    conn.close()
    monkeypatch.setattr(settings, "sqlite_db_path", str(old_db))

    await database.init_db()
    db = sqlite3.connect(old_db)
    cols = {r[1] for r in db.execute("PRAGMA table_info(client_users)")}
    assert {"login_score", "login_score_at"} <= cols
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"client_login_failures", "client_login_pad"} <= tables
    assert db.execute("SELECT failed_attempts, locked_until FROM client_users").fetchone() == (0, None)
    user = await user_store.get_by_id("usr_old")
    assert user["locked"] is False and user["throttled"] is False and user["username"] == "old.client"
    assert await user_store.verify_credentials("old.client", WRONG, ADDR_A) is None
    assert await user_store.verify_credentials("old.client", PASSWORD, ADDR_B)

    before = db.execute("SELECT login_score, login_score_at FROM client_users").fetchone()
    await database.init_db()
    await database.init_db()
    assert db.execute("SELECT login_score, login_score_at FROM client_users").fetchone() == before
    assert before[0] == pytest.approx(1, abs=0.01)
    assert db.execute("SELECT COUNT(*) FROM client_login_failures").fetchone()[0] == 2


# ============================ pruning (F3) ============================

async def test_lockout_rows_are_pruned():
    u = await user_store.create_user("prune.me", PASSWORD)
    now = time.time()
    day = 86400
    rows = [  # (client_ip, last_failed_at, locked_until, last_success_at, kept?)
        ("1.0.0.1", now - 2 * day, None, None, False),             # stale failures
        ("1.0.0.2", now - 60, None, None, True),                   # recent failure
        ("1.0.0.3", now - 2 * day, now + 600, None, True),         # still locked
        ("1.0.0.4", None, None, now - 10 * day, True),             # known address
        ("1.0.0.5", None, None, now - 40 * day, False),            # no longer known
        ("net:2.0.0.0/24", now - 3 * day, now - 1, None, True),    # network: kept 7 days
        ("net:3.0.0.0/24", now - 8 * day, None, None, False),
    ]
    for ip, failed_at, lock, success, _ in rows:
        await _exec("INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at, "
                    "locked_until, last_success_at) VALUES (?, ?, 3, ?, ?, ?)",
                    (u["id"], ip, failed_at, lock, success))
    assert await user_store.purge_login_failures() == 3
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        async with conn.execute("SELECT client_ip FROM client_login_failures ORDER BY client_ip") as cur:
            left = [r[0] for r in await cur.fetchall()]
    assert left == sorted(ip for ip, *_, kept in rows if kept)

    # and it runs by itself after an attempt (at most once per interval)
    await _exec("INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at) "
                "VALUES (?, '1.0.0.9', 1, ?)", (u["id"], now - 2 * day))
    user_store._last_login_failure_prune = 0.0
    await user_store.verify_credentials("nobody.here", WRONG, "1.0.0.10")
    assert await _scalar("SELECT COUNT(*) FROM client_login_failures WHERE client_ip = '1.0.0.9'") == 0


async def test_F3_a_flood_of_failure_rows_cannot_evict_a_known_address(monkeypatch):
    """98fce4b capped the table by evicting the oldest activity of ANY row, so an
    attacker creating enough failure rows pushed out the victim's known address
    (its sign-in was the oldest activity). Now rows that mark a known address
    are never evicted, and address rows go before network rows."""
    victim = await user_store.create_user("victim", PASSWORD)
    other = await user_store.create_user("other", PASSWORD)
    now = time.time()
    await _exec("INSERT INTO client_login_failures (user_id, client_ip, last_success_at) "
                "VALUES (?, '203.0.113.20', ?)", (victim["id"], now - 20 * 86400))
    for i in range(10):
        await _exec("INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at) "
                    "VALUES (?, ?, 1, ?)", (other["id"], f"198.51.100.{i}", now - 60 + i))
    await _exec("INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at) "
                "VALUES (?, 'net:198.51.100.0/24', 3, ?)", (other["id"], now - 3600))
    monkeypatch.setattr(user_store, "LOGIN_FAILURE_MAX_ROWS", 4)
    assert await user_store.purge_login_failures() == 7
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        async with conn.execute("SELECT client_ip FROM client_login_failures") as cur:
            left = {r[0] for r in await cur.fetchall()}
    assert "203.0.113.20" in left and "net:198.51.100.0/24" in left
    assert left - {"203.0.113.20", "net:198.51.100.0/24"} == {"198.51.100.7", "198.51.100.8", "198.51.100.9"}


# ================= F4: a proxy that is not trusted is reported =================

def test_F4_login_behind_an_untrusted_proxy_logs_a_warning(monkeypatch):
    """98fce4b: behind a host-side proxy in the Docker setup every client looked
    like the bridge gateway and nothing said so. Now the login logs
    untrusted_proxy_headers, at most hourly per peer."""
    enable_portal(monkeypatch)
    rec = LogRecorder()
    monkeypatch.setattr(security, "logger", rec)
    monkeypatch.setattr(security, "_untrusted_proxy_warned", {})
    gateway = client_from("172.18.0.1")
    for _ in range(3):
        gateway.post(LOGIN_PATH, json={"username": "x.y", "password": "z" * 12},
                     headers={"X-Forwarded-For": "203.0.113.5"})
    warned = rec.find("untrusted_proxy_headers")
    assert len(warned) == 1 and warned[0]["peer"] == "172.18.0.1"
    # no warning without the header, or from a public peer sending its own header
    gateway.post(LOGIN_PATH, json={"username": "x.y", "password": "z" * 12})
    client_from("8.8.4.4").post(LOGIN_PATH, json={"username": "x.y", "password": "z" * 12},
                                     headers={"X-Forwarded-For": "1.2.3.4"})
    assert len(rec.find("untrusted_proxy_headers")) == 1


def test_F4_compose_trusts_the_docker_gateway_and_takes_the_real_client():
    """docker-compose.yml sets FORWARDED_ALLOW_IPS so that a proxy on the host
    (arriving through the bridge gateway) is trusted. uvicorn then takes the
    client from the right of X-Forwarded-For, so a header the client forged
    itself is not believed."""
    import re
    from pathlib import Path
    from uvicorn.middleware.proxy_headers import _TrustedHosts
    compose = (Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text()
    m = re.search(r'^\s*FORWARDED_ALLOW_IPS:\s*"([^"]+)"', compose, re.M)
    assert m, "docker-compose.yml must set FORWARDED_ALLOW_IPS"
    trusted = _TrustedHosts(m.group(1))
    assert not trusted.always_trust
    for gateway in ("172.17.0.1", "172.18.0.1", "192.168.16.1", "127.0.0.1"):
        assert gateway in trusted, gateway
    # host nginx appends the real client to whatever the client sent
    assert trusted.get_trusted_client_address("6.6.6.6, 203.0.113.5")[0] == "203.0.113.5"
    assert "203.0.113.5" not in trusted
