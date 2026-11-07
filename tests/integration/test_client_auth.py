"""
Client portal accounts and sessions: user_store (hashing, policy, lockout,
idle/absolute expiry, revocation), the login/logout/me API, the engineer account
management API (portal_admin) and the portal prerequisites guard.
"""
import time

import aiosqlite
import pytest
from fastapi.testclient import TestClient

from client_auth_helpers import (
    ADMIN_USERS, ENGINEER, ENGINEER_KEY, LOGIN_PATH, PASSWORD, LogRecorder,
    admin_create, enable_portal, login, session_header,
)
from src.config import settings
from src.middleware import security
from src.services import portal_guard
from src.storage import runtime_settings, user_store


async def _exec(sql: str, params: tuple = ()) -> None:
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute(sql, params)
        await conn.commit()


async def _scalar(sql: str, params: tuple = ()):
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        async with conn.execute(sql, params) as cur:
            row = await cur.fetchone()
    return row[0] if row else None


# ============================== user_store ==============================

def test_hash_format_and_check():
    h = user_store.hash_password(PASSWORD)
    scheme, n, r, p, salt, digest = h.split("$")
    assert (scheme, n, r, p) == ("scrypt", str(2 ** 14), "8", "1")
    import base64
    assert len(base64.b64decode(salt)) == 16
    assert user_store.check_password(PASSWORD, h)
    assert not user_store.check_password(PASSWORD + "x", h)
    assert user_store.hash_password(PASSWORD) != h  # salted
    for bad in ("", "plain", "scrypt$1$2$3$x$y", "bcrypt$16384$8$1$AAAA$AAAA", "scrypt$a$b$c$d$e"):
        assert not user_store.check_password(PASSWORD, bad)


async def test_create_user_and_never_expose_hash():
    u = await user_store.create_user("  Alice.Corp@x-1  ", PASSWORD, " Alice ")
    assert u["username"] == "Alice.Corp@x-1" and u["display_name"] == "Alice"
    assert u["role"] == "client" and u["disabled"] is False and u["locked"] is False
    assert u["id"].startswith("usr_")
    assert "password_hash" not in u
    for fetched in (await user_store.get_by_id(u["id"]), await user_store.get_by_username("alice.corp@X-1"),
                    (await user_store.list_users())[0]):
        assert fetched["id"] == u["id"] and "password_hash" not in fetched
    stored = await _scalar("SELECT password_hash FROM client_users WHERE id = ?", (u["id"],))
    assert stored.startswith("scrypt$") and PASSWORD not in stored


async def test_username_is_unique_case_insensitively():
    await user_store.create_user("alice", PASSWORD)
    with pytest.raises(user_store.DuplicateUsernameError):
        await user_store.create_user("ALICE", PASSWORD)
    with pytest.raises(ValueError):
        await user_store.create_user("Alice", PASSWORD)


@pytest.mark.parametrize("username", ["ab", "a" * 65, "has space", "émile", "a/b", "", "x;drop"])
async def test_username_policy(username):
    with pytest.raises(ValueError):
        await user_store.create_user(username, PASSWORD)


@pytest.mark.parametrize("password", ["short", "x" * 11, "y" * 257, " " * 20, "sameasuser01"])
async def test_password_policy(password):
    with pytest.raises(ValueError):
        await user_store.create_user("sameasuser01", password)


async def test_password_policy_boundaries():
    await user_store.create_user("edge1", "x" * 12)
    await user_store.create_user("edge2", "y" * 256)


async def test_verify_credentials_success_and_failures():
    u = await user_store.create_user("bob", PASSWORD)
    ok = await user_store.verify_credentials("BOB", PASSWORD, "1.1.1.1")
    assert ok["id"] == u["id"] and ok["last_login_at"] and "password_hash" not in ok
    assert await user_store.verify_credentials("bob", PASSWORD + "!", "1.1.1.1") is None
    assert await user_store.verify_credentials("nobody", PASSWORD, "1.1.1.1") is None
    assert await user_store.verify_credentials("", "", "1.1.1.1") is None
    assert await user_store.verify_credentials("bob", PASSWORD + "z" * 300, "1.1.1.1") is None


async def test_unknown_user_still_runs_the_hash(monkeypatch):
    calls = []
    real = user_store.check_password

    def spy(password, stored):
        calls.append(stored)
        return real(password, stored)

    monkeypatch.setattr(user_store, "check_password", spy)
    assert await user_store.verify_credentials("ghost", PASSWORD, "ip") is None
    assert await user_store.verify_credentials("not a valid name!", PASSWORD, "ip") is None
    assert len(calls) == 2 and all(c.startswith("scrypt$") for c in calls)


async def _pair(user_id: str, ip: str):
    """(failed_attempts, locked_until, last_success_at) of one (account, address) row."""
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        async with conn.execute(
            "SELECT failed_attempts, locked_until, last_success_at FROM client_login_failures "
            "WHERE user_id = ? AND client_ip = ?", (user_id, ip)) as cur:
            return await cur.fetchone()


async def test_lockout_after_max_failures_and_expiry():
    """The lock is per (account, address): it refuses the correct password from
    the locked address only, and runs out after client_login_lockout_minutes."""
    await runtime_settings.set("client_login_max_failures", 3)
    await runtime_settings.set("client_login_lockout_minutes", 5)
    u = await user_store.create_user("carol", PASSWORD)
    for _ in range(2):
        assert await user_store.verify_credentials("carol", "wrong-password!", "ip") is None
    assert (await _pair(u["id"], "ip"))[0] == 2
    assert not (await user_store.get_by_id(u["id"]))["locked"]
    assert await user_store.verify_credentials("carol", "wrong-password!", "ip") is None
    locked = await user_store.get_by_id(u["id"])
    assert locked["locked"] and locked["locked_addresses"] == 1 and not locked["throttled"]
    assert locked["locked_until"] > time.time() + 200
    # correct password is refused from the locked address, indistinguishably
    assert await user_store.verify_credentials("carol", PASSWORD, "ip") is None
    # lock runs out -> fresh start
    await _exec("UPDATE client_login_failures SET locked_until = ? WHERE user_id = ?", (time.time() - 1, u["id"]))
    ok = await user_store.verify_credentials("carol", PASSWORD, "ip")
    assert ok and ok["locked"] is False and ok["locked_until"] is None
    failed, lock, last_success = await _pair(u["id"], "ip")
    assert failed == 0 and lock is None and last_success > time.time() - 5


async def test_expired_lock_restarts_the_failure_count():
    await runtime_settings.set("client_login_max_failures", 3)
    u = await user_store.create_user("dora", PASSWORD)
    await _exec("INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at, "
                "locked_until) VALUES (?, 'ip', 3, ?, ?)", (u["id"], time.time() - 400, time.time() - 1))
    assert await user_store.verify_credentials("dora", "wrong-password!", "ip") is None
    assert (await _pair(u["id"], "ip"))[:2] == (1, None)
    assert not (await user_store.get_by_id(u["id"]))["locked"]


async def test_concurrent_wrong_passwords_all_count_towards_the_lockout():
    """Regression: the failure count was read before the slow hash check and
    written back as read+1, so a burst of parallel guesses counted as ONE failure
    and never locked the account."""
    import asyncio
    await runtime_settings.set("client_login_max_failures", 5)
    u = await user_store.create_user("burst", PASSWORD)
    results = await asyncio.gather(*(
        user_store.verify_credentials("burst", f"wrong-password-{i:02d}", "ip") for i in range(12)))
    assert results == [None] * 12
    after = await user_store.get_by_id(u["id"])
    assert after["locked"] is True and after["locked_addresses"] == 1
    assert (await _pair(u["id"], "ip"))[0] == 5
    # attempts refused by the lock are not counted against the account either
    assert after["failed_attempts"] == 5
    assert await user_store.verify_credentials("burst", PASSWORD, "ip") is None


@pytest.mark.parametrize("lock_sql", [
    # the address got locked out while this request was hashing
    "INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at, locked_until) "
    "VALUES (:id, 'ip', 10, :now, :later)",
    # the account-wide slow-down started while this request was hashing
    "UPDATE client_users SET locked_until = :later WHERE id = :id",
])
async def test_correct_password_refused_if_the_account_locked_during_the_hash(monkeypatch, lock_sql):
    """Regression: the lock state was taken from the row read before hashing, so
    a correct guess racing a burst that locked the account still logged in."""
    import sqlite3
    u = await user_store.create_user("racer", PASSWORD)
    real = user_store.check_password

    def lock_then_check(password, stored):
        conn = sqlite3.connect(settings.sqlite_db_path)
        conn.execute(lock_sql, {"id": u["id"], "now": time.time(), "later": time.time() + 600})
        conn.commit()
        conn.close()
        return real(password, stored)

    monkeypatch.setattr(user_store, "check_password", lock_then_check)
    assert await user_store.verify_credentials("racer", PASSWORD, "ip") is None
    assert (await user_store.get_by_id(u["id"]))["last_login_at"] is None


async def test_concurrent_logins_cannot_outrun_the_address_throttle(monkeypatch):
    """Regression: the per-address limit was checked before the (slow) credential
    check and recorded after it, so parallel logins all passed the check."""
    import asyncio
    import httpx
    from src.main import app
    enable_portal(monkeypatch)
    monkeypatch.setattr(security.auth_limiter, "max_failures", 3)
    calls = []

    async def slow_reject(username, password, client_ip):
        calls.append(username)
        await asyncio.sleep(0.05)
        return None

    monkeypatch.setattr(user_store, "verify_credentials", slow_reject)
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        responses = await asyncio.gather(*(
            ac.post(LOGIN_PATH, json={"username": f"user{i}", "password": "nope nope nope"})
            for i in range(10)))
    codes = sorted(r.status_code for r in responses)
    assert codes == [401] * 3 + [429] * 7, codes
    assert len(calls) == 3


def test_oversized_client_api_bodies_are_refused_before_parsing(client: TestClient, monkeypatch):
    """Regression: the unauthenticated login read and parsed bodies of any size
    (a few 200 MB posts took the process to ~2 GB)."""
    enable_portal(monkeypatch)
    admin_create(client, "bulky")
    pad = "x" * (security.CLIENT_API_MAX_BODY_BYTES + 1)
    res = client.post(LOGIN_PATH, json={"username": "bulky", "password": PASSWORD, "pad": pad})
    assert res.status_code == 413 and res.json() == {"detail": "Request body too large"}
    # chunked (no Content-Length) is counted too
    chunks = (b'{"username": "bulky", "password": "' + b"y" * 40_000 + b'"}' for _ in range(2))
    res = client.post(LOGIN_PATH, content=chunks, headers={"Content-Type": "application/json"})
    assert res.status_code == 413
    # normal bodies still work, including export's
    token = login(client, "bulky")
    res = client.post("/client/api/alerts/export", json={"fields": ["alert_id"]}, headers=session_header(token))
    assert res.status_code == 200, res.text


def test_successful_login_is_not_counted_by_the_address_throttle(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    monkeypatch.setattr(security.auth_limiter, "max_failures", 3)
    admin_create(client, "steady")
    for _ in range(5):
        assert login(client, "steady")


async def test_unlock_and_set_password_clear_lockout():
    await runtime_settings.set("client_login_max_failures", 1)
    u = await user_store.create_user("erin", PASSWORD)
    await user_store.verify_credentials("erin", "wrong-password!", "ip")
    assert (await user_store.get_by_id(u["id"]))["locked"]
    await user_store.unlock_user(u["id"])
    assert await user_store.verify_credentials("erin", PASSWORD, "ip")
    await user_store.verify_credentials("erin", "wrong-password!", "ip")
    assert (await user_store.get_by_id(u["id"]))["locked"]
    await user_store.set_password(u["id"], "a brand new passphrase")
    assert not (await user_store.get_by_id(u["id"]))["locked"]
    # a password reset also forgets the account's known addresses
    assert await _scalar("SELECT COUNT(*) FROM client_login_failures WHERE user_id = ?", (u["id"],)) == 0
    assert await user_store.verify_credentials("erin", "a brand new passphrase", "ip")
    assert await user_store.verify_credentials("erin", PASSWORD, "ip") is None


async def test_disabled_user_cannot_log_in():
    u = await user_store.create_user("frank", PASSWORD)
    await user_store.set_disabled(u["id"], True)
    assert await user_store.verify_credentials("frank", PASSWORD, "ip") is None
    await user_store.set_disabled(u["id"], False)
    assert await user_store.verify_credentials("frank", PASSWORD, "ip")


async def test_unknown_ids_raise_lookup_error():
    for call in (user_store.set_password("nope", PASSWORD), user_store.set_disabled("nope", True),
                 user_store.unlock_user("nope")):
        with pytest.raises(LookupError):
            await call
    assert await user_store.delete_user("nope") is False
    assert await user_store.get_by_id("nope") is None


async def test_session_roundtrip_and_token_stored_hashed():
    u = await user_store.create_user("gina", PASSWORD)
    token, expires_at = await user_store.create_session(u["id"], "10.0.0.1")
    assert len(token) >= 40
    assert expires_at == pytest.approx(time.time() + 12 * 3600, abs=5)
    assert await _scalar("SELECT COUNT(*) FROM client_sessions WHERE token_hash = ?", (token,)) == 0
    resolved = await user_store.resolve_session(token)
    assert resolved["id"] == u["id"] and "password_hash" not in resolved
    assert resolved["session_expires_at"] <= expires_at
    assert await user_store.resolve_session("not-a-token") is None
    assert await user_store.resolve_session("") is None
    await user_store.delete_session(token)
    await user_store.delete_session(token)  # idempotent
    assert await user_store.resolve_session(token) is None


async def test_idle_timeout_and_last_seen_sliding():
    await runtime_settings.set("client_session_idle_minutes", 10)
    u = await user_store.create_user("hank", PASSWORD)
    token, _ = await user_store.create_session(u["id"], "ip")
    # 9 minutes idle: still alive, and the lookup slides last_seen_at
    await _exec("UPDATE client_sessions SET last_seen_at = ?", (time.time() - 540,))
    assert await user_store.resolve_session(token)
    assert await _scalar("SELECT last_seen_at FROM client_sessions") > time.time() - 5
    # 11 minutes idle: gone (and the row is removed)
    await _exec("UPDATE client_sessions SET last_seen_at = ?", (time.time() - 660,))
    assert await user_store.resolve_session(token) is None
    assert await _scalar("SELECT COUNT(*) FROM client_sessions") == 0


async def test_last_seen_writes_are_throttled():
    u = await user_store.create_user("ivan", PASSWORD)
    token, _ = await user_store.create_session(u["id"], "ip")
    t0 = time.time() - 10
    await _exec("UPDATE client_sessions SET last_seen_at = ?", (t0,))
    assert await user_store.resolve_session(token)
    assert await _scalar("SELECT last_seen_at FROM client_sessions") == t0


async def test_absolute_expiry_even_when_active():
    await runtime_settings.set("client_session_max_hours", 2)
    u = await user_store.create_user("jane", PASSWORD)
    token, _ = await user_store.create_session(u["id"], "ip")
    await _exec("UPDATE client_sessions SET expires_at = ?", (time.time() - 1,))
    assert await user_store.resolve_session(token) is None
    # a shortened max lifetime applies to sessions that already exist
    token, _ = await user_store.create_session(u["id"], "ip")
    await _exec("UPDATE client_sessions SET created_at = ?, last_seen_at = ?",
                (time.time() - 3 * 3600, time.time()))
    assert await user_store.resolve_session(token) is None


async def test_disable_password_reset_and_delete_revoke_sessions():
    u = await user_store.create_user("kate", PASSWORD)
    t1, _ = await user_store.create_session(u["id"], "ip")
    await user_store.set_password(u["id"], "another long passphrase")
    assert await user_store.resolve_session(t1) is None

    t2, _ = await user_store.create_session(u["id"], "ip")
    await user_store.set_disabled(u["id"], True)
    assert await user_store.resolve_session(t2) is None
    await user_store.set_disabled(u["id"], False)

    t3, _ = await user_store.create_session(u["id"], "ip")
    t4, _ = await user_store.create_session(u["id"], "ip")
    assert (await user_store.list_users())[0]["active_sessions"] == 2
    assert await user_store.revoke_sessions(u["id"]) == 2
    assert await user_store.resolve_session(t3) is None and await user_store.resolve_session(t4) is None

    t5, _ = await user_store.create_session(u["id"], "ip")
    assert await user_store.delete_user(u["id"]) is True
    assert await user_store.resolve_session(t5) is None
    assert await _scalar("SELECT COUNT(*) FROM client_sessions") == 0


async def test_disabled_user_session_rejected_even_if_row_survives():
    u = await user_store.create_user("liam", PASSWORD)
    token, _ = await user_store.create_session(u["id"], "ip")
    await _exec("UPDATE client_users SET disabled = 1")
    assert await user_store.resolve_session(token) is None


async def test_purge_expired_sessions_and_active_counts():
    await runtime_settings.set("client_session_idle_minutes", 10)
    u = await user_store.create_user("mia", PASSWORD)
    live, _ = await user_store.create_session(u["id"], "ip")
    idle, _ = await user_store.create_session(u["id"], "ip")
    old, _ = await user_store.create_session(u["id"], "ip")
    import hashlib
    h = lambda t: hashlib.sha256(t.encode()).hexdigest()  # noqa: E731
    await _exec("UPDATE client_sessions SET last_seen_at = ? WHERE token_hash = ?", (time.time() - 3600, h(idle)))
    await _exec("UPDATE client_sessions SET expires_at = ? WHERE token_hash = ?", (time.time() - 1, h(old)))
    assert (await user_store.list_users())[0]["active_sessions"] == 1
    assert await user_store.purge_expired_sessions() == 2
    assert await user_store.resolve_session(live)
    assert await user_store.purge_expired_sessions() == 0


# ============================== login / logout / me ==============================

def test_login_me_logout_happy_path(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    admin_create(client, "nina", display_name="Nina K")
    res = client.post(LOGIN_PATH, json={"username": "NINA", "password": PASSWORD})
    assert res.status_code == 200
    body = res.json()
    assert set(body) == {"token", "expires_at", "idle_timeout_seconds", "user"}
    assert body["user"] == {"username": "nina", "display_name": "Nina K"}
    assert body["idle_timeout_seconds"] == 3600
    assert res.headers["cache-control"] == "no-store"
    token = body["token"]

    me = client.get("/client/api/auth/me", headers=session_header(token))
    assert me.status_code == 200
    assert me.json()["user"] == {"username": "nina", "display_name": "Nina K"}
    assert me.json()["expires_at"] <= body["expires_at"]
    assert me.headers["cache-control"] == "no-store"

    assert client.post("/client/api/auth/logout", headers=session_header(token)).json() == {"ok": True}
    assert client.get("/client/api/auth/me", headers=session_header(token)).status_code == 401
    assert client.post("/client/api/auth/logout", headers=session_header(token)).status_code == 401


def test_login_failures_are_generic(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    admin_create(client, "oscar")
    disabled = admin_create(client, "olga")["user"]
    client.post(f"{ADMIN_USERS}/{disabled['id']}/disable", headers=ENGINEER)
    bodies = []
    for username, password in [("oscar", "wrong password!!"), ("nobody", PASSWORD), ("olga", PASSWORD),
                               ("", ""), ("bad name!", PASSWORD)]:
        res = client.post(LOGIN_PATH, json={"username": username, "password": password})
        assert res.status_code == 401, (username, res.text)
        bodies.append(res.json())
    assert all(b == {"detail": "Invalid username or password"} for b in bodies)


def test_login_rejects_malformed_body(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    assert client.post(LOGIN_PATH, json={"username": "x" * 300, "password": "y"}).status_code == 422
    assert client.post(LOGIN_PATH).status_code == 422


def test_session_only_via_header(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    admin_create(client, "paula")
    token = login(client, "paula")
    assert client.get("/client/api/auth/me").status_code == 401
    assert client.get("/client/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    client.cookies.set("X-Client-Session", token)
    assert client.get("/client/api/auth/me").status_code == 401
    client.cookies.clear()
    assert client.get(f"/client/api/auth/me?token={token}").status_code == 401
    assert client.get("/client/api/auth/me", headers={"X-Client-Session": "garbage"}).json() == {
        "detail": "Not authenticated"}


def test_login_is_throttled_per_address(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    monkeypatch.setattr(security.auth_limiter, "max_failures", 3)
    admin_create(client, "quinn")
    for _ in range(3):
        assert client.post(LOGIN_PATH, json={"username": "quinn", "password": "nope nope nope"}).status_code == 401
    blocked = client.post(LOGIN_PATH, json={"username": "quinn", "password": PASSWORD})
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) > 0


def test_account_lockout_through_api(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    monkeypatch.setattr(settings, "client_login_max_failures", 2)
    created = admin_create(client, "rita")["user"]
    for _ in range(2):
        client.post(LOGIN_PATH, json={"username": "rita", "password": "nope nope nope"})
    res = client.post(LOGIN_PATH, json={"username": "rita", "password": PASSWORD})
    assert res.status_code == 401 and res.json() == {"detail": "Invalid username or password"}
    listed = client.get(ADMIN_USERS, headers=ENGINEER).json()["users"][0]
    assert listed["locked"] is True
    assert client.post(f"{ADMIN_USERS}/{created['id']}/unlock", headers=ENGINEER).json()["user"]["locked"] is False
    assert login(client, "rita")


def test_audit_events_contain_no_secrets(client: TestClient, monkeypatch):
    from src.api import client_auth, portal_admin
    enable_portal(monkeypatch)
    rec = LogRecorder()
    store_rec = LogRecorder()
    monkeypatch.setattr(client_auth, "logger", rec)
    monkeypatch.setattr(portal_admin, "logger", rec)
    monkeypatch.setattr(user_store, "logger", store_rec)

    created = client.post(ADMIN_USERS, json={"username": "sam"}, headers=ENGINEER).json()
    generated = created["generated_password"]
    reset = client.post(f"{ADMIN_USERS}/{created['user']['id']}/password", json={}, headers=ENGINEER).json()
    new_pw = reset["generated_password"]
    bad = client.post(LOGIN_PATH, json={"username": "sam", "password": "typo-password-1"})
    pw_in_user_box = client.post(LOGIN_PATH, json={"username": "MySecretPass#1 x", "password": "z"})
    assert bad.status_code == pw_in_user_box.status_code == 401
    token = login(client, "sam", new_pw)
    client.post("/client/api/auth/logout", headers=session_header(token))

    events = rec.events()
    for expected in ("client_user_created", "client_user_password_reset", "client_login_failed",
                     "client_login_succeeded", "client_logout"):
        assert expected in events, events
    # successful sign-ins name the account by its stored name; failed ones never
    # carry what was typed into the username box (not even a valid-looking name)
    assert rec.find("client_login_succeeded")[0]["account"] == "sam"
    assert rec.find("client_user_created")[0]["account"] == "sam"
    failed = rec.find("client_login_failed")
    assert len(failed) == 2 and all(set(f) == {"client_ip"} for f in failed)
    assert all("username" not in fields for _, _, fields in rec.records + store_rec.records)
    assert "bad_password" in store_rec.dump()
    unknown = [f for f in store_rec.find("client_login_rejected") if f["reason"] == "unknown_user"]
    assert len(unknown) == 1 and len(unknown[0]["attempt"]) == 12
    everything = rec.dump() + store_rec.dump()
    for secret in (generated, new_pw, token, "typo-password-1", "MySecretPass#1", ENGINEER_KEY):
        assert secret not in everything


# ============================== portal disabled / guard ==============================

def test_portal_disabled_by_default(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", ENGINEER_KEY)
    monkeypatch.setattr(settings, "client_portal_enabled", False)
    admin_create(client, "tom")
    disabled = {"detail": "client portal disabled"}
    res = client.post(LOGIN_PATH, json={"username": "tom", "password": PASSWORD})
    assert (res.status_code, res.json()) == (404, disabled)
    res = client.get("/client/api/auth/me", headers=session_header("anything"))
    assert (res.status_code, res.json()) == (404, disabled)


async def test_runtime_switch_controls_the_portal(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    admin_create(client, "uma")
    token = login(client, "uma")
    await runtime_settings.set("client_portal_enabled", False)
    assert client.get("/client/api/auth/me", headers=session_header(token)).status_code == 404
    await runtime_settings.set("client_portal_enabled", True)
    assert client.get("/client/api/auth/me", headers=session_header(token)).status_code == 200


@pytest.mark.parametrize("key", ["", "short-key"])
def test_portal_refuses_service_with_blank_or_weak_dashboard_key(client: TestClient, monkeypatch, key):
    enable_portal(monkeypatch)
    admin_create(client, "vera")
    token = login(client, "vera")
    monkeypatch.setattr(settings, "dashboard_access_key", key)
    assert client.post(LOGIN_PATH, json={"username": "vera", "password": PASSWORD}).status_code == 404
    assert client.get("/client/api/auth/me", headers=session_header(token)).status_code == 404


def test_portal_prerequisites_ok(monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", "")
    ok, reason = portal_guard.portal_prerequisites_ok()
    assert not ok and "blank" in reason
    monkeypatch.setattr(settings, "dashboard_access_key", "x" * 15)
    ok, reason = portal_guard.portal_prerequisites_ok()
    assert not ok and "shorter" in reason
    monkeypatch.setattr(settings, "dashboard_access_key", "x" * 16)
    assert portal_guard.portal_prerequisites_ok() == (True, "")


async def test_startup_guard(monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", "")
    monkeypatch.setattr(settings, "client_portal_enabled", False)
    monkeypatch.setattr(settings, "app_env", "production")
    await portal_guard.check_at_startup()  # portal off: nothing to enforce
    await runtime_settings.set("client_portal_enabled", True)  # dashboard override wins over env
    with pytest.raises(RuntimeError, match="client portal"):
        await portal_guard.check_at_startup()
    monkeypatch.setattr(settings, "app_env", "development")
    rec = LogRecorder()
    monkeypatch.setattr(portal_guard, "logger", rec)
    await portal_guard.check_at_startup()  # logs, does not raise
    assert "client_portal_unsafe_config" in rec.events()
    monkeypatch.setattr(settings, "dashboard_access_key", ENGINEER_KEY)
    monkeypatch.setattr(settings, "app_env", "production")
    await portal_guard.check_at_startup()


def test_production_config_flags_portal_with_weak_key(monkeypatch):
    from src import main
    monkeypatch.setattr(settings, "client_portal_enabled", True)
    monkeypatch.setattr(settings, "dashboard_access_key", "short")
    assert any("CLIENT_PORTAL_ENABLED" in p for p in main.production_config_problems())
    monkeypatch.setattr(settings, "dashboard_access_key", ENGINEER_KEY)
    assert not any("CLIENT_PORTAL_ENABLED" in p for p in main.production_config_problems())


# ============================== engineer account management ==============================

def test_admin_create_with_generated_password(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    res = client.post(ADMIN_USERS, json={"username": "walt", "display_name": "Walt"}, headers=ENGINEER)
    assert res.status_code == 201
    body = res.json()
    pw = body["generated_password"]
    assert len(pw) >= 20
    assert "password_hash" not in body["user"] and "password" not in body["user"]
    assert login(client, "walt", pw)
    # returned once: never again in a listing
    listing = client.get(ADMIN_USERS, headers=ENGINEER)
    assert pw not in listing.text and "scrypt$" not in listing.text
    assert listing.json()["users"][0]["active_sessions"] == 1


def test_admin_create_with_explicit_password_returns_no_generated(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    body = admin_create(client, "xena")
    assert "generated_password" not in body
    assert PASSWORD not in str(body)


@pytest.mark.parametrize("payload,status,fragment", [
    ({"username": "ab"}, 400, "Username"),
    ({"username": "good.name", "password": "short"}, 400, "at least 12"),
    ({"username": "good.name", "password": "x" * 300}, 400, "at most 256"),
    ({"username": "good.name", "role": "admin"}, 422, ""),
    ({}, 422, ""),
])
def test_admin_create_validation(client: TestClient, monkeypatch, payload, status, fragment):
    enable_portal(monkeypatch)
    res = client.post(ADMIN_USERS, json=payload, headers=ENGINEER)
    assert res.status_code == status
    if fragment:
        assert fragment in res.json()["detail"]


def test_admin_duplicate_username_is_409(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    admin_create(client, "yuri")
    res = client.post(ADMIN_USERS, json={"username": "YURI"}, headers=ENGINEER)
    assert res.status_code == 409 and "taken" in res.json()["detail"]


def test_admin_reset_password_invalidates_sessions(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    uid = admin_create(client, "zack")["user"]["id"]
    token = login(client, "zack")
    res = client.post(f"{ADMIN_USERS}/{uid}/password", json={"password": "the new passphrase"}, headers=ENGINEER)
    assert res.status_code == 200 and "generated_password" not in res.json()
    assert client.get("/client/api/auth/me", headers=session_header(token)).status_code == 401
    assert client.post(LOGIN_PATH, json={"username": "zack", "password": PASSWORD}).status_code == 401
    assert login(client, "zack", "the new passphrase")
    # no body -> generated
    gen = client.post(f"{ADMIN_USERS}/{uid}/password", headers=ENGINEER).json()["generated_password"]
    assert login(client, "zack", gen)
    bad = client.post(f"{ADMIN_USERS}/{uid}/password", json={"password": "short"}, headers=ENGINEER)
    assert bad.status_code == 400


def test_admin_disable_enable_revoke_delete(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    uid = admin_create(client, "amy.b")["user"]["id"]
    token = login(client, "amy.b")
    res = client.post(f"{ADMIN_USERS}/{uid}/disable", headers=ENGINEER)
    assert res.json()["user"]["disabled"] is True
    assert client.get("/client/api/auth/me", headers=session_header(token)).status_code == 401
    assert client.post(LOGIN_PATH, json={"username": "amy.b", "password": PASSWORD}).status_code == 401
    assert client.post(f"{ADMIN_USERS}/{uid}/enable", headers=ENGINEER).json()["user"]["disabled"] is False

    t1, t2 = login(client, "amy.b"), login(client, "amy.b")
    res = client.post(f"{ADMIN_USERS}/{uid}/revoke-sessions", headers=ENGINEER).json()
    assert res["revoked"] == 2
    assert client.get("/client/api/auth/me", headers=session_header(t1)).status_code == 401
    assert client.get("/client/api/auth/me", headers=session_header(t2)).status_code == 401

    t3 = login(client, "amy.b")
    assert client.delete(f"{ADMIN_USERS}/{uid}", headers=ENGINEER).json() == {"deleted": True}
    assert client.get("/client/api/auth/me", headers=session_header(t3)).status_code == 401
    assert client.get(ADMIN_USERS, headers=ENGINEER).json()["users"] == []


@pytest.mark.parametrize("method,suffix", [
    ("post", "/password"), ("post", "/disable"), ("post", "/enable"), ("post", "/unlock"),
    ("post", "/revoke-sessions"), ("delete", ""),
])
def test_admin_unknown_id_is_404(client: TestClient, monkeypatch, method, suffix):
    enable_portal(monkeypatch)
    res = getattr(client, method)(f"{ADMIN_USERS}/usr_missing{suffix}", headers=ENGINEER)
    assert res.status_code == 404 and res.json() == {"detail": "Client user not found"}


def test_admin_endpoints_require_engineer_key(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    uid = admin_create(client, "ben.c")["user"]["id"]
    token = login(client, "ben.c")
    probes = [("get", ADMIN_USERS, None), ("post", ADMIN_USERS, {"username": "intruder"}),
              ("post", f"{ADMIN_USERS}/{uid}/password", {}), ("post", f"{ADMIN_USERS}/{uid}/disable", None),
              ("delete", f"{ADMIN_USERS}/{uid}", None)]
    for method, path, body in probes:
        kwargs = {"json": body} if body is not None else {}
        for headers in ({}, session_header(token), {"X-Dashboard-Key": "wrong"},
                        {"Authorization": f"Bearer {ENGINEER_KEY}"}):
            res = getattr(client, method)(path, headers=headers, **kwargs)
            assert res.status_code == 401, (method, path, headers, res.status_code)
        security.auth_limiter.reset()
    # nothing changed
    users = client.get(ADMIN_USERS, headers=ENGINEER).json()["users"]
    assert [u["username"] for u in users] == ["ben.c"] and users[0]["disabled"] is False


def test_admin_cross_origin_mutation_rejected(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    res = client.post(ADMIN_USERS, json={"username": "evil.user"},
                      headers={**ENGINEER, "Origin": "https://evil.example"})
    assert res.status_code == 403
