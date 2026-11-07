"""
Client portal user accounts and sessions (tables client_users / client_sessions).

Accounts are managed by engineers from the dashboard (create, reset password,
enable/disable, delete, revoke sessions) — there is no self-service signup and no
CLI. Passwords are stored only as salted slow hashes; the session token (sent by
the portal in the X-Client-Session header) is an opaque random value of which
only a SHA-256 hash is stored.

A "user" is a plain dict WITHOUT the password hash:
    id, username, display_name, role ("client"), disabled (bool),
    failed_attempts (account-wide wrong passwords in the current backstop window),
    throttled_until (float|None), throttled (bool), locked_addresses (int),
    locked_until (float|None: latest end of any lock or slow-down),
    locked (bool: any address locked out, or the account slowed down),
    created_at, password_changed_at, last_login_at
list_users() adds `active_sessions`; resolve_session() adds `session_expires_at`
(the moment the session ends if it stays idle, capped by its absolute expiry).

Sign-in lock-out (verify_credentials). Wrong passwords are counted per
(account, client address):
  - client_login_max_failures wrong passwords in a row from one address lock
    THAT address out of THAT account for client_login_lockout_minutes. The real
    user signing in from anywhere else is not affected, so a stranger who knows
    a username cannot lock the client out.
  - Account-wide backstop: once client_login_account_max_failures wrong
    passwords from all addresses together fall inside
    client_login_account_window_minutes, the account is slowed down: after each
    further wrong password, attempts are refused for 1 s, then 2, 4, ... up to
    client_login_account_max_delay_seconds. The slow-down never applies to an
    address that signed in to the account in the last KNOWN_ADDRESS_DAYS days.
Refused attempts get the same answer as a wrong password; the reason is logged
server-side only (by user id, never the typed username).

Lock-out / session lifetimes come from runtime_settings, read at call time so
dashboard changes apply live — including to sessions that already exist (a
shortened idle/max lifetime ends them on their next use).
"""
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
import time
import uuid
from typing import Any
import aiosqlite
import structlog
from src.storage import runtime_settings
from src.storage.database import db_session

logger = structlog.get_logger(__name__)

User = dict[str, Any]

# --- policy ---
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 64
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]+$")
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 256
DISPLAY_NAME_MAX_LENGTH = 128

# --- hashing ---
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_BYTES = 16
SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024
_HASH_SCHEME = "scrypt"

# A session's last_seen_at is rewritten at most this often (seconds), so a busy
# portal page does not turn every API call into a DB write.
LAST_SEEN_WRITE_INTERVAL = 30.0

# --- sign-in lock-out ---
# An address that signed in to an account within this many days is "known" to
# it and exempt from the account-wide slow-down (not from its own address lock).
KNOWN_ADDRESS_DAYS = 30
# A per-address failure count whose last failure is older than this starts again.
ADDRESS_FAILURE_MEMORY_SECONDS = 24 * 3600
# client_login_failures housekeeping: at most one prune per interval, and a hard
# cap on rows (oldest activity dropped first) against a spray from many addresses.
LOGIN_FAILURE_PRUNE_INTERVAL = 300.0
LOGIN_FAILURE_MAX_ROWS = 50_000
_last_login_failure_prune = 0.0

# Key for attempt_fingerprint(): random per process, never stored or logged.
_ATTEMPT_KEY = secrets.token_bytes(32)

_USER_COLUMNS = (
    "id, username, display_name, role, disabled, failed_attempts, locked_until, "
    "created_at, password_changed_at, last_login_at"
)


class DuplicateUsernameError(ValueError):
    """The username is already taken (compared case-insensitively)."""


# ------------------------------ helpers ------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=dklen, maxmem=_SCRYPT_MAXMEM)


def hash_password(password: str) -> str:
    """Self-describing scrypt hash: scrypt$n$r$p$salt_b64$hash_b64. CPU-bound
    (tens of ms) — call through asyncio.to_thread from async code."""
    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
    return f"{_HASH_SCHEME}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def check_password(password: str, stored: str) -> bool:
    """Constant-time check of `password` against a hash_password() string.
    A malformed stored value simply fails."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        n_i, r_i, p_i = int(n), int(r), int(p)
        if scheme != _HASH_SCHEME or not (2 <= n_i <= 2 ** 20 and 1 <= r_i <= 32 and 1 <= p_i <= 16):
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(hash_b64, validate=True)
        if not expected:
            return False
        actual = _scrypt(password, salt, n_i, r_i, p_i, len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


_dummy_hash: str | None = None


def _get_dummy_hash() -> str:
    """A real hash of a random throwaway password, so a login for an unknown user
    costs the same scrypt work as one for a real user."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_urlsafe(24))
    return _dummy_hash


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def normalize_username(username: Any) -> str:
    """Strips the username and validates its shape. Raises ValueError."""
    if not isinstance(username, str):
        raise ValueError("Username is required")
    name = username.strip()
    if not (USERNAME_MIN_LENGTH <= len(name) <= USERNAME_MAX_LENGTH):
        raise ValueError(
            f"Username must be {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} characters")
    if not USERNAME_RE.match(name):
        raise ValueError("Username may contain only letters, digits and . _ @ -")
    return name


def validate_password(password: Any, username: str | None = None) -> str:
    """Password policy: 12-256 characters, not the username. Raises ValueError."""
    if not isinstance(password, str):
        raise ValueError("Password is required")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters")
    if not password.strip():
        raise ValueError("Password must not be only whitespace")
    if username and password.strip().lower() == username.strip().lower():
        raise ValueError("Password must not be the same as the username")
    return password


def _clean_display_name(display_name: Any) -> str | None:
    if display_name is None:
        return None
    if not isinstance(display_name, str):
        raise ValueError("Display name must be text")
    name = display_name.strip()
    if len(name) > DISPLAY_NAME_MAX_LENGTH:
        raise ValueError(f"Display name must be at most {DISPLAY_NAME_MAX_LENGTH} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("Display name must not contain control characters")
    return name or None


def generate_password() -> str:
    """A strong random password (24 URL-safe characters, ~144 bits)."""
    return secrets.token_urlsafe(18)


def address_key(client_ip: Any) -> str:
    """The address a sign-in failure is counted against. IPv6 clients are grouped
    by /64 (one subscriber usually holds a whole /64, so per-address counting
    would otherwise be trivially dodged); IPv4 and anything unparsable as is."""
    text = str(client_ip or "unknown")[:64]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return text
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def attempt_fingerprint(username: Any) -> str:
    """A short keyed hash of a typed username, so the log can tell repeated
    attempts at the same unknown name apart WITHOUT recording what was typed (a
    password pasted into the username box must never reach the log). The key is
    random per process, so the value cannot be reversed or checked offline."""
    text = username.strip().lower()[:256] if isinstance(username, str) else ""
    return hmac.new(_ATTEMPT_KEY, text.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]


def _row_to_user(row: Any, now: float | None = None) -> User:
    now = time.time() if now is None else now
    throttled_until = row[6]
    throttled = bool(throttled_until and throttled_until > now)
    return {
        "id": row[0],
        "username": row[1],
        "display_name": row[2],
        "role": row[3],
        "disabled": bool(row[4]),
        "failed_attempts": int(row[5] or 0),
        "throttled_until": throttled_until if throttled else None,
        "throttled": throttled,
        # completed by _attach_lock_info() where the dashboard needs it
        "locked_addresses": 0,
        "locked_until": throttled_until if throttled else None,
        "locked": throttled,
        "created_at": row[7],
        "password_changed_at": row[8],
        "last_login_at": row[9],
    }


async def _attach_lock_info(conn: aiosqlite.Connection, users: list[User], now: float) -> None:
    """Adds the per-address locks to each user: locked_addresses, and locked /
    locked_until covering them as well as the account-wide slow-down."""
    if not users:
        return
    async with conn.execute(
        "SELECT user_id, COUNT(*), MAX(locked_until) FROM client_login_failures "
        "WHERE locked_until > ? GROUP BY user_id", (now,),
    ) as cur:
        locks = {row[0]: (int(row[1]), row[2]) for row in await cur.fetchall()}
    for user in users:
        count, until = locks.get(user["id"], (0, None))
        user["locked_addresses"] = count
        if count:
            user["locked"] = True
            user["locked_until"] = max(until, user["locked_until"] or 0)


async def _lifetimes() -> tuple[float, float]:
    """(idle_seconds, max_seconds) from runtime settings."""
    idle = await runtime_settings.get("client_session_idle_minutes")
    max_hours = await runtime_settings.get("client_session_max_hours")
    return float(idle) * 60.0, float(max_hours) * 3600.0


# The one definition of "this session is still alive", shared by resolve,
# list (active counts) and purge. Parameters: now, idle_s, now, max_s, now.
_ALIVE_SQL = (
    "(COALESCE(s.last_seen_at, s.created_at, 0) + ? > ?) "
    "AND (COALESCE(s.created_at, 0) + ? > ?) "
    "AND (COALESCE(s.expires_at, 0) > ?)"
)


def _alive_params(now: float, idle_s: float, max_s: float) -> tuple[float, ...]:
    return (idle_s, now, max_s, now, now)


# ------------------------------ accounts ------------------------------

async def create_user(username: str, password: str, display_name: str | None = None) -> User:
    """Creates a client account. Raises ValueError on a bad/duplicate username
    (case-insensitive; DuplicateUsernameError, a ValueError subclass) or a
    password that fails the policy."""
    name = normalize_username(username)
    validate_password(password, name)
    display = _clean_display_name(display_name)
    if await get_by_username(name) is not None:
        raise DuplicateUsernameError("That username is already taken")
    password_hash = await asyncio.to_thread(hash_password, password)
    user_id = "usr_" + uuid.uuid4().hex[:16]
    now = time.time()
    async with db_session() as conn:
        try:
            await conn.execute(
                "INSERT INTO client_users (id, username, display_name, role, password_hash, "
                "disabled, failed_attempts, locked_until, created_at, password_changed_at, last_login_at) "
                "VALUES (?, ?, ?, 'client', ?, 0, 0, NULL, ?, ?, NULL)",
                (user_id, name, display, password_hash, now, now),
            )
            await conn.commit()
        except aiosqlite.IntegrityError:
            raise DuplicateUsernameError("That username is already taken") from None
    user = await get_by_id(user_id)
    assert user is not None
    return user


_CLEAR_BACKSTOP_SQL = "failed_attempts = 0, locked_until = NULL, failure_window_start = NULL"


async def set_password(user_id: str, password: str) -> None:
    """Resets the password (policy-checked), clears every lock-out (per address
    and account-wide), forgets the account's known addresses, and revokes all
    the user's sessions. Raises ValueError (policy) or LookupError (unknown user)."""
    user = await get_by_id(user_id)
    if user is None:
        raise LookupError("Unknown user")
    validate_password(password, user["username"])
    password_hash = await asyncio.to_thread(hash_password, password)
    async with db_session() as conn:
        cur = await conn.execute(
            "UPDATE client_users SET password_hash = ?, password_changed_at = ?, "
            f"{_CLEAR_BACKSTOP_SQL} WHERE id = ?",
            (password_hash, time.time(), user_id),
        )
        if cur.rowcount == 0:
            raise LookupError("Unknown user")
        await conn.execute("DELETE FROM client_sessions WHERE user_id = ?", (user_id,))
        await conn.execute("DELETE FROM client_login_failures WHERE user_id = ?", (user_id,))
        await conn.commit()


async def set_disabled(user_id: str, disabled: bool) -> None:
    """Enables/disables an account. Disabling also revokes its sessions.
    Raises LookupError for an unknown user."""
    async with db_session() as conn:
        cur = await conn.execute(
            "UPDATE client_users SET disabled = ? WHERE id = ?", (1 if disabled else 0, user_id))
        if cur.rowcount == 0:
            raise LookupError("Unknown user")
        if disabled:
            await conn.execute("DELETE FROM client_sessions WHERE user_id = ?", (user_id,))
        await conn.commit()


async def unlock_user(user_id: str) -> None:
    """Clears every lock-out of the account: all its per-address locks and
    failure counts, and the account-wide slow-down and its counter. Known
    addresses are kept. Raises LookupError."""
    async with db_session() as conn:
        cur = await conn.execute(
            f"UPDATE client_users SET {_CLEAR_BACKSTOP_SQL} WHERE id = ?", (user_id,))
        if cur.rowcount == 0:
            raise LookupError("Unknown user")
        await conn.execute(
            "DELETE FROM client_login_failures WHERE user_id = ? AND last_success_at IS NULL",
            (user_id,))
        await conn.execute(
            "UPDATE client_login_failures SET failed_attempts = 0, last_failed_at = NULL, "
            "locked_until = NULL WHERE user_id = ?", (user_id,))
        await conn.commit()


async def delete_user(user_id: str) -> bool:
    """Deletes the account and (by cascade) its sessions. Returns False if it did not exist."""
    async with db_session() as conn:
        # Explicit as well as by cascade, so it holds even without foreign_keys.
        await conn.execute("DELETE FROM client_sessions WHERE user_id = ?", (user_id,))
        await conn.execute("DELETE FROM client_login_failures WHERE user_id = ?", (user_id,))
        cur = await conn.execute("DELETE FROM client_users WHERE id = ?", (user_id,))
        await conn.commit()
        return cur.rowcount > 0


async def list_users() -> list[User]:
    """All client accounts, newest first, each with a live `active_sessions` count."""
    now = time.time()
    idle_s, max_s = await _lifetimes()
    async with db_session() as conn:
        async with conn.execute(
            f"SELECT {_USER_COLUMNS}, "
            f"(SELECT COUNT(*) FROM client_sessions s WHERE s.user_id = client_users.id AND {_ALIVE_SQL}) "
            "FROM client_users ORDER BY created_at DESC, username",
            _alive_params(now, idle_s, max_s),
        ) as cur:
            rows = await cur.fetchall()
        users = []
        for row in rows:
            user = _row_to_user(row, now)
            user["active_sessions"] = int(row[10] or 0)
            users.append(user)
        await _attach_lock_info(conn, users, now)
    return users


async def _get_one(where: str, param: str) -> User | None:
    now = time.time()
    async with db_session() as conn:
        async with conn.execute(
            f"SELECT {_USER_COLUMNS} FROM client_users WHERE {where}", (param,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        user = _row_to_user(row, now)
        await _attach_lock_info(conn, [user], now)
    return user


async def get_by_id(user_id: str) -> User | None:
    """One user by id, or None."""
    if not isinstance(user_id, str) or not user_id:
        return None
    return await _get_one("id = ?", user_id)


async def get_by_username(username: str) -> User | None:
    """One user by username (case-insensitive), or None."""
    if not isinstance(username, str) or not username.strip():
        return None
    return await _get_one("username = ? COLLATE NOCASE", username.strip())


# ------------------------------ login ------------------------------

_POLICY_KEYS = (
    "client_login_max_failures", "client_login_lockout_minutes",
    "client_login_account_max_failures", "client_login_account_window_minutes",
    "client_login_account_max_delay_seconds",
)

_PRUNE_SQL = (
    "DELETE FROM client_login_failures WHERE (locked_until IS NULL OR locked_until <= ?) "
    "AND COALESCE(last_failed_at, 0) <= ? AND COALESCE(last_success_at, 0) <= ?"
)


async def _prune_login_failures(conn: aiosqlite.Connection, now: float) -> int:
    """Drops (account, address) rows that no longer matter: not locked, no
    failure within ADDRESS_FAILURE_MEMORY_SECONDS and no sign-in within
    KNOWN_ADDRESS_DAYS. Then enforces LOGIN_FAILURE_MAX_ROWS, oldest activity
    first. Does not commit."""
    cur = await conn.execute(_PRUNE_SQL, (
        now, now - ADDRESS_FAILURE_MEMORY_SECONDS, now - KNOWN_ADDRESS_DAYS * 86400))
    removed = max(cur.rowcount, 0)
    async with conn.execute("SELECT COUNT(*) FROM client_login_failures") as c:
        excess = int((await c.fetchone())[0]) - LOGIN_FAILURE_MAX_ROWS
    if excess > 0:
        cur = await conn.execute(
            "DELETE FROM client_login_failures WHERE rowid IN ("
            "SELECT rowid FROM client_login_failures ORDER BY MAX(COALESCE(last_failed_at, 0), "
            "COALESCE(last_success_at, 0), COALESCE(locked_until, 0)) LIMIT ?)", (excess,))
        removed += max(cur.rowcount, 0)
    return removed


async def purge_login_failures() -> int:
    """Housekeeping for client_login_failures (see _prune_login_failures).
    Returns how many rows were removed."""
    global _last_login_failure_prune
    now = time.time()
    _last_login_failure_prune = now
    async with db_session() as conn:
        removed = await _prune_login_failures(conn, now)
        await conn.commit()
    return removed


async def verify_credentials(username: str, password: str, client_ip: str) -> User | None:
    """
    Checks a login. Returns the user on success, None on ANY failure (unknown
    user, wrong password, disabled, address locked out, account slowed down) so
    the API can answer identically and not reveal which accounts exist. Takes the
    same time for unknown users (dummy hash) and always runs the hash before
    looking at lock state. Counts a wrong password against (account, address)
    and against the account-wide backstop — see the module docstring. Success
    resets that address's count, marks it known and sets last_login_at.
    The reason for a failure is logged server-side only, by user id; the typed
    username is never logged (only attempt_fingerprint() for unknown accounts).
    """
    password = password if isinstance(password, str) else ""
    # An over-long password never matches (policy max) — don't spend scrypt on it
    # beyond the normal cost: hash a bounded prefix so timing stays flat.
    candidate = password[:PASSWORD_MAX_LENGTH + 1]
    try:
        name = normalize_username(username)
    except ValueError:
        name = None

    row = None
    if name is not None:
        async with db_session() as conn:
            async with conn.execute(
                "SELECT id, password_hash FROM client_users WHERE username = ? COLLATE NOCASE",
                (name,),
            ) as cur:
                row = await cur.fetchone()

    if row is None:
        await asyncio.to_thread(check_password, candidate, _get_dummy_hash())
        logger.info("client_login_rejected", reason="unknown_user",
                    attempt=attempt_fingerprint(username), client_ip=client_ip)
        return None

    user_id, stored_hash = row
    ok = await asyncio.to_thread(check_password, candidate, stored_hash)
    ok = ok and len(password) <= PASSWORD_MAX_LENGTH
    policy = {key: int(await runtime_settings.get(key)) for key in _POLICY_KEYS}
    return await _settle_attempt(user_id, ok, client_ip, policy)


async def _settle_attempt(user_id: str, ok: bool, client_ip: str,
                          policy: dict[str, int]) -> User | None:
    """Applies the lock-out rules to one checked attempt, in ONE write
    transaction: the lock state is read after the (slow) hash, and concurrent
    attempts are serialised, so a burst of parallel guesses all count and a
    correct guess racing a lock-out is still refused."""
    global _last_login_failure_prune
    addr = address_key(client_ip)
    now = time.time()
    who = {"user_id": user_id, "client_ip": client_ip}
    async with db_session() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute(
            "SELECT disabled, failed_attempts, locked_until, failure_window_start "
            "FROM client_users WHERE id = ?", (user_id,),
        ) as cur:
            acct = await cur.fetchone()
        if acct is None:  # deleted while the password was being checked
            await conn.rollback()
            logger.info("client_login_rejected", reason="unknown_user", **who)
            return None
        disabled, acct_failures, throttled_until, window_start = acct
        async with conn.execute(
            "SELECT failed_attempts, last_failed_at, locked_until, last_success_at "
            "FROM client_login_failures WHERE user_id = ? AND client_ip = ?", (user_id, addr),
        ) as cur:
            pair = await cur.fetchone()
        pair_failures, pair_last_failed, pair_locked_until, last_success = pair or (0, None, None, None)
        known = bool(last_success and last_success > now - KNOWN_ADDRESS_DAYS * 86400)

        reason = None
        if pair_locked_until and pair_locked_until > now:
            reason = "address_locked"
        elif disabled:
            reason = "disabled"
        elif throttled_until and throttled_until > now and not known:
            reason = "throttled"
        if reason:
            # Not counted: the answer did not depend on the password.
            await conn.rollback()
            logger.warning("client_login_rejected", reason=reason, **who)
            return None

        if ok:
            await conn.execute("UPDATE client_users SET last_login_at = ? WHERE id = ?", (now, user_id))
            await conn.execute(
                "INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, "
                "last_failed_at, locked_until, last_success_at) VALUES (?, ?, 0, NULL, NULL, ?) "
                "ON CONFLICT(user_id, client_ip) DO UPDATE SET failed_attempts = 0, "
                "last_failed_at = NULL, locked_until = NULL, last_success_at = excluded.last_success_at",
                (user_id, addr, now),
            )
            await conn.commit()
            return await get_by_id(user_id)

        # --- wrong password: this address's count ---
        max_failures = policy["client_login_max_failures"]
        lockout_minutes = policy["client_login_lockout_minutes"]
        # An expired lock, or a last failure long ago, starts a fresh count.
        fresh = (pair_locked_until is not None or not pair_last_failed
                 or pair_last_failed <= now - ADDRESS_FAILURE_MEMORY_SECONDS)
        pair_failures = 1 if fresh else int(pair_failures or 0) + 1
        pair_lock = now + lockout_minutes * 60 if pair_failures >= max_failures else None
        await conn.execute(
            "INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, "
            "last_failed_at, locked_until, last_success_at) VALUES (?, ?, ?, ?, ?, NULL) "
            "ON CONFLICT(user_id, client_ip) DO UPDATE SET failed_attempts = excluded.failed_attempts, "
            "last_failed_at = excluded.last_failed_at, locked_until = excluded.locked_until",
            (user_id, addr, pair_failures, now, pair_lock),
        )

        # --- wrong password: the account-wide backstop ---
        acct_max = policy["client_login_account_max_failures"]
        window_s = policy["client_login_account_window_minutes"] * 60
        if not window_start or window_start <= now - window_s:
            window_start, acct_failures = now, 1
        else:
            acct_failures = int(acct_failures or 0) + 1
        throttle = None
        if acct_failures >= acct_max:
            # 1 s at the threshold, doubling with each further wrong password.
            delay = min(float(policy["client_login_account_max_delay_seconds"]),
                        2.0 ** min(acct_failures - acct_max, 30))
            throttle = now + delay
        await conn.execute(
            "UPDATE client_users SET failed_attempts = ?, failure_window_start = ?, "
            "locked_until = ? WHERE id = ?",
            (acct_failures, window_start, throttle, user_id),
        )
        if now - _last_login_failure_prune >= LOGIN_FAILURE_PRUNE_INTERVAL:
            _last_login_failure_prune = now
            await _prune_login_failures(conn, now)
        await conn.commit()

    logger.warning("client_login_rejected", reason="bad_password", failed_attempts=pair_failures,
                   account_failures=acct_failures, **who)
    if pair_failures == max_failures:
        logger.warning("client_account_locked", scope="address", lockout_minutes=lockout_minutes,
                       failed_attempts=pair_failures, **who)
    if acct_failures == acct_max:
        logger.warning("client_account_throttled", account_failures=acct_failures,
                       window_minutes=policy["client_login_account_window_minutes"], **who)
    return None


# ------------------------------ sessions ------------------------------

async def create_session(user_id: str, client_ip: str) -> tuple[str, float]:
    """Starts a session. Returns (token, expires_at). The token is the secret
    session value, returned once and never stored (only its hash is).
    expires_at is the absolute expiry (login + client_session_max_hours); the
    session also ends earlier after client_session_idle_minutes without use."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    _, max_s = await _lifetimes()
    expires_at = now + max_s
    async with db_session() as conn:
        await conn.execute(
            "INSERT INTO client_sessions (token_hash, user_id, created_at, last_seen_at, expires_at, client_ip) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (_token_hash(token), user_id, now, now, expires_at, (client_ip or "")[:64]),
        )
        await conn.commit()
    return token, expires_at


async def resolve_session(token: str) -> User | None:
    """
    Maps a session token to its user, or None if unknown, expired (idle or absolute
    max), or the user is disabled/deleted. A valid lookup slides last_seen_at
    (written at most every LAST_SEEN_WRITE_INTERVAL seconds).
    """
    if not isinstance(token, str) or not token or len(token) > 512:
        return None
    token_hash = _token_hash(token)
    now = time.time()
    idle_s, max_s = await _lifetimes()
    async with db_session() as conn:
        async with conn.execute(
            f"SELECT {', '.join('u.' + c.strip() for c in _USER_COLUMNS.split(','))}, "
            "s.created_at, s.last_seen_at, s.expires_at, "
            f"CASE WHEN {_ALIVE_SQL} THEN 1 ELSE 0 END "
            "FROM client_sessions s JOIN client_users u ON u.id = s.user_id "
            "WHERE s.token_hash = ?",
            (*_alive_params(now, idle_s, max_s), token_hash),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        user = _row_to_user(row, now)
        created_at, last_seen_at, expires_at, alive = row[10], row[11], row[12], row[13]
        if not alive or user["disabled"]:
            await conn.execute("DELETE FROM client_sessions WHERE token_hash = ?", (token_hash,))
            await conn.commit()
            return None
        last_seen = last_seen_at or created_at or now
        if now - last_seen >= LAST_SEEN_WRITE_INTERVAL:
            await conn.execute(
                "UPDATE client_sessions SET last_seen_at = ? WHERE token_hash = ?", (now, token_hash))
            await conn.commit()
            last_seen = now
    absolute = min(float(expires_at or 0), float(created_at or 0) + max_s)
    user["session_expires_at"] = min(absolute, last_seen + idle_s)
    return user


async def delete_session(token: str) -> None:
    """Logs out one session (idempotent)."""
    if not isinstance(token, str) or not token:
        return
    async with db_session() as conn:
        await conn.execute("DELETE FROM client_sessions WHERE token_hash = ?", (_token_hash(token),))
        await conn.commit()


async def revoke_sessions(user_id: str) -> int:
    """Ends all of a user's sessions. Returns how many were removed."""
    async with db_session() as conn:
        cur = await conn.execute("DELETE FROM client_sessions WHERE user_id = ?", (user_id,))
        await conn.commit()
        return max(cur.rowcount, 0)


async def purge_expired_sessions() -> int:
    """Deletes sessions past their idle/absolute expiry. Returns how many."""
    now = time.time()
    idle_s, max_s = await _lifetimes()
    async with db_session() as conn:
        cur = await conn.execute(
            f"DELETE FROM client_sessions WHERE token_hash IN ("
            f"SELECT s.token_hash FROM client_sessions s WHERE NOT ({_ALIVE_SQL}))",
            _alive_params(now, idle_s, max_s),
        )
        await conn.commit()
        return max(cur.rowcount, 0)
