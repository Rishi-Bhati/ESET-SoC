"""
Client portal user accounts and sessions (tables client_users / client_sessions).

Accounts are managed by engineers from the dashboard (create, reset password,
enable/disable, delete, revoke sessions) — there is no self-service signup and no
CLI. Passwords are stored only as salted slow hashes; the session token (sent by
the portal in the X-Client-Session header) is an opaque random value of which
only a SHA-256 hash is stored.

A "user" is a plain dict WITHOUT the password hash:
    id, username, display_name, role ("client"), disabled (bool), failed_attempts,
    locked_until (float|None), locked (bool), created_at, password_changed_at,
    last_login_at
list_users() adds `active_sessions`; resolve_session() adds `session_expires_at`
(the moment the session ends if it stays idle, capped by its absolute expiry).

Lockout / session lifetimes come from runtime_settings (client_login_max_failures,
client_login_lockout_minutes, client_session_idle_minutes, client_session_max_hours),
read at call time so dashboard changes apply live — including to sessions that
already exist (a shortened idle/max lifetime ends them on their next use).
"""
import asyncio
import base64
import hashlib
import hmac
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


def _row_to_user(row: Any, now: float | None = None) -> User:
    now = time.time() if now is None else now
    locked_until = row[6]
    return {
        "id": row[0],
        "username": row[1],
        "display_name": row[2],
        "role": row[3],
        "disabled": bool(row[4]),
        "failed_attempts": int(row[5] or 0),
        "locked_until": locked_until,
        "locked": bool(locked_until and locked_until > now),
        "created_at": row[7],
        "password_changed_at": row[8],
        "last_login_at": row[9],
    }


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


async def set_password(user_id: str, password: str) -> None:
    """Resets the password (policy-checked), clears the lockout and failed-attempt
    counter, and revokes all the user's sessions. Raises ValueError (policy) or
    LookupError (unknown user)."""
    user = await get_by_id(user_id)
    if user is None:
        raise LookupError("Unknown user")
    validate_password(password, user["username"])
    password_hash = await asyncio.to_thread(hash_password, password)
    async with db_session() as conn:
        cur = await conn.execute(
            "UPDATE client_users SET password_hash = ?, password_changed_at = ?, "
            "failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (password_hash, time.time(), user_id),
        )
        if cur.rowcount == 0:
            raise LookupError("Unknown user")
        await conn.execute("DELETE FROM client_sessions WHERE user_id = ?", (user_id,))
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
    """Clears a lockout and the failed-attempt counter. Raises LookupError."""
    async with db_session() as conn:
        cur = await conn.execute(
            "UPDATE client_users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
        if cur.rowcount == 0:
            raise LookupError("Unknown user")
        await conn.commit()


async def delete_user(user_id: str) -> bool:
    """Deletes the account and (by cascade) its sessions. Returns False if it did not exist."""
    async with db_session() as conn:
        # Explicit as well as by cascade, so it holds even without foreign_keys.
        await conn.execute("DELETE FROM client_sessions WHERE user_id = ?", (user_id,))
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
    return users


async def get_by_id(user_id: str) -> User | None:
    """One user by id, or None."""
    if not isinstance(user_id, str) or not user_id:
        return None
    async with db_session() as conn:
        async with conn.execute(
            f"SELECT {_USER_COLUMNS} FROM client_users WHERE id = ?", (user_id,)) as cur:
            row = await cur.fetchone()
    return _row_to_user(row) if row else None


async def get_by_username(username: str) -> User | None:
    """One user by username (case-insensitive), or None."""
    if not isinstance(username, str) or not username.strip():
        return None
    async with db_session() as conn:
        async with conn.execute(
            f"SELECT {_USER_COLUMNS} FROM client_users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ) as cur:
            row = await cur.fetchone()
    return _row_to_user(row) if row else None


# ------------------------------ login ------------------------------

async def verify_credentials(username: str, password: str, client_ip: str) -> User | None:
    """
    Checks a login. Returns the user on success, None on ANY failure (unknown
    user, wrong password, disabled, locked) so the API can answer identically and
    not reveal which accounts exist. Takes the same time for unknown users (dummy
    hash). Counts failures and locks the account after client_login_max_failures
    for client_login_lockout_minutes; success resets the counter and sets last_login_at.
    The reason for a failure is logged server-side only.
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
                f"SELECT {_USER_COLUMNS}, password_hash FROM client_users "
                "WHERE username = ? COLLATE NOCASE", (name,),
            ) as cur:
                row = await cur.fetchone()

    if row is None:
        await asyncio.to_thread(check_password, candidate, _get_dummy_hash())
        logger.info("client_login_rejected", reason="unknown_user", client_ip=client_ip)
        return None

    now = time.time()
    user = _row_to_user(row, now)
    stored_hash = row[10]
    ok = await asyncio.to_thread(check_password, candidate, stored_hash)
    ok = ok and len(password) <= PASSWORD_MAX_LENGTH

    if user["locked"]:
        logger.warning("client_login_rejected", reason="locked", user_id=user["id"], client_ip=client_ip)
        return None
    if user["disabled"]:
        logger.warning("client_login_rejected", reason="disabled", user_id=user["id"], client_ip=client_ip)
        return None

    if not ok:
        max_failures = int(await runtime_settings.get("client_login_max_failures"))
        lockout_minutes = int(await runtime_settings.get("client_login_lockout_minutes"))
        # Counted in ONE statement against the current row, not the row read
        # before the (slow) hash check: concurrent wrong guesses must each count,
        # or a burst of parallel logins would never reach the lockout.
        # A lockout that has run out starts a fresh count; a lock set meanwhile
        # by a concurrent request is kept as is.
        next_attempts = "(CASE WHEN locked_until IS NULL THEN failed_attempts + 1 ELSE 1 END)"
        async with db_session() as conn:
            await conn.execute(
                "UPDATE client_users SET "
                "failed_attempts = CASE WHEN locked_until > ? THEN failed_attempts "
                f"ELSE {next_attempts} END, "
                "locked_until = CASE WHEN locked_until > ? THEN locked_until "
                f"WHEN {next_attempts} >= ? THEN ? ELSE NULL END "
                "WHERE id = ?",
                (now, now, max_failures, now + lockout_minutes * 60, user["id"]),
            )
            await conn.commit()
            async with conn.execute(
                "SELECT failed_attempts, locked_until FROM client_users WHERE id = ?", (user["id"],),
            ) as cur:
                row = await cur.fetchone()
        attempts, locked_until = (row[0], row[1]) if row else (None, None)
        logger.warning("client_login_rejected", reason="bad_password", user_id=user["id"],
                       failed_attempts=attempts, client_ip=client_ip)
        if locked_until is not None and attempts == max_failures:
            logger.warning("client_account_locked", user_id=user["id"],
                           lockout_minutes=lockout_minutes, client_ip=client_ip)
        return None

    async with db_session() as conn:
        # Only if the account is (still) unlocked and enabled NOW: a concurrent
        # burst may have locked it while this request was hashing.
        cur = await conn.execute(
            "UPDATE client_users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? "
            "WHERE id = ? AND disabled = 0 AND (locked_until IS NULL OR locked_until <= ?)",
            (now, user["id"], now),
        )
        await conn.commit()
    if cur.rowcount != 1:
        logger.warning("client_login_rejected", reason="locked", user_id=user["id"], client_ip=client_ip)
        return None
    return await get_by_id(user["id"])


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
