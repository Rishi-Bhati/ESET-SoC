"""
Client portal user accounts and sessions (tables client_users / client_sessions).

Accounts are managed by engineers from the dashboard (create, reset password,
enable/disable, delete, revoke sessions) — there is no self-service signup and no
CLI. Passwords are stored only as salted slow hashes; the session token (sent by
the portal in the X-Client-Session header) is an opaque random value of which
only a SHA-256 hash is stored.

A "user" is a plain dict WITHOUT the password hash:
    id, username, display_name, role ("client"), disabled (bool),
    created_at, password_changed_at, last_login_at, and the sign-in state:
    failed_attempts (int: the account-wide wrong-password score, see below),
    throttled (bool: the account is in backstop mode), locked_addresses (int),
    locked_networks (int), locked_until (float|None: latest end of any lock),
    locked (bool: some address or network is locked out of the account)
list_users() adds `active_sessions`; resolve_session() adds `session_expires_at`
(the moment the session ends if it stays idle, capped by its absolute expiry).

Sign-in lock-out (verify_credentials). The rule it is built around: nothing an
attacker does from other networks can make a correct password fail from yours.
There is no account-wide refusal of any kind. Instead:
  - Per address (an IPv4 address, an IPv6 /64): client_login_max_failures wrong
    passwords in a row lock THAT address out of THAT account for
    client_login_lockout_minutes.
  - Account-wide score: each wrong password adds 1, and the score drains by
    client_login_account_max_failures every client_login_account_decay_hours
    (it never resets at a boundary). While it is at or above
    client_login_account_max_failures the account is in BACKSTOP mode: a wrong
    password from an address that has not signed in to the account within
    KNOWN_ADDRESS_DAYS is also counted against its NETWORK (IPv4 /24, IPv6 /48).
    After client_login_backstop_max_failures of them that network is locked out
    of the account for client_login_lockout_minutes, doubling with each further
    wrong password from it up to client_login_backstop_max_lock_hours. A
    network's count survives its locks and is forgotten only after
    NETWORK_FAILURE_MEMORY_SECONDS without a wrong password from it.
  - Every attempt — unknown username or real account, any outcome — reads the
    policy, runs the password hash and executes the same database statements
    (see _settle_attempt), and every refusal gets the same answer. The reason is
    logged server-side only, by user id; what was typed as the username is never
    logged.

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
from src.utils.password_strength import weak_password_reason

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
# it: exempt from the backstop's network counting and network locks (not from
# its own address lock). Known only by signing in, i.e. with the password.
KNOWN_ADDRESS_DAYS = 30
_KNOWN_SECONDS = KNOWN_ADDRESS_DAYS * 86400
# A per-address failure count whose last failure is older than this starts again.
ADDRESS_FAILURE_MEMORY_SECONDS = 24 * 3600
# A network's (backstop) count is kept this long after its last wrong password,
# so its doubling lock does not start over when a lock ends. Covers the largest
# client_login_backstop_max_lock_hours (168).
NETWORK_FAILURE_MEMORY_SECONDS = 7 * 86400
# client_login_failures keys: an address as address_key(), a network as this
# prefix + network_key().
NETWORK_KEY_PREFIX = "net:"
# Housekeeping: at most one prune per interval, and a cap on rows that do not
# mark a known address (rows that do are never evicted).
LOGIN_FAILURE_PRUNE_INTERVAL = 300.0
LOGIN_FAILURE_MAX_ROWS = 50_000
_last_login_failure_prune = 0.0
# Every sign-in attempt executes exactly this many write statements (see
# _settle_attempt); the unused ones go to client_login_pad.
_WRITE_SLOTS = 3

_USER_COLUMNS = (
    "id, username, display_name, role, disabled, login_score, login_score_at, "
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
    """Password policy: 12-256 characters, not the username, and not one of the
    passwords attackers try first (see utils/password_strength). Raises ValueError."""
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
    reason = weak_password_reason(password, username)
    if reason:
        raise ValueError(reason)
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


def network_key(client_ip: Any) -> str:
    """The network a backstop-mode failure is counted against: IPv4 /24, IPv6
    /48 (what one subscriber, hosting customer or small office typically holds,
    so spreading guesses over many addresses of it gains nothing)."""
    text = str(client_ip or "unknown")[:64]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return NETWORK_KEY_PREFIX + text
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    prefix = 24 if isinstance(ip, ipaddress.IPv4Address) else 48
    return NETWORK_KEY_PREFIX + str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _row_to_user(row: Any, now: float | None = None) -> User:
    """The account columns. The sign-in state (failed_attempts, throttled,
    locks) is filled in by _attach_lock_info() where it is needed."""
    return {
        "id": row[0],
        "username": row[1],
        "display_name": row[2],
        "role": row[3],
        "disabled": bool(row[4]),
        "failed_attempts": int(row[5] or 0),
        "throttled": False,
        "locked_addresses": 0,
        "locked_networks": 0,
        "locked_until": None,
        "locked": False,
        "created_at": row[7],
        "password_changed_at": row[8],
        "last_login_at": row[9],
    }


_POLICY_KEYS = (
    "client_login_max_failures", "client_login_lockout_minutes",
    "client_login_account_max_failures", "client_login_account_decay_hours",
    "client_login_backstop_max_failures", "client_login_backstop_max_lock_hours",
)


async def _login_policy() -> dict[str, int]:
    return {key: int(await runtime_settings.get(key)) for key in _POLICY_KEYS}


def _current_score(score: Any, score_at: Any, now: float, policy: dict[str, int]) -> float:
    """The account-wide score after draining since it was last written."""
    if not score:
        return 0.0
    rate = policy["client_login_account_max_failures"] / (policy["client_login_account_decay_hours"] * 3600.0)
    return max(0.0, float(score) - max(0.0, now - float(score_at or now)) * rate)


async def _attach_lock_info(conn: aiosqlite.Connection, users: list[User], now: float) -> None:
    """Fills in each user's sign-in state: failed_attempts (current score),
    throttled (backstop mode), locked_addresses / locked_networks, and locked /
    locked_until covering both kinds of lock."""
    if not users:
        return
    policy = await _login_policy()
    ids = [u["id"] for u in users]
    marks = ",".join("?" * len(ids))
    async with conn.execute(
        f"SELECT id, login_score, login_score_at FROM client_users WHERE id IN ({marks})", ids,
    ) as cur:
        scores = {row[0]: _current_score(row[1], row[2], now, policy) for row in await cur.fetchall()}
    async with conn.execute(
        "SELECT user_id, substr(client_ip, 1, ?) = ?, COUNT(*), MAX(locked_until) "
        f"FROM client_login_failures WHERE locked_until > ? AND user_id IN ({marks}) GROUP BY 1, 2",
        (len(NETWORK_KEY_PREFIX), NETWORK_KEY_PREFIX, now, *ids),
    ) as cur:
        locks = [(row[0], bool(row[1]), int(row[2]), row[3]) for row in await cur.fetchall()]
    for user in users:
        score = scores.get(user["id"], 0.0)
        user["failed_attempts"] = round(score)
        user["throttled"] = round(score) >= policy["client_login_account_max_failures"]
        for user_id, is_network, count, until in locks:
            if user_id != user["id"]:
                continue
            user["locked_networks" if is_network else "locked_addresses"] = count
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


_CLEAR_SCORE_SQL = "failed_attempts = 0, locked_until = NULL, login_score = NULL, login_score_at = NULL"


async def set_password(user_id: str, password: str) -> None:
    """Resets the password (policy-checked), clears every lock-out (addresses,
    networks, account score), forgets the account's known addresses, and revokes
    all the user's sessions. Raises ValueError (policy) or LookupError (unknown user)."""
    user = await get_by_id(user_id)
    if user is None:
        raise LookupError("Unknown user")
    validate_password(password, user["username"])
    password_hash = await asyncio.to_thread(hash_password, password)
    async with db_session() as conn:
        cur = await conn.execute(
            "UPDATE client_users SET password_hash = ?, password_changed_at = ?, "
            f"{_CLEAR_SCORE_SQL} WHERE id = ?",
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
    """Clears every lock-out of the account: its locked-out addresses and their
    counts, its network counts and locks, and the account-wide score (which ends
    backstop mode). Known addresses are kept. Raises LookupError."""
    async with db_session() as conn:
        cur = await conn.execute(
            f"UPDATE client_users SET {_CLEAR_SCORE_SQL} WHERE id = ?", (user_id,))
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

async def _prune_login_failures(conn: aiosqlite.Connection, now: float) -> int:
    """Drops client_login_failures rows that no longer matter, then enforces
    LOGIN_FAILURE_MAX_ROWS. Does not commit.
      - an address row: not locked, no failure within ADDRESS_FAILURE_MEMORY_SECONDS
        and no sign-in within KNOWN_ADDRESS_DAYS;
      - a network row: not locked and no failure within NETWORK_FAILURE_MEMORY_SECONDS.
    The cap counts only rows that do NOT mark a known address, and evicts them
    oldest first, address rows before network rows. A known-address row is never
    evicted, so a flood of failure rows cannot cost a client its known address."""
    is_net = "substr(client_ip, 1, ?) = ?"
    net = (len(NETWORK_KEY_PREFIX), NETWORK_KEY_PREFIX)
    cur = await conn.execute(
        "DELETE FROM client_login_failures WHERE (locked_until IS NULL OR locked_until <= ?) AND ("
        f"(NOT {is_net} AND COALESCE(last_failed_at, 0) <= ? AND COALESCE(last_success_at, 0) <= ?) "
        f"OR ({is_net} AND COALESCE(last_failed_at, 0) <= ?))",
        (now, *net, now - ADDRESS_FAILURE_MEMORY_SECONDS, now - _KNOWN_SECONDS,
         *net, now - NETWORK_FAILURE_MEMORY_SECONDS),
    )
    removed = max(cur.rowcount, 0)
    evictable = "COALESCE(last_success_at, 0) <= ?"
    async with conn.execute(
            f"SELECT COUNT(*) FROM client_login_failures WHERE {evictable}", (now - _KNOWN_SECONDS,)) as c:
        excess = int((await c.fetchone())[0]) - LOGIN_FAILURE_MAX_ROWS
    if excess > 0:
        cur = await conn.execute(
            "DELETE FROM client_login_failures WHERE rowid IN (SELECT rowid FROM client_login_failures "
            f"WHERE {evictable} ORDER BY {is_net}, "
            "MAX(COALESCE(last_failed_at, 0), COALESCE(locked_until, 0)) LIMIT ?)",
            (now - _KNOWN_SECONDS, *net, excess))
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
    user, wrong password, disabled, address or network locked out) so the API can
    answer identically and not reveal which accounts exist. An unknown username
    takes the same path as a real one: policy read, one lookup, a scrypt check
    (against a dummy hash), then _settle_attempt's fixed set of statements.
    Lock state is read only after the hash. See the module docstring for the
    lock-out rules. The typed username is never logged.
    """
    password = password if isinstance(password, str) else ""
    # An over-long password never matches (policy max) — don't spend scrypt on it
    # beyond the normal cost: hash a bounded prefix so timing stays flat.
    candidate = password[:PASSWORD_MAX_LENGTH + 1]
    policy = await _login_policy()
    try:
        name = normalize_username(username)
    except ValueError:
        name = ""  # still looked up (finds nothing), for the same work
    async with db_session() as conn:
        async with conn.execute(
            "SELECT id, password_hash FROM client_users WHERE username = ? COLLATE NOCASE", (name,),
        ) as cur:
            row = await cur.fetchone()
    user_id, stored_hash = row if row else (None, _get_dummy_hash())
    ok = await asyncio.to_thread(check_password, candidate, stored_hash)
    ok = ok and row is not None and len(password) <= PASSWORD_MAX_LENGTH
    user = await _settle_attempt(user_id, ok, client_ip, policy)
    if time.time() - _last_login_failure_prune >= LOGIN_FAILURE_PRUNE_INTERVAL:
        try:
            await purge_login_failures()
        except Exception as e:  # housekeeping must never fail a login
            logger.warning("client_login_failures_purge_failed", error=str(e))
    return user


_SELECT_ROW_SQL = ("SELECT failed_attempts, last_failed_at, locked_until, last_success_at "
                   "FROM client_login_failures WHERE user_id = ? AND client_ip = ?")
_UPSERT_FAILURE_SQL = (
    "INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at, "
    "locked_until, last_success_at) VALUES (?, ?, ?, ?, ?, NULL) "
    "ON CONFLICT(user_id, client_ip) DO UPDATE SET failed_attempts = excluded.failed_attempts, "
    "last_failed_at = excluded.last_failed_at, locked_until = excluded.locked_until")
_UPSERT_SUCCESS_SQL = (
    "INSERT INTO client_login_failures (user_id, client_ip, failed_attempts, last_failed_at, "
    "locked_until, last_success_at) VALUES (?, ?, 0, NULL, NULL, ?) "
    "ON CONFLICT(user_id, client_ip) DO UPDATE SET failed_attempts = 0, last_failed_at = NULL, "
    "locked_until = NULL, last_success_at = excluded.last_success_at")
_PAD_SQL = ("INSERT INTO client_login_pad (slot, at) VALUES (?, ?) "
            "ON CONFLICT(slot) DO UPDATE SET at = excluded.at")


async def _settle_attempt(user_id: str | None, ok: bool, client_ip: str,
                          policy: dict[str, int]) -> User | None:
    """Applies the lock-out rules to one checked attempt (user_id None = unknown
    username) in ONE write transaction: the lock state is read after the (slow)
    hash, and concurrent attempts are serialised, so a burst of parallel guesses
    all count and a correct guess racing a lock-out is still refused.

    Whatever the outcome it executes the same statements: BEGIN IMMEDIATE, three
    SELECTs (account, address row, network row), exactly _WRITE_SLOTS writes (the
    ones the outcome needs, the rest to client_login_pad) and COMMIT — so an
    unknown username costs what a real one does."""
    addr, net = address_key(client_ip), network_key(client_ip)
    now = time.time()
    uid = user_id or ""
    writes: list[tuple[str, tuple]] = []
    events: list[tuple[str, str, dict[str, Any]]] = []
    who = {"user_id": user_id, "client_ip": client_ip}
    succeeded = False
    async with db_session() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute(
                "SELECT disabled, login_score, login_score_at FROM client_users WHERE id = ?", (uid,)) as cur:
            acct = await cur.fetchone()
        async with conn.execute(_SELECT_ROW_SQL, (uid, addr)) as cur:
            pair = await cur.fetchone()
        async with conn.execute(_SELECT_ROW_SQL, (uid, net)) as cur:
            group = await cur.fetchone()

        pair_failures, pair_last_failed, pair_locked_until, last_success = pair or (0, None, None, None)
        net_failures, net_last_failed, net_locked_until, _ = group or (0, None, None, None)
        known = bool(last_success and last_success > now - _KNOWN_SECONDS)

        if acct is None:  # unknown username (or deleted while the hash ran)
            events.append(("info", "client_login_rejected",
                           {"reason": "unknown_user", "client_ip": client_ip}))
        elif pair_locked_until and pair_locked_until > now:
            events.append(("warning", "client_login_rejected", {"reason": "address_locked", **who}))
        elif not known and net_locked_until and net_locked_until > now:
            events.append(("warning", "client_login_rejected", {"reason": "network_locked", **who}))
        elif acct[0]:
            events.append(("warning", "client_login_rejected", {"reason": "disabled", **who}))
        elif ok:
            writes.append(("UPDATE client_users SET last_login_at = ? WHERE id = ?", (now, uid)))
            writes.append((_UPSERT_SUCCESS_SQL, (uid, addr, now)))
            succeeded = True
        else:
            writes.extend(_count_wrong_password(
                uid, addr, net, now, policy, known, acct,
                (pair_failures, pair_last_failed, pair_locked_until),
                (net_failures, net_last_failed), events, who))

        assert len(writes) <= _WRITE_SLOTS
        for slot in range(len(writes), _WRITE_SLOTS):
            writes.append((_PAD_SQL, (slot, now)))
        for sql, params in writes:
            await conn.execute(sql, params)
        await conn.commit()

    for level, event, fields in events:
        getattr(logger, level)(event, **fields)
    return await get_by_id(uid) if succeeded else None


def _count_wrong_password(uid: str, addr: str, net: str, now: float, policy: dict[str, int],
                          known: bool, acct: Any, pair: tuple, group: tuple,
                          events: list, who: dict[str, Any]) -> list[tuple[str, tuple]]:
    """The writes (at most _WRITE_SLOTS) and log events for one wrong password."""
    writes: list[tuple[str, tuple]] = []
    lockout_s = policy["client_login_lockout_minutes"] * 60

    # this address
    max_failures = policy["client_login_max_failures"]
    failures, last_failed, locked_until = pair
    # An expired lock, or a last failure long ago, starts a fresh count.
    fresh = (locked_until is not None or not last_failed
             or last_failed <= now - ADDRESS_FAILURE_MEMORY_SECONDS)
    failures = 1 if fresh else int(failures or 0) + 1
    writes.append((_UPSERT_FAILURE_SQL, (uid, addr, failures, now,
                                         now + lockout_s if failures >= max_failures else None)))
    if failures == max_failures:
        events.append(("warning", "client_account_locked",
                       {"scope": "address", "lockout_minutes": lockout_s // 60,
                        "failed_attempts": failures, **who}))

    # the account-wide score, and backstop mode
    threshold = policy["client_login_account_max_failures"]
    # Compared rounded: the score drains continuously, so N quick wrong passwords
    # score a hair under N.
    before = _current_score(acct[1], acct[2], now, policy)
    score = before + 1
    in_backstop = round(score) >= threshold
    writes.append(("UPDATE client_users SET login_score = ?, login_score_at = ? WHERE id = ?",
                   (score, now, uid)))
    if round(before) < threshold <= round(score):
        events.append(("warning", "client_account_throttled",
                       {"account_failures": round(score), "client_ip": who["client_ip"],
                        "user_id": who["user_id"]}))
    fields: dict[str, Any] = {"reason": "bad_password", "failed_attempts": failures,
                              "account_failures": round(score)}

    # this network, in backstop mode, unless the address is known to the account
    if in_backstop and not known:
        allowance = policy["client_login_backstop_max_failures"]
        net_failures, net_last_failed = group
        # Not restarted by an expired lock: the lock keeps doubling.
        if not net_last_failed or net_last_failed <= now - NETWORK_FAILURE_MEMORY_SECONDS:
            net_failures = 0
        net_failures = int(net_failures or 0) + 1
        net_lock = None
        if net_failures >= allowance:
            lock_s = min(policy["client_login_backstop_max_lock_hours"] * 3600.0,
                         lockout_s * 2.0 ** min(net_failures - allowance, 30))
            net_lock = now + lock_s
            events.append(("warning", "client_account_locked",
                           {"scope": "network", "lockout_minutes": int(lock_s // 60),
                            "failed_attempts": net_failures, **who}))
        writes.append((_UPSERT_FAILURE_SQL, (uid, net, net_failures, now, net_lock)))
        fields["network_failures"] = net_failures
    events.insert(0, ("warning", "client_login_rejected", {**fields, **who}))
    return writes


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
