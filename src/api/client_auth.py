"""
Client portal login / logout / current user.

The portal authenticates with an opaque session token returned by POST /login and
sent back on every call in the X-Client-Session header (see
src/middleware/auth.py: require_client). Only a hash of the token is stored.

    POST /client/api/auth/login   {username, password}
         200 {token, expires_at, idle_timeout_seconds, user: {username, display_name}}
         401 {"detail": "Invalid username or password"}   (any failure, same body)
         429 Retry-After                                   (address throttled)
         404 {"detail": "client portal disabled"}
    POST /client/api/auth/logout  (X-Client-Session)  200 {"ok": true}
    GET  /client/api/auth/me      (X-Client-Session)  200 {user: {...}, expires_at}

Audit events (structlog): client_login_succeeded, client_login_failed,
client_logout. Passwords and tokens are never logged, and neither is the
username TYPED into a failed login (a client who pastes their password into the
username box would otherwise leave it in the log): user_store logs the account's
user_id for an existing account and only reason=unknown_user otherwise.
Successful-login and logout events name the account by its stored username
(field `account`), which is the validated name the engineer created.
"""
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
import structlog
from src.middleware.auth import CLIENT_SESSION_HEADER, require_client, require_portal_enabled
from src.middleware.security import auth_limiter, client_key, warn_if_untrusted_proxy
from src.storage import runtime_settings, user_store

router = APIRouter(prefix="/client/api/auth", tags=["Client Portal Auth"])
logger = structlog.get_logger(__name__)

LOGIN_FAILED_DETAIL = "Invalid username or password"


class LoginRequest(BaseModel):
    # Generous bounds: anything that cannot be a valid credential still gets the
    # same generic 401 (and costs the same hashing work) rather than a 422 that
    # would describe the policy to a guesser.
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=1024)


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    """What the portal is told about its own user."""
    return {"username": user["username"], "display_name": user.get("display_name")}


@router.post("/login", dependencies=[Depends(require_portal_enabled)])
async def login(body: LoginRequest, request: Request) -> dict[str, Any]:
    client_ip = client_key(request)
    warn_if_untrusted_proxy(request)
    wait = auth_limiter.retry_after(client_ip)
    if wait:
        logger.warning("client_login_throttled", client_ip=client_ip)
        raise HTTPException(status_code=429, detail="Too many failed attempts",
                            headers={"Retry-After": str(wait)})

    # Counted as a failure up front (no await between the check above and this),
    # and withdrawn only once the credentials prove correct: otherwise a burst of
    # parallel logins would all pass retry_after() while the first ones are
    # still hashing, and the per-address limit would never apply.
    auth_limiter.record_failure(client_ip)
    user = await user_store.verify_credentials(body.username, body.password, client_ip)
    if user is None:
        # No username here, not even a valid-looking one: see the module docstring.
        logger.warning("client_login_failed", client_ip=client_ip)
        raise HTTPException(status_code=401, detail=LOGIN_FAILED_DETAIL)
    auth_limiter.forgive(client_ip)

    token, expires_at = await user_store.create_session(user["id"], client_ip)
    # Opportunistic housekeeping instead of a background loop.
    try:
        purged = await user_store.purge_expired_sessions()
        if purged:
            logger.info("client_sessions_purged", count=purged)
    except Exception as e:  # never fail a good login over housekeeping
        logger.warning("client_sessions_purge_failed", error=str(e))

    idle_minutes = await runtime_settings.get("client_session_idle_minutes")
    logger.info("client_login_succeeded", user_id=user["id"], account=user["username"],
                client_ip=client_ip)
    return {
        "token": token,
        "expires_at": expires_at,
        "idle_timeout_seconds": int(idle_minutes) * 60,
        "user": public_user(user),
    }


@router.post("/logout")
async def logout(request: Request, user: dict[str, Any] = Depends(require_client)) -> dict[str, Any]:
    await user_store.delete_session(request.headers.get(CLIENT_SESSION_HEADER) or "")
    logger.info("client_logout", user_id=user["id"], account=user["username"],
                client_ip=client_key(request))
    return {"ok": True}


@router.get("/me")
async def me(user: dict[str, Any] = Depends(require_client)) -> dict[str, Any]:
    return {"user": public_user(user), "expires_at": user.get("session_expires_at")}
