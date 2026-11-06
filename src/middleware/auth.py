"""
The three credentials, each accepted only on its own route class:

  * validate_eset_token — ingest (/webhook/*): `Authorization` header.
  * require_engineer    — engineering API (/dashboard/api/*, /status/*):
                          `X-Dashboard-Key` header only (dashboard._check_access
                          is the same check for handlers that call it inline).
  * require_client      — client portal API (/client/api/*): `X-Client-Session`
                          header only (the token returned by POST
                          /client/api/auth/login). Never accepts the dashboard key
                          or the webhook token, and the engineer routes never
                          accept a client session.
"""
import hmac
from typing import Any
from fastapi import Request, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
import structlog
from src.config import settings
from src.middleware.security import auth_limiter, check_engineer_key, client_key
from src.services import portal_guard
from src.storage import user_store

logger = structlog.get_logger(__name__)

CLIENT_SESSION_HEADER = "X-Client-Session"
PORTAL_DISABLED_STATUS = 404
PORTAL_DISABLED_DETAIL = "client portal disabled"
CLIENT_UNAUTHORIZED_DETAIL = "Not authenticated"


# ------------------------------ engineer ------------------------------

def check_engineer_access(request: Request) -> None:
    """
    If DASHBOARD_ACCESS_KEY is configured, require it via the X-Dashboard-Key
    header (constant-time compare, wrong keys throttled per address). Blank key =
    open. Raises HTTPException 401/429. dashboard._check_access delegates here.
    """
    if not settings.dashboard_access_key:
        return  # open; nothing about the request is inspected (as before)
    failure = check_engineer_key(
        request.headers.get("x-dashboard-key") or "", client_key(request), request.url.path)
    if failure is not None:
        status, detail, headers = failure
        raise HTTPException(status_code=status, detail=detail, headers=headers or None)


async def require_engineer(request: Request) -> None:
    """FastAPI dependency form of check_engineer_access, e.g.
    APIRouter(..., dependencies=[Depends(require_engineer)])."""
    check_engineer_access(request)


# ------------------------------ client ------------------------------

def _portal_disabled() -> HTTPException:
    return HTTPException(status_code=PORTAL_DISABLED_STATUS, detail=PORTAL_DISABLED_DETAIL)


async def require_portal_enabled(request: Request) -> None:
    """Dependency: 404 {"detail": "client portal disabled"} unless the portal is
    switched on (runtime setting client_portal_enabled) AND its prerequisites
    hold (a strong dashboard key — see services/portal_guard.py)."""
    ok, reason = await portal_guard.portal_available()
    if not ok:
        if reason and reason != "client portal is switched off":
            logger.error("client_portal_refused_unsafe_config", problem=reason,
                         path=request.url.path)
        raise _portal_disabled()


async def require_client(request: Request) -> dict[str, Any]:
    """
    Dependency for every /client/api/* route except login. Reads ONLY the
    X-Client-Session header and returns the user dict (no password hash; includes
    `session_expires_at`). Also stored on request.state.client_user.

      404 {"detail": "client portal disabled"} — portal off or unsafe config
      429                                     — address throttled (auth failures)
      401 {"detail": "Not authenticated"}     — missing/unknown/expired session,
                                                 disabled or deleted user

    Use it as a dependency (not an inline call), so it runs before request
    validation: router-level `dependencies=[Depends(require_client)]` or a
    `user = Depends(require_client)` parameter.
    """
    await require_portal_enabled(request)
    client_ip = client_key(request)
    wait = auth_limiter.retry_after(client_ip)
    if wait:
        raise HTTPException(status_code=429, detail="Too many failed attempts",
                            headers={"Retry-After": str(wait)})
    token = request.headers.get(CLIENT_SESSION_HEADER) or ""
    # An invalid/expired token is not counted as a guess: tokens are 256-bit
    # random values (unguessable), and a portal tab left open past the idle
    # timeout would otherwise throttle everyone behind the same address.
    user = await user_store.resolve_session(token) if token else None
    if user is None:
        raise HTTPException(status_code=401, detail=CLIENT_UNAUTHORIZED_DETAIL)
    request.state.client_user = user
    return user


# ------------------------------ ingest ------------------------------

# Webhooks from ESET may send credentials in the Authorization header.
# We configure APIKeyHeader to retrieve this header.
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def validate_eset_token(
    request: Request,
    api_key: str | None = Security(api_key_header),
) -> None:
    """
    Validates ESET webhook authorization token using a timing-attack safe comparison.
    If unauthorized, logs client details and raises 401 with no response body detail.
    """
    client_ip = client_key(request)
    wait = auth_limiter.retry_after(client_ip)
    if wait:
        raise HTTPException(status_code=429, headers={"Retry-After": str(wait)})

    if not api_key:
        logger.warning("auth_failed_missing_header", client_ip=client_ip)
        raise HTTPException(status_code=401)
        
    # Standardize header token: check if it's 'Bearer <token>' or just '<token>'
    token = api_key
    if api_key.lower().startswith("bearer "):
        token = api_key[7:].strip()
        
    expected_token = settings.eset_webhook_auth_token
    if not expected_token:
        # Not configured (e.g. APP_SECRETS_SECRET_ID not loaded yet): refuse
        # everything rather than accept an empty token.
        logger.error("auth_failed_token_not_configured", client_ip=client_ip)
        raise HTTPException(status_code=401)

    # Timing-safe comparison to prevent side-channel analysis
    if not hmac.compare_digest(token.encode("utf-8"), expected_token.encode("utf-8")):
        auth_limiter.record_failure(client_ip)
        logger.warning("auth_failed_token_mismatch", client_ip=client_ip)
        raise HTTPException(status_code=401)
        
    logger.debug("auth_success", client_ip=client_ip)
