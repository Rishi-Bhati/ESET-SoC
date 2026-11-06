"""
Preconditions for running the client portal.

The portal is internet-facing for client staff, so it may only run when the
engineering API behind it is locked: with a blank (or weak) DASHBOARD_ACCESS_KEY
every /dashboard/api/* route is open to anyone who can reach the port, which
would hand a client — or anyone — the whole engineering surface.

    ok, reason = portal_guard.portal_prerequisites_ok()   # sync, cheap
    ok, reason = await portal_guard.portal_available()    # + the runtime on/off switch

Used by:
  * src/middleware/auth.py (require_client / login) — the portal refuses service.
  * the settings API — refuse to switch client_portal_enabled ON while not ok.
  * src/main.py startup — production refuses to start, other envs log an error.
"""
import structlog
from src.config import settings
from src.storage import runtime_settings

logger = structlog.get_logger(__name__)

MIN_DASHBOARD_KEY_LENGTH = 16


def portal_prerequisites_ok() -> tuple[bool, str]:
    """(True, "") when the portal may run; otherwise (False, a reason safe to show
    to an engineer in the dashboard). Does not look at the on/off switch."""
    key = settings.dashboard_access_key or ""
    if not key.strip():
        return False, ("DASHBOARD_ACCESS_KEY is blank: the engineering API would be open to anyone "
                       "who can reach the client portal. Set a dashboard key first.")
    if len(key) < MIN_DASHBOARD_KEY_LENGTH:
        return False, (f"DASHBOARD_ACCESS_KEY is shorter than {MIN_DASHBOARD_KEY_LENGTH} characters. "
                       "Set a stronger dashboard key first.")
    return True, ""


async def portal_available() -> tuple[bool, str]:
    """(True, "") when the portal is switched on (effective runtime value) AND its
    prerequisites hold."""
    if not await runtime_settings.get("client_portal_enabled"):
        return False, "client portal is switched off"
    return portal_prerequisites_ok()


async def check_at_startup() -> None:
    """Startup guard, run after init_db(). When the portal is enabled (effective
    runtime value: dashboard override, else CLIENT_PORTAL_ENABLED) but its
    prerequisites fail, production refuses to start; other environments log an
    error (and the portal still refuses service at request time)."""
    try:
        enabled = await runtime_settings.get("client_portal_enabled")
    except Exception as e:  # unreadable DB value: fall back to the env default
        logger.error("client_portal_guard_setting_unreadable", error=str(e))
        enabled = runtime_settings.default("client_portal_enabled")
    if not enabled:
        return
    ok, reason = portal_prerequisites_ok()
    if ok:
        return
    logger.error("client_portal_unsafe_config", problem=reason)
    if settings.app_env.lower() == "production":
        raise RuntimeError("Refusing to start with APP_ENV=production: client portal is enabled but " + reason)
