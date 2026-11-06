"""Engineer API for dashboard-editable portal settings: GET all / PUT one / reset one, backed by storage/runtime_settings.py. Gated by the dashboard key via dashboard._check_access."""
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.api.dashboard import _check_access
from src.storage import runtime_settings

router = APIRouter(prefix="/dashboard/api/portal-settings", tags=["Portal Settings"])
logger = structlog.get_logger(__name__)


class SettingUpdate(BaseModel):
    value: Any


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _known_spec(key: str) -> runtime_settings.SettingSpec:
    """404 for a key that is not in the registry, before anything is written."""
    spec = runtime_settings.REGISTRY.get(key)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"Unknown setting: {key!r}")
    return spec


def _validate(spec: runtime_settings.SettingSpec, value: Any) -> Any:
    """Coerces and validates through the store; ValueError's message is UI-safe."""
    try:
        return runtime_settings.validate(spec.key, value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


def _prerequisite_problem() -> str | None:
    """
    Why the client portal may not be switched on, or None if it may.

    The guard module lives with the rest of the portal, so it is imported here
    rather than at module load: an installation without it (or a partially
    applied deploy) must not fail to start the dashboard. A missing guard is
    treated as "no prerequisites declared".
    """
    try:
        from src.services.portal_guard import portal_prerequisites_ok
    except ImportError:
        return None
    ok, reason = portal_prerequisites_ok()
    return None if ok else (str(reason) or "Portal prerequisites are not met")


@router.get("")
async def list_portal_settings(request: Request) -> dict[str, Any]:
    """Every registry setting with its effective value, default, source and constraints."""
    _check_access(request)
    return {"settings": await runtime_settings.get_all()}


@router.put("/{key}")
async def update_portal_setting(request: Request, key: str, payload: SettingUpdate) -> dict[str, Any]:
    """Saves a dashboard override for one setting; takes effect on the next read."""
    _check_access(request)
    spec = _known_spec(key)
    value = _validate(spec, payload.value)

    # Enabling the portal is the one change that can make the service
    # unreachable or unusable, so it waits for the portal's own preflight.
    if spec.key == "client_portal_enabled" and value:
        problem = _prerequisite_problem()
        if problem is not None:
            raise HTTPException(status_code=409, detail=problem)

    await runtime_settings.set(key, value)
    logger.info("portal_setting_updated", key=key, value=value, client_ip=_client_ip(request))
    return {"key": key, "value": value, "source": "db"}


@router.delete("/{key}")
async def reset_portal_setting(request: Request, key: str) -> dict[str, Any]:
    """Drops the dashboard override so the env default applies again."""
    _check_access(request)
    _known_spec(key)
    removed = await runtime_settings.reset(key)
    value = await runtime_settings.get(key)
    logger.info("portal_setting_reset", key=key, value=value, had_override=removed,
                client_ip=_client_ip(request))
    return {"key": key, "value": value, "source": await runtime_settings.source(key)}
