"""
Engineer API for client-portal accounts: list, create, reset password,
enable/disable, unlock, delete, revoke sessions. There is no CLI — the dashboard
is the only way to manage client accounts.

Every route is gated by the dashboard key (router-level require_engineer, the
same check as dashboard._check_access; the /dashboard/api/ prefix gate in
middleware/security.py applies too). Password hashes are never returned. A
generated password is returned exactly once, in the response that created it.

    GET    /dashboard/api/portal/users                       -> {users: [User]}
    POST   /dashboard/api/portal/users                       {username, password?, display_name?}
                                                             -> 201 {user, generated_password?}
    POST   /dashboard/api/portal/users/{id}/password         {password?} -> {user, generated_password?}
    POST   /dashboard/api/portal/users/{id}/disable          -> {user}
    POST   /dashboard/api/portal/users/{id}/enable           -> {user}
    POST   /dashboard/api/portal/users/{id}/unlock           -> {user}
    POST   /dashboard/api/portal/users/{id}/revoke-sessions  -> {user, revoked}
    DELETE /dashboard/api/portal/users/{id}                  -> {deleted: true}

Errors: 404 {"detail": "Client user not found"}; 400 {"detail": <policy message>};
409 {"detail": "That username is already taken"}; 422 for a malformed body.
"""
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
import structlog
from src.middleware.auth import require_engineer
from src.middleware.security import client_key
from src.storage import user_store

router = APIRouter(
    prefix="/dashboard/api/portal",
    tags=["Portal Admin"],
    dependencies=[Depends(require_engineer)],
)
logger = structlog.get_logger(__name__)

NOT_FOUND = "Client user not found"


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str | None = None
    display_name: str | None = None


class SetPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str | None = None


def _audit(event: str, request: Request, **fields: Any) -> None:
    logger.info(event, actor="engineer", client_ip=client_key(request), **fields)


async def _user_or_404(user_id: str) -> dict[str, Any]:
    user = await user_store.get_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return user


def _password_or_generated(password: str | None) -> tuple[str, bool]:
    """Blank/omitted -> a generated password (returned once to the engineer)."""
    if password is None or password == "":
        return user_store.generate_password(), True
    return password, False


@router.get("/users")
async def list_users() -> dict[str, Any]:
    return {"users": await user_store.list_users()}


@router.post("/users", status_code=201)
async def create_user(body: CreateUserRequest, request: Request) -> dict[str, Any]:
    password, generated = _password_or_generated(body.password)
    try:
        user = await user_store.create_user(body.username, password, body.display_name)
    except user_store.DuplicateUsernameError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit("client_user_created", request, user_id=user["id"], username=user["username"],
           password_generated=generated)
    out: dict[str, Any] = {"user": user}
    if generated:
        out["generated_password"] = password
    return out


@router.post("/users/{user_id}/password")
async def reset_password(user_id: str, request: Request,
                         body: SetPasswordRequest | None = None) -> dict[str, Any]:
    await _user_or_404(user_id)
    password, generated = _password_or_generated(body.password if body else None)
    try:
        await user_store.set_password(user_id, password)
    except LookupError:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    user = await _user_or_404(user_id)
    _audit("client_user_password_reset", request, user_id=user_id, username=user["username"],
           password_generated=generated)
    out: dict[str, Any] = {"user": user}
    if generated:
        out["generated_password"] = password
    return out


async def _set_disabled(user_id: str, disabled: bool, request: Request) -> dict[str, Any]:
    try:
        await user_store.set_disabled(user_id, disabled)
    except LookupError:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    user = await _user_or_404(user_id)
    _audit("client_user_disabled" if disabled else "client_user_enabled", request,
           user_id=user_id, username=user["username"])
    return {"user": user}


@router.post("/users/{user_id}/disable")
async def disable_user(user_id: str, request: Request) -> dict[str, Any]:
    return await _set_disabled(user_id, True, request)


@router.post("/users/{user_id}/enable")
async def enable_user(user_id: str, request: Request) -> dict[str, Any]:
    return await _set_disabled(user_id, False, request)


@router.post("/users/{user_id}/unlock")
async def unlock_user(user_id: str, request: Request) -> dict[str, Any]:
    try:
        await user_store.unlock_user(user_id)
    except LookupError:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    user = await _user_or_404(user_id)
    _audit("client_user_unlocked", request, user_id=user_id, username=user["username"])
    return {"user": user}


@router.post("/users/{user_id}/revoke-sessions")
async def revoke_sessions(user_id: str, request: Request) -> dict[str, Any]:
    user = await _user_or_404(user_id)
    revoked = await user_store.revoke_sessions(user_id)
    _audit("client_user_sessions_revoked", request, user_id=user_id, username=user["username"],
           revoked=revoked)
    return {"user": await _user_or_404(user_id), "revoked": revoked}


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, request: Request) -> dict[str, Any]:
    user = await _user_or_404(user_id)
    if not await user_store.delete_user(user_id):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    _audit("client_user_deleted", request, user_id=user_id, username=user["username"])
    return {"deleted": True}
