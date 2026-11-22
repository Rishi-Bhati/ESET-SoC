"""Engineer API to hide alerts from every view and report without deleting them
(storage/hidden_store.py). Gated by the dashboard key via dashboard._check_access;
POSTs also pass the same-origin check in middleware/security.py."""
import re
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, field_validator

from src.api.dashboard import _check_access
from src.storage import hidden_store

router = APIRouter(prefix="/dashboard/api/alerts", tags=["Hidden alerts"])

# Same alphabet as the other alert-id routes (ids double as result file names).
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
MAX_IDS = 5000
MAX_REASON_LENGTH = 500
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _check_ids(ids: list[str]) -> list[str]:
    bad = [i for i in ids if not _ID_RE.fullmatch(i or "") or i in (".", "..")]
    if bad:
        raise ValueError(f"invalid alert ids: {bad[:5]}")
    return ids


class HideRequest(BaseModel):
    correlation_ids: list[str] = Field(..., min_length=1, max_length=MAX_IDS)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)

    @field_validator("correlation_ids")
    @classmethod
    def _valid_ids(cls, ids: list[str]) -> list[str]:
        return _check_ids(ids)

    @field_validator("reason")
    @classmethod
    def _clean_reason(cls, value: str | None) -> str | None:
        cleaned = _CONTROL_RE.sub("", value or "").strip()
        return cleaned or None


class UnhideRequest(BaseModel):
    correlation_ids: list[str] = Field(..., min_length=1, max_length=MAX_IDS)

    @field_validator("correlation_ids")
    @classmethod
    def _valid_ids(cls, ids: list[str]) -> list[str]:
        return _check_ids(ids)


@router.get("/hidden")
async def list_hidden(request: Request) -> dict[str, Any]:
    _check_access(request)
    rows = await hidden_store.list_hidden()
    return {"hidden": rows, "count": len(rows)}


@router.post("/hide")
async def hide_alerts(request: Request, body: HideRequest) -> dict[str, Any]:
    _check_access(request)
    hidden = await hidden_store.hide(body.correlation_ids, hidden_by="dashboard", reason=body.reason)
    return {"hidden": hidden, "requested": len(set(body.correlation_ids))}


@router.post("/unhide")
async def unhide_alerts(request: Request, body: UnhideRequest) -> dict[str, Any]:
    _check_access(request)
    restored = await hidden_store.unhide(body.correlation_ids)
    return {"unhidden": restored, "requested": len(set(body.correlation_ids))}
