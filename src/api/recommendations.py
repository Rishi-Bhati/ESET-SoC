"""Engineer API for alert recommendations (create / list / retract). Gated by the dashboard key via dashboard._check_access."""
import os
import re
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator

from src.api.dashboard import _check_access
from src.config import settings
from src.services import recommendation_notifier
from src.storage import job_store, recommendation_store
from src.utils import events

router = APIRouter(prefix="/dashboard/api", tags=["Recommendations"])
logger = structlog.get_logger(__name__)

# Ids become file names under output_dir (result files) so only this alphabet is accepted.
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

MAX_CIDS = 500
MAX_BODY_LENGTH = 4000
MAX_AUTHOR_LENGTH = 100
MAX_REASON_LENGTH = 500

# Control characters, except tab (\x09) and newline (\x0a), which the text may
# legitimately contain. Everything else is removed before storage or rendering.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _clean(value: str) -> str:
    return _CONTROL_RE.sub("", value or "").strip()


def _valid_id(value: str) -> bool:
    return _ID_RE.fullmatch(value or "") is not None


def _require_valid_id(value: str, what: str) -> str:
    if not _valid_id(value):
        raise HTTPException(status_code=400, detail=f"Invalid {what}")
    return value


async def _alert_exists(correlation_id: str) -> bool:
    """An alert exists if it has a jobs row or a result file. Caller validated the id."""
    if await job_store.get_job(correlation_id) is not None:
        return True
    return os.path.exists(os.path.join(settings.output_dir, f"{correlation_id}.json"))


class RecommendationCreate(BaseModel):
    body: str
    author: str

    @field_validator("body")
    @classmethod
    def _validate_body(cls, value: str) -> str:
        cleaned = _clean(value)
        if not cleaned:
            raise ValueError("Recommendation text is required")
        if len(cleaned) > MAX_BODY_LENGTH:
            raise ValueError(f"Recommendation text must be at most {MAX_BODY_LENGTH} characters")
        return cleaned

    @field_validator("author")
    @classmethod
    def _validate_author(cls, value: str) -> str:
        cleaned = _clean(value)
        if not cleaned:
            raise ValueError("author is required")
        if len(cleaned) > MAX_AUTHOR_LENGTH:
            raise ValueError(f"author must be at most {MAX_AUTHOR_LENGTH} characters")
        return cleaned


class RecommendationRetract(BaseModel):
    author: str
    reason: str = ""

    @field_validator("author")
    @classmethod
    def _validate_author(cls, value: str) -> str:
        cleaned = _clean(value)
        if not cleaned:
            raise ValueError("author is required")
        if len(cleaned) > MAX_AUTHOR_LENGTH:
            raise ValueError(f"author must be at most {MAX_AUTHOR_LENGTH} characters")
        return cleaned

    @field_validator("reason")
    @classmethod
    def _validate_reason(cls, value: str) -> str:
        cleaned = _clean(value)
        if len(cleaned) > MAX_REASON_LENGTH:
            raise ValueError(f"Reason must be at most {MAX_REASON_LENGTH} characters")
        return cleaned


@router.get("/alerts/{correlation_id}/recommendations")
async def list_alert_recommendations(request: Request, correlation_id: str) -> dict[str, Any]:
    """Every recommendation for an alert, oldest first, including retracted ones —
    this is the engineer's view; the client portal only reads active ones."""
    _check_access(request)
    _require_valid_id(correlation_id, "correlation id")
    if not await _alert_exists(correlation_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    recommendations = await recommendation_store.list_for_alert(correlation_id, include_retracted=True)
    return {"recommendations": recommendations}


@router.post("/alerts/{correlation_id}/recommendations", status_code=201)
async def create_alert_recommendation(
    request: Request, correlation_id: str, payload: RecommendationCreate
) -> dict[str, Any]:
    """
    Adds a recommendation to an alert, and — when recommendation_email_enabled is
    on — queues the client email (src/services/recommendation_notifier.py). The
    recommendation is saved whatever happens to the email; `notification` says
    whether one was queued and, if not, why.
    """
    _check_access(request)
    _require_valid_id(correlation_id, "correlation id")
    if not await _alert_exists(correlation_id):
        raise HTTPException(status_code=404, detail="Alert not found")

    recommendation = await recommendation_store.create(correlation_id, payload.body, payload.author)
    # Audit trail: ids only, never the body text.
    logger.info(
        "recommendation_api_created",
        recommendation_id=recommendation["id"],
        correlation_id=correlation_id,
        author=recommendation["author"],
    )
    await events.emit("recommendation_added", {
        "correlation_id": correlation_id,
        "recommendation_id": recommendation["id"],
    })
    notification = await recommendation_notifier.notify_recommendation_added(recommendation)
    if notification["queued"]:
        recommendation["notification_email_id"] = notification["email_id"]
        recommendation_notifier.dispatch_soon()
    return {"recommendation": recommendation, "notification": notification}


@router.post("/recommendations/{recommendation_id}/retract")
async def retract_recommendation(
    request: Request, recommendation_id: str, payload: RecommendationRetract
) -> dict[str, Any]:
    """Withdraws a recommendation (the record stays). Retracting twice keeps the first reason."""
    _check_access(request)
    _require_valid_id(recommendation_id, "recommendation id")
    before = await recommendation_store.get(recommendation_id)
    if before is None:
        raise HTTPException(status_code=404, detail="Recommendation not found")

    recommendation = await recommendation_store.retract(recommendation_id, payload.author, payload.reason)
    if recommendation is None:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    # Audit trail: ids only, never the reason text.
    logger.info(
        "recommendation_api_retracted",
        recommendation_id=recommendation_id,
        correlation_id=recommendation["correlation_id"],
        author=payload.author,
    )
    # Only a first retraction of a recommendation the client was emailed about
    # sends the "withdrawn" email.
    notification = {"queued": False, "email_id": None, "reason": "already_retracted"}
    if before.get("retracted_at") is None:
        notification = await recommendation_notifier.notify_recommendation_retracted(recommendation)
        if notification["queued"]:
            recommendation_notifier.dispatch_soon()
    return {"recommendation": recommendation, "notification": notification}


@router.get("/recommendations/counts")
async def get_recommendation_counts(request: Request, cids: str | None = None) -> dict[str, Any]:
    """Active recommendation counts for a comma-separated list of alert ids (max 500)."""
    _check_access(request)
    ids = [part.strip() for part in (cids or "").split(",")]
    ids = [cid for cid in ids if cid]
    if len(ids) > MAX_CIDS:
        raise HTTPException(status_code=400, detail=f"At most {MAX_CIDS} cids per request")
    for cid in ids:
        _require_valid_id(cid, "correlation id")
    return {"counts": await recommendation_store.counts(ids)}
