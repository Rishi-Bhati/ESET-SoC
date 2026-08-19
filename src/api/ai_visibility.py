"""
AI Visibility / Observability API.

A read-only surface (plus one narrowly-scoped mutation: manual redaction) over the
AI traces recorded by src/services/ai/trace_recorder.py. Reuses the dashboard's
existing access-key check (src/api/dashboard.py: _check_access) rather than
introducing a second, divergent auth implementation for the same dashboard surface.

Every trace returned here has ALREADY been redacted at capture time
(src/services/ai/redaction.py) before it was ever written to SQLite — this router
performs no redaction of its own on read. It can only ever apply MORE redaction, via
POST .../redact, never reveal something capture-time redaction already removed.
"""
from typing import Any
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import structlog
from src.api.dashboard import _check_access
from src.storage import ai_trace_store

router = APIRouter(prefix="/dashboard/api/ai", tags=["AI Visibility"])
logger = structlog.get_logger(__name__)


@router.get("/overview")
async def get_ai_overview(request: Request) -> dict[str, Any]:
    """Status/counters for the AI Visibility Overview cards."""
    _check_access(request)
    return await ai_trace_store.overview_counts()


@router.get("/traces")
async def list_ai_traces(
    request: Request,
    limit: int = 50,
    status: str | None = None,
    risk: str | None = None,
    component: str | None = None,
) -> dict[str, Any]:
    """Recent AI traces, most recent first, for the Recent AI Traces table."""
    _check_access(request)
    limit = max(1, min(limit, 200))
    traces = await ai_trace_store.list_traces(limit=limit, status=status, risk=risk, component=component)
    return {"traces": traces}


@router.get("/traces/{trace_id}")
async def get_ai_trace(request: Request, trace_id: str) -> dict[str, Any]:
    """Full detail for one trace: input, output, timeline, security findings — already redacted."""
    _check_access(request)
    trace = await ai_trace_store.get_trace(trace_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    return {"trace": trace}


class ManualRedactionRequest(BaseModel):
    field_path: str
    start: int
    end: int


@router.post("/traces/{trace_id}/redact")
async def redact_ai_trace_field(
    request: Request, trace_id: str, payload: ManualRedactionRequest,
) -> dict[str, Any]:
    """
    Permanently overwrites the given character range of one text field in the stored
    trace with a fixed [REDACTED] marker. The original text is not retained anywhere
    else in the trace — this cannot be undone from the UI or the API.
    """
    _check_access(request)
    try:
        trace = await ai_trace_store.apply_manual_redaction(
            trace_id, payload.field_path, payload.start, payload.end,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    logger.info("ai_trace_manual_redaction_applied", trace_id=trace_id, field_path=payload.field_path)
    return {"status": "redacted", "trace": trace}
