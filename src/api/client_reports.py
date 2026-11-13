"""
Client portal access to weekly report history/downloads (client session required).

  GET /client/api/reports                        reports that were produced (not skipped/failed)
  GET /client/api/reports/{period_key}/download  the archived LOW/MEDIUM workbook
  GET  /client/api/reports/on-demand             weeks a client may build a report for (+ counts)
  POST /client/api/reports/on-demand             build one now and download it: {period_key,
                                                 include_high_risk?, header_lang?}. Not stored,
                                                 not emailed, not added to the history.

Only client-safe fields are returned (no file paths, recipients, email ids or errors).
"""
import os
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from src.api.client import _active_exports
from src.middleware.auth import require_client
from src.services import weekly_report
from src.storage import runtime_settings, weekly_report_store

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/client/api/reports", tags=["Client Portal Reports"],
                   dependencies=[Depends(require_client)])

# Runs whose report exists for the client (generated, whether emailed or not).
_VISIBLE = frozenset({weekly_report_store.GENERATED, weekly_report_store.QUEUED,
                      weekly_report_store.SENT, weekly_report_store.NO_RECIPIENTS})
_COUNT_KEYS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "total", "high_risk", "low_medium")
_NO_STORE = {"Cache-Control": "no-store"}


def _client_row(row: dict[str, Any]) -> dict[str, Any] | None:
    try:
        period = weekly_report.period_from_key(row["period_key"])
        path = weekly_report.report_path(period.key)
    except ValueError:
        return None
    counts = row.get("counts") or {}
    return {
        "period_key": period.key,
        "period_start": period.start.isoformat(),
        "period_end": period.end.isoformat(),
        "last_day": period.last_day.isoformat(),
        "timezone": "JST",
        "generated_at": row.get("completed_at"),
        "counts": {k: counts.get(k, 0) for k in _COUNT_KEYS},
        "has_file": os.path.isfile(path),
    }


@router.get("")
async def list_reports(limit: int = 100) -> dict[str, Any]:
    rows = await weekly_report_store.list_reports(limit=max(1, min(limit, 500)))
    out = [_client_row(r) for r in rows if r["status"] in _VISIBLE]
    return {"reports": [r for r in out if r is not None]}


@router.get("/{period_key}/download")
async def download_report(period_key: str) -> FileResponse:
    try:
        key = weekly_report.validate_period_key(period_key)
    except ValueError:
        raise HTTPException(status_code=404, detail="Report not found") from None
    row = await weekly_report_store.get(key)
    path = weekly_report.report_path(key)    # built from the validated key, never the stored path
    if row is None or row["status"] not in _VISIBLE or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, media_type=weekly_report.XLSX_MEDIA_TYPE,
                        filename=weekly_report.download_filename(key),
                        content_disposition_type="attachment", headers=_NO_STORE)


# ------------------------------------------------------------------ on demand

def _now() -> datetime:
    """Current time (a seam for tests)."""
    return datetime.now(timezone.utc)


class OnDemandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    period_key: str = Field(..., max_length=16)
    include_high_risk: bool = False
    header_lang: str = Field("ja", max_length=8)


async def _on_demand_body(request: Request) -> OnDemandRequest:
    """Parsed only after require_client has passed (see client._export_body)."""
    try:
        raw = await request.json()
    except ValueError:
        raise RequestValidationError([{"type": "json_invalid", "loc": ("body",),
                                       "msg": "JSON decode error", "input": {}}]) from None
    try:
        return OnDemandRequest.model_validate(raw)
    except ValidationError as e:
        raise RequestValidationError(
            [{**err, "loc": ("body", *err["loc"])} for err in e.errors(include_url=False)]) from None


@router.get("/on-demand")
async def on_demand_options() -> dict[str, Any]:
    return {
        "weeks": await weekly_report.on_demand_weeks(_now()),
        "max_weeks_back": weekly_report.ON_DEMAND_MAX_WEEKS_BACK,
        "max_alerts": await runtime_settings.get("client_export_max_alerts"),
    }


@router.post("/on-demand", openapi_extra={"requestBody": {"required": True, "content": {
    "application/json": {"schema": OnDemandRequest.model_json_schema()}}}})
async def on_demand_report(request: Request, user: dict[str, Any] = Depends(require_client)) -> Response:
    body = await _on_demand_body(request)
    if body.header_lang not in ("ja", "en"):
        raise HTTPException(status_code=400, detail="header_lang must be ja or en")
    now = _now()
    try:
        period = weekly_report.on_demand_period(body.period_key, now)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    # One export or report at a time per user (shared with /alerts/export).
    user_id = str(user.get("id") or user.get("username"))
    if user_id in _active_exports:
        raise HTTPException(status_code=429, detail="An export is already running. Please wait for it to finish.",
                            headers={"Retry-After": "5"})
    _active_exports.add(user_id)
    try:
        report = await weekly_report.build_on_demand(
            period, include_high_risk=body.include_high_risk, header_lang=body.header_lang,
            max_rows=int(await runtime_settings.get("client_export_max_alerts")), now=now)
    finally:
        _active_exports.discard(user_id)

    logger.info("client_weekly_report_on_demand", account=user.get("username"), period_key=period.key,
                include_high_risk=body.include_high_risk, header_lang=body.header_lang,
                rows=report.rows, matching=report.matching, in_progress=report.in_progress)
    return Response(
        content=report.content, media_type=weekly_report.XLSX_MEDIA_TYPE,
        headers={**_NO_STORE,
                 "Content-Disposition": f'attachment; filename="{report.filename}"',
                 "X-Alert-Count": str(report.rows),
                 "X-Report-Period": period.key})
