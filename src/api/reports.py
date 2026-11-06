"""
Engineer API for weekly reports (schedule + history, preview, run now / regenerate,
archived download). Every handler is gated by the dashboard key via
dashboard._check_access, run as a router dependency so it happens before any
request validation.

  GET  /dashboard/api/reports/weekly                         schedule + history
  GET  /dashboard/api/reports/weekly/preview?period_key=...  xlsx built on the fly (nothing stored/sent)
  POST /dashboard/api/reports/weekly/run                     {"period_key"?: str, "regenerate"?: bool}
  GET  /dashboard/api/reports/weekly/{period_key}/download   archived xlsx
"""
import os
import time
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from src.api.dashboard import _check_access
from src.services import weekly_report
from src.storage import weekly_report_store

async def _gate(request: Request) -> None:
    """Every route: dashboard key (dashboard._check_access)."""
    _check_access(request)

router = APIRouter(prefix="/dashboard/api/reports", tags=["Weekly Reports"],
                   dependencies=[Depends(_gate)])

_NO_STORE = {"Cache-Control": "no-store"}


def _now() -> float:
    """Current epoch seconds (a seam for tests)."""
    return time.time()


class RunRequest(BaseModel):
    period_key: str | None = None
    regenerate: bool = False


def _base_key(period_key: str) -> str:
    try:
        return weekly_report.validate_period_key(period_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


def _history_row(row: dict[str, Any]) -> dict[str, Any]:
    key = row["period_key"]
    try:
        has_file = os.path.isfile(weekly_report.report_path(key))
        period = weekly_report.period_from_key(key).to_dict()
    except ValueError:
        has_file, period = False, {}
    return {
        **period,
        "period_key": key,
        "status": row["status"],
        "trigger": row["trigger"],
        "claimed_at": row["claimed_at"],
        "completed_at": row["completed_at"],
        "email_id": row["email_id"],
        "recipients": row["recipients"],
        "counts": row["counts"],
        "findings": row["findings"],
        "has_file": has_file,
        "file_sha256": row["file_sha256"],
        "attachment_included": row["attachment_included"],
        "resend_count": row["resend_count"],
        "attempts": row["attempts"],
        "error": row["error"],
    }


@router.get("/weekly")
async def weekly_overview(limit: int = Query(50, ge=1, le=500),
                          offset: int = Query(0, ge=0)) -> dict[str, Any]:
    info = await weekly_report.schedule_info()
    rows = await weekly_report_store.list_reports(limit=limit, offset=offset)
    return {**info, "reports": [_history_row(r) for r in rows]}


@router.get("/weekly/preview")
async def weekly_preview(period_key: str | None = None) -> Response:
    if period_key:
        period = weekly_report.period_from_key(_base_key(period_key))
    else:
        period = await weekly_report.latest_due_period()
    content = await weekly_report.build_content(period, always_build_file=True)
    filename = f"preview_{weekly_report.download_filename(period.key)}"
    return Response(
        content=content.xlsx or b"", media_type=weekly_report.XLSX_MEDIA_TYPE,
        headers={**_NO_STORE, "Content-Disposition": f'attachment; filename="{filename}"',
                 "X-Report-Period": period.key,
                 "X-Report-Rows": str(content.counts["rows_in_file"])},
    )


@router.post("/weekly/run")
async def weekly_run(body: RunRequest | None = None) -> dict[str, Any]:
    body = body or RunRequest()
    if body.period_key:
        key = _base_key(body.period_key)
        # A week that has not ended yet would be archived (and shown to the
        # client) with only part of its alerts, and the recorded run would stop
        # the scheduler from producing the complete report once it is due.
        # Preview covers looking at an unfinished week.
        if weekly_report.period_from_key(key).end_epoch > _now():
            raise HTTPException(status_code=400,
                                detail=f"{key} has not ended yet; use preview to look at it")
    else:
        key = (await weekly_report.latest_due_period()).key
    result = await weekly_report.generate_report(key, trigger="manual", regenerate=body.regenerate)
    row = await weekly_report_store.get(key)
    return {**result, "report": _history_row(row) if row else None}


@router.get("/weekly/{period_key}/download")
async def weekly_download(period_key: str) -> FileResponse:
    key = _base_key(period_key)
    path = weekly_report.report_path(key)   # built from the validated key only
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="No archived workbook for this period")
    return FileResponse(path, media_type=weekly_report.XLSX_MEDIA_TYPE,
                        filename=weekly_report.download_filename(key), headers=_NO_STORE)
