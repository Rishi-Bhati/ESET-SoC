"""
Client portal access to weekly report history/downloads (client session required).

  GET /client/api/reports                        reports that were produced (not skipped/failed)
  GET /client/api/reports/{period_key}/download  the archived LOW/MEDIUM workbook

Only client-safe fields are returned (no file paths, recipients, email ids or errors).
"""
import os
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from src.middleware.auth import require_client
from src.services import weekly_report
from src.storage import weekly_report_store

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
