"""
Client portal read API: alerts list/detail, export field catalogue, spreadsheet export.
Every route requires a client session (X-Client-Session, see middleware/auth.require_client).

  GET  /client/api/alerts               filtered, paged list + per-severity counts
  GET  /client/api/stats?days=N         Home charts: per-day/week severity counts, top devices and
                                        threats, alerts with advice; plus the previous N days' totals
  GET  /client/api/alerts/{alert_id}    one alert: registry fields grouped, active recommendations
  GET  /client/api/export/fields        the field catalogue the export/UI may offer
  POST /client/api/alerts/export        .xlsx of the filtered alerts with the chosen columns

SECURITY: alert data reaches the client ONLY through the field registry
(services/client_fields.REGISTRY) — never by returning a raw result dict, a job row or a
recommendation row. Error text, file paths and internal columns are never echoed.
"""
import math
import re
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from src.middleware.auth import require_client
from src.services import alert_catalog, client_stats
from src.services.alert_catalog import AlertBundle, BundleQuery
from src.services.client_fields import (
    DEFAULT_FIELDS, GROUP_LABELS, REGISTRY, WEEKLY_FIELDS, field_catalog,
)
from src.services.client_workbook import build_workbook
from src.storage import alert_index_store, runtime_settings
from src.utils.jst_time import JST, jst_day_start_epoch, jst_range_epoch

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/client/api", tags=["Client Portal"],
                   dependencies=[Depends(require_client)])

RISKS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
SUMMARY_EXCERPT_CHARS = 200
EXPORT_CHUNK = 500
_ID_PATTERN = r"^[A-Za-z0-9._-]{1,128}$"

# user id -> an export is running for that user (single event loop; check-and-add has no await).
_active_exports: set[str] = set()


# ------------------------------------------------------------------ helpers

def _bad(message: str) -> HTTPException:
    return HTTPException(status_code=400, detail=message)


def _parse_risks(raw: list[str] | None) -> list[str] | None:
    """Upper-cased, de-duplicated risk levels (None = no filter). 400 on an unknown level."""
    if not raw:
        return None
    out: list[str] = []
    for item in raw:
        level = str(item).strip().upper()
        if level not in RISKS:
            raise _bad(f"Invalid risk level. Allowed: {', '.join(RISKS)}")
        if level not in out:
            out.append(level)
    return out


def _parse_window(from_date: str | None, to_date: str | None) -> tuple[float | None, float | None]:
    """JST calendar days, both inclusive -> (inclusive start epoch, exclusive end epoch)."""
    try:
        start = jst_day_start_epoch(from_date) if from_date else None
        end = jst_day_start_epoch(to_date) + 86400 if to_date else None
    except (ValueError, TypeError):
        raise _bad("Dates must be valid calendar dates in YYYY-MM-DD format")
    if start is not None and end is not None and start >= end:
        raise _bad("'from' must not be after 'to'")
    return start, end


def _parse_sort(sort: str | None) -> str:
    value = (sort or "desc").strip().lower()
    if value not in ("asc", "desc"):
        raise _bad("sort must be 'asc' or 'desc'")
    return value


def _json_value(value: Any) -> Any:
    return value if value is None or isinstance(value, (str, int, float, bool)) else str(value)


def _field(bundle: AlertBundle, key: str) -> Any:
    return _json_value(REGISTRY[key].extractor(bundle))


def _to_int_or_none(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _list_item(bundle: AlertBundle) -> dict[str, Any]:
    recs = bundle.recommendations
    summary = str(_field(bundle, "ai_alert_summary_ja") or "")
    created = [t for t in (_to_int_or_none(r.get("created_at")) for r in recs) if t is not None]
    return {
        "alert_id": _field(bundle, "alert_id"),
        "eset_alert_id": _field(bundle, "eset_alert_id"),
        "received_at": _to_int_or_none(bundle.job.get("created_at")),
        "risk_level": _field(bundle, "risk_level"),
        "eset_severity": _field(bundle, "eset_severity"),
        "detection_name": _field(bundle, "detection_name"),
        "endpoint_name": _field(bundle, "endpoint_name"),
        "ai_summary_excerpt": summary[:SUMMARY_EXCERPT_CHARS],
        "recommendation_count": len(recs),
        "latest_recommendation_at": max(created) if created else None,
    }


def _group_labels() -> dict[str, dict[str, str]]:
    return {g: {"ja": ja, "en": en} for g, (ja, en) in GROUP_LABELS.items()}


# -------------------------------------------------------------------- list

@router.get("/alerts")
async def list_alerts(
    risk: str | None = Query(None, max_length=64, description="comma list of LOW,MEDIUM,HIGH,CRITICAL"),
    from_: str | None = Query(None, alias="from", max_length=32, description="YYYY-MM-DD (JST), inclusive"),
    to: str | None = Query(None, max_length=32, description="YYYY-MM-DD (JST), inclusive"),
    page: int = Query(1, ge=1, le=1_000_000),
    page_size: int = Query(25, ge=1, le=100),
    sort: str = Query("desc", max_length=8),
) -> dict[str, Any]:
    risks = _parse_risks([p for p in (risk or "").split(",") if p.strip()])
    start, end = _parse_window(from_, to)
    order = _parse_sort(sort)

    counts = await alert_index_store.counts_by_risk(received_from=start, received_to=end)
    bundles, total = await alert_catalog.list_bundles(BundleQuery(
        risk_levels=risks, received_from=start, received_to=end,
        limit=page_size, offset=(page - 1) * page_size, order=order))
    return {
        "items": [_list_item(b) for b in bundles],
        "total": total,
        "page": page,
        "pages": max(1, math.ceil(total / page_size)),
        "counts_by_risk": {level: int(counts.get(level, 0)) for level in reversed(RISKS)},
    }


# -------------------------------------------------------------------- stats

def _today_jst():
    """Today's JST calendar date (a function so tests can pin it)."""
    return datetime.now(JST).date()


@router.get("/stats")
async def alert_stats(days: int = Query(30, ge=1, le=366)) -> dict[str, Any]:
    """Aggregates for the Home charts over the `days` JST days ending today, plus the
    same-length period before it for comparison. Counts only: the names it returns are
    the device and detection names the alert list already shows."""
    first, last = client_stats.period_days(_today_jst(), days)
    prev_first, prev_last = client_stats.previous_period(first, days)
    cur = await alert_index_store.window_aggregates(*jst_range_epoch(first.isoformat(), last.isoformat()))
    prev = await alert_index_store.window_aggregates(*jst_range_epoch(prev_first.isoformat(), prev_last.isoformat()))

    chart, size = client_stats.buckets(cur["by_day"], first, last)
    top_devices, other_devices = client_stats.ranked(cur["devices"])
    top_threats, other_threats = client_stats.ranked(cur["threats"])
    cur_totals = client_stats.totals(cur["by_day"])
    prev_totals = client_stats.totals(prev["by_day"])
    return {
        "days": days,
        "from": first.isoformat(),
        "to": last.isoformat(),
        "bucket_days": size,
        "buckets": chart,
        "totals": cur_totals,
        "total": sum(cur_totals.values()),
        "devices_affected": client_stats.distinct_named(cur["devices"]),
        "with_advice": cur["with_advice"],
        "latest_advice_at": cur["latest_advice_at"],
        "top_devices": top_devices,
        "other_devices": other_devices,
        "top_threats": top_threats,
        "other_threats": other_threats,
        "previous": {
            "from": prev_first.isoformat(),
            "to": prev_last.isoformat(),
            "totals": prev_totals,
            "total": sum(prev_totals.values()),
            "devices_affected": client_stats.distinct_named(prev["devices"]),
        },
    }


# ------------------------------------------------------------------ detail

@router.get("/alerts/{alert_id}")
async def alert_detail(alert_id: str = Path(..., max_length=256)) -> dict[str, Any]:
    if not re.fullmatch(_ID_PATTERN, alert_id):
        raise _bad("Invalid alert id")
    bundle = await alert_catalog.load_bundle(alert_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    grouped: dict[str, dict[str, Any]] = {g: {} for g in GROUP_LABELS}
    for key, spec in REGISTRY.items():
        grouped.setdefault(spec.group, {})[key] = _field(bundle, key)
    recommendations = [
        {"id": r.get("id"), "body": r.get("body"), "author": r.get("author"),
         "created_at": _to_int_or_none(r.get("created_at"))}
        for r in bundle.recommendations if not r.get("retracted_at")
    ]
    return {
        "alert": {g: v for g, v in grouped.items() if v},
        "groups": _group_labels(),
        "recommendations": recommendations,
    }


# ----------------------------------------------------------- export fields

@router.get("/export/fields")
async def export_fields() -> dict[str, Any]:
    return {
        "fields": field_catalog(),
        "groups": _group_labels(),
        "default_fields": list(DEFAULT_FIELDS),
        "weekly_fields": list(WEEKLY_FIELDS),
        "max_alerts": await runtime_settings.get("client_export_max_alerts"),
    }


# ------------------------------------------------------------------ export

class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    risk: list[str] = Field(default_factory=list, max_length=4)
    from_: str | None = Field(None, alias="from", max_length=32)
    to: str | None = Field(None, max_length=32)
    limit: int | None = Field(None, ge=1, le=1_000_000)
    fields: list[str] = Field(..., min_length=1, max_length=50)
    header_lang: str = Field("ja", max_length=8)
    sort: str = Field("desc", max_length=8)
    include_info_sheet: bool = False


def _release(user_id: str) -> None:
    _active_exports.discard(user_id)


async def _export_body(request: Request) -> ExportRequest:
    """The request body, parsed only AFTER require_client has passed. Declared as a
    body parameter, FastAPI would decode the JSON before running any dependency,
    so a caller without a session would get a 422 instead of the 401."""
    try:
        raw = await request.json()
    except ValueError:
        raise RequestValidationError([{"type": "json_invalid", "loc": ("body",),
                                       "msg": "JSON decode error", "input": {}}]) from None
    try:
        return ExportRequest.model_validate(raw)
    except ValidationError as e:
        raise RequestValidationError(
            [{**err, "loc": ("body", *err["loc"])} for err in e.errors(include_url=False)]) from None


@router.post("/alerts/export", openapi_extra={"requestBody": {"required": True, "content": {
    "application/json": {"schema": ExportRequest.model_json_schema(by_alias=True)}}}})
async def export_alerts(request: Request, user: dict[str, Any] = Depends(require_client)) -> Response:
    body = await _export_body(request)
    risks = _parse_risks(body.risk)
    start, end = _parse_window(body.from_, body.to)
    order = _parse_sort(body.sort)
    for key in body.fields:
        if len(key) > 64:
            raise _bad("Invalid field key")
    max_alerts = int(await runtime_settings.get("client_export_max_alerts"))
    limit = body.limit if body.limit is not None else max_alerts
    if limit > max_alerts:
        raise _bad(f"limit must be between 1 and {max_alerts}")

    user_id = str(user.get("id") or user.get("username"))
    if user_id in _active_exports:
        raise HTTPException(status_code=429, detail="An export is already running. Please wait for it to finish.",
                            headers={"Retry-After": "5"})
    _active_exports.add(user_id)
    try:
        now = datetime.now(JST)
        bundles: list[AlertBundle] = []
        total = None
        offset = 0
        while total is None or offset < min(total, limit):
            chunk, total = await alert_catalog.list_bundles(BundleQuery(
                risk_levels=risks, received_from=start, received_to=end,
                limit=min(EXPORT_CHUNK, limit - offset), offset=offset, order=order))
            bundles.extend(chunk)
            offset += EXPORT_CHUNK
        try:
            content = await build_workbook(
                bundles, body.fields, body.header_lang, body.include_info_sheet,
                title=f"SOC Lite alerts {now.strftime('%Y-%m-%d %H:%M')} JST")
        except ValueError as e:               # unknown/duplicate field, empty selection, bad header_lang
            raise _bad(str(e))
    finally:
        _release(user_id)

    logger.info("client_export", username=user.get("username"), fields=list(body.fields),
                filter={"risk": risks, "from": body.from_, "to": body.to, "sort": order, "limit": limit},
                header_lang=body.header_lang, count=len(bundles))
    filename = f"soc-lite-client-alerts-{now.strftime('%Y%m%d-%H%M%S')}.xlsx"
    return Response(
        content=content, media_type=XLSX_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "X-Alert-Count": str(len(bundles)),
                 "Cache-Control": "no-store"})
