"""
Assembles everything known about an alert for the client portal, exports and the
weekly report: the `jobs` row, the result file as a dict (the same JSON the
dashboard reads, so old files without newer fields still work), and the alert's
ACTIVE recommendations.
"""
import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, NamedTuple, Collection
import structlog
from src.config import settings
from src.storage import alert_index_store, job_store, recommendation_store
from src.storage.alert_index_store import DEFAULT_STATUSES

logger = structlog.get_logger(__name__)

# Ids become file names under output_dir, so only this alphabet is ever used for a path.
_CID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_READ_CONCURRENCY = 16


class AlertBundle(NamedTuple):
    job: dict[str, Any]                       # row from storage/job_store.py
    result: dict[str, Any]                    # parsed result JSON (PipelineResult.model_dump shape)
    recommendations: list[dict[str, Any]]     # active only, oldest first


@dataclass
class BundleQuery:
    risk_levels: Collection[str] | None = None
    received_from: float | None = None        # inclusive, epoch seconds
    received_to: float | None = None          # exclusive
    statuses: Collection[str] = field(default_factory=lambda: set(DEFAULT_STATUSES))
    limit: int = 50
    offset: int = 0
    order: str = "desc"                       # by received_at


def _valid_id(correlation_id: Any) -> bool:
    return (
        isinstance(correlation_id, str)
        and _CID_RE.fullmatch(correlation_id) is not None
        and correlation_id not in (".", "..")
    )


def _read_result(correlation_id: str) -> dict[str, Any] | None:
    """The parsed result file, or None if missing/corrupt. Caller validated the id."""
    path = os.path.join(settings.output_dir, f"{correlation_id}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.warning("alert_catalog_result_unreadable", correlation_id=correlation_id, error=str(e))
        return None
    if not isinstance(data, dict):
        logger.warning("alert_catalog_result_unreadable", correlation_id=correlation_id, error="not an object")
        return None
    return data


async def load_bundle(correlation_id: str) -> AlertBundle | None:
    """The bundle for one alert, or None if the id is invalid or the job or its result
    file is missing/unreadable."""
    if not _valid_id(correlation_id):
        return None
    job = await job_store.get_job(correlation_id)
    if job is None:
        return None
    result = await asyncio.to_thread(_read_result, correlation_id)
    if result is None:
        return None
    recommendations = await recommendation_store.list_for_alert(correlation_id)
    return AlertBundle(job, result, recommendations)


async def list_bundles(query: BundleQuery) -> tuple[list[AlertBundle], int]:
    """Bundles for the alerts matching `query` (via alert_index_store.query), plus the
    total match count ignoring limit/offset. Alerts whose result file cannot be read
    are skipped but still counted in the total."""
    rows, total = await alert_index_store.query(
        risk_levels=query.risk_levels, received_from=query.received_from,
        received_to=query.received_to, statuses=query.statuses,
        limit=query.limit, offset=query.offset, order=query.order,
    )
    ids = [r["correlation_id"] for r in rows if _valid_id(r["correlation_id"])]
    if not ids:
        return [], total

    gate = asyncio.Semaphore(_READ_CONCURRENCY)

    async def fetch(cid: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        async with gate:
            job = await job_store.get_job(cid)
            result = await asyncio.to_thread(_read_result, cid)
            return job, result

    fetched, recs = await asyncio.gather(
        asyncio.gather(*(fetch(cid) for cid in ids)),
        recommendation_store.list_for_alerts(ids),
    )
    bundles: list[AlertBundle] = []
    for cid, (job, result) in zip(ids, fetched):
        if job is None or result is None:
            logger.warning("alert_catalog_bundle_skipped", correlation_id=cid,
                           job_found=job is not None, result_found=result is not None)
            continue
        bundles.append(AlertBundle(job, result, recs.get(cid, [])))
    return bundles, total
