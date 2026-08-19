"""
Persistence for AI Visibility traces (see src/models/ai_trace.py and
src/services/ai/trace_recorder.py, which is the only module that should write here).

Traces are stored the way this app already stores "content that needs listing/
filtering plus one big JSON blob of detail" — see src/storage/delivery_store.py for
the same pattern: a handful of indexed columns for querying, plus a JSON column
holding the full, already-redacted trace. Redaction happens before a value ever
reaches this module (src/services/ai/redaction.py) — nothing here inspects or
sanitizes content, it only stores and retrieves it.

A row is upserted twice in the normal lifecycle: once when the call starts
(status=STARTED, so an in-flight AI call is visible in the dashboard immediately)
and once when it completes. apply_manual_redaction() additionally mutates a row
in place, permanently, when an operator redacts part of a trace from the dashboard.
"""
import json
import time
from typing import Any

import structlog

from src.storage.database import db_session

logger = structlog.get_logger(__name__)


async def save_trace(trace: Any) -> None:
    """Upserts the full trace row. `trace` is an AITrace (src/models/ai_trace.py)."""
    data = trace.model_dump()
    async with db_session() as conn:
        await conn.execute(
            """
            INSERT INTO ai_traces
                (trace_id, correlation_id, component, provider, model, status, risk,
                 started_at, completed_at, duration_ms, security_findings_count,
                 external_data_transfer, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(trace_id) DO UPDATE SET
                status = excluded.status,
                risk = excluded.risk,
                completed_at = excluded.completed_at,
                duration_ms = excluded.duration_ms,
                security_findings_count = excluded.security_findings_count,
                external_data_transfer = excluded.external_data_transfer,
                data_json = excluded.data_json
            """,
            (
                data["trace_id"], data["correlation_id"], data["component"],
                data["provider"], data["model"], data["status"], data["risk"],
                data["started_at"], data["completed_at"], data["duration_ms"],
                len(data["security_findings"]), int(data["external_data_transfer"]),
                json.dumps(data),
            ),
        )
        await conn.commit()


async def get_trace(trace_id: str) -> dict[str, Any] | None:
    async with db_session() as conn:
        async with conn.execute(
            "SELECT data_json FROM ai_traces WHERE trace_id = ?", (trace_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return json.loads(row[0]) if row else None


async def get_latest_trace_by_correlation(correlation_id: str) -> dict[str, Any] | None:
    async with db_session() as conn:
        async with conn.execute(
            "SELECT trace_id FROM ai_traces WHERE correlation_id = ? ORDER BY started_at DESC LIMIT 1",
            (correlation_id,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return await get_trace(row[0])


async def list_traces(
    limit: int = 50,
    status: str | None = None,
    risk: str | None = None,
    component: str | None = None,
) -> list[dict[str, Any]]:
    """Lightweight rows for the Recent AI Traces table — no data_json parsing needed."""
    query = """
        SELECT trace_id, correlation_id, component, provider, model, status, risk,
               started_at, completed_at, duration_ms, security_findings_count,
               external_data_transfer
        FROM ai_traces
    """
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if risk:
        clauses.append("risk = ?")
        params.append(risk)
    if component:
        clauses.append("component = ?")
        params.append(component)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY started_at DESC LIMIT ?"
    params.append(limit)

    out = []
    async with db_session() as conn:
        async with conn.execute(query, params) as cursor:
            async for row in cursor:
                out.append({
                    "trace_id": row[0], "correlation_id": row[1], "component": row[2],
                    "provider": row[3], "model": row[4], "status": row[5], "risk": row[6],
                    "started_at": row[7], "completed_at": row[8], "duration_ms": row[9],
                    "security_findings_count": row[10], "external_data_transfer": bool(row[11]),
                })
    return out


async def overview_counts() -> dict[str, Any]:
    """Aggregate counters for the AI Visibility Overview cards."""
    now = time.time()
    day_start = now - 24 * 3600

    async with db_session() as conn:
        async def _scalar(query: str, params: tuple = ()) -> int:
            async with conn.execute(query, params) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 0

        active = await _scalar("SELECT COUNT(*) FROM ai_traces WHERE status = 'STARTED'")
        today = await _scalar("SELECT COUNT(*) FROM ai_traces WHERE started_at >= ?", (day_start,))
        total = await _scalar("SELECT COUNT(*) FROM ai_traces")
        security_alerts = await _scalar(
            "SELECT COUNT(*) FROM ai_traces WHERE risk IN "
            "('SENSITIVE_DATA_DETECTED','SECRET_DETECTED','BLOCKED','FAILED_SECURITY_CHECK','ERROR')"
        )
        external_calls_today = await _scalar(
            "SELECT COUNT(*) FROM ai_traces WHERE started_at >= ? AND external_data_transfer = 1",
            (day_start,),
        )

        providers: list[str] = []
        async with conn.execute(
            "SELECT DISTINCT provider, model FROM ai_traces ORDER BY provider"
        ) as cursor:
            async for provider, model in cursor:
                providers.append(f"{provider}/{model}")

        by_risk: dict[str, int] = {}
        async with conn.execute("SELECT risk, COUNT(*) FROM ai_traces GROUP BY risk") as cursor:
            async for risk, count in cursor:
                by_risk[risk] = count

    return {
        "active_requests": active,
        "requests_today": today,
        "total_traces": total,
        "security_alerts": security_alerts,
        "external_calls_today": external_calls_today,
        "providers": providers,
        "by_risk": by_risk,
    }


def _resolve_parent(root: dict[str, Any], path: str) -> tuple[Any, Any]:
    """
    Walks a dot/bracket path like 'input_redacted.normalized_alert.raw_content' or
    'data_categories[2].value_preview' and returns (parent_container, final_key).
    """
    tokens: list[Any] = []
    for part in path.replace("]", "").split("."):
        for sub in part.split("["):
            if sub == "":
                continue
            tokens.append(int(sub) if sub.isdigit() else sub)
    if not tokens:
        raise ValueError("empty field_path")

    node: Any = root
    try:
        for t in tokens[:-1]:
            node = node[t]
    except (KeyError, IndexError, TypeError) as e:
        raise ValueError(f"invalid field_path: {path}") from e
    return node, tokens[-1]


async def apply_manual_redaction(trace_id: str, field_path: str, start: int, end: int) -> dict[str, Any]:
    """
    Permanently overwrites the [start:end) character range of the string found at
    `field_path` inside the stored trace with a fixed [REDACTED] marker, and records
    the action in manual_redactions. The ORIGINAL substring is never written anywhere
    else — once applied it cannot be recovered from the stored trace or the API.
    """
    trace = await get_trace(trace_id)
    if trace is None:
        raise ValueError("trace not found")

    node, key = _resolve_parent(trace, field_path)
    try:
        current = node[key]
    except (KeyError, IndexError, TypeError) as e:
        raise ValueError(f"invalid field_path: {field_path}") from e

    if not isinstance(current, str):
        raise ValueError(f"field_path '{field_path}' does not address a text field")
    if not (0 <= start < end <= len(current)):
        raise ValueError("redaction range is out of bounds")

    original_length = end - start
    original_substring = current[start:end]
    node[key] = current[:start] + "[REDACTED]" + current[end:]

    # The same underlying value is also copied — independently — into
    # data_categories[].value_preview for the Data Sent to the Model table
    # (see trace_recorder.build_alert_data_categories). Redacting only input_redacted
    # would leave that second copy recoverable, breaking the "cannot be recovered from
    # the API" guarantee, so scrub any exact occurrence there too.
    scrubbed_previews = 0
    if len(original_substring) >= 3:
        for cat in trace.get("data_categories", []) or []:
            preview = cat.get("value_preview")
            if isinstance(preview, str) and original_substring in preview:
                cat["value_preview"] = preview.replace(original_substring, "[REDACTED]")
                scrubbed_previews += 1

    now = time.time()
    trace.setdefault("manual_redactions", []).append({
        "field_path": field_path, "redacted_at": now,
        "original_length": original_length, "actor": "dashboard_operator",
        "linked_previews_scrubbed": scrubbed_previews,
    })
    trace.setdefault("security_findings", []).append({
        "category": "MANUAL_REDACTION", "field_path": field_path, "method": "manual",
        "masked_preview": "[REDACTED]", "detected_at": now,
    })

    async with db_session() as conn:
        await conn.execute(
            "UPDATE ai_traces SET data_json = ?, security_findings_count = ? WHERE trace_id = ?",
            (json.dumps(trace), len(trace["security_findings"]), trace_id),
        )
        await conn.commit()
    logger.info("ai_trace_manual_redaction", trace_id=trace_id, field_path=field_path)
    return trace


async def append_policy_check(trace_id: str, event: dict[str, Any], *, blocked: bool) -> dict[str, Any] | None:
    """
    Appends a policy-check timeline event to an already-persisted trace, and — if the
    check failed — flips the trace's status/risk to BLOCKED. Used by the orchestrator
    to attach the post-generation safety-lint result (src/services/ai/lint_checker.py)
    to the same trace the generation call itself produced.
    """
    trace = await get_trace(trace_id)
    if trace is None:
        return None

    trace.setdefault("events", []).append(event)
    if blocked:
        trace["status"] = "BLOCKED"
        trace["risk"] = "BLOCKED"
        trace.setdefault("security_findings", []).append({
            "category": "POLICY_VIOLATION", "field_path": "output", "method": "automatic",
            "masked_preview": (event.get("detail") or "")[:200],
            "detected_at": event.get("ts", time.time()),
        })

    async with db_session() as conn:
        await conn.execute(
            "UPDATE ai_traces SET status = ?, risk = ?, security_findings_count = ?, data_json = ? "
            "WHERE trace_id = ?",
            (trace["status"], trace["risk"], len(trace["security_findings"]), json.dumps(trace), trace_id),
        )
        await conn.commit()
    return trace
