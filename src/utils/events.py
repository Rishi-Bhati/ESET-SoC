"""
Single shared event bus for live dashboard updates.

Replaces the per-module `set_broadcaster` duplication that previously lived in
job_store, output_writer and email_outbox. Wired once in main.py; a no-op until
then, so importing modules never depend on a running server.
"""
from typing import Any
import structlog

logger = structlog.get_logger(__name__)

_broadcaster: Any = None

# Pipeline stages, in execution order. The dashboard's flow graph renders one
# node per stage, so this list is the contract between backend and graph.
STAGES = ["INGEST", "NORMALIZE", "RISK", "INTEL", "AI", "LINT", "OUTPUT", "EMAIL", "SEND"]


def set_broadcaster(broadcaster: Any) -> None:
    global _broadcaster
    _broadcaster = broadcaster


def get_broadcaster() -> Any:
    return _broadcaster


async def emit(event_type: str, data: dict[str, Any]) -> None:
    """Fan an event out to connected dashboard clients. Never raises."""
    if _broadcaster is None:
        return
    try:
        await _broadcaster.broadcast(event_type, data)
    except Exception as e:  # a dashboard problem must never break the pipeline
        logger.warning("event_emit_failed", event_type=event_type, error=str(e))


async def emit_stage(
    correlation_id: str,
    stage: str,
    state: str,
    detail: str | None = None,
    **extra: Any,
) -> None:
    """
    Reports progress of a single pipeline stage.

    state: "active" | "ok" | "failed" | "skipped"
    """
    await emit("pipeline_stage", {
        "correlation_id": correlation_id,
        "stage": stage,
        "state": state,
        "detail": detail,
        **extra,
    })
