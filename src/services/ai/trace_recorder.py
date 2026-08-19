"""
Instrumentation API for AI Visibility / Observability.

This is the ONLY place AI calls should be instrumented from. src/services/ai/
gemini_service.py and src/pipeline/orchestrator.py call into this module rather
than writing to storage or the event bus directly, so the trace schema and its
redaction guarantee stay in exactly one place.

Lifecycle of one trace:

    trace = await start_trace(...)         # persisted immediately as STARTED, broadcast live
    await record_input(trace, ...)         # redacted before it ever touches trace.input_redacted
    await record_config(trace, ...)
    call = await record_external_call_start(trace, ...)
    await record_event(trace, ...)         # ad-hoc timeline entries, broadcast live
    await record_retry(trace, ...)
    await record_external_call_end(trace, call, ...)
    await record_output(trace, ...)        # redacted before it ever touches trace.output_redacted
    await build_decision_summary(trace, ...)
    await complete_trace(trace, status=..., risk=...)   # persisted, broadcast live

    # from a different call site (orchestrator.py), once the AI phase's own follow-up
    # safety lint has run, correlated by correlation_id rather than holding the trace:
    await attach_policy_check(correlation_id, name=..., passed=..., detail=...)

Every text value that enters a trace through record_input / record_output /
record_event's `detail` / `data` arguments is passed through
src/services/ai/redaction.py first — this module never stores a raw value it was
given if that value looks like a secret.

AI observability must never become a new way for the actual alert pipeline to fail.
Every function below is defensive: a failure while recording a trace is logged and
swallowed, never raised, exactly like src/utils/events.py already does for WebSocket
broadcast. Functions that take a `trace` argument treat `trace is None` (meaning an
earlier step already failed to even start a trace) as a silent no-op.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from src.models.ai_trace import (
    AIDataCategory, AIExternalCall, AISecurityFinding, AITrace, AITraceEvent,
)
from src.services.ai.redaction import redact_value
from src.storage import ai_trace_store
from src.utils import events

logger = structlog.get_logger(__name__)


def new_trace_id() -> str:
    return f"ai-{uuid.uuid4().hex[:12]}"


def _record_findings(trace: AITrace, path_findings: list[tuple[str, Any]]) -> None:
    now = time.time()
    for path, finding in path_findings:
        trace.security_findings.append(AISecurityFinding(
            category=finding.category,
            field_path=path or "(root)",
            method="automatic",
            masked_preview=finding.masked,
            detected_at=now,
        ))


async def _safe_save(trace: AITrace) -> None:
    try:
        await ai_trace_store.save_trace(trace)
    except Exception as e:
        logger.warning("ai_trace_persist_failed", trace_id=trace.trace_id, error=str(e))


async def _emit_event(trace: AITrace, type_: str, label: str,
                       detail: str | None = None, data: dict[str, Any] | None = None) -> None:
    redacted_detail, detail_findings = redact_value(detail, f"event.{type_}.detail")
    redacted_data, data_findings = redact_value(data or {}, f"event.{type_}.data")
    _record_findings(trace, detail_findings + data_findings)

    ev = AITraceEvent(ts=time.time(), type=type_, label=label, detail=redacted_detail, data=redacted_data)
    trace.events.append(ev)
    await events.emit("ai_trace_event", {
        "trace_id": trace.trace_id, "correlation_id": trace.correlation_id,
        "component": trace.component, "ts": ev.ts, "type": ev.type,
        "label": ev.label, "detail": ev.detail,
    })


async def start_trace(
    *, correlation_id: str, component: str, action: str, provider: str, model: str,
    objective: str = "",
) -> AITrace | None:
    try:
        trace = AITrace(
            trace_id=new_trace_id(), correlation_id=correlation_id, component=component,
            action=action, provider=provider, model=model, status="STARTED", risk="REVIEW",
            started_at=time.time(), objective=objective,
        )
        await _emit_event(trace, "request_started", "Request started",
                           detail=f"{component} → {provider}/{model}")
        await _safe_save(trace)
        await events.emit("ai_trace_started", {
            "trace_id": trace.trace_id, "correlation_id": correlation_id,
            "component": component, "provider": provider, "model": model,
            "started_at": trace.started_at,
        })
        return trace
    except Exception as e:
        logger.warning("ai_trace_start_failed", correlation_id=correlation_id, error=str(e))
        return None


async def record_event(trace: AITrace | None, type_: str, label: str,
                        detail: str | None = None, data: dict[str, Any] | None = None) -> None:
    if trace is None:
        return
    try:
        await _emit_event(trace, type_, label, detail, data)
    except Exception as e:
        logger.warning("ai_trace_event_failed", trace_id=getattr(trace, "trace_id", None), error=str(e))


# Maps NormalizedAlert field names to a human data-exposure category — see
# src/models/normalized_alert.py for the authoritative field list this mirrors.
_FIELD_CATEGORY: dict[str, str] = {
    "source": "System metadata", "event_type": "System metadata", "alert_id": "System metadata",
    "detection_uuid": "System metadata", "target_uuid": "System metadata", "occurred_at": "System metadata",
    "severity": "System metadata", "detection_name": "Company data", "endpoint_name": "Company data",
    "endpoint_type": "System metadata", "user_name": "Personal information", "os_name": "System metadata",
    "action_taken": "Company data", "threat_handled": "System metadata", "isolation_status": "System metadata",
    "object_type": "System metadata", "object_uri": "Company data", "file_hash": "Other (threat indicator)",
    "url": "URLs", "ip_address": "System metadata", "domain": "URLs",
    "raw_subject": "Company data (free text)", "raw_content": "Company data (free text)",
}


def build_alert_data_categories(alert: Any, risk_level: str, threat_intel: Any) -> list[AIDataCategory]:
    """
    Categorizes exactly what src/services/ai/gemini_service.py actually sends to the
    model — derived from the real NormalizedAlert/ThreatIntelResult fields, not a
    generic guess. `raw_payload` is never included: it is deliberately excluded from
    the prompt (see gemini_service.py) and is therefore never part of this trace.
    """
    out: list[AIDataCategory] = []
    try:
        dump = alert.model_dump(exclude={"raw_payload"})
        for field, value in dump.items():
            if value in (None, "", "UNKNOWN"):
                continue
            preview, _ = redact_value(str(value), f"normalized_alert.{field}")
            out.append(AIDataCategory(
                category=_FIELD_CATEGORY.get(field, "Other"),
                field=f"normalized_alert.{field}",
                origin="Ingested alert, normalized by src/services/normalizer.py",
                value_preview=str(preview)[:160],
            ))

        out.append(AIDataCategory(
            category="Application-generated context", field="calculated_risk_level",
            origin="Deterministic rule-based risk engine (src/services/risk_engine.py) — not the AI",
            value_preview=risk_level,
        ))

        ti = threat_intel.model_dump()
        out.append(AIDataCategory(
            category="Retrieved data (third-party)", field="threat_intelligence.virustotal",
            origin="VirusTotal lookup, pre-fetched by the pipeline before the AI call "
                   "(src/services/threat_intel/virustotal.py)",
            value_preview=f"status={ti['virustotal']['status']}",
        ))
        out.append(AIDataCategory(
            category="Retrieved data (third-party)", field="threat_intelligence.abuseipdb",
            origin="AbuseIPDB lookup, pre-fetched by the pipeline before the AI call "
                   "(src/services/threat_intel/abuseipdb.py)",
            value_preview=f"status={ti['abuseipdb']['status']}",
        ))
    except Exception as e:
        logger.warning("ai_trace_categorize_failed", error=str(e))
    return out


async def record_input(
    trace: AITrace | None, *, data_categories: list[AIDataCategory],
    raw_input: dict[str, Any], context_notes: list[str] | None = None,
) -> None:
    if trace is None:
        return
    try:
        redacted, findings = redact_value(raw_input, "input")
        _record_findings(trace, findings)
        trace.input_redacted = redacted
        trace.data_categories = data_categories
        trace.context_notes = context_notes or []

        await _emit_event(
            trace, "context_collected", "Context collected",
            detail=f"{len(data_categories)} data field(s) categorized from the pipeline",
        )
        if findings:
            await _emit_event(
                trace, "sensitive_data_scan", "Sensitive-data scan",
                detail=f"{len(findings)} finding(s) auto-redacted before storage",
            )
        else:
            await _emit_event(trace, "sensitive_data_scan", "Sensitive-data scan",
                               detail="No sensitive patterns matched")
    except Exception as e:
        logger.warning("ai_trace_record_input_failed", trace_id=getattr(trace, "trace_id", None), error=str(e))


async def record_config(trace: AITrace | None, config: dict[str, Any]) -> None:
    if trace is None:
        return
    try:
        trace.config = config
    except Exception as e:
        logger.warning("ai_trace_record_config_failed", trace_id=getattr(trace, "trace_id", None), error=str(e))


async def record_external_call_start(
    trace: AITrace | None, *, service: str, domain: str, purpose: str,
    initiated_by: str, data_sent_category: str = "",
) -> AIExternalCall | None:
    if trace is None:
        return None
    try:
        call = AIExternalCall(
            service=service, domain=domain, purpose=purpose, initiated_by=initiated_by,
            requested_at=time.time(), data_sent_category=data_sent_category,
        )
        trace.external_calls.append(call)
        await _emit_event(trace, "external_call_started", f"Contacting {service}", detail=purpose)
        return call
    except Exception as e:
        logger.warning("ai_trace_external_call_start_failed", error=str(e))
        return None


async def record_external_call_end(
    trace: AITrace | None, call: AIExternalCall | None, *, status: str,
    data_returned_category: str = "",
) -> None:
    if trace is None or call is None:
        return
    try:
        call.responded_at = time.time()
        call.status = status
        call.latency_ms = (call.responded_at - call.requested_at) * 1000
        call.data_returned_category = data_returned_category
        await _emit_event(
            trace, "external_call_finished", f"{call.service} responded",
            detail=f"{status} in {call.latency_ms:.0f}ms",
        )
    except Exception as e:
        logger.warning("ai_trace_external_call_end_failed", error=str(e))


async def record_retry(trace: AITrace | None, attempt: int, delay: float, error: str | None) -> None:
    if trace is None:
        return
    try:
        await _emit_event(
            trace, "retry", f"Retrying after attempt {attempt} failed",
            detail=f"waiting {delay:.1f}s before retry" + (f" — {error}" if error else ""),
        )
    except Exception as e:
        logger.warning("ai_trace_record_retry_failed", error=str(e))


async def record_output(trace: AITrace | None, output: dict[str, Any] | None,
                         *, usage: dict[str, Any] | None = None) -> None:
    if trace is None:
        return
    try:
        if output is not None:
            redacted, findings = redact_value(output, "output")
            _record_findings(trace, findings)
            trace.output_redacted = redacted
        trace.usage = usage
        await _emit_event(trace, "model_response_received", "Model response received",
                           detail="Structured output parsed" if output else "No output")
    except Exception as e:
        logger.warning("ai_trace_record_output_failed", error=str(e))


async def build_decision_summary(
    trace: AITrace | None, *, task: str, context_used: list[str],
    decision: str, confidence: str, policy_checks: list[str],
) -> None:
    if trace is None:
        return
    try:
        trace.decision_summary = {
            "task": task,
            "context_used": context_used,
            "decision": decision,
            "confidence": confidence,
            "policy_checks": policy_checks,
            "note": (
                "This is an observable decision summary reconstructed from application "
                "signals (input data, model configuration, the provider's response, and "
                "policy checks) — it is not the model's internal chain-of-thought, which "
                "this integration does not request and this application cannot see."
            ),
        }
    except Exception as e:
        logger.warning("ai_trace_decision_summary_failed", error=str(e))


async def complete_trace(trace: AITrace | None, *, status: str, risk: str, error: str | None = None) -> None:
    if trace is None:
        return
    try:
        trace.completed_at = time.time()
        trace.duration_ms = (trace.completed_at - trace.started_at) * 1000
        trace.status = status
        trace.risk = risk
        trace.error = error
        trace.external_data_transfer = any(
            c.initiated_by == "ai_provider_request" for c in trace.external_calls
        )

        await _emit_event(
            trace, "trace_completed", f"Trace {status.lower()}",
            detail=error or f"Completed in {trace.duration_ms:.0f}ms",
        )
        await _safe_save(trace)
        await events.emit("ai_trace_completed", {
            "trace_id": trace.trace_id, "correlation_id": trace.correlation_id,
            "component": trace.component, "provider": trace.provider, "model": trace.model,
            "status": status, "risk": risk, "duration_ms": trace.duration_ms,
            "security_findings": len(trace.security_findings),
        })
        logger.info("ai_trace_completed", trace_id=trace.trace_id, status=status, risk=risk,
                    findings=len(trace.security_findings))
    except Exception as e:
        logger.warning("ai_trace_complete_failed", trace_id=getattr(trace, "trace_id", None), error=str(e))


async def attach_policy_check(correlation_id: str, *, name: str, passed: bool, detail: str) -> None:
    """
    Attaches a policy-check result (e.g. the post-generation safety lint in
    src/services/ai/lint_checker.py) to the most recent AI trace for this
    correlation_id. Called from src/pipeline/orchestrator.py, which runs the lint
    check after GeminiAIService.generate() has already returned and its trace has
    already been persisted — so this looks the trace up by correlation_id rather than
    holding a reference to the AITrace object across that call boundary.
    """
    try:
        row = await ai_trace_store.get_latest_trace_by_correlation(correlation_id)
        if row is None:
            return
        trace_id = row["trace_id"]
        event = {
            "ts": time.time(), "type": "policy_check", "label": name,
            "detail": detail, "data": {"passed": passed},
        }
        updated = await ai_trace_store.append_policy_check(trace_id, event, blocked=not passed)
        if updated is None:
            return

        await events.emit("ai_trace_event", {
            "trace_id": trace_id, "correlation_id": correlation_id,
            "component": updated.get("component"), "ts": event["ts"], "type": event["type"],
            "label": event["label"], "detail": event["detail"],
        })
        if not passed:
            await events.emit("ai_trace_completed", {
                "trace_id": trace_id, "correlation_id": correlation_id,
                "component": updated.get("component"), "provider": updated.get("provider"),
                "model": updated.get("model"), "status": "BLOCKED", "risk": "BLOCKED",
                "duration_ms": updated.get("duration_ms"),
                "security_findings": len(updated.get("security_findings", [])),
            })
    except Exception as e:
        logger.warning("ai_trace_policy_attach_failed", correlation_id=correlation_id, error=str(e))
