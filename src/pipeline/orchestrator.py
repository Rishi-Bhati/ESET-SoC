import asyncio
from datetime import datetime, timezone
import structlog
from src.config import settings
from src.models.raw_payload import EsetRawPayload
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult
from src.models.pipeline_result import PipelineResult
from src.models.ai_output import AIOutput, AIRunMetadata
from src.prompts.system_prompts import PROMPT_VERSION
from src.services import (
    normalizer, risk_engine, output_writer, email_composer, email_outbox, email_dispatcher,
)
from src.services.threat_intel.aggregator import gather_threat_intel
from src.services.ai import factory as ai_factory
from src.services.ai.base import AIConfigurationError, AIGenerationError
from src.services.ai.output_validator import validate_ai_output
from src.services.ai import trace_recorder
from src.storage import job_store, observation_store
from src.utils import events

logger = structlog.get_logger(__name__)


def _unbuilt_provider_metadata(error: Exception) -> AIRunMetadata:
    """Audit record for a provider that could not even be constructed
    (unknown AI_PROVIDER, missing model name, missing SDK)."""
    name = ai_factory.configured_provider_name()
    setting = ai_factory.MODEL_SETTING.get(name)
    return AIRunMetadata(
        provider=name or "unset",
        model=(getattr(settings, setting, "") if setting else "") or "unset",
        prompt_version=PROMPT_VERSION,
        status="FAILED",
        error_type="ConfigurationError",
        error=str(error)[:300],
    )


async def _compose_notifications(correlation_id: str, result: PipelineResult, *, fallback: bool) -> list:
    """This alert's emails, recorded in the result (the audit trail) before the
    result file is written. Never raises: a notification problem must not lose
    the alert."""
    try:
        emails = await (email_composer.compose_fallback_emails(result) if fallback
                        else email_composer.compose_emails(result))
    except Exception as email_error:
        logger.error("pipeline_email_composition_failed", error=str(email_error), correlation_id=correlation_id)
        await events.emit_stage(correlation_id, "EMAIL", "failed", detail=str(email_error)[:200])
        return []
    result.notifications = [
        {"email_id": e.email_id, "notification_type": e.notification_type, "recipients": e.to,
         "kind": "ai_fallback" if fallback else "ai_generated", "queued_at": e.created_at}
        for e in emails
    ]
    return emails


async def _queue_notifications(correlation_id: str, emails: list, *, fallback: bool) -> None:
    try:
        await email_outbox.add_emails(emails)
    except Exception as email_error:
        logger.error("pipeline_email_queue_failed", error=str(email_error), correlation_id=correlation_id)
        await events.emit_stage(correlation_id, "EMAIL", "failed", detail=str(email_error)[:200])
        return
    if emails:
        await events.emit_stage(
            correlation_id, "EMAIL", "ok",
            detail=(f"{len(emails)} 'AI summary failed' notice(s) queued" if fallback
                    else f"{len(emails)} email(s) queued"),
        )
        # Hand off to the mail service without blocking the pipeline.
        # Anything not accepted stays queued for the sweeper.
        asyncio.create_task(email_dispatcher.dispatch_soon())
    else:
        await events.emit_stage(correlation_id, "EMAIL", "skipped", detail="No recipients configured")


async def process_alert_pipeline(correlation_id: str, raw_payload: dict, source: str) -> None:
    """
    ESET alert -> normalization -> threat intel -> rule-based risk -> AI text
    generation -> validation -> result file -> notifications.

    The risk level is decided by src/services/risk_engine.py before the AI is
    called, and the AI's output is rejected if it disagrees. Any AI failure
    (provider down, timeout, bad key, invalid or blocked output) still records
    the alert as PARTIAL and sends our team a deterministic "AI summary
    generation failed" notice. No alert is ever silently lost.

    Each phase emits a `pipeline_stage` event so the dashboard's flow graph can
    render the alert advancing through the pipeline in real time.
    """
    received_at = datetime.now(timezone.utc).isoformat()
    logger.info("pipeline_started", correlation_id=correlation_id, source=source)

    await job_store.update_job_status(correlation_id, "PROCESSING")
    await events.emit_stage(correlation_id, "INGEST", "ok", detail=f"Received via {source}")

    alert = None
    risk_level = "MEDIUM"
    risk_rationale = "Pipeline failed before risk calculation"
    risk_factors: list[dict] = []
    intel = None

    try:
        # Step 1: Parse the raw payload and run normalization
        await events.emit_stage(correlation_id, "NORMALIZE", "active")
        raw = EsetRawPayload(**raw_payload)
        alert = normalizer.normalize(raw, source)
        await events.emit_stage(
            correlation_id, "NORMALIZE", "ok",
            detail=f"{alert.detection_name} on {alert.endpoint_name}",
        )

        # Step 2: External threat intelligence — an input to the risk rules
        await events.emit_stage(correlation_id, "INTEL", "active")
        intel = await gather_threat_intel(alert)
        await events.emit_stage(
            correlation_id, "INTEL", "ok",
            detail=f"VirusTotal {intel.virustotal.status} · AbuseIPDB {intel.abuseipdb.status}",
        )

        # Step 3: Rule-based risk assessment. The only place risk is decided.
        await events.emit_stage(correlation_id, "RISK", "active")
        try:
            observed = await observation_store.record_and_count(
                correlation_id, alert.detection_name, alert.endpoint_name,
            )
        except Exception as obs_error:
            # Correlation history is an enrichment; losing it must not stop the alert.
            logger.warning("risk_observation_failed", error=str(obs_error), correlation_id=correlation_id)
            observed = 1
        # Simulated verdicts (USE_MOCK_THREAT_INTEL) must never change a real
        # alert's risk level.
        assessment = risk_engine.assess_risk(
            alert, None if settings.use_mock_threat_intel else intel, observed_endpoint_count=observed,
        )
        risk_level, risk_rationale = assessment.level, assessment.rationale
        risk_factors = assessment.factor_dicts()
        await events.emit_stage(
            correlation_id, "RISK", "ok",
            detail=risk_rationale, risk_level=risk_level,
        )

    except Exception as e:
        logger.error("pipeline_unrecoverable_failure", error=str(e), correlation_id=correlation_id)
        await events.emit_stage(correlation_id, "NORMALIZE", "failed", detail=str(e)[:200])

        if alert is None:
            alert = NormalizedAlert(raw_payload=raw_payload)
        result = PipelineResult(
            correlation_id=correlation_id, source=source, received_at=received_at,
            processed_at=datetime.now(timezone.utc).isoformat(), pipeline_status="FAILED",
            normalized_alert=alert, risk_level=risk_level, risk_rationale=risk_rationale,
            risk_factors=risk_factors, threat_intel=intel or ThreatIntelResult(), error=str(e),
        )
        await output_writer.write_result(result)
        await job_store.update_job_status(correlation_id, "FAILED", error=str(e))
        logger.info("pipeline_completed_failed", correlation_id=correlation_id)
        return

    # Step 4: AI explanation and notification text
    ai_output: AIOutput | None = None
    ai_run: AIRunMetadata | None = None
    ai_error: str | None = None
    await events.emit_stage(correlation_id, "AI", "active", detail="Generating notification text")
    try:
        provider = ai_factory.get_ai_provider()
        generated = await provider.generate(
            alert, risk_level, intel, risk_rationale=risk_rationale, risk_factors=risk_factors,
        )
        ai_output, ai_run = generated.output, generated.metadata
        await events.emit_stage(
            correlation_id, "AI", "ok",
            detail=f"{ai_run.provider}/{ai_run.model}" + (f" · {ai_run.request_id}" if ai_run.request_id else ""),
        )
    except AIGenerationError as gen_error:
        ai_run, ai_error = gen_error.metadata, str(gen_error)
    except AIConfigurationError as config_error:
        ai_run, ai_error = _unbuilt_provider_metadata(config_error), f"ConfigurationError: {config_error}"
    except Exception as unexpected:  # never let the AI phase take the alert down with it
        ai_run = _unbuilt_provider_metadata(unexpected)
        ai_run.error_type = type(unexpected).__name__
        ai_error = f"{type(unexpected).__name__}: AI phase failed"
        logger.exception("pipeline_ai_phase_unexpected_error", correlation_id=correlation_id)

    if ai_output is None:
        logger.error("pipeline_ai_phase_failed", error=ai_error, correlation_id=correlation_id)
        await events.emit_stage(correlation_id, "AI", "failed", detail=(ai_error or "")[:200])

    # Step 5: Validate the output before anything is sent — risk level unchanged,
    # nothing empty, no prohibited claims (src/services/ai/output_validator.py).
    if ai_output is not None:
        await events.emit_stage(correlation_id, "LINT", "active")
        issues = validate_ai_output(ai_output, risk_level)
        if issues:
            ai_run.status = "BLOCKED"
            ai_run.validation_issues = issues
            ai_run.error_type = "OutputValidationFailed"
            ai_error = f"AI output blocked by validation: {issues}"
            await trace_recorder.attach_policy_check(
                correlation_id, name="Output validation & safety lint", passed=False,
                detail=f"Blocked: {issues}",
            )
            await events.emit_stage(correlation_id, "LINT", "failed", detail=f"{len(issues)} issue(s)")
            logger.warning("pipeline_ai_output_blocked", issues=issues, correlation_id=correlation_id)
            ai_output = None
        else:
            await trace_recorder.attach_policy_check(
                correlation_id, name="Output validation & safety lint", passed=True,
                detail="Risk level unchanged, all sections present, no prohibited claims.",
            )
            await events.emit_stage(correlation_id, "LINT", "ok", detail="Risk level unchanged · no prohibited claims")

    # Step 6: Record the result (the audit record), then notify.
    succeeded = ai_output is not None
    result = PipelineResult(
        correlation_id=correlation_id,
        source=source,
        received_at=received_at,
        processed_at=datetime.now(timezone.utc).isoformat(),
        pipeline_status="SUCCESS" if succeeded else "PARTIAL",
        normalized_alert=alert,
        risk_level=risk_level,
        risk_rationale=risk_rationale,
        risk_factors=risk_factors,
        threat_intel=intel,
        ai_output=ai_output,
        ai_run=ai_run,
        error=None if succeeded else f"AI generation failed: {ai_error}",
    )
    # Composed before the result is written, so the result file records what was queued.
    emails = await _compose_notifications(correlation_id, result, fallback=not succeeded)
    await output_writer.write_result(result)
    await _queue_notifications(correlation_id, emails, fallback=not succeeded)

    if succeeded:
        await job_store.update_job_status(correlation_id, "SUCCESS")
        logger.info("pipeline_completed_success", correlation_id=correlation_id,
                    ai_request_id=ai_run.request_id if ai_run else None)
    else:
        await job_store.update_job_status(correlation_id, "PARTIAL", error=result.error)
        logger.info("pipeline_completed_partial", correlation_id=correlation_id)
