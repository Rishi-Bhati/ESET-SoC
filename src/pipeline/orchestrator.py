from datetime import datetime, timezone
import structlog
from src.models.raw_payload import EsetRawPayload
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult
from src.models.pipeline_result import PipelineResult
from src.services import normalizer, risk_engine, output_writer
from src.services.threat_intel.aggregator import gather_threat_intel
from src.services.ai.gemini_service import GeminiAIService
from src.services.ai.lint_checker import lint_ai_output
from src.storage import job_store

logger = structlog.get_logger(__name__)

async def process_alert_pipeline(correlation_id: str, raw_payload: dict, source: str) -> None:
    """
    Orchestrates the entire ingestion and analysis pipeline.
    Ensures that any failure (AI outage, parser error, etc.) is captured,
    writes a corresponding output file to disk (either PARTIAL or FAILED),
    and updates SQLite. No alert is ever silently lost.
    """
    received_at = datetime.now(timezone.utc).isoformat()
    logger.info("pipeline_started", correlation_id=correlation_id, source=source)
    
    # 1. Update SQLite status to PROCESSING
    await job_store.update_job_status(correlation_id, "PROCESSING")
    
    # Pre-declare variables for fallback/failed results
    alert = None
    risk_level = "MEDIUM"
    risk_rationale = "Pipeline failed before risk calculation"
    intel = None
    ai_output = None
    
    try:
        # Step 1: Parse the raw payload and run normalization
        raw = EsetRawPayload(**raw_payload)
        alert = normalizer.normalize(raw, source)
        
        # Step 2: Calculate deterministic risk level
        risk_level, risk_rationale = risk_engine.compute_risk(alert)
        
        # Step 3: Fetch Threat Intelligence verdicts in parallel
        intel = await gather_threat_intel(alert)
        
        # Step 4: AI Translation and Summarization (Gemini Flash)
        ai_service = GeminiAIService()
        try:
            ai_output = await ai_service.generate(alert, risk_level, intel)
            
            # Step 5: Post-generation lint check
            lint_ai_output(ai_output)
            
            # Step 6: Assemble and write SUCCESS result
            processed_at = datetime.now(timezone.utc).isoformat()
            result = PipelineResult(
                correlation_id=correlation_id,
                source=source,
                received_at=received_at,
                processed_at=processed_at,
                pipeline_status="SUCCESS",
                normalized_alert=alert,
                risk_level=risk_level,
                risk_rationale=risk_rationale,
                threat_intel=intel,
                ai_output=ai_output
            )
            await output_writer.write_result(result)
            await job_store.update_job_status(correlation_id, "SUCCESS")
            logger.info("pipeline_completed_success", correlation_id=correlation_id)
            
        except Exception as ai_error:
            logger.error("pipeline_ai_phase_failed", error=str(ai_error), correlation_id=correlation_id)
            
            # Write a PARTIAL file to output directory (saves risk calculation & intel)
            processed_at = datetime.now(timezone.utc).isoformat()
            result = PipelineResult(
                correlation_id=correlation_id,
                source=source,
                received_at=received_at,
                processed_at=processed_at,
                pipeline_status="PARTIAL",
                normalized_alert=alert,
                risk_level=risk_level,
                risk_rationale=risk_rationale,
                threat_intel=intel or ThreatIntelResult(),
                ai_output=None,
                error=f"AI generation failed: {ai_error}"
            )
            await output_writer.write_result(result)
            await job_store.update_job_status(correlation_id, "PARTIAL", error=str(ai_error))
            logger.info("pipeline_completed_partial", correlation_id=correlation_id)
            
    except Exception as e:
        logger.error("pipeline_unrecoverable_failure", error=str(e), correlation_id=correlation_id)
        
        # In case of normalizer failure, build empty placeholder schema
        if alert is None:
            alert = NormalizedAlert(raw_payload=raw_payload)
            
        # Write FAILED result to output directory
        processed_at = datetime.now(timezone.utc).isoformat()
        result = PipelineResult(
            correlation_id=correlation_id,
            source=source,
            received_at=received_at,
            processed_at=processed_at,
            pipeline_status="FAILED",
            normalized_alert=alert,
            risk_level=risk_level,
            risk_rationale=risk_rationale,
            threat_intel=intel or ThreatIntelResult(),
            ai_output=None,
            error=str(e)
        )
        await output_writer.write_result(result)
        await job_store.update_job_status(correlation_id, "FAILED", error=str(e))
        logger.info("pipeline_completed_failed", correlation_id=correlation_id)
