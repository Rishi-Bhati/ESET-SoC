from typing import Any
from pydantic import BaseModel, Field
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult
from src.models.ai_output import AIOutput, AIRunMetadata

class PipelineResult(BaseModel):
    """
    The final schema written to disk as JSON after the pipeline runs. It is the
    per-alert audit record: the normalized alert, the rule-based risk decision
    and the factors behind it, the AI call that explained it (request ID
    included), the AI output, and the notifications queued from it.
    """
    correlation_id: str
    source: str  # WEBHOOK, SYSLOG, MANUAL, etc.
    received_at: str  # ISO8601
    processed_at: str  # ISO8601
    pipeline_status: str  # SUCCESS, PARTIAL, FAILED
    normalized_alert: NormalizedAlert
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL — decided by src/services/risk_engine.py only
    risk_rationale: str
    # Each rule that fired, in order: {"rule", "effect", "detail"} (see risk_engine.RiskFactor).
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
    threat_intel: ThreatIntelResult = Field(default_factory=ThreatIntelResult)
    ai_output: AIOutput | None = None
    ai_run: AIRunMetadata | None = None
    # Notifications staged for this alert: {"email_id", "notification_type", "recipients", "kind"}.
    # Delivery outcomes live in the email_deliveries table, keyed by email_id.
    notifications: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
