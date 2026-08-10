from pydantic import BaseModel, Field
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult
from src.models.ai_output import AIOutput

class PipelineResult(BaseModel):
    """
    The final schema written to disk as JSON after the pipeline runs.
    """
    correlation_id: str
    source: str  # WEBHOOK, SYSLOG, MANUAL, etc.
    received_at: str  # ISO8601
    processed_at: str  # ISO8601
    pipeline_status: str  # SUCCESS, PARTIAL, FAILED
    normalized_alert: NormalizedAlert
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_rationale: str
    threat_intel: ThreatIntelResult = Field(default_factory=ThreatIntelResult)
    ai_output: AIOutput | None = None
    error: str | None = None
