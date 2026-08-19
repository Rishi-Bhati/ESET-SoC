"""
Data contracts for AI Visibility / Observability.

An AITrace records the complete, auditable lifecycle of one call from this
application to an AI provider. Today that means exactly one call site:
GeminiAIService.generate() in src/services/ai/gemini_service.py, invoked once per
alert from src/pipeline/orchestrator.py. If a second AI integration is ever added,
it should produce AITrace objects through src/services/ai/trace_recorder.py too,
rather than inventing a parallel schema.

An AITrace answers, for any past AI interaction: what was sent, what category of
data that was, what model/provider received it, what came back, whether anything
sensitive was detected, and what the application did with the result.

Nothing here ever stores a raw secret. Every text value that reaches an AITrace has
already passed through src/services/ai/redaction.py at the point it was recorded
(see trace_recorder.py) — the dashboard UI is never the only thing standing between
a captured payload and an exposed credential.
"""
from typing import Any
from pydantic import BaseModel, Field


class AITraceEvent(BaseModel):
    """One entry in a trace's chronological timeline (the Live Activity feed)."""
    ts: float                      # unix timestamp
    type: str                      # e.g. "request_started", "context_collected", "policy_check", ...
    label: str                     # short human label shown in the timeline
    detail: str | None = None      # already-redacted free text, if any
    data: dict[str, Any] = Field(default_factory=dict)   # already-redacted structured extras


class AISecurityFinding(BaseModel):
    """One sensitive-data detection or manual redaction, for the Security Findings list."""
    category: str            # e.g. "API_KEY", "PASSWORD", "PRIVATE_KEY", "EMAIL_PII", "POLICY_VIOLATION", ...
    field_path: str          # where in the trace it was found, e.g. "input.normalized_alert.raw_content"
    method: str              # "automatic" | "manual"
    masked_preview: str      # e.g. "sk-********************9x2" or "[REDACTED: API_KEY]"
    detected_at: float


class AIDataCategory(BaseModel):
    """One categorized slice of data sent to the model (the Data Flow / exposure section)."""
    category: str             # User-provided data / Company data / System metadata / Personal
                               # information / URLs / Retrieved data (third-party) / Application-
                               # generated context / Other
    field: str                # source field name, e.g. "normalized_alert.endpoint_name"
    origin: str                # where this data actually came from in the pipeline
    value_preview: str        # redacted, truncated preview of the actual value


class AIExternalCall(BaseModel):
    """One external network contact associated with this trace."""
    service: str
    domain: str
    purpose: str
    initiated_by: str        # "ai_provider_request" | "pipeline_context_prefetch"
    requested_at: float
    responded_at: float | None = None
    status: str = "PENDING"  # PENDING | OK | ERROR | TIMEOUT
    latency_ms: float | None = None
    data_sent_category: str = ""
    data_returned_category: str = ""


class AITrace(BaseModel):
    trace_id: str
    correlation_id: str
    component: str                 # e.g. "pipeline.ai_generate"
    action: str                    # e.g. "generate_bilingual_notifications"
    provider: str                  # e.g. "google_gemini"
    model: str                     # e.g. "gemini-3.1-flash-lite"
    status: str = "STARTED"        # STARTED | SUCCESS | BLOCKED | FAILED | ERROR
    risk: str = "REVIEW"           # SAFE | REVIEW | SENSITIVE_DATA_DETECTED | SECRET_DETECTED |
                                    # FAILED_SECURITY_CHECK | BLOCKED | ERROR
    started_at: float
    completed_at: float | None = None
    duration_ms: float | None = None

    objective: str = ""                              # plain-language task/objective
    config: dict[str, Any] = Field(default_factory=dict)

    data_categories: list[AIDataCategory] = Field(default_factory=list)
    context_notes: list[str] = Field(default_factory=list)   # honest "what was/wasn't included" notes

    input_redacted: dict[str, Any] = Field(default_factory=dict)
    output_redacted: dict[str, Any] | None = None

    events: list[AITraceEvent] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)   # always [] today — see gemini_service.py
    external_calls: list[AIExternalCall] = Field(default_factory=list)

    security_findings: list[AISecurityFinding] = Field(default_factory=list)
    manual_redactions: list[dict[str, Any]] = Field(default_factory=list)

    decision_summary: dict[str, Any] = Field(default_factory=dict)
    usage: dict[str, Any] | None = None
    external_data_transfer: bool = False
    error: str | None = None
