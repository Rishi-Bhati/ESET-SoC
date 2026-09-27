"""
The structured output every AI provider must return, and the audit record of
the call that produced it.

AIOutput mirrors the field list the client specified for the OpenAI integration
one-for-one. It is enforced three times:

  1. as the provider's structured-output JSON schema (strict mode on OpenAI —
     see src/services/ai/schema_builder.py), with `risk_level` pinned to the one
     value the rule engine computed, so the model cannot emit any other level;
  2. by Pydantic when the response is parsed (extra keys rejected);
  3. by src/services/ai/output_validator.py (risk level unchanged, no empty
     sections, no prohibited claims) before anything is sent to anyone.
"""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RISK_LEVELS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class AIOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_level: RiskLevel = Field(
        description="Copy of the predefined risk level given in the input. Never changed or re-assessed.",
    )
    alert_summary_ja: str = Field(
        description="Plain-language Japanese summary of the ESET alert, using only the provided facts.",
    )
    risk_reason_ja: str = Field(
        description="Japanese explanation of why the rule engine assigned the given risk level, "
                    "based only on the provided risk factors and alert facts.",
    )
    client_notification_ja: str = Field(
        description="Short, polite Japanese notification message for the client (Mac Systems): "
                    "what was detected, current status, and what they are asked to confirm.",
    )
    internal_summary_ja: str = Field(
        description="Japanese summary for our internal team: facts, risk reason, open questions, "
                    "and what to prepare before responding to the client.",
    )
    engineer_summary_en: str = Field(
        description="English technical summary for overseas engineers: detection, endpoint, "
                    "indicators, handling status, risk basis, unknowns, and investigation pointers.",
    )
    recommended_initial_actions_ja: list[str] = Field(
        description="Japanese list of cautious, non-destructive initial actions. Any containment or "
                    "destructive step must be phrased as requiring human confirmation.",
    )
    additional_confirmation_items_ja: list[str] = Field(
        description="Japanese list of items that should be confirmed with the client or in ESET PROTECT.",
    )
    unknown_items: list[str] = Field(
        description="Missing or unclear information, one entry per item, in the form "
                    "'<field or topic>: Unknown' or '<field or topic>: Needs confirmation'.",
    )
    backlog_comment_ja: str = Field(
        description="Japanese Backlog issue comment draft for tracking this alert.",
    )
    email_subject_ja: str = Field(
        description="Japanese subject line for the client notification email, including the risk level.",
    )
    email_body_ja: str = Field(
        description="Japanese body of the client notification email: formal business Japanese, "
                    "summary, current status, requested confirmations, and a note that details "
                    "are still being confirmed where applicable.",
    )


class AIRunMetadata(BaseModel):
    """
    Audit record of one AI generation attempt for one alert — stored in the
    alert's result file whether the call succeeded or not, so every alert can
    be traced to the provider request that produced (or failed to produce) its
    text. Holds identifiers and counts only: never the API key, never the
    provider's raw error body (which can echo part of a key).
    """
    provider: str
    model: str
    prompt_version: str
    status: Literal["SUCCESS", "FAILED", "BLOCKED", "SKIPPED"] = "FAILED"
    # x-request-id header from the provider — what their support asks for.
    request_id: str | None = None
    # The completion/response object's own ID, when the provider returns one.
    response_id: str | None = None
    # The exact model version that served the call (may differ from the alias configured).
    served_model: str | None = None
    attempts: int = 0
    duration_ms: float | None = None
    usage: dict[str, Any] | None = None
    finish_reason: str | None = None
    error_type: str | None = None
    error: str | None = None
    validation_issues: list[str] = Field(default_factory=list)
    trace_id: str | None = None
    masked_fields: list[str] = Field(default_factory=list)
