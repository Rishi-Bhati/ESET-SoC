from pydantic import BaseModel, Field

class ClientNotificationJa(BaseModel):
    summary: str = Field(description="Summary of the alert for the client in Japanese")
    current_status: str = Field(description="Current handling status of the threat/endpoint in Japanese")
    required_confirmation: str = Field(description="Action/items client needs to confirm/do in Japanese")

class CThreeNotificationJa(BaseModel):
    summary: str = Field(description="Summary of the alert for front-office coordination in Japanese")
    assessment: str = Field(description="Severity/impact assessment in Japanese")
    front_office_notes: str = Field(description="Operational guidance/action items for C-Three Index front-office in Japanese")
    draft_client_response: str = Field(description="Formal Japanese message template to be sent to the client")

class InternalNotificationJa(BaseModel):
    summary: str = Field(description="Detailed technical summary for internal team in Japanese")
    assessment: str = Field(description="In-depth assessment of threat activity in Japanese")
    recommended_actions: list[str] = Field(description="Step-by-step actions for internal engineers in Japanese")
    draft_client_response: str = Field(description="Refined response draft for internal review in Japanese")

class EngineerNotificationEn(BaseModel):
    alert_summary: str = Field(description="Detailed technical alert summary for engineers in English")
    assessment: str = Field(description="Assessment of endpoint status and threat level in English")
    confirmed_information: list[str] = Field(description="Facts confirmed by the alert payload in English")
    unknown_information: list[str] = Field(description="Crucial information that is currently unknown or missing in English")
    investigation_items: list[str] = Field(description="Key items/artifacts the analyst should investigate next in English")
    recommended_actions: list[str] = Field(description="Recommended mitigation steps in English")
    draft_client_response: str = Field(description="Technical translation or draft response for the client in English")

class EngineerNotificationJa(BaseModel):
    """
    The same engineer-facing technical report as EngineerNotificationEn, written in
    Japanese.

    Why it exists: the engineer report is the only one of the four notifications
    that carries the AI's full analytical breakdown (what it treats as confirmed,
    what is still unknown, what to investigate), so the dashboard uses it — not the
    audience-specific client/C-Three/internal emails — as the "AI assessment" panel
    and the AI Content list snippet. With an English-only engineer report that panel
    stayed English no matter what the dashboard's JA/EN toggle said. This field is
    that same report in Japanese, so the assessment follows the language toggle.

    It is display content, not a fifth email: src/services/email_composer.py still
    sends exactly four notifications, and ENGINEER_EN still carries the English text.

    Field-for-field parallel to EngineerNotificationEn on purpose — the two are
    rendered by the same dashboard component, and a JA-only or EN-only field would
    make one language silently lose a section.
    """
    alert_summary: str = Field(description="Detailed technical alert summary for engineers in Japanese")
    assessment: str = Field(description="Assessment of endpoint status and threat level in Japanese")
    confirmed_information: list[str] = Field(description="Facts confirmed by the alert payload, in Japanese")
    unknown_information: list[str] = Field(description="Crucial information that is currently unknown or missing, in Japanese")
    investigation_items: list[str] = Field(description="Key items/artifacts the analyst should investigate next, in Japanese")
    recommended_actions: list[str] = Field(description="Recommended mitigation steps in Japanese")
    draft_client_response: str = Field(description="Technical draft response for the client in Japanese")

class AIOutput(BaseModel):
    """
    Standard schema forced on the Gemini Structured Output call.
    Ensures precise, type-safe bilingual outputs.
    """
    risk_level: str = Field(description="Calculated risk level: LOW, MEDIUM, HIGH, or CRITICAL")
    client_notification_ja: ClientNotificationJa
    cthree_notification_ja: CThreeNotificationJa
    internal_notification_ja: InternalNotificationJa
    engineer_notification_en: EngineerNotificationEn
    engineer_notification_ja: EngineerNotificationJa
