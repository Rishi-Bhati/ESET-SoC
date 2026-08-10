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
