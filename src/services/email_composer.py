from datetime import datetime, timezone
import structlog
from src.models.pipeline_result import PipelineResult
from src.models.email_message import EmailMessage
from src.storage import settings_store

logger = structlog.get_logger(__name__)


def _parse_recipients(raw: str) -> list[str]:
    return [addr.strip() for addr in raw.split(",") if addr.strip()]


def _subject(result: PipelineResult) -> str:
    alert = result.normalized_alert
    return f"[{result.risk_level}] {alert.detection_name} — {alert.endpoint_name}"


def _client_body(result: PipelineResult) -> str:
    n = result.ai_output.client_notification_ja
    return (
        f"概要 (Summary): {n.summary}\n\n"
        f"現在の状況 (Current Status): {n.current_status}\n\n"
        f"確認事項 (Required Confirmation): {n.required_confirmation}"
    )


def _cthree_body(result: PipelineResult) -> str:
    n = result.ai_output.cthree_notification_ja
    return (
        f"概要 (Summary): {n.summary}\n\n"
        f"評価 (Assessment): {n.assessment}\n\n"
        f"フロントオフィス対応 (Front Office Notes): {n.front_office_notes}\n\n"
        f"クライアント返信案 (Draft Client Response): {n.draft_client_response}"
    )


def _internal_body(result: PipelineResult) -> str:
    n = result.ai_output.internal_notification_ja
    actions = "\n".join(f"- {item}" for item in n.recommended_actions)
    return (
        f"概要 (Summary): {n.summary}\n\n"
        f"評価 (Assessment): {n.assessment}\n\n"
        f"推奨アクション (Recommended Actions):\n{actions}\n\n"
        f"クライアント返信案 (Draft Client Response): {n.draft_client_response}"
    )


def _engineer_body(result: PipelineResult) -> str:
    n = result.ai_output.engineer_notification_en
    confirmed = "\n".join(f"- {item}" for item in n.confirmed_information)
    unknown = "\n".join(f"- {item}" for item in n.unknown_information)
    investigate = "\n".join(f"- {item}" for item in n.investigation_items)
    actions = "\n".join(f"- {item}" for item in n.recommended_actions)
    return (
        f"Alert Summary: {n.alert_summary}\n\n"
        f"Assessment: {n.assessment}\n\n"
        f"Confirmed Information:\n{confirmed}\n\n"
        f"Unknown Information:\n{unknown}\n\n"
        f"Investigation Items:\n{investigate}\n\n"
        f"Recommended Actions:\n{actions}\n\n"
        f"Draft Client Response: {n.draft_client_response}"
    )


# (notification_type, recipient setting, body formatter)
_NOTIFICATION_SPECS = [
    ("CLIENT_JA", "client_notification_emails", _client_body),
    ("CTHREE_JA", "cthree_notification_emails", _cthree_body),
    ("INTERNAL_JA", "internal_notification_emails", _internal_body),
    ("ENGINEER_EN", "engineer_notification_emails", _engineer_body),
]


async def compose_emails(result: PipelineResult) -> list[EmailMessage]:
    """
    Builds one EmailMessage per configured AI notification variant for a
    successfully-processed alert. Only called when ai_output is present —
    PARTIAL/FAILED pipeline runs have no AI content to email.

    Recipients come from the dashboard-editable settings store, falling back to
    the .env values (see src/storage/settings_store.py).
    """
    if result.ai_output is None:
        return []

    created_at = datetime.now(timezone.utc).isoformat()
    subject = _subject(result)
    messages: list[EmailMessage] = []

    for notification_type, settings_field, body_fn in _NOTIFICATION_SPECS:
        recipients = _parse_recipients(await settings_store.get_effective(settings_field))
        if not recipients:
            logger.warning(
                "email_composer_no_recipients_configured",
                notification_type=notification_type,
                correlation_id=result.correlation_id,
            )
            continue

        messages.append(EmailMessage(
            email_id=f"{result.correlation_id}-{notification_type}",
            correlation_id=result.correlation_id,
            notification_type=notification_type,
            to=recipients,
            subject=subject,
            body=body_fn(result),
            risk_level=result.risk_level,
            endpoint_name=result.normalized_alert.endpoint_name,
            detection_name=result.normalized_alert.detection_name,
            created_at=created_at,
        ))

    return messages
