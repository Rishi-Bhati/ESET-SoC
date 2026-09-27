"""
Composes outbound notification emails for a processed alert.

Two paths:

* compose_emails() — the AI output is present and passed validation. Four
  audience-specific emails are built from its fields:
    CLIENT_JA   (Mac Systems)     the AI-drafted client email: email_subject_ja / email_body_ja
    CTHREE_JA   (C-Three Index)   review request: the client draft plus risk reason,
                                  confirmation items and unknowns, for front-office review
    INTERNAL_JA (our team)        internal summary, initial actions, open items, Backlog draft
    ENGINEER_EN (our engineers)   English technical summary plus the rule engine's factors

* compose_fallback_emails() — the AI call failed or its output was blocked.
  The alert is still recorded, and our own team (INTERNAL_JA, ENGINEER_EN) is
  told so with a deterministic template built only from the normalized alert
  and the rule engine's decision. Nothing goes to the client or C-Three on
  this path: client-facing text without the AI draft would need a human to
  write it anyway.

Recipients come from the dashboard-editable settings store, falling back to
the .env values (see src/storage/settings_store.py).
"""
from datetime import datetime, timezone
import structlog
from src.models.pipeline_result import PipelineResult
from src.models.email_message import EmailMessage
from src.storage import settings_store

logger = structlog.get_logger(__name__)

FALLBACK_SUFFIX = "AI_FALLBACK"


def _parse_recipients(raw: str) -> list[str]:
    return [addr.strip() for addr in raw.split(",") if addr.strip()]


def _subject(result: PipelineResult) -> str:
    alert = result.normalized_alert
    return f"[{result.risk_level}] {alert.detection_name} — {alert.endpoint_name}"


def _bullets(items: list[str]) -> str:
    cleaned = [item for item in items if item and item.strip()]
    return "\n".join(f"- {item}" for item in cleaned) if cleaned else "- なし / None"


def _factor_lines(result: PipelineResult) -> str:
    lines = [f.get("detail", "") for f in result.risk_factors if f.get("effect") in ("base", "raised")]
    return _bullets(lines) if lines else f"- {result.risk_rationale}"


def _client_subject(result: PipelineResult) -> str:
    subject = result.ai_output.email_subject_ja.strip()
    # The risk label must be visible in the client's inbox even if the model
    # left it out; the validator has already rejected a contradicting one.
    if result.risk_level not in subject:
        subject = f"【{result.risk_level}】{subject}"
    return subject


def _client_body(result: PipelineResult) -> str:
    return result.ai_output.email_body_ja.strip()


def _cthree_body(result: PipelineResult) -> str:
    ai = result.ai_output
    return (
        "クライアント向け通知文の確認をお願いいたします。\n\n"
        f"【リスクレベル】{result.risk_level}（ルールベース判定）\n\n"
        f"【概要】\n{ai.alert_summary_ja}\n\n"
        f"【リスク判定の理由】\n{ai.risk_reason_ja}\n\n"
        f"【クライアントへの追加確認事項】\n{_bullets(ai.additional_confirmation_items_ja)}\n\n"
        f"【不明・要確認事項】\n{_bullets(ai.unknown_items)}\n\n"
        "―――― クライアント向けメール案 ――――\n"
        f"件名: {_client_subject(result)}\n\n"
        f"{ai.email_body_ja.strip()}"
    )


def _internal_body(result: PipelineResult) -> str:
    ai = result.ai_output
    return (
        f"{ai.internal_summary_ja}\n\n"
        f"【リスクレベル】{result.risk_level}（ルールベース判定）\n\n"
        f"【リスク判定の理由】\n{ai.risk_reason_ja}\n\n"
        f"【推奨初動対応】\n{_bullets(ai.recommended_initial_actions_ja)}\n\n"
        f"【追加確認事項】\n{_bullets(ai.additional_confirmation_items_ja)}\n\n"
        f"【不明・要確認事項】\n{_bullets(ai.unknown_items)}\n\n"
        f"【クライアント向け通知文】\n{ai.client_notification_ja}\n\n"
        f"【Backlogコメント案】\n{ai.backlog_comment_ja}\n\n"
        f"相関ID: {result.correlation_id}"
    )


def _engineer_body(result: PipelineResult) -> str:
    ai = result.ai_output
    return (
        f"{ai.engineer_summary_en}\n\n"
        f"RISK LEVEL: {result.risk_level} (rule-based)\n"
        f"RULES APPLIED:\n{_factor_lines(result)}\n\n"
        f"UNKNOWN / NEEDS CONFIRMATION:\n{_bullets(ai.unknown_items)}\n\n"
        f"Correlation ID: {result.correlation_id}"
    )


# (notification_type, recipient setting, subject formatter, body formatter)
_NOTIFICATION_SPECS = [
    ("CLIENT_JA", "client_notification_emails", _client_subject, _client_body),
    ("CTHREE_JA", "cthree_notification_emails", _subject, _cthree_body),
    ("INTERNAL_JA", "internal_notification_emails", _subject, _internal_body),
    ("ENGINEER_EN", "engineer_notification_emails", _subject, _engineer_body),
]


def _alert_fact_lines(result: PipelineResult) -> str:
    a = result.normalized_alert
    rows = [
        ("Detection", a.detection_name), ("Endpoint", f"{a.endpoint_name} ({a.endpoint_type})"),
        ("Occurred at", a.occurred_at), ("ESET severity", a.severity), ("Action taken", a.action_taken),
        ("Threat handled", a.threat_handled), ("Isolated", a.isolation_status),
        ("Object", a.object_uri), ("File hash", a.file_hash), ("IP", a.ip_address), ("Domain", a.domain),
    ]
    return "\n".join(f"- {label}: {value}" for label, value in rows)


def _ai_failure_reason(result: PipelineResult) -> str:
    run = result.ai_run
    if run is None:
        return "unknown"
    parts = [run.error_type or run.status]
    if run.error:
        parts.append(run.error)
    if run.validation_issues:
        parts.append("; ".join(run.validation_issues[:5]))
    if run.request_id:
        parts.append(f"request_id={run.request_id}")
    return " — ".join(parts)


def _fallback_internal_body(result: PipelineResult) -> str:
    return (
        "AIによる要約・通知文の生成に失敗したため、アラート情報のみをお送りします。\n"
        "アラートは記録済みです。クライアントへの通知は自動送信されていません。"
        "ダッシュボードで内容を確認のうえ、対応をお願いいたします。\n\n"
        f"【リスクレベル】{result.risk_level}（ルールベース判定）\n\n"
        f"【リスク判定の根拠】\n{_factor_lines(result)}\n\n"
        f"【アラート情報】\n{_alert_fact_lines(result)}\n\n"
        f"【AI生成失敗の理由】\n{_ai_failure_reason(result)}\n\n"
        f"相関ID: {result.correlation_id}"
    )


def _fallback_engineer_body(result: PipelineResult) -> str:
    return (
        "AI summary generation FAILED for this alert. The alert has been recorded; "
        "no client notification was sent. Review it in the dashboard.\n\n"
        f"RISK LEVEL: {result.risk_level} (rule-based)\n"
        f"RULES APPLIED:\n{_factor_lines(result)}\n\n"
        f"ALERT FACTS:\n{_alert_fact_lines(result)}\n\n"
        f"AI FAILURE: {_ai_failure_reason(result)}\n\n"
        f"Correlation ID: {result.correlation_id}"
    )


def _fallback_subject(result: PipelineResult) -> str:
    alert = result.normalized_alert
    return f"[{result.risk_level}][AI要約生成失敗] {alert.detection_name} — {alert.endpoint_name}"


_FALLBACK_SPECS = [
    ("INTERNAL_JA", "internal_notification_emails", _fallback_subject, _fallback_internal_body),
    ("ENGINEER_EN", "engineer_notification_emails", _fallback_subject, _fallback_engineer_body),
]


async def _build(result: PipelineResult, specs, email_id_suffix: str = "") -> list[EmailMessage]:
    created_at = datetime.now(timezone.utc).isoformat()
    messages: list[EmailMessage] = []
    for notification_type, settings_field, subject_fn, body_fn in specs:
        recipients = _parse_recipients(await settings_store.get_effective(settings_field))
        if not recipients:
            logger.warning(
                "email_composer_no_recipients_configured",
                notification_type=notification_type,
                correlation_id=result.correlation_id,
            )
            continue
        messages.append(EmailMessage(
            email_id=f"{result.correlation_id}-{notification_type}{email_id_suffix}",
            correlation_id=result.correlation_id,
            notification_type=notification_type,
            to=recipients,
            subject=subject_fn(result),
            body=body_fn(result),
            risk_level=result.risk_level,
            endpoint_name=result.normalized_alert.endpoint_name,
            detection_name=result.normalized_alert.detection_name,
            created_at=created_at,
        ))
    return messages


async def compose_emails(result: PipelineResult) -> list[EmailMessage]:
    """
    One EmailMessage per notification type with configured recipients, for an
    alert whose AI output passed validation. Returns [] without AI output.
    """
    if result.ai_output is None:
        return []
    return await _build(result, _NOTIFICATION_SPECS)


async def compose_fallback_emails(result: PipelineResult) -> list[EmailMessage]:
    """
    'AI summary generation failed' notices for our own team, built without AI.
    """
    return await _build(result, _FALLBACK_SPECS, email_id_suffix=f"-{FALLBACK_SUFFIX}")
