"""
Composes outbound notification emails for a processed alert.

Two paths:

* compose_emails() — the AI output is present and passed validation. Four
  audience-specific emails are built from its fields:
    CLIENT_JA   (Mac Systems)     the AI-drafted client email: email_subject_ja / email_body_ja
    CTHREE_JA   (C-Three Index)   review request: the client draft plus risk reason and
                                  confirmation items, for front-office review
    INTERNAL_JA (our team)        internal summary, initial actions, open items, Backlog draft
    ENGINEER_EN (our engineers)   English technical summary plus the rule engine's factors

* compose_fallback_emails() — the AI call failed or its output was blocked.
  The alert is still recorded, and our own team (INTERNAL_JA, ENGINEER_EN) is
  told so with a deterministic template built only from the normalized alert
  and the rule engine's decision. Only the alert fields the raw request
  actually carried are listed; an absent field gets no row at all. Nothing goes to the client or C-Three on
  this path: client-facing text without the AI draft would need a human to
  write it anyway.

Every email is described once as an EmailDocument and rendered twice by
src/services/email_layout.py: plain text (EmailMessage.body — shown in the
dashboard outbox) and HTML (EmailMessage.html — what the mail service sends).

Recipients come from the dashboard-editable settings store, falling back to
the .env values (see src/storage/settings_store.py).
"""
from datetime import datetime, timezone
import structlog
from src.models.normalized_alert import NormalizedAlert
from src.models.pipeline_result import PipelineResult
from src.models.email_message import EmailMessage
from src.services.email_layout import EmailDocument, Section, render_html, render_text
from src.services.risk_text_ja import to_japanese
from src.storage import settings_store

logger = structlog.get_logger(__name__)

FALLBACK_SUFFIX = "AI_FALLBACK"


def _parse_recipients(raw: str) -> list[str]:
    return [addr.strip() for addr in raw.split(",") if addr.strip()]


def _alert_label(result: PipelineResult) -> str:
    """'<detection> — <endpoint>' from whichever of the two the alert reported.
    Falls back to the correlation ID, never to a placeholder for the names."""
    alert = result.normalized_alert
    names = [name for name in (alert.detection_name, alert.endpoint_name) if name]
    return " — ".join(names) or result.correlation_id


def _subject(result: PipelineResult) -> str:
    return f"[{result.risk_level}] {_alert_label(result)}"


def _client_subject(result: PipelineResult) -> str:
    subject = result.ai_output.email_subject_ja.strip()
    # The risk label must be visible in the client's inbox even if the model
    # left it out; the validator has already rejected a contradicting one.
    if result.risk_level not in subject:
        subject = f"【{result.risk_level}】{subject}"
    return subject


# ------------------------------------------------------------------ shared blocks

def _factor_details(result: PipelineResult) -> list[str]:
    lines = [f.get("detail", "") for f in result.risk_factors if f.get("effect") in ("base", "raised")]
    return lines or [result.risk_rationale]


def _defang(value: str | None, kind: str) -> str | None:
    """Indicators are written so no mail client turns them into a live link:
    hxxp://example[.]com, 185.220.101[.]5."""
    if not value:
        return value
    if kind == "url":
        scheme, sep, rest = value.partition("://")
        if sep:
            host, slash, path = rest.partition("/")
            return f"{scheme.replace('http', 'hxxp')}://{host.replace('.', '[.]')}{slash}{path}"
        return value.replace(".", "[.]")
    head, dot, last = value.rpartition(".")
    return f"{head}[.]{last}" if dot else value


def _yes_no(value: str | None, lang: str) -> str | None:
    if value not in ("true", "false"):
        return value
    if lang == "ja":
        return "はい" if value == "true" else "いいえ"
    return "Yes" if value == "true" else "No"


def _endpoint_fact(a: NormalizedAlert) -> str | None:
    if a.endpoint_name and a.endpoint_type:
        return f"{a.endpoint_name} ({a.endpoint_type})"
    return a.endpoint_name or a.endpoint_type


def _alert_facts(result: PipelineResult, lang: str) -> Section:
    """One row per fact the alert actually reported — an absent field gets no
    row, not an "UNKNOWN" one. A section with no rows is not rendered at all."""
    a = result.normalized_alert
    ja = lang == "ja"
    rows = [
        ("検知名" if ja else "Detection", a.detection_name, False),
        ("エンドポイント" if ja else "Endpoint", _endpoint_fact(a), False),
        ("発生日時" if ja else "Occurred at", a.occurred_at, False),
        ("ESETの重大度" if ja else "ESET severity", a.severity, False),
        ("実施された対応" if ja else "Action taken", a.action_taken, False),
        ("脅威の処理済み" if ja else "Threat handled", _yes_no(a.threat_handled, lang), False),
        ("端末の隔離" if ja else "Isolated", _yes_no(a.isolation_status, lang), False),
        ("対象オブジェクト" if ja else "Object", a.object_uri, True),
        ("ファイルハッシュ" if ja else "File hash", a.file_hash, True),
        ("URL", _defang(a.url, "url"), True),
        ("IPアドレス" if ja else "IP", _defang(a.ip_address, "ip"), True),
        ("ドメイン" if ja else "Domain", _defang(a.domain, "domain"), True),
    ]
    return Section("アラート情報" if ja else "Alert details",
                   rows=[(label, value.strip(), mono) for label, value, mono in rows if value and value.strip()])


def _footer(result: PipelineResult, lang: str) -> list[str]:
    if lang == "ja":
        return [f"相関ID：{result.correlation_id}",
                "ESET SOC Lite による自動通知です。詳細はダッシュボードで確認できます。"]
    return [f"Correlation ID: {result.correlation_id}",
            "Sent automatically by ESET SOC Lite. Full details are in the dashboard."]


def _email(subject: str, doc: EmailDocument, text: str | None = None) -> tuple[str, str, str]:
    """(subject, plain-text body, HTML body) for one notification."""
    return subject, text if text is not None else render_text(doc), render_html(doc)


# ------------------------------------------------------------------ AI-generated notifications

def _client_email(result: PipelineResult) -> tuple[str, str, str]:
    subject = _client_subject(result)
    body = result.ai_output.email_body_ja.strip()
    # The heading repeats the subject without the 【LEVEL】 prefix — the badge
    # beneath it already says the level.
    heading = subject.replace(f"【{result.risk_level}】", "").strip() or subject
    doc = EmailDocument(lang="ja", heading=heading, risk_level=result.risk_level, lead=body)
    # The client receives the AI-drafted body exactly as written (and as C-Three
    # reviewed it); only the HTML adds the header around it.
    return _email(subject, doc, text=body)


def _cthree_email(result: PipelineResult) -> tuple[str, str, str]:
    ai = result.ai_output
    doc = EmailDocument(
        lang="ja", risk_level=result.risk_level,
        eyebrow="ESET SOC Lite ｜ シースリー向け レビュー依頼",
        heading=f"クライアント向け通知文のご確認：{_alert_label(result)}",
        lead="クライアントへ送付する通知文の確認をお願いいたします。リスクレベルはルールベースで判定したものです。",
        sections=[
            _alert_facts(result, "ja"),
            Section("概要", text=ai.alert_summary_ja),
            Section("リスク判定の理由", text=ai.risk_reason_ja),
            Section("クライアントへの追加確認事項", items=ai.additional_confirmation_items_ja),
            Section("要確認事項", items=ai.unknown_items),
            Section("クライアント向けメール案", quote=f"件名：{_client_subject(result)}\n\n{ai.email_body_ja.strip()}"),
        ],
        footer=_footer(result, "ja"),
    )
    return _email(_subject(result), doc)


def _internal_email(result: PipelineResult) -> tuple[str, str, str]:
    ai = result.ai_output
    doc = EmailDocument(
        lang="ja", risk_level=result.risk_level,
        eyebrow="ESET SOC Lite ｜ 社内向けサマリー",
        heading=_alert_label(result),
        lead=ai.internal_summary_ja,
        sections=[
            _alert_facts(result, "ja"),
            Section("リスク判定の理由", text=ai.risk_reason_ja),
            Section("推奨初動対応", items=ai.recommended_initial_actions_ja, numbered=True),
            Section("追加確認事項", items=ai.additional_confirmation_items_ja),
            Section("要確認事項", items=ai.unknown_items),
            Section("クライアント向け通知文", quote=ai.client_notification_ja),
            Section("Backlogコメント案", quote=ai.backlog_comment_ja),
        ],
        footer=_footer(result, "ja"),
    )
    return _email(_subject(result), doc)


def _engineer_email(result: PipelineResult) -> tuple[str, str, str]:
    ai = result.ai_output
    doc = EmailDocument(
        lang="en", risk_level=result.risk_level,
        eyebrow="ESET SOC Lite | Engineer report",
        heading=_alert_label(result),
        sections=[
            Section("Summary", text=ai.engineer_summary_en),
            _alert_facts(result, "en"),
            Section("Rules applied (rule-based risk level)", items=_factor_details(result)),
            Section("Needs confirmation", items=ai.unknown_items),
        ],
        footer=_footer(result, "en"),
    )
    return _email(_subject(result), doc)


# (notification_type, recipient setting, composer -> (subject, text, html))
_NOTIFICATION_SPECS = [
    ("CLIENT_JA", "client_notification_emails", _client_email),
    ("CTHREE_JA", "cthree_notification_emails", _cthree_email),
    ("INTERNAL_JA", "internal_notification_emails", _internal_email),
    ("ENGINEER_EN", "engineer_notification_emails", _engineer_email),
]


# ------------------------------------------------------------------ AI-failure notices

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


def _fallback_subject(result: PipelineResult) -> str:
    return f"[{result.risk_level}][AI要約生成失敗] {_alert_label(result)}"


def _fallback_internal_email(result: PipelineResult) -> tuple[str, str, str]:
    doc = EmailDocument(
        lang="ja", risk_level=result.risk_level,
        eyebrow="ESET SOC Lite ｜ AI要約生成失敗のお知らせ",
        heading=_alert_label(result),
        lead=("AIによる要約・通知文の生成に失敗したため、アラート情報のみをお送りします。\n"
              "アラートは記録済みです。クライアントへの通知は自動送信されていません。"
              "ダッシュボードで内容を確認のうえ、対応をお願いいたします。"),
        sections=[
            _alert_facts(result, "ja"),
            Section("リスク判定の根拠", items=[to_japanese(d) for d in _factor_details(result)]),
            Section("AI生成失敗の理由", text=_ai_failure_reason(result)),
        ],
        footer=_footer(result, "ja"),
    )
    return _email(_fallback_subject(result), doc)


def _fallback_engineer_email(result: PipelineResult) -> tuple[str, str, str]:
    doc = EmailDocument(
        lang="en", risk_level=result.risk_level,
        eyebrow="ESET SOC Lite | AI summary failed",
        heading=_alert_label(result),
        lead=("AI summary generation FAILED for this alert. The alert has been recorded; "
              "no client notification was sent. Review it in the dashboard."),
        sections=[
            _alert_facts(result, "en"),
            Section("Rules applied (rule-based risk level)", items=_factor_details(result)),
            Section("AI failure", text=_ai_failure_reason(result)),
        ],
        footer=_footer(result, "en"),
    )
    return _email(_fallback_subject(result), doc)


_FALLBACK_SPECS = [
    ("INTERNAL_JA", "internal_notification_emails", _fallback_internal_email),
    ("ENGINEER_EN", "engineer_notification_emails", _fallback_engineer_email),
]


async def _build(result: PipelineResult, specs, email_id_suffix: str = "") -> list[EmailMessage]:
    created_at = datetime.now(timezone.utc).isoformat()
    messages: list[EmailMessage] = []
    for notification_type, settings_field, compose in specs:
        recipients = _parse_recipients(await settings_store.get_effective(settings_field))
        if not recipients:
            logger.warning(
                "email_composer_no_recipients_configured",
                notification_type=notification_type,
                correlation_id=result.correlation_id,
            )
            continue
        subject, body, html = compose(result)
        messages.append(EmailMessage(
            email_id=f"{result.correlation_id}-{notification_type}{email_id_suffix}",
            correlation_id=result.correlation_id,
            notification_type=notification_type,
            to=recipients,
            subject=subject,
            body=body,
            html=html,
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
