"""
Emails the client when an engineer adds a recommendation to an alert, and again
when a recommendation that was emailed is retracted.

Switched by the runtime setting `recommendation_email_enabled` (dashboard Emails
tab; off by default). Recipients: `recommendation_notification_emails`, or
`client_notification_emails` when that is blank (settings_store).

The email is client-facing and Japanese (with an English lead line), like the
weekly report. It carries only what the client portal already shows for the
alert: risk level, detection and device names, received time, the alert id, and
the recommendation text and author. A retraction email never includes the
engineer's retraction reason (an internal note). Each email gets a stable
email_id (`rec-<id>` / `rec-<id>-retracted`), so it is queued at most once.

Never raises: a mail problem must not fail adding or retracting the
recommendation itself; the reason is returned instead.
"""
from datetime import datetime, timezone
from typing import Any

import structlog

from src.models.email_message import EmailMessage
from src.services import alert_catalog, email_dispatcher, email_outbox
from src.services.email_layout import EmailDocument, Section, render_html, render_text, risk_label
from src.storage import delivery_store, recommendation_store, runtime_settings, settings_store
from src.utils.jst_time import JST

logger = structlog.get_logger(__name__)

NOTIFICATION_TYPE = "RECOMMENDATION_JA"
RETRACTED_TYPE = "RECOMMENDATION_RETRACTED_JA"


def _parse_recipients(raw: str) -> list[str]:
    return [addr.strip() for addr in (raw or "").split(",") if addr.strip()]


def _jst(epoch: Any) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), JST).strftime("%Y年%m月%d日 %H:%M JST")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def _known(value: Any) -> str | None:
    return value if isinstance(value, str) and value and value != "UNKNOWN" else None


def _alert_facts(cid: str, bundle: alert_catalog.AlertBundle | None) -> tuple[dict[str, Any], list]:
    result = bundle.result if bundle else {}
    normalized = result.get("normalized_alert") if isinstance(result.get("normalized_alert"), dict) else {}
    risk = str(result.get("risk_level") or "").upper() or "LOW"
    facts = {
        "risk": risk,
        "detection": _known(normalized.get("detection_name")),
        "endpoint": _known(normalized.get("endpoint_name")),
        "received": _jst(bundle.job.get("created_at")) if bundle else "",
    }
    rows = [("リスクレベル", risk_label(risk, "ja"), False)]
    if facts["detection"]:
        rows.append(("検知名", facts["detection"], False))
    if facts["endpoint"]:
        rows.append(("端末", facts["endpoint"], False))
    if facts["received"]:
        rows.append(("受信日時", facts["received"], False))
    rows.append(("アラートID", cid, True))
    return facts, rows


def _label(facts: dict[str, Any], cid: str) -> str:
    return " — ".join(n for n in (facts["detection"], facts["endpoint"]) if n) or cid


async def _portal_link(cid: str) -> str:
    base = await runtime_settings.get("client_portal_url")
    return f"{base}/#/alerts/{cid}" if base else ""


def compose(rec: dict[str, Any], bundle: alert_catalog.AlertBundle | None, *, recipients: list[str],
            portal_link: str, retracted: bool = False) -> EmailMessage:
    cid = rec["correlation_id"]
    facts, alert_rows = _alert_facts(cid, bundle)
    label = _label(facts, cid)
    if retracted:
        heading = "推奨対策の取り下げのお知らせ"
        lead = ("以前お送りした次のアラートの推奨対策を、担当エンジニアが取り下げました。"
                "この推奨対策はクライアントポータルにも表示されなくなります。"
                "ご不明な点は担当エンジニアまでお問い合わせください。\n"
                "Your engineer has withdrawn the recommended action below for this alert.")
        rec_sections = [Section("取り下げた推奨対策 / Withdrawn recommendation", quote=rec.get("body") or ""),
                        Section("取り下げの詳細", rows=[("取り下げ日時", _jst(rec.get("retracted_at")), False)])]
        subject = f"【推奨対策の取り下げ】[{facts['risk']}] {label}"
        email_id = f"rec-{rec['id']}-retracted"
        ntype = RETRACTED_TYPE
    else:
        heading = "担当エンジニアから推奨対策が届きました"
        lead = ("次のアラートについて、担当エンジニアが推奨対策を追加しました。"
                "内容をご確認のうえ、対応をお願いいたします。\n"
                "Your engineer has added a recommended action for the alert below.")
        rec_sections = [Section("推奨対策 / Recommended action", quote=rec.get("body") or ""),
                        Section("推奨対策の詳細", rows=[("担当エンジニア", rec.get("author") or "", False),
                                                    ("追加日時", _jst(rec.get("created_at")), False)])]
        subject = f"【推奨対策】[{facts['risk']}] {label}"
        email_id = f"rec-{rec['id']}"
        ntype = NOTIFICATION_TYPE
    sections = [*rec_sections, Section("対象のアラート / Alert", rows=alert_rows)]
    if portal_link:
        sections.append(Section("クライアントポータル", text="アラートの詳細と、ほかの推奨対策はポータルで確認できます。",
                                rows=[("URL", portal_link, True)]))
    doc = EmailDocument(
        lang="ja", risk_level=facts["risk"],
        eyebrow="ESET SOC Lite ｜ 推奨対策 / Recommendation",
        heading=heading, lead=lead, sections=sections,
        footer=[f"推奨対策ID：{rec['id']}", "ESET SOC Lite による自動送信です。",
                "Sent automatically by ESET SOC Lite."],
    )
    return EmailMessage(
        email_id=email_id, correlation_id=cid, notification_type=ntype, to=recipients,
        subject=subject, body=render_text(doc), html=render_html(doc), risk_level=facts["risk"],
        endpoint_name=facts["endpoint"], detection_name=facts["detection"],
        created_at=datetime.now(timezone.utc).isoformat(),
    )


async def _queue(rec: dict[str, Any], *, retracted: bool) -> dict[str, Any]:
    if not await runtime_settings.get("recommendation_email_enabled"):
        return {"queued": False, "email_id": None, "reason": "recommendation_email_disabled"}
    recipients = _parse_recipients(await settings_store.get_effective_with_fallback(
        "recommendation_notification_emails", "client_notification_emails"))
    if not recipients:
        logger.warning("recommendation_email_no_recipients", recommendation_id=rec["id"])
        return {"queued": False, "email_id": None, "reason": "no_recipients"}
    bundle = await alert_catalog.load_bundle(rec["correlation_id"])
    message = compose(rec, bundle, recipients=recipients,
                      portal_link=await _portal_link(rec["correlation_id"]), retracted=retracted)
    if await delivery_store.get_delivery(message.email_id) is not None:
        return {"queued": False, "email_id": message.email_id, "reason": "already_queued"}
    await email_outbox.add_emails([message])
    if not retracted:
        await recommendation_store.set_notification_email_id(rec["id"], message.email_id)
    logger.info("recommendation_email_queued", recommendation_id=rec["id"], email_id=message.email_id,
                correlation_id=rec["correlation_id"], retracted=retracted, recipients=len(recipients))
    return {"queued": True, "email_id": message.email_id, "reason": None}


async def notify_recommendation_added(recommendation: dict[str, Any]) -> dict[str, Any]:
    """Queues the 'new recommendation' email. Returns {"queued", "email_id", "reason"}."""
    try:
        return await _queue(recommendation, retracted=False)
    except Exception as e:
        logger.error("recommendation_email_failed", recommendation_id=recommendation.get("id"), error=str(e))
        return {"queued": False, "email_id": None, "reason": "error"}


async def notify_recommendation_retracted(recommendation: dict[str, Any]) -> dict[str, Any]:
    """Queues the 'recommendation withdrawn' email, only if the client was emailed
    about this recommendation in the first place."""
    if not recommendation.get("notification_email_id"):
        return {"queued": False, "email_id": None, "reason": "never_emailed"}
    try:
        return await _queue(recommendation, retracted=True)
    except Exception as e:
        logger.error("recommendation_email_failed", recommendation_id=recommendation.get("id"), error=str(e))
        return {"queued": False, "email_id": None, "reason": "error"}


def dispatch_soon() -> None:
    """Hands the queued email off without making the API call wait for it."""
    import asyncio
    asyncio.create_task(email_dispatcher.dispatch_soon())
