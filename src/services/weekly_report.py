"""
Weekly client report: on the configured weekday/time (JST) builds a workbook for the
previous period, archives it, records the run in weekly_reports (idempotent per
period via weekly_report_store.claim) and — only when weekly_report_email_enabled —
queues it as an email.

Content agreed with the client:
  * the workbook lists ONLY LOW and MEDIUM alerts, with ONLY client_fields.WEEKLY_FIELDS;
  * HIGH and CRITICAL alerts are handled immediately elsewhere, so they are NOT in
    the workbook, but they ARE counted and listed in the summary (counts + findings).
A period with no LOW/MEDIUM alerts is still recorded (counts, findings) but has no
workbook ("has_file": false).

Period: a due slot is the most recent configured weekday+time (JST) at/before now.
Its period is the full ISO week before the slot's week: previous Monday 00:00 JST
(inclusive) to the Monday 00:00 JST of the slot's week (exclusive), by the alert's
RECEIVED time (alert_index.received_at). period_key is that ISO week, "2026-W45".
Because the key depends only on the slot's week, moving the weekday/time within a
week never produces a second report for the same period.

All behaviour is controlled by runtime_settings (weekly_report_enabled,
weekly_report_weekday, weekly_report_time, weekly_report_check_interval_seconds,
weekly_report_max_findings_listed, weekly_report_email_enabled, client_portal_url,
email_attachments_enabled, email_attachment_max_bytes), re-read on every call so
dashboard changes apply without a restart.
"""
import asyncio
import base64
import hashlib
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, NamedTuple
import structlog
from src.config import reports_dir
from src.models.email_message import EmailAttachment, EmailMessage
from src.services.email_delivery import limits as mail_limits
from src.services import alert_catalog, client_workbook, email_outbox
from src.services.alert_catalog import BundleQuery
from src.services.client_fields import WEEKLY_FIELDS
from src.services.email_layout import EmailDocument, Section, render_html, render_text, risk_label
from src.storage import alert_index_store, delivery_store, runtime_settings, settings_store
from src.storage import weekly_report_store as store
from src.storage.runtime_settings import WEEKDAYS
from src.utils.jst_time import JST

logger = structlog.get_logger(__name__)

NOTIFICATION_TYPE = "WEEKLY_REPORT_JA"
PERIOD_KEY_RE = re.compile(r"^\d{4}-W\d{2}(-r\d+)?$")
LOW_MEDIUM: tuple[str, ...] = ("LOW", "MEDIUM")
HIGH_RISK: tuple[str, ...] = ("CRITICAL", "HIGH")   # "high-risk" includes CRITICAL
PAGE_SIZE = 1000                  # LOW/MEDIUM alerts loaded per page (no overall cap)
SUMMARY_EXCERPT_CHARS = 200
MAX_AUTO_ATTEMPTS = 3             # the scheduler retries a FAILED period this many times in all
XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
FILE_OMITTED_NO_ALERTS = "no LOW/MEDIUM alerts in the period"


# ------------------------------------------------------------------ period math (pure)

def to_jst(moment: datetime) -> datetime:
    """`moment` in JST. A naive datetime is taken as UTC (the server clock)."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(JST)


def _parse_hhmm(hhmm: str) -> tuple[int, int]:
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", str(hhmm).strip())
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise ValueError(f"time must be HH:MM, got {hhmm!r}")
    return int(m.group(1)), int(m.group(2))


def _weekday_index(weekday: str) -> int:
    try:
        return WEEKDAYS.index(str(weekday).strip().upper())
    except ValueError:
        raise ValueError(f"weekday must be one of {', '.join(WEEKDAYS)}, got {weekday!r}") from None


def due_slot(now: datetime, weekday: str, hhmm: str) -> datetime:
    """The most recent `weekday` at `hhmm` JST at or before `now` (tz-aware JST)."""
    current = to_jst(now)
    hour, minute = _parse_hhmm(hhmm)
    back = (current.weekday() - _weekday_index(weekday)) % 7
    slot = (current - timedelta(days=back)).replace(hour=hour, minute=minute, second=0, microsecond=0)
    if slot > current:
        slot -= timedelta(days=7)
    return slot


def next_slot(now: datetime, weekday: str, hhmm: str) -> datetime:
    """The first `weekday` at `hhmm` JST strictly after `now`."""
    return due_slot(now, weekday, hhmm) + timedelta(days=7)


class Period(NamedTuple):
    """Unpacks as (period_key, start_dt, end_dt); start inclusive, end exclusive, JST."""
    key: str
    start: datetime
    end: datetime

    @property
    def start_epoch(self) -> float:
        return self.start.timestamp()

    @property
    def end_epoch(self) -> float:
        return self.end.timestamp()

    @property
    def last_day(self) -> date:
        return (self.end - timedelta(days=1)).date()

    def label_ja(self) -> str:
        s, e = self.start, self.last_day
        return f"{s.year}年{s.month:02d}月{s.day:02d}日〜{e.year}年{e.month:02d}月{e.day:02d}日"

    def to_dict(self) -> dict[str, Any]:
        return {
            "period_key": self.key,
            "period_start": self.start.isoformat(),
            "period_end": self.end.isoformat(),
            "period_start_epoch": self.start_epoch,
            "period_end_epoch": self.end_epoch,
            "last_day": self.last_day.isoformat(),
            "timezone": "JST",
        }


def _period_from_start(start: datetime) -> Period:
    year, week, _ = start.isocalendar()
    return Period(f"{year:04d}-W{week:02d}", start, start + timedelta(days=7))


def period_for_slot(slot: datetime) -> Period:
    """The period reported in `slot`: previous Monday 00:00 JST up to (exclusive) the
    Monday 00:00 JST of the slot's own week. Key = ISO week of the period start."""
    s = to_jst(slot)
    end = (s - timedelta(days=s.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    return _period_from_start(end - timedelta(days=7))


def validate_period_key(period_key: Any) -> str:
    """The base key ("2026-W45") of a valid key (a "-r<n>" suffix is accepted and
    dropped). Raises ValueError for anything else, including impossible weeks."""
    if not isinstance(period_key, str) or not PERIOD_KEY_RE.fullmatch(period_key):
        raise ValueError("period_key must look like 2026-W45")
    base = period_key.split("-r", 1)[0]
    year, week = int(base[:4]), int(base[6:8])
    try:
        date.fromisocalendar(year, week, 1)
    except ValueError:
        raise ValueError(f"{base} is not a valid ISO week") from None
    return base


def period_from_key(period_key: str) -> Period:
    base = validate_period_key(period_key)
    monday = date.fromisocalendar(int(base[:4]), int(base[6:8]), 1)
    return _period_from_start(datetime(monday.year, monday.month, monday.day, tzinfo=JST))


def report_path(period_key: str) -> str:
    """Archive path, built ONLY from the validated key: <reports_dir>/weekly/<key>.xlsx."""
    return os.path.join(reports_dir(), "weekly", f"{validate_period_key(period_key)}.xlsx")


def download_filename(period_key: str) -> str:
    return f"weekly_report_{validate_period_key(period_key)}.xlsx"


async def schedule() -> tuple[str, str]:
    """(weekday, "HH:MM") currently configured (live)."""
    return (await runtime_settings.get("weekly_report_weekday"),
            await runtime_settings.get("weekly_report_time"))


async def latest_due_period(now: datetime | None = None) -> Period:
    weekday, hhmm = await schedule()
    return period_for_slot(due_slot(now or datetime.now(timezone.utc), weekday, hhmm))


# ------------------------------------------------------------------ content

@dataclass
class ReportContent:
    period: Period
    counts: dict[str, Any]
    findings: list[dict[str, Any]]
    xlsx: bytes | None = None
    title: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def _excerpt(text: Any, limit: int = SUMMARY_EXCERPT_CHARS) -> str:
    if not isinstance(text, str):
        return ""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def _jst_text(epoch: Any) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), JST).strftime("%Y-%m-%d %H:%M JST")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


async def _high_risk_findings(period: Period, cap: int) -> tuple[list[dict[str, Any]], int]:
    """CRITICAL first, then HIGH, oldest first within each; at most `cap`. Also the
    total number of high-risk alerts in the period."""
    rows: list[dict[str, Any]] = []
    total = 0
    for level in HIGH_RISK:
        page, n = await alert_index_store.query(
            risk_levels=[level], received_from=period.start_epoch, received_to=period.end_epoch,
            limit=max(1, cap - len(rows)), order="asc",
        )
        total += n
        rows += page[:max(0, cap - len(rows))]
    findings = []
    for row in rows:
        cid = row["correlation_id"]
        bundle = await alert_catalog.load_bundle(cid)
        ai = (bundle.result.get("ai_output") if bundle else None) or {}
        findings.append({
            "alert_id": cid,
            "eset_alert_id": row.get("eset_alert_id"),
            "received_at": row.get("received_at"),
            "received_at_jst": _jst_text(row.get("received_at")),
            "risk_level": row.get("risk_level"),
            "detection_name": row.get("detection_name"),
            "endpoint_name": row.get("endpoint_name"),
            "ai_summary": _excerpt(ai.get("alert_summary_ja") if isinstance(ai, dict) else None),
            "recommendation_count": len(bundle.recommendations) if bundle else 0,
        })
    return findings, total


async def _low_medium_bundles(period: Period) -> list[alert_catalog.AlertBundle]:
    """Every LOW/MEDIUM alert of the period, paged (no overall cap), oldest first."""
    bundles: list[alert_catalog.AlertBundle] = []
    offset = 0
    while True:
        page, total = await alert_catalog.list_bundles(BundleQuery(
            risk_levels=set(LOW_MEDIUM), received_from=period.start_epoch,
            received_to=period.end_epoch, limit=PAGE_SIZE, offset=offset, order="asc",
        ))
        bundles += page
        offset += PAGE_SIZE
        if offset >= total:
            return bundles


def _title(period: Period) -> str:
    return f"週次アラートレポート {period.label_ja()} (JST) [{period.key}]"


async def build_content(period: Period, *, always_build_file: bool = False) -> ReportContent:
    """Counts, high-risk findings and the LOW/MEDIUM workbook for `period`. Stores
    and sends nothing. Without LOW/MEDIUM alerts the workbook is omitted (None)
    unless always_build_file (preview), which builds a header-only one."""
    cap = await runtime_settings.get("weekly_report_max_findings_listed")
    by_risk = await alert_index_store.counts_by_risk(period.start_epoch, period.end_epoch)
    findings, high_total = await _high_risk_findings(period, cap)
    bundles = await _low_medium_bundles(period)
    title = _title(period)
    xlsx = None
    if bundles or always_build_file:
        xlsx = await client_workbook.build_workbook(
            bundles, WEEKLY_FIELDS, "ja", include_info_sheet=True, title=title)
    counts = {
        **{level: by_risk.get(level, 0) for level in alert_index_store.RISK_ORDER},
        "total": sum(by_risk.get(level, 0) for level in alert_index_store.RISK_ORDER),
        "high_risk": by_risk.get("CRITICAL", 0) + by_risk.get("HIGH", 0),
        "low_medium": by_risk.get("MEDIUM", 0) + by_risk.get("LOW", 0),
        "rows_in_file": len(bundles),
        "findings_listed": len(findings),
        "findings_total": high_total,
        "has_file": bool(bundles),
        "file_size": len(xlsx) if (xlsx is not None and bundles) else None,
        "file_omitted_reason": None if bundles else FILE_OMITTED_NO_ALERTS,
    }
    return ReportContent(period, counts, findings, xlsx, title)


def _write_atomic(path: str, data: bytes) -> str:
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".weekly_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return hashlib.sha256(data).hexdigest()


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# ------------------------------------------------------------------ email

def _parse_recipients(raw: str) -> list[str]:
    return [addr.strip() for addr in (raw or "").split(",") if addr.strip()]


def _headline_risk(counts: dict[str, Any]) -> str:
    for level in alert_index_store.RISK_ORDER:
        if counts.get(level):
            return level
    return "LOW"


def _finding_line(f: dict[str, Any]) -> str:
    names = " — ".join(n for n in (f.get("detection_name"), f.get("endpoint_name")) if n) or "(名称なし)"
    line = f"[{f.get('risk_level')}] {f.get('received_at_jst')} {names}（ID: {f.get('alert_id')}）"
    if f.get("ai_summary"):
        line += f"\n  概要：{f['ai_summary']}"
    line += f"\n  エンジニア推奨対策：{f.get('recommendation_count', 0)}件"
    return line


def compose_email(
    content: ReportContent, *, email_id: str, recipients: list[str], portal_url: str,
    attachment: EmailAttachment | None, attachment_too_large: bool = False,
) -> EmailMessage:
    period, counts = content.period, content.counts
    end_text = f"{period.end.year}年{period.end.month:02d}月{period.end.day:02d}日 00:00"
    start_text = f"{period.start.year}年{period.start.month:02d}月{period.start.day:02d}日 00:00"
    lead = (
        f"{period.label_ja()}（JST）の週次アラートレポートをお送りします。\n"
        f"This is the weekly ESET SOC Lite alert report for {period.start:%Y-%m-%d} to "
        f"{period.last_day:%Y-%m-%d} (JST)."
    )
    summary_rows = [
        ("対象期間", f"{start_text} 〜 {end_text} JST（受信日時ベース、終了時刻を含まない）", False),
        ("レポートID", period.key, True),
        (risk_label("CRITICAL", "ja"), f"{counts.get('CRITICAL', 0)}件", False),
        (risk_label("HIGH", "ja"), f"{counts.get('HIGH', 0)}件", False),
        (risk_label("MEDIUM", "ja"), f"{counts.get('MEDIUM', 0)}件", False),
        (risk_label("LOW", "ja"), f"{counts.get('LOW', 0)}件", False),
        ("合計", f"{counts.get('total', 0)}件", False),
    ]
    sections = [Section("集計 / Summary", rows=summary_rows)]

    findings = content.findings
    if findings:
        items = [_finding_line(f) for f in findings]
        hidden = counts.get("findings_total", len(findings)) - len(findings)
        if hidden > 0:
            items.append(f"ほか {hidden} 件はクライアントポータルでご確認ください。")
        sections.append(Section("高リスク検知（HIGH / CRITICAL）", items=items))
    else:
        sections.append(Section("高リスク検知（HIGH / CRITICAL）",
                                text="対象期間中の HIGH / CRITICAL の検知はありませんでした。"))

    if not counts.get("has_file"):
        file_text = "対象期間中の LOW / MEDIUM アラートはありませんでした（Excel ファイルはありません）。"
    elif attachment is not None:
        file_text = (f"LOW / MEDIUM アラート {counts.get('rows_in_file', 0)} 件の詳細を、"
                     f"添付の Excel ファイル（{attachment.filename}）でお送りします。")
    else:
        why = "ファイルサイズが大きいため添付していません。" if attachment_too_large else ""
        where = f"クライアントポータル（{portal_url}）" if portal_url else "クライアントポータル"
        file_text = (f"LOW / MEDIUM アラート {counts.get('rows_in_file', 0)} 件の詳細（Excel）は、"
                     f"{why}{where}からダウンロードできます。")
    file_text += "\nHIGH / CRITICAL の検知は個別に対応するため、Excel ファイルには含まれていません。"
    sections.append(Section("LOW / MEDIUM アラート一覧（Excel）", text=file_text))
    if portal_url:
        sections.append(Section("クライアントポータル", rows=[("URL", portal_url, True)]))

    doc = EmailDocument(
        lang="ja", risk_level=_headline_risk(counts),
        eyebrow="ESET SOC Lite ｜ 週次レポート / Weekly report",
        heading=f"週次アラートレポート（{period.label_ja()}）",
        lead=lead, sections=sections,
        footer=[f"レポートID：{period.key}",
                "ESET SOC Lite による自動送信です。",
                "Sent automatically by ESET SOC Lite."],
    )
    return EmailMessage(
        email_id=email_id,
        correlation_id=email_id,
        notification_type=NOTIFICATION_TYPE,
        to=recipients,
        subject=f"【週次レポート】ESET SOC Lite アラート週次報告 {period.label_ja()}（{period.key}）",
        body=render_text(doc),
        html=render_html(doc),
        risk_level=_headline_risk(counts),
        created_at=datetime.now(timezone.utc).isoformat(),
        attachments=[attachment] if attachment is not None else [],
    )


async def _queue_email(content: ReportContent, email_id: str) -> tuple[str, dict[str, Any]]:
    """Queues the report email (once per email_id). Returns (status, fields to store)."""
    recipients = _parse_recipients(await settings_store.get_effective_with_fallback(
        "weekly_report_emails", "client_notification_emails"))
    if not recipients:
        logger.error("weekly_report_no_recipients", period_key=content.period.key)
        return store.NO_RECIPIENTS, {"error": "email enabled but no recipients configured "
                                              "(weekly_report_emails / client_notification_emails)",
                                     "recipients": []}
    attachment = None
    too_large = False
    if content.counts.get("has_file") and content.xlsx is not None:
        if await runtime_settings.get("email_attachments_enabled"):
            if len(content.xlsx) <= await runtime_settings.get("email_attachment_max_bytes"):
                attachment = EmailAttachment(
                    filename=download_filename(content.period.key), content_type=XLSX_MEDIA_TYPE,
                    content_base64=base64.b64encode(content.xlsx).decode("ascii"),
                    size_bytes=len(content.xlsx),
                )
            else:
                too_large = True
    portal_url = await runtime_settings.get("client_portal_url")
    message = compose_email(
        content, email_id=email_id, recipients=recipients,
        portal_url=portal_url, attachment=attachment, attachment_too_large=too_large,
    )
    if attachment is not None:
        # The mail service rejects (413) anything over ~1.4 MB of raw attachment
        # once base64/JSON overhead and the HTML body are counted, whatever
        # email_attachment_max_bytes says. Checking the real composed message
        # here means the report still goes out — pointing at the portal — instead
        # of being dead-lettered at handoff.
        violation = mail_limits.message_violation(message)
        if violation:
            logger.warning("weekly_report_attachment_exceeds_mail_limits",
                           email_id=email_id, size_bytes=attachment.size_bytes, reason=violation)
            attachment, too_large = None, True
            message = compose_email(
                content, email_id=email_id, recipients=recipients,
                portal_url=portal_url, attachment=None, attachment_too_large=True,
            )
    # The claim already makes this single-flight; this guards the narrow window of a
    # crash between queueing and recording the status (the stale claim is re-run).
    if await delivery_store.get_delivery(email_id) is None:
        await email_outbox.add_emails([message])
    else:
        logger.warning("weekly_report_email_already_queued", email_id=email_id)
    return store.QUEUED, {"email_id": email_id, "recipients": recipients,
                          "attachment_included": attachment is not None}


# ------------------------------------------------------------------ runs

async def _produce(period: Period, *, resend: bool) -> dict[str, Any]:
    content = await build_content(period)
    path = report_path(period.key)
    file_fields: dict[str, Any]
    if content.counts["has_file"] and content.xlsx is not None:
        sha = await asyncio.to_thread(_write_atomic, path, content.xlsx)
        file_fields = {"file_path": path, "file_sha256": sha}
    else:
        await asyncio.to_thread(_remove_quietly, path)   # a regenerated period may have had one
        file_fields = {"clear_file": True}

    status = store.GENERATED
    extra: dict[str, Any] = {"attachment_included": False}
    if await runtime_settings.get("weekly_report_email_enabled"):
        email_id = f"weekly-report-{period.key}"
        if resend:
            email_id += f"-r{await store.increment_resend(period.key)}"
        status, extra = await _queue_email(content, email_id)
    await store.update_status(period.key, status, counts=content.counts, findings=content.findings,
                              **file_fields, **extra)
    logger.info("weekly_report_generated", period_key=period.key, status=status,
                has_file=content.counts["has_file"], total=content.counts["total"])
    return {
        "period_key": period.key,
        "action": {store.GENERATED: "generated", store.QUEUED: "queued",
                   store.NO_RECIPIENTS: "no_recipients"}[status],
        "status": status,
        "counts": content.counts,
        "has_file": content.counts["has_file"],
        "email_id": extra.get("email_id"),
    }


async def generate_report(period_key: str, *, trigger: str = "manual",
                          regenerate: bool = False) -> dict[str, Any]:
    """
    Produces the report for `period_key` once (raises ValueError for an invalid key).
    Idempotent: when the period is already done or being produced by someone else,
    returns {"action": "none", "status": <current>}. regenerate=True re-produces a
    finished period (overwrites the archive; when email is enabled re-queues it as
    "weekly-report-<key>-r<n>"). Ordinary failures are recorded as FAILED and
    returned as {"action": "failed", "error": ...}, never raised.
    """
    period = period_from_key(period_key)
    resend = False
    if regenerate and await store.get(period.key) is not None:
        claimed = await store.reclaim_for_regenerate(period.key, trigger)
        resend = claimed
    else:
        claimed = await store.claim(
            period.key, period.start_epoch, period.end_epoch, trigger,
            max_attempts=MAX_AUTO_ATTEMPTS if trigger == "scheduled" else None,
        )
    if not claimed:
        row = await store.get(period.key)
        return {"period_key": period.key, "action": "none",
                "status": row["status"] if row else None}
    try:
        return await _produce(period, resend=resend)
    except Exception as e:
        logger.exception("weekly_report_failed", period_key=period.key, error=str(e))
        try:
            await store.update_status(period.key, store.FAILED, error=f"{type(e).__name__}: {e}"[:500])
        except Exception as e2:  # the stale-claim timeout recovers the row
            logger.error("weekly_report_status_update_failed", period_key=period.key, error=str(e2))
        return {"period_key": period.key, "action": "failed", "status": store.FAILED,
                "error": f"{type(e).__name__}: {e}"[:500]}


def _needs_run(row: dict[str, Any] | None) -> bool:
    if row is None:
        return True
    if row["status"] == store.FAILED:
        return row["attempts"] < MAX_AUTO_ATTEMPTS
    if row["status"] == store.CLAIMED:
        return (row["claimed_at"] or 0) < time.time() - store.STALE_CLAIM_SECONDS
    return False


async def tick(now: datetime | None = None) -> dict[str, Any]:
    """
    One scheduler check at `now` (tz-aware or naive UTC; default = current time): if the
    weekly report is due and its period is unclaimed, generate it (and queue the email
    when weekly_report_email_enabled). Returns
    {"due": bool, "period_key": str | None, "action": "disabled" | "baseline" | "none" |
    "generated" | "queued" | "no_recipients" | "failed", ...}.
    Must never raise for ordinary failures (record them in weekly_reports instead).

    On the very first enable (no weekly_reports rows at all) the current due period is
    recorded as SKIPPED (trigger "baseline"), so enabling never sends a surprise report
    for a past week; the first report is the next scheduled one.
    """
    if not await runtime_settings.get("weekly_report_enabled"):
        return {"due": False, "period_key": None, "action": "disabled"}
    period = await latest_due_period(now)
    if await store.count() == 0:
        inserted = await store.record_skipped(
            period.key, period.start_epoch, period.end_epoch, "baseline",
            "baseline: weekly report enabled; reports start with the next scheduled period",
        )
        if inserted:
            logger.info("weekly_report_baseline_recorded", period_key=period.key)
        return {"due": False, "period_key": period.key, "action": "baseline" if inserted else "none"}
    row = await store.get(period.key)
    if not _needs_run(row):
        return {"due": False, "period_key": period.key, "action": "none",
                "status": row["status"] if row else None}
    result = await generate_report(period.key, trigger="scheduled")
    return {"due": True, **result}


async def schedule_info(now: datetime | None = None) -> dict[str, Any]:
    """Live schedule summary for the engineer dashboard."""
    now = now or datetime.now(timezone.utc)
    weekday, hhmm = await schedule()
    upcoming = next_slot(now, weekday, hhmm)
    due = period_for_slot(due_slot(now, weekday, hhmm))
    return {
        "enabled": await runtime_settings.get("weekly_report_enabled"),
        "email_enabled": await runtime_settings.get("weekly_report_email_enabled"),
        "schedule": {"weekday": weekday, "time": hhmm, "timezone": "JST"},
        "next_run_at": upcoming.isoformat(),
        "next_period": period_for_slot(upcoming).to_dict(),
        "latest_due_period": due.to_dict(),
    }


async def run_scheduler_loop() -> None:
    """
    Background task started from the app lifespan. Each iteration re-reads
    runtime_settings: when weekly_report_enabled is false it does nothing and just
    sleeps; when true it calls tick(). Errors are logged and never end the loop;
    cancellation (shutdown) propagates.
    """
    logger.info("weekly_report_loop_started")
    while True:
        interval = 60
        try:
            interval = await runtime_settings.get("weekly_report_check_interval_seconds")
            if await runtime_settings.get("weekly_report_enabled"):
                await tick()
        except asyncio.CancelledError:
            logger.info("weekly_report_loop_stopped")
            raise
        except Exception as e:
            logger.error("weekly_report_loop_error", error=str(e))
        try:
            await asyncio.sleep(max(1, interval))
        except asyncio.CancelledError:
            logger.info("weekly_report_loop_stopped")
            raise
