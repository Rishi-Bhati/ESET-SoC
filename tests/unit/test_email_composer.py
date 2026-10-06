import json

import pytest
from src.config import settings
from src.models.ai_output import AIRunMetadata
from src.models.normalized_alert import NormalizedAlert
from src.models.pipeline_result import PipelineResult
from src.services import email_composer, email_outbox
from ai_fakes import sample_output


def _ai_output(risk="HIGH"):
    return sample_output(
        risk, "Win32/Example.A",
        recommended_initial_actions_ja=["対応1", "対応2"],
        additional_confirmation_items_ja=["確認事項1"],
        unknown_items=["file_hash: Unknown", "threat_handled: Needs confirmation"],
        email_subject_ja=f"【{risk}】セキュリティアラートのご報告",
        email_body_ja="お世話になっております。確認事項がございます。",
        backlog_comment_ja="Backlog下書き",
    )


def _result(status="SUCCESS", ai=True, risk="HIGH"):
    return PipelineResult(
        correlation_id="cid-123", source="WEBHOOK",
        received_at="2026-01-01T00:00:00Z", processed_at="2026-01-01T00:00:05Z",
        pipeline_status=status,
        normalized_alert=NormalizedAlert(
            detection_name="Win32/Example.A", endpoint_name="HOST-01", severity=risk),
        risk_level=risk, risk_rationale="because",
        risk_factors=[{"rule": "severity_high_unhandled", "effect": "base",
                       "detail": "Alert severity is HIGH and the threat is not handled."}],
        ai_output=_ai_output(risk) if ai else None,
        ai_run=None if ai else AIRunMetadata(
            provider="openai", model="gpt-test", prompt_version="v2.0", status="FAILED",
            error_type="Timeout", error="No response within 60s", request_id="req_abc"),
    )


@pytest.fixture
def all_recipients(monkeypatch):
    monkeypatch.setattr(settings, "client_notification_emails", "client@example.com")
    monkeypatch.setattr(settings, "cthree_notification_emails", "a@example.com, b@example.com")
    monkeypatch.setattr(settings, "internal_notification_emails", "internal@example.com")
    monkeypatch.setattr(settings, "engineer_notification_emails", "eng@example.com")


@pytest.mark.asyncio
async def test_composes_one_email_per_notification_type(all_recipients):
    emails = await email_composer.compose_emails(_result())
    assert [e.notification_type for e in emails] == [
        "CLIENT_JA", "CTHREE_JA", "INTERNAL_JA", "ENGINEER_EN"]
    assert all(e.status == "PENDING" for e in emails)
    assert all(e.correlation_id == "cid-123" for e in emails)


@pytest.mark.asyncio
async def test_email_ids_are_unique_and_deterministic(all_recipients):
    emails = await email_composer.compose_emails(_result())
    ids = [e.email_id for e in emails]
    assert len(set(ids)) == 4
    assert "cid-123-CLIENT_JA" in ids


@pytest.mark.asyncio
async def test_subject_carries_risk_detection_and_endpoint(all_recipients):
    emails = {e.notification_type: e for e in await email_composer.compose_emails(_result(risk="CRITICAL"))}
    for kind in ("CTHREE_JA", "INTERNAL_JA", "ENGINEER_EN"):
        assert emails[kind].subject == "[CRITICAL] Win32/Example.A — HOST-01"
    # The client gets the AI-drafted subject, which carries the risk label.
    assert emails["CLIENT_JA"].subject == "【CRITICAL】セキュリティアラートのご報告"


@pytest.mark.asyncio
async def test_client_subject_gets_the_risk_label_if_the_model_left_it_out(all_recipients):
    result = _result()
    result.ai_output.email_subject_ja = "セキュリティアラートのご報告"
    client_mail = next(e for e in await email_composer.compose_emails(result) if e.notification_type == "CLIENT_JA")
    assert client_mail.subject == "【HIGH】セキュリティアラートのご報告"


@pytest.mark.asyncio
async def test_multiple_recipients_are_split(all_recipients):
    emails = await email_composer.compose_emails(_result())
    cthree = next(e for e in emails if e.notification_type == "CTHREE_JA")
    assert cthree.to == ["a@example.com", "b@example.com"]


@pytest.mark.asyncio
async def test_bodies_contain_their_notification_content(all_recipients):
    emails = {e.notification_type: e.body for e in await email_composer.compose_emails(_result())}
    assert emails["CLIENT_JA"] == "お世話になっております。確認事項がございます。"
    # C-Three reviews the client draft before it matters: draft + reasons + open items.
    assert "お世話になっております。確認事項がございます。" in emails["CTHREE_JA"]
    assert "確認事項1" in emails["CTHREE_JA"] and "threat_handled: Needs confirmation" in emails["CTHREE_JA"]
    assert "対応1" in emails["INTERNAL_JA"] and "対応2" in emails["INTERNAL_JA"]
    assert "Backlog下書き" in emails["INTERNAL_JA"]
    assert "[MOCK] Technical summary" in emails["ENGINEER_EN"]
    assert "Alert severity is HIGH" in emails["ENGINEER_EN"]
    assert "file_hash: Unknown" in emails["ENGINEER_EN"]


@pytest.mark.asyncio
async def test_fallback_notice_goes_to_our_team_only(all_recipients):
    emails = await email_composer.compose_fallback_emails(_result(status="PARTIAL", ai=False))
    assert [e.notification_type for e in emails] == ["INTERNAL_JA", "ENGINEER_EN"]
    assert all(e.email_id.endswith("-AI_FALLBACK") for e in emails)
    assert all("[AI要約生成失敗]" in e.subject and e.subject.startswith("[HIGH]") for e in emails)
    internal, engineer = emails
    assert "Win32/Example.A" in internal.body and "アラートの重大度は HIGH（高）で、脅威は処理されていません。" in internal.body
    assert "Timeout" in engineer.body and "req_abc" in engineer.body
    assert "no client notification was sent" in engineer.body


@pytest.mark.asyncio
async def test_types_without_recipients_are_skipped(monkeypatch):
    monkeypatch.setattr(settings, "client_notification_emails", "client@example.com")
    monkeypatch.setattr(settings, "cthree_notification_emails", "")
    monkeypatch.setattr(settings, "internal_notification_emails", "   ")
    monkeypatch.setattr(settings, "engineer_notification_emails", "")

    emails = await email_composer.compose_emails(_result())
    assert [e.notification_type for e in emails] == ["CLIENT_JA"]


@pytest.mark.asyncio
async def test_no_emails_without_ai_output(all_recipients):
    assert await email_composer.compose_emails(_result(status="PARTIAL", ai=False)) == []
    assert await email_composer.compose_emails(_result(status="FAILED", ai=False)) == []


# --------------------------- only the fields the alert reported ---------------------------

def _minimal_result(alert: NormalizedAlert, ai=True, **ai_overrides) -> PipelineResult:
    return PipelineResult(
        correlation_id="cid-min", source="WEBHOOK",
        received_at="2026-01-01T00:00:00Z", processed_at="2026-01-01T00:00:05Z",
        pipeline_status="SUCCESS" if ai else "PARTIAL", normalized_alert=alert,
        risk_level="HIGH", risk_rationale="Alert severity is HIGH and the threat is not reported as handled.",
        ai_output=sample_output("HIGH", **ai_overrides) if ai else None,
        ai_run=None if ai else AIRunMetadata(
            provider="openai", model="gpt-test", prompt_version="v2.2", status="FAILED", error_type="Timeout"),
    )


@pytest.mark.asyncio
async def test_fallback_lists_only_the_reported_alert_facts(all_recipients):
    alert = NormalizedAlert(source="WEBHOOK", detection_name="Win32/Agent.X", severity="HIGH")
    internal, engineer = await email_composer.compose_fallback_emails(_minimal_result(alert, ai=False))
    assert "・検知名：Win32/Agent.X" in internal.body and "・ESETの重大度：HIGH" in internal.body
    assert "- Detection: Win32/Agent.X" in engineer.body and "- ESET severity: HIGH" in engineer.body
    for absent in ("Endpoint", "Occurred at", "Action taken", "Threat handled", "Isolated",
                   "Object", "File hash", "URL", "- IP", "Domain"):
        assert absent not in engineer.body and absent not in engineer.html, absent
    for absent in ("エンドポイント", "発生日時", "実施された対応", "脅威の処理済み", "端末の隔離",
                   "対象オブジェクト", "ファイルハッシュ", "URL", "IPアドレス", "ドメイン"):
        assert absent not in internal.body and absent not in internal.html, absent
    for mail in (internal, engineer):
        for text in (mail.body, mail.html):
            assert "UNKNOWN" not in text and "Unknown" not in text and "None" not in text
    assert engineer.subject == "[HIGH][AI要約生成失敗] Win32/Agent.X"
    assert engineer.endpoint_name is None and engineer.detection_name == "Win32/Agent.X"


@pytest.mark.asyncio
async def test_reported_false_is_shown_but_absent_is_not(all_recipients):
    alert = NormalizedAlert(detection_name="Win32/Agent.X", threat_handled="false")
    _, engineer = await email_composer.compose_fallback_emails(_minimal_result(alert, ai=False))
    assert "- Threat handled: No" in engineer.body
    assert "Isolated" not in engineer.body


@pytest.mark.asyncio
async def test_endpoint_row_has_no_placeholder_for_a_missing_type(all_recipients):
    alert = NormalizedAlert(endpoint_name="HOST-01")
    _, engineer = await email_composer.compose_fallback_emails(_minimal_result(alert, ai=False))
    assert "- Endpoint: HOST-01\n" in engineer.body


@pytest.mark.asyncio
async def test_alert_with_no_recognized_fields_has_no_facts_section(all_recipients):
    internal, engineer = await email_composer.compose_fallback_emails(_minimal_result(NormalizedAlert(), ai=False))
    assert "ALERT FACTS" not in engineer.body and "【アラート情報】" not in internal.body
    # The subject never carries a placeholder for the missing names.
    assert engineer.subject == "[HIGH][AI要約生成失敗] cid-min"


@pytest.mark.asyncio
async def test_subjects_use_only_the_reported_names(all_recipients):
    alert = NormalizedAlert(endpoint_name="HOST-01")
    emails = {e.notification_type: e for e in await email_composer.compose_emails(_minimal_result(alert))}
    assert emails["ENGINEER_EN"].subject == "[HIGH] HOST-01"
    assert emails["ENGINEER_EN"].detection_name is None


@pytest.mark.asyncio
async def test_empty_confirmation_list_adds_no_section(all_recipients):
    result = _minimal_result(NormalizedAlert(detection_name="Win32/Agent.X"), unknown_items=[])
    emails = {e.notification_type: e.body for e in await email_composer.compose_emails(result)}
    assert "NEEDS CONFIRMATION" not in emails["ENGINEER_EN"]
    assert "【要確認事項】" not in emails["INTERNAL_JA"] and "【要確認事項】" not in emails["CTHREE_JA"]
    for body in emails.values():
        assert "不明" not in body and "Unknown" not in body and "UNKNOWN" not in body


# --------------------------- outbox persistence ---------------------------

@pytest.fixture
def temp_outbox(tmp_path, monkeypatch):
    monkeypatch.setattr(email_outbox, "OUTBOX_DIR", str(tmp_path))
    monkeypatch.setattr(email_outbox, "OUTBOX_PATH", str(tmp_path / "outbox.json"))


@pytest.mark.asyncio
async def test_outbox_roundtrip_and_append(all_recipients, temp_outbox):
    assert await email_outbox.list_emails() == []

    await email_outbox.add_emails(await email_composer.compose_emails(_result()))
    assert len(await email_outbox.list_emails()) == 4

    second = _result()
    second.correlation_id = "cid-456"
    await email_outbox.add_emails(await email_composer.compose_emails(second))
    assert len(await email_outbox.list_emails()) == 8


@pytest.mark.asyncio
async def test_outbox_holds_only_pending_entries(all_recipients, temp_outbox):
    await email_outbox.add_emails(await email_composer.compose_emails(_result()))
    assert all(e["status"] == "PENDING" for e in await email_outbox.list_emails())


@pytest.mark.asyncio
async def test_remove_email_drops_only_the_target(all_recipients, temp_outbox):
    await email_outbox.add_emails(await email_composer.compose_emails(_result()))
    await email_outbox.remove_email("cid-123-CLIENT_JA")

    remaining = await email_outbox.list_emails()
    assert len(remaining) == 3
    assert "cid-123-CLIENT_JA" not in {e["email_id"] for e in remaining}


@pytest.mark.asyncio
async def test_add_empty_list_is_noop(temp_outbox):
    await email_outbox.add_emails([])
    assert await email_outbox.list_emails() == []


@pytest.mark.asyncio
async def test_corrupt_outbox_file_is_recovered(all_recipients, temp_outbox):
    with open(email_outbox.OUTBOX_PATH, "w") as f:
        f.write("{ not valid json")

    await email_outbox.add_emails(await email_composer.compose_emails(_result()))
    assert len(await email_outbox.list_emails()) == 4


def test_mail_handoff_includes_email_id_for_idempotency():
    from src.models.email_message import EmailMessage
    from src.services.email_delivery.eset_mail import EsetMailProvider

    message = EmailMessage(
        email_id="cid-123-CLIENT_JA",
        correlation_id="cid-123",
        notification_type="CLIENT_JA",
        to=["client@example.com"],
        subject="[HIGH] Win32/Example.A — HOST-01",
        body="body",
        risk_level="HIGH",
        endpoint_name="HOST-01",
        detection_name="Win32/Example.A",
        created_at="2026-01-01T00:00:00Z",
    )

    payload = {
        "to": message.to,
        "subject": message.subject,
        "body": message.body,
        "email_id": message.email_id,
    }
    body_bytes, headers = EsetMailProvider(
        url="https://example.test/api/send",
        api_key="key",
        api_secret="secret",
        security_mode="api-key-only",
        timeout=15,
    ).build_request(payload)

    assert json.loads(body_bytes.decode("utf-8"))["email_id"] == "cid-123-CLIENT_JA"
    assert headers["X-API-Key"] == "key"


def test_default_email_timeout_is_longer_than_the_flaky_15s_window():
    from src.services.email_delivery.eset_mail import EsetMailProvider

    provider = EsetMailProvider(
        url="https://example.test/api/send",
        api_key="key",
        api_secret="secret",
        security_mode="api-key-only",
    )

    assert provider.timeout > 15


# --------------------------- layout ---------------------------

@pytest.mark.asyncio
async def test_every_email_has_an_html_version_with_its_content(all_recipients):
    for mail in await email_composer.compose_emails(_result()):
        assert mail.html.startswith("<!DOCTYPE html>")
        assert "HIGH" in mail.html
        if mail.notification_type != "CLIENT_JA":  # the client email carries no internal IDs
            assert "cid-123" in mail.html
    client = next(m for m in await email_composer.compose_emails(_result()) if m.notification_type == "CLIENT_JA")
    assert "お世話になっております。確認事項がございます。" in client.html
    assert 'lang="ja"' in client.html


@pytest.mark.asyncio
async def test_html_escapes_alert_values(all_recipients):
    alert = NormalizedAlert(detection_name="<script>alert(1)</script>", endpoint_name="H&ST")
    for mail in await email_composer.compose_fallback_emails(_minimal_result(alert, ai=False)):
        assert "<script>" not in mail.html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in mail.html and "H&amp;ST" in mail.html


@pytest.mark.asyncio
async def test_indicators_are_defanged(all_recipients):
    alert = NormalizedAlert(detection_name="X", url="http://evil.example/a.b", domain="evil.example",
                            ip_address="185.220.101.5")
    _, engineer = await email_composer.compose_fallback_emails(_minimal_result(alert, ai=False))
    assert "- URL: hxxp://evil[.]example/a.b" in engineer.body
    assert "- Domain: evil[.]example" in engineer.body
    assert "- IP: 185.220.101[.]5" in engineer.body
    assert "http://evil.example" not in engineer.html


def test_mail_handoff_sends_the_html_version():
    from src.models.email_message import EmailMessage
    from src.services.email_delivery.eset_mail import EsetMailProvider

    provider = EsetMailProvider(url="https://example.test/api/send", api_key="key",
                                api_secret="secret", security_mode="api-key-only")
    base = dict(email_id="e1", correlation_id="c", notification_type="ENGINEER_EN", to=["a@example.com"],
                subject="s", body="plain", risk_level="HIGH", created_at="2026-01-01T00:00:00Z")
    with_html = provider.build_payload(EmailMessage(**base, html="<!DOCTYPE html><p>x</p>"))
    assert with_html["html"] == "<!DOCTYPE html><p>x</p>" and "body" not in with_html
    legacy = provider.build_payload(EmailMessage(**base))
    assert legacy["body"] == "plain" and "html" not in legacy
