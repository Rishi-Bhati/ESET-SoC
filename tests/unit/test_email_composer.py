import pytest
from src.config import settings
from src.models.ai_output import (
    AIOutput, ClientNotificationJa, CThreeNotificationJa,
    InternalNotificationJa, EngineerNotificationEn,
)
from src.models.normalized_alert import NormalizedAlert
from src.models.pipeline_result import PipelineResult
from src.services import email_composer, email_outbox


def _ai_output(risk="HIGH"):
    return AIOutput(
        risk_level=risk,
        client_notification_ja=ClientNotificationJa(
            summary="要約", current_status="対応中", required_confirmation="確認事項"),
        cthree_notification_ja=CThreeNotificationJa(
            summary="要約", assessment="評価", front_office_notes="連絡", draft_client_response="下書き"),
        internal_notification_ja=InternalNotificationJa(
            summary="要約", assessment="評価", recommended_actions=["対応1", "対応2"], draft_client_response="下書き"),
        engineer_notification_en=EngineerNotificationEn(
            alert_summary="Summary", assessment="Assessment",
            confirmed_information=["c1"], unknown_information=["u1"],
            investigation_items=["i1"], recommended_actions=["a1"],
            draft_client_response="Draft"),
    )


def _result(status="SUCCESS", ai=True, risk="HIGH"):
    return PipelineResult(
        correlation_id="cid-123", source="WEBHOOK",
        received_at="2026-01-01T00:00:00Z", processed_at="2026-01-01T00:00:05Z",
        pipeline_status=status,
        normalized_alert=NormalizedAlert(
            detection_name="Win32/Example.A", endpoint_name="HOST-01", severity=risk),
        risk_level=risk, risk_rationale="because",
        ai_output=_ai_output(risk) if ai else None,
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
    emails = await email_composer.compose_emails(_result(risk="CRITICAL"))
    assert all(e.subject == "[CRITICAL] Win32/Example.A — HOST-01" for e in emails)


@pytest.mark.asyncio
async def test_multiple_recipients_are_split(all_recipients):
    emails = await email_composer.compose_emails(_result())
    cthree = next(e for e in emails if e.notification_type == "CTHREE_JA")
    assert cthree.to == ["a@example.com", "b@example.com"]


@pytest.mark.asyncio
async def test_bodies_contain_their_notification_content(all_recipients):
    emails = {e.notification_type: e.body for e in await email_composer.compose_emails(_result())}
    assert "確認事項" in emails["CLIENT_JA"]
    assert "下書き" in emails["CTHREE_JA"]
    assert "対応1" in emails["INTERNAL_JA"] and "対応2" in emails["INTERNAL_JA"]
    assert "Investigation Items" in emails["ENGINEER_EN"] and "i1" in emails["ENGINEER_EN"]


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
