import pytest
from src.models.email_message import EmailMessage
from src.storage import delivery_store


def _message(email_id: str, correlation_id: str) -> EmailMessage:
    return EmailMessage(
        email_id=email_id,
        correlation_id=correlation_id,
        notification_type="CLIENT_JA",
        to=["a@example.com"],
        subject="s",
        body="b",
        risk_level="HIGH",
        endpoint_name="HOST-01",
        detection_name="Test.Detection",
        created_at="2026-01-01T00:00:00Z",
    )


@pytest.mark.asyncio
async def test_list_deliveries_filters_by_correlation_id():
    """
    Backs the Pipeline Flow EMAIL/SEND stage detail and the alert detail modal:
    both need "this alert's own emails", not the full handoff history.
    """
    await delivery_store.record_pending(_message("email-a-1", "corr-a"))
    await delivery_store.record_pending(_message("email-b-1", "corr-b"))
    await delivery_store.record_pending(_message("email-a-2", "corr-a"))

    rows = await delivery_store.list_deliveries(correlation_id="corr-a")
    assert {r["email_id"] for r in rows} == {"email-a-1", "email-a-2"}
    assert all(r["correlation_id"] == "corr-a" for r in rows)


@pytest.mark.asyncio
async def test_list_deliveries_correlation_id_and_status_combine():
    await delivery_store.record_pending(_message("email-c-1", "corr-c"))
    await delivery_store.record_attempt(
        "email-c-1", status=delivery_store.ACCEPTED, remote_id="99", error=None,
    )
    await delivery_store.record_pending(_message("email-c-2", "corr-c"))

    accepted = await delivery_store.list_deliveries(correlation_id="corr-c", status=delivery_store.ACCEPTED)
    assert [r["email_id"] for r in accepted] == ["email-c-1"]


@pytest.mark.asyncio
async def test_list_deliveries_unknown_correlation_id_returns_empty():
    rows = await delivery_store.list_deliveries(correlation_id="does-not-exist")
    assert rows == []
