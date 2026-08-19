"""
Tests the AI Visibility instrumentation layer directly (src/services/ai/trace_recorder.py,
src/storage/ai_trace_store.py) against the real temp SQLite database set up by
tests/conftest.py. End-to-end coverage through the actual Gemini call path and the
dashboard API lives in tests/integration/test_ai_visibility_api.py.
"""
import pytest
from src.services.ai import trace_recorder
from src.storage import ai_trace_store


@pytest.mark.asyncio
async def test_full_trace_lifecycle_persists_and_redacts():
    trace = await trace_recorder.start_trace(
        correlation_id="trace-test-1", component="pipeline.ai_generate",
        action="generate_bilingual_notifications", provider="google_gemini",
        model="gemini-3.1-flash-lite", objective="test objective",
    )
    assert trace is not None
    assert trace.status == "STARTED"

    await trace_recorder.record_input(
        trace,
        data_categories=[],
        raw_input={"normalized_alert": {"raw_content": "password: hunter2live!", "endpoint_name": "HOST-1"}},
        context_notes=["note one"],
    )
    assert "hunter2live" not in str(trace.input_redacted)
    assert trace.input_redacted["normalized_alert"]["endpoint_name"] == "HOST-1"
    assert any(f.category == "GENERIC_SECRET_ASSIGNMENT" for f in trace.security_findings)

    await trace_recorder.record_config(trace, {"temperature": 0.1})
    assert trace.config == {"temperature": 0.1}

    call = await trace_recorder.record_external_call_start(
        trace, service="Google Generative AI (Gemini)", domain="generativelanguage.googleapis.com",
        purpose="test", initiated_by="ai_provider_request",
    )
    assert call is not None
    await trace_recorder.record_external_call_end(trace, call, status="OK")
    assert call.status == "OK"
    assert call.latency_ms is not None

    await trace_recorder.record_output(trace, {"risk_level": "HIGH"}, usage={"total_tokens": 42})
    assert trace.output_redacted == {"risk_level": "HIGH"}
    assert trace.usage == {"total_tokens": 42}

    await trace_recorder.build_decision_summary(
        trace, task="t", context_used=["a"], decision="d", confidence="none", policy_checks=["p"],
    )
    assert "chain-of-thought" in trace.decision_summary["note"]

    await trace_recorder.complete_trace(trace, status="SUCCESS", risk="SENSITIVE_DATA_DETECTED")
    assert trace.status == "SUCCESS"
    assert trace.external_data_transfer is True  # had an ai_provider_request external call

    stored = await ai_trace_store.get_trace(trace.trace_id)
    assert stored is not None
    assert stored["status"] == "SUCCESS"
    assert "hunter2live" not in str(stored)
    assert stored["external_data_transfer"] is True
    assert len(stored["security_findings"]) >= 1


@pytest.mark.asyncio
async def test_none_trace_is_a_safe_noop_everywhere():
    # Simulates start_trace() itself having failed. Every downstream call must
    # tolerate trace=None without raising, so a bug in observability can never break
    # the actual AI call it wraps.
    await trace_recorder.record_event(None, "x", "y")
    await trace_recorder.record_input(None, data_categories=[], raw_input={})
    await trace_recorder.record_config(None, {})
    call = await trace_recorder.record_external_call_start(
        None, service="s", domain="d", purpose="p", initiated_by="ai_provider_request")
    assert call is None
    await trace_recorder.record_external_call_end(None, None, status="OK")
    await trace_recorder.record_retry(None, 1, 1.0, "err")
    await trace_recorder.record_output(None, {"a": 1})
    await trace_recorder.build_decision_summary(
        None, task="t", context_used=[], decision="d", confidence="c", policy_checks=[])
    await trace_recorder.complete_trace(None, status="SUCCESS", risk="SAFE")
    # reaching this line without an exception is the assertion


@pytest.mark.asyncio
async def test_attach_policy_check_flips_status_to_blocked():
    trace = await trace_recorder.start_trace(
        correlation_id="trace-test-policy", component="pipeline.ai_generate",
        action="generate_bilingual_notifications", provider="google_gemini",
        model="gemini-3.1-flash-lite",
    )
    await trace_recorder.complete_trace(trace, status="SUCCESS", risk="SAFE")

    await trace_recorder.attach_policy_check(
        "trace-test-policy", name="Prohibited-phrase safety lint", passed=False,
        detail="Blocked: found 'infection confirmed'",
    )

    stored = await ai_trace_store.get_trace(trace.trace_id)
    assert stored["status"] == "BLOCKED"
    assert stored["risk"] == "BLOCKED"
    assert any(e["type"] == "policy_check" for e in stored["events"])
    assert any(f["category"] == "POLICY_VIOLATION" for f in stored["security_findings"])


@pytest.mark.asyncio
async def test_attach_policy_check_on_unknown_correlation_is_a_noop():
    # Must not raise even if no trace exists for this correlation_id.
    await trace_recorder.attach_policy_check("no-such-correlation-id", name="x", passed=True, detail="d")


@pytest.mark.asyncio
async def test_manual_redaction_permanently_overwrites_and_cannot_be_recovered():
    trace = await trace_recorder.start_trace(
        correlation_id="trace-test-manual-redact", component="pipeline.ai_generate",
        action="generate_bilingual_notifications", provider="google_gemini",
        model="gemini-3.1-flash-lite",
    )
    await trace_recorder.record_input(
        trace, data_categories=[],
        raw_input={"normalized_alert": {"raw_content": "the internal codename is PROJECT-FALCON"}},
    )
    await trace_recorder.complete_trace(trace, status="SUCCESS", risk="SAFE")

    stored = await ai_trace_store.get_trace(trace.trace_id)
    text = stored["input_redacted"]["normalized_alert"]["raw_content"]
    start = text.index("PROJECT-FALCON")
    end = start + len("PROJECT-FALCON")

    updated = await ai_trace_store.apply_manual_redaction(
        trace.trace_id, "input_redacted.normalized_alert.raw_content", start, end)
    assert "PROJECT-FALCON" not in updated["input_redacted"]["normalized_alert"]["raw_content"]
    assert "[REDACTED]" in updated["input_redacted"]["normalized_alert"]["raw_content"]
    assert updated["manual_redactions"][0]["field_path"] == "input_redacted.normalized_alert.raw_content"

    refetched = await ai_trace_store.get_trace(trace.trace_id)
    assert "PROJECT-FALCON" not in str(refetched)


@pytest.mark.asyncio
async def test_manual_redaction_rejects_out_of_bounds_range():
    trace = await trace_recorder.start_trace(
        correlation_id="trace-test-bounds", component="pipeline.ai_generate",
        action="generate_bilingual_notifications", provider="google_gemini",
        model="gemini-3.1-flash-lite",
    )
    await trace_recorder.record_input(
        trace, data_categories=[], raw_input={"normalized_alert": {"raw_content": "short"}})
    await trace_recorder.complete_trace(trace, status="SUCCESS", risk="SAFE")

    with pytest.raises(ValueError):
        await ai_trace_store.apply_manual_redaction(
            trace.trace_id, "input_redacted.normalized_alert.raw_content", 0, 9999)


@pytest.mark.asyncio
async def test_manual_redaction_rejects_non_text_field():
    trace = await trace_recorder.start_trace(
        correlation_id="trace-test-nontext", component="pipeline.ai_generate",
        action="generate_bilingual_notifications", provider="google_gemini",
        model="gemini-3.1-flash-lite",
    )
    await trace_recorder.complete_trace(trace, status="SUCCESS", risk="SAFE")
    with pytest.raises(ValueError):
        await ai_trace_store.apply_manual_redaction(trace.trace_id, "started_at", 0, 1)


@pytest.mark.asyncio
async def test_manual_redaction_rejects_unknown_trace():
    with pytest.raises(ValueError):
        await ai_trace_store.apply_manual_redaction("no-such-trace-id", "a.b", 0, 1)


def test_build_alert_data_categories_never_includes_raw_payload():
    from src.models.normalized_alert import NormalizedAlert
    from src.models.threat_intel import ThreatIntelResult

    alert = NormalizedAlert(
        detection_name="Win32/Test", endpoint_name="HOST-1", user_name="alice",
        raw_payload={"secret_internal_field": "should never appear"},
    )
    cats = trace_recorder.build_alert_data_categories(alert, "HIGH", ThreatIntelResult())
    fields = {c.field for c in cats}
    assert "normalized_alert.raw_payload" not in fields
    assert "normalized_alert.detection_name" in fields
    # user_name is categorized as personal information, not silently dropped or mislabeled
    user_cat = next(c for c in cats if c.field == "normalized_alert.user_name")
    assert user_cat.category == "Personal information"
