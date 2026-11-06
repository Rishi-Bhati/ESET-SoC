"""
The client field allowlist (src/services/client_fields.py) — the only path by
which alert data reaches a client spreadsheet. These tests pin the exact key set
and prove that nothing internal leaks through any extractor.
"""
import json
from datetime import datetime, timezone

import pytest

from src.models.ai_output import AIOutput
from src.services.alert_catalog import AlertBundle
from src.services import client_fields
from src.services.client_fields import REGISTRY, WEEKLY_FIELDS, field_catalog, get_fields
from src.utils.jst_time import JST

# ---------------------------------------------------------------- the guard

# Adding, removing or renaming a client-visible field must be a deliberate,
# reviewed change: update this set AND re-check the never-expose rules.
EXPECTED_KEYS = [
    "alert_id", "eset_alert_id",
    "received_at_jst", "occurred_at_jst",
    "risk_level", "eset_severity", "detection_name", "endpoint_name", "endpoint_type", "os_name",
    "user_name", "action_taken", "threat_handled", "isolation_status", "object_type", "object_uri",
    "file_hash", "url", "ip_address", "domain", "raw_subject", "raw_content", "raw_alert_json",
    "ai_alert_summary_ja", "ai_risk_reason_ja", "ai_client_notification_ja",
    "ai_recommended_actions_ja", "ai_confirmation_items_ja",
    "engineer_recommendations",
]

# The only AIOutput fields a client may ever see. Any AIOutput field added later
# is treated as internal by the leak test below until it is deliberately allowed.
CLIENT_AI_FIELDS = {
    "alert_summary_ja", "risk_reason_ja", "client_notification_ja",
    "recommended_initial_actions_ja", "additional_confirmation_items_ja",
}

NORMALIZED_ALLOWED = (
    "alert_id", "severity", "detection_name", "endpoint_name", "endpoint_type", "os_name", "user_name",
    "action_taken", "threat_handled", "isolation_status", "object_type", "object_uri", "file_hash",
    "url", "ip_address", "domain", "raw_subject", "raw_content",
)


def test_registry_is_exactly_the_allowed_key_set():
    assert list(REGISTRY) == EXPECTED_KEYS
    assert len(set(EXPECTED_KEYS)) == len(EXPECTED_KEYS)


def test_weekly_fields_are_exactly_what_the_client_asked_for():
    assert WEEKLY_FIELDS == [
        "alert_id", "eset_alert_id", "received_at_jst", "occurred_at_jst", "risk_level",
        "detection_name", "endpoint_name", "action_taken", "threat_handled",
        "ai_alert_summary_ja", "ai_risk_reason_ja", "engineer_recommendations",
    ]
    assert all(k in REGISTRY for k in WEEKLY_FIELDS)


def test_every_field_has_labels_a_known_group_and_a_callable():
    for spec in REGISTRY.values():
        assert spec.label_ja.strip() and spec.label_en.strip(), spec.key
        assert spec.group in client_fields.GROUP_LABELS, spec.key
        assert callable(spec.extractor)
    assert {s.key for s in REGISTRY.values() if s.default_selected} >= {"alert_id", "risk_level", "detection_name"}
    assert client_fields.DEFAULT_FIELDS == [k for k in EXPECTED_KEYS if REGISTRY[k].default_selected]


def test_field_catalog_is_ui_metadata_only():
    catalog = field_catalog()
    assert [c["key"] for c in catalog] == EXPECTED_KEYS
    for entry in catalog:
        assert set(entry) == {"key", "label_ja", "label_en", "group", "default_selected"}
    json.dumps(catalog)              # serialisable for the API


def test_get_fields_keeps_order_and_rejects_unknown_keys():
    assert [s.key for s in get_fields(["risk_level", "alert_id"])] == ["risk_level", "alert_id"]
    with pytest.raises(ValueError, match="internal_summary_ja"):
        get_fields(["alert_id", "internal_summary_ja"])
    with pytest.raises(ValueError):
        get_fields(["ai_run"])
    with pytest.raises(ValueError):
        get_fields([["alert_id"]])
    with pytest.raises(ValueError):
        get_fields("alert_id")


# ---------------------------------------------------------- leak fixture

CREATED_AT = datetime(2026, 9, 20, 2, 5, 30, tzinfo=timezone.utc).timestamp()


def sentinel_bundle() -> tuple[AlertBundle, dict[str, str], list[str]]:
    """A bundle where every value holds a unique sentinel. Returns the bundle, the
    sentinel each allowed field must surface, and every sentinel that must never
    reach a client."""
    forbidden: list[str] = []

    def secret(name: str) -> str:
        value = f"SECRET_{name.upper()}_7f3a"
        forbidden.append(value)
        return value

    ai_output = {}
    for name, field in AIOutput.model_fields.items():
        is_list = "list" in str(field.annotation)
        if name in CLIENT_AI_FIELDS:
            ai_output[name] = [f"ALLOWED_AI_{name}_{i}" for i in (1, 2)] if is_list else f"ALLOWED_AI_{name}"
        else:
            ai_output[name] = [secret(f"ai_{name}_{i}") for i in (1, 2)] if is_list else secret(f"ai_{name}")

    normalized = {name: f"ALLOWED_NA_{name}" for name in NORMALIZED_ALLOWED}
    normalized.update({
        "occurred_at": "2026-09-20T02:05:00Z",
        "source": secret("na_source"),
        "event_type": secret("na_event_type"),
        "detection_uuid": secret("na_detection_uuid"),
        "target_uuid": secret("na_target_uuid"),
        "raw_payload": {"alert_id": "ALLOWED_RAW_ALERT", "note": "ALLOWED_RAW_NOTE"},
    })
    original = {"alert_id": "ALLOWED_RAW_ALERT", "detail": "ALLOWED_RAW_DETAIL"}

    result = {
        "correlation_id": "cid-0001",
        "source": secret("result_source"),
        "received_at": "2026-09-20T02:05:31+00:00",
        "processed_at": secret("processed_at"),
        "pipeline_status": secret("pipeline_status"),
        "normalized_alert": normalized,
        "risk_level": "HIGH",
        "risk_rationale": secret("risk_rationale"),
        "risk_factors": [{"rule": secret("rf_rule"), "effect": secret("rf_effect"), "detail": secret("rf_detail")}],
        "threat_intel": {
            "virustotal": {"status": secret("vt_status"), "permalink": secret("vt_permalink"),
                           "query": secret("vt_query"), "error": secret("vt_error")},
            "abuseipdb": {"status": secret("abuse_status"), "country_code": secret("abuse_cc"),
                          "query": secret("abuse_query"), "error": secret("abuse_error")},
            "mock_verdict": secret("mock_verdict"),
        },
        "ai_output": ai_output,
        "ai_run": {
            "provider": secret("provider"), "model": secret("model"), "prompt_version": secret("prompt"),
            "status": secret("ai_status"), "request_id": secret("request_id"), "response_id": secret("resp_id"),
            "trace_id": secret("trace_id"), "error": secret("ai_error"),
            "validation_issues": [secret("validation_issue")], "masked_fields": [secret("masked")],
            "usage": {"tokens": secret("usage")},
        },
        "notifications": [{"email_id": secret("email_id"), "notification_type": secret("ntype"),
                           "recipients": [secret("recipient") + "@example.com"], "kind": secret("kind")}],
        "email_deliveries": [{"subject": secret("delivery_subject"), "error": secret("delivery_error")}],
        "error": secret("result_error"),
        "result_path": "/srv/" + secret("server_path") + "/output/alerts/cid-0001.json",
    }
    job = {
        "correlation_id": "cid-0001",
        "source": secret("job_source"),
        "status": secret("job_status"),
        "raw_payload": {"alert_id": "ALLOWED_RAW_ALERT", "raw_payload": original},
        "created_at": CREATED_AT,
        "updated_at": CREATED_AT + 60,
        "error": secret("job_error"),
    }
    recommendations = [
        {"id": secret("rec_id_1"), "correlation_id": "cid-0001", "body": "ALLOWED_REC_SECOND",
         "author": "eng.b", "created_at": CREATED_AT + 7200, "retracted_at": None, "retracted_by": None,
         "retract_reason": None, "notification_email_id": secret("rec_email_1")},
        {"id": secret("rec_id_2"), "correlation_id": "cid-0001", "body": "ALLOWED_REC_FIRST",
         "author": "eng.a", "created_at": CREATED_AT + 3600, "retracted_at": None, "retracted_by": None,
         "retract_reason": None, "notification_email_id": None},
        # A retracted one must never reach a client even if a bundle wrongly carries it.
        {"id": secret("rec_id_3"), "correlation_id": "cid-0001", "body": secret("retracted_body"),
         "author": secret("retracted_author"), "created_at": CREATED_AT + 5000,
         "retracted_at": CREATED_AT + 5100, "retracted_by": secret("retracted_by"),
         "retract_reason": secret("retract_reason"), "notification_email_id": None},
    ]

    expected = {
        "alert_id": "cid-0001",
        "eset_alert_id": "ALLOWED_NA_alert_id",
        "received_at_jst": "2026-09-20 11:05:30",
        "occurred_at_jst": "2026-09-20 11:05:00",
        "risk_level": "HIGH",
        "eset_severity": "ALLOWED_NA_severity",
        "raw_alert_json": json.dumps(original, ensure_ascii=False),
        "ai_alert_summary_ja": "ALLOWED_AI_alert_summary_ja",
        "ai_risk_reason_ja": "ALLOWED_AI_risk_reason_ja",
        "ai_client_notification_ja": "ALLOWED_AI_client_notification_ja",
        "ai_recommended_actions_ja": "1. ALLOWED_AI_recommended_initial_actions_ja_1\n"
                                     "2. ALLOWED_AI_recommended_initial_actions_ja_2",
        "ai_confirmation_items_ja": "1. ALLOWED_AI_additional_confirmation_items_ja_1\n"
                                    "2. ALLOWED_AI_additional_confirmation_items_ja_2",
        "engineer_recommendations": "[2026-09-20 12:05 JST] eng.a: ALLOWED_REC_FIRST\n"
                                    "[2026-09-20 13:05 JST] eng.b: ALLOWED_REC_SECOND",
    }
    for name in NORMALIZED_ALLOWED:
        if name not in ("alert_id", "severity"):
            expected[name] = f"ALLOWED_NA_{name}"
    return AlertBundle(job=job, result=result, recommendations=recommendations), expected, forbidden


def test_every_aioutput_field_is_classified():
    # If AIOutput grows a field, the fixture marks it forbidden automatically;
    # this just proves the allowed names still exist on the model.
    assert CLIENT_AI_FIELDS <= set(AIOutput.model_fields)


def test_each_extractor_returns_exactly_its_own_value():
    bundle, expected, _ = sentinel_bundle()
    assert set(expected) == set(EXPECTED_KEYS)
    for key, spec in REGISTRY.items():
        assert spec.extractor(bundle) == expected[key], key


def test_no_internal_sentinel_reaches_any_extractor():
    bundle, _, forbidden = sentinel_bundle()
    assert len(forbidden) > 40
    output = "\n".join(str(spec.extractor(bundle)) for spec in REGISTRY.values())
    leaked = [s for s in forbidden if s in output]
    assert not leaked, f"internal data exposed: {leaked}"
    assert "SECRET_" not in output and "/srv/" not in output


# ---------------------------------------------------------- partial data

def test_partial_alert_where_the_ai_failed_gives_empty_ai_cells():
    bundle = AlertBundle(
        job={"correlation_id": "cid-p", "created_at": CREATED_AT, "raw_payload": {}},
        result={"correlation_id": "cid-p", "risk_level": "LOW", "pipeline_status": "PARTIAL",
                "normalized_alert": {"detection_name": "Eicar"}, "ai_output": None,
                "ai_run": {"status": "FAILED", "error": "timeout"}, "error": "AI generation failed"},
        recommendations=[],
    )
    values = {k: s.extractor(bundle) for k, s in REGISTRY.items()}
    assert values["detection_name"] == "Eicar" and values["risk_level"] == "LOW"
    for key in ("ai_alert_summary_ja", "ai_risk_reason_ja", "ai_client_notification_ja",
                "ai_recommended_actions_ja", "ai_confirmation_items_ja", "engineer_recommendations",
                "endpoint_name", "occurred_at_jst", "raw_alert_json"):
        assert values[key] == "", key


@pytest.mark.parametrize("bundle", [
    AlertBundle(job={}, result={}, recommendations=[]),
    AlertBundle(job=None, result=None, recommendations=None),
    AlertBundle(job={"created_at": "not a number", "raw_payload": "garbage"},
                result={"normalized_alert": "garbage", "ai_output": ["x"], "risk_level": {"a": 1}},
                recommendations=["garbage", {"created_at": None}]),
])
def test_extractors_never_raise_on_malformed_data(bundle):
    for key, spec in REGISTRY.items():
        assert isinstance(spec.extractor(bundle), str), key


def test_legacy_result_shapes_and_placeholders():
    bundle = AlertBundle(
        job={"correlation_id": "cid-l", "created_at": CREATED_AT,
             "raw_payload": {"subject": "TEST"}},
        result={
            "correlation_id": "cid-l", "risk_level": "MEDIUM",
            "normalized_alert": {"alert_id": "UNKNOWN", "endpoint_name": "UNKNOWN",
                                 "occurred_at": "UNKNOWN", "detection_name": "Firewall"},
            "ai_output": {"client_notification_ja": {"summary": "検知しました。", "current_status": "確認中です。",
                                                     "required_confirmation": "ご確認ください。"},
                          "internal_notification_ja": {"summary": "SECRET_INTERNAL"}},
        },
        recommendations=[],
    )
    values = {k: s.extractor(bundle) for k, s in REGISTRY.items()}
    assert values["eset_alert_id"] == values["endpoint_name"] == values["occurred_at_jst"] == ""
    assert values["ai_client_notification_ja"] == "検知しました。\n確認中です。\nご確認ください。"
    assert values["raw_alert_json"] == '{"subject": "TEST"}'      # no inner payload: the stored one
    assert "SECRET_INTERNAL" not in "".join(values.values())


def test_times_are_jst_and_an_unzoned_time_is_never_guessed():
    def occurred(value):
        b = AlertBundle(job={}, result={"normalized_alert": {"occurred_at": value}}, recommendations=[])
        return REGISTRY["occurred_at_jst"].extractor(b)
    assert occurred("2026-09-20T23:30:00+00:00") == "2026-09-21 08:30:00"
    assert occurred("2026/09/20 23:30:00").startswith("2026/09/20 23:30:00 (")
    assert "not converted" in occurred("2026/09/20 23:30:00")

    # Without a job row, the result file's receipt time is used.
    b = AlertBundle(job={}, result={"received_at": "2026-09-20T15:00:00+00:00"}, recommendations=[])
    assert REGISTRY["received_at_jst"].extractor(b) == "2026-09-21 00:00:00"
    expected = datetime.fromtimestamp(CREATED_AT, tz=JST).strftime("%Y-%m-%d %H:%M:%S")
    b = AlertBundle(job={"created_at": CREATED_AT}, result={}, recommendations=[])
    assert REGISTRY["received_at_jst"].extractor(b) == expected


def test_retracted_recommendations_are_excluded_on_the_client_path():
    bundle, _, _ = sentinel_bundle()
    text = REGISTRY["engineer_recommendations"].extractor(bundle)
    assert text.splitlines()[-1].endswith("ALLOWED_REC_SECOND"), "newest last"
    assert "SECRET_RETRACTED" not in text and len(text.splitlines()) == 2
