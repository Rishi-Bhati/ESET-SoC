"""
Structured-output schemas built from AIOutput.

OpenAI strict mode rejects a schema unless every object lists all of its
properties in `required` and sets additionalProperties=false; Gemini rejects
$ref/$defs/additionalProperties and its SDK drops `required` when handed a
Pydantic class. Both builders must also pin risk_level to one value.
"""
import json
import pytest
from src.models.ai_output import AIOutput
from src.services.ai.schema_builder import build_gemini_schema, build_strict_json_schema

CLIENT_FIELDS = {
    "risk_level", "alert_summary_ja", "risk_reason_ja", "client_notification_ja",
    "internal_summary_ja", "engineer_summary_en", "recommended_initial_actions_ja",
    "additional_confirmation_items_ja", "unknown_items", "backlog_comment_ja",
    "email_subject_ja", "email_body_ja",
}


def test_output_fields_are_exactly_the_clients_field_list():
    assert set(AIOutput.model_fields) == CLIENT_FIELDS


def test_strict_schema_requires_every_property_and_forbids_extras():
    schema = build_strict_json_schema(AIOutput)
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"]) == CLIENT_FIELDS
    raw = json.dumps(schema)
    assert "$ref" not in raw and "$defs" not in raw and '"title"' not in raw and '"default"' not in raw


def test_strict_schema_risk_level_is_an_enum_and_can_be_pinned():
    assert build_strict_json_schema(AIOutput)["properties"]["risk_level"]["enum"] == [
        "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    pinned = build_strict_json_schema(AIOutput, pin={"risk_level": ["MEDIUM"]})
    assert pinned["properties"]["risk_level"]["enum"] == ["MEDIUM"]


def test_list_fields_keep_item_types():
    for build in (build_strict_json_schema, build_gemini_schema):
        prop = build(AIOutput)["properties"]["unknown_items"]
        assert prop["type"] == "array" and prop["items"]["type"] == "string"


def test_pinning_an_unknown_property_is_an_error():
    with pytest.raises(KeyError):
        build_strict_json_schema(AIOutput, pin={"not_a_field": ["x"]})


def test_gemini_schema_keeps_required_and_strips_unsupported_keys():
    schema = build_gemini_schema(AIOutput, pin={"risk_level": ["HIGH"]})
    assert set(schema["required"]) == CLIENT_FIELDS
    assert schema["properties"]["risk_level"]["enum"] == ["HIGH"]
    raw = json.dumps(schema)
    assert "$ref" not in raw and "additionalProperties" not in raw and '"title"' not in raw


def test_gemini_sdk_generation_config_preserves_required():
    genai = pytest.importorskip("google.generativeai")
    cfg = genai.types.GenerationConfig(
        response_mime_type="application/json",
        response_schema=build_gemini_schema(AIOutput),
        max_output_tokens=8192,
    )
    assert "required" in str(cfg.response_schema)
