"""
Regression guard for the Gemini structured-output bug.

The SDK's own Pydantic->Schema converter drops every `required` array, which let
Gemini return objects like {"risk_level": "HIGH"} and pushed every alert down the
PARTIAL path. build_gemini_schema must preserve `required` at every level.
"""
import google.generativeai as genai
from src.models.ai_output import AIOutput
from src.services.ai.schema_builder import build_gemini_schema


def test_required_preserved_at_top_level():
    schema = build_gemini_schema(AIOutput)
    assert set(schema["required"]) == {
        "risk_level",
        "client_notification_ja",
        "cthree_notification_ja",
        "internal_notification_ja",
        "engineer_notification_en",
    }


def test_required_preserved_in_nested_models():
    props = build_gemini_schema(AIOutput)["properties"]

    assert set(props["client_notification_ja"]["required"]) == {
        "summary", "current_status", "required_confirmation"}
    assert set(props["cthree_notification_ja"]["required"]) == {
        "summary", "assessment", "front_office_notes", "draft_client_response"}
    assert set(props["internal_notification_ja"]["required"]) == {
        "summary", "assessment", "recommended_actions", "draft_client_response"}
    assert set(props["engineer_notification_en"]["required"]) == {
        "alert_summary", "assessment", "confirmed_information", "unknown_information",
        "investigation_items", "recommended_actions", "draft_client_response"}


def test_refs_are_inlined_and_unsupported_keys_stripped():
    import json
    raw = json.dumps(build_gemini_schema(AIOutput))
    # Gemini rejects JSON-Schema references and unknown keywords
    assert "$ref" not in raw
    assert "$defs" not in raw
    assert "additionalProperties" not in raw
    assert '"title"' not in raw


def test_list_fields_keep_item_types():
    props = build_gemini_schema(AIOutput)["properties"]
    actions = props["internal_notification_ja"]["properties"]["recommended_actions"]
    assert actions["type"] == "array"
    assert actions["items"]["type"] == "string"


def test_sdk_generation_config_preserves_required():
    """The schema must still carry `required` after the SDK ingests it."""
    cfg = genai.types.GenerationConfig(
        response_mime_type="application/json",
        response_schema=build_gemini_schema(AIOutput),
        temperature=0.1,
        max_output_tokens=8192,
    )
    assert "required" in str(cfg.response_schema)


def test_sdk_native_conversion_still_drops_required():
    """
    Documents *why* build_gemini_schema exists. If a future SDK version fixes this,
    this test fails and the workaround can be reconsidered.
    """
    import google.generativeai.types.content_types as ct
    import json
    native = json.dumps(ct._schema_for_class(AIOutput), default=str)
    assert '"required"' not in native
