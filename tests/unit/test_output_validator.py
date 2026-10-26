import pytest
from src.services.ai.output_validator import validate_ai_output
from ai_fakes import sample_output


def test_clean_output_passes():
    assert validate_ai_output(sample_output("HIGH"), "HIGH") == []


def test_a_different_risk_level_is_rejected():
    issues = validate_ai_output(sample_output("LOW"), "HIGH")
    assert any(i.startswith("risk_level_modified") for i in issues)


def test_a_contradicting_bracketed_label_in_the_text_is_rejected():
    output = sample_output("HIGH", email_subject_ja="【LOW】セキュリティアラートのご報告")
    assert any("contradicting_risk_label: email_subject_ja" in i for i in validate_ai_output(output, "HIGH"))


def test_mentioning_the_eset_severity_in_prose_is_fine():
    output = sample_output("MEDIUM", risk_reason_ja="ESETの深刻度はHIGHですが、脅威は処理済みです。")
    assert validate_ai_output(output, "MEDIUM") == []


def test_empty_sections_are_rejected():
    output = sample_output("HIGH", email_body_ja="  ", recommended_initial_actions_ja=[" "])
    issues = validate_ai_output(output, "HIGH")
    assert "empty_field: email_body_ja" in issues
    assert "empty_list: recommended_initial_actions_ja" in issues


def test_unknown_items_may_be_empty():
    assert validate_ai_output(sample_output("HIGH", unknown_items=[]), "HIGH") == []


def test_prohibited_claims_are_rejected():
    output = sample_output("HIGH", client_notification_ja="ご安心ください。環境は安全です。")
    assert "prohibited_phrase: 環境は安全です" in validate_ai_output(output, "HIGH")


# ------------------------------ times in JST ------------------------------

@pytest.mark.parametrize("field, text", [
    ("email_body_ja", "・検知日時: 2026年9月20日 03:05（UTC）"),
    ("email_body_ja", "検知日時: 2026-09-20T03:05:00Z"),
    ("client_notification_ja", "2026-09-20 03:05:00+00:00 に検知されました。"),
    ("engineer_summary_en", "Detected at 03:05 UTC on HOST-01."),
    ("engineer_summary_en", "Detected at UTC 03:05."),
    ("internal_summary_ja", "検知日時（GMT）: 2026-09-20 03:05"),
    ("internal_summary_ja", "協定世界時で3時5分に検知。"),
    ("alert_summary_ja", "2026-09-20T08:35:00+05:30 に検知。"),
])
def test_a_time_in_another_zone_is_rejected(field, text):
    issues = validate_ai_output(sample_output("HIGH", **{field: text}), "HIGH")
    assert any(i.startswith(f"non_jst_time: {field}") for i in issues), issues


def test_a_time_in_a_list_field_is_checked_too():
    output = sample_output("HIGH", recommended_initial_actions_ja=["03:05 UTC 以降のログを確認する"])
    assert any("non_jst_time: recommended_initial_actions_ja" in i for i in validate_ai_output(output, "HIGH"))


@pytest.mark.parametrize("text", [
    "検知日時: 2026年09月20日 12:05:00 JST",
    "Detected at 2026-09-20 12:05:00 JST.",
    "2026-09-20T12:05:00+09:00 に検知。",
    "12:05 (UTC+9) に検知。",
    "Endpoint UTC-SRV-01 reported the detection.",   # a host name, not a time zone
    "GMT-Updater.exe が検知されました。",
])
def test_jst_times_and_zone_like_names_pass(text):
    assert validate_ai_output(sample_output("HIGH", email_body_ja=text), "HIGH") == []


def test_copying_an_unconverted_detection_time_verbatim_is_allowed():
    # The raw value could not be converted and contains "UTC" itself; the model
    # was told to copy it exactly, so that copy must not block the output.
    unconverted = "2026-09-20T03:05:00+05:30 UTC（日時形式不明・JST未換算）"
    output = sample_output("HIGH", email_body_ja=f"検知日時: {unconverted}")
    assert validate_ai_output(output, "HIGH", allowed_times=(unconverted,)) == []
    assert validate_ai_output(output, "HIGH") != []
