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
