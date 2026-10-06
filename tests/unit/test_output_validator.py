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


def test_simplified_chinese_characters_are_rejected():
    # 检 / 测 / 应 are simplified-Chinese forms of 検 / 測 / 応 — never valid Japanese.
    output = sample_output("HIGH", alert_summary_ja="ESETが脅威を检测しました。対应をお願いします。")
    issues = validate_ai_output(output, "HIGH")
    assert "non_japanese_characters: alert_summary_ja contains 检测应" in issues


def test_chinese_characters_in_list_fields_are_rejected():
    output = sample_output("HIGH", recommended_initial_actions_ja=["端末の状态を確認する"])
    assert any(i.startswith("non_japanese_characters: recommended_initial_actions_ja")
               for i in validate_ai_output(output, "HIGH"))


def test_ordinary_japanese_kanji_pass():
    output = sample_output("HIGH", alert_summary_ja="髙橋様の端末で検出された脅威への対応状況を確認しています。")
    assert validate_ai_output(output, "HIGH") == []


def test_characters_quoted_verbatim_from_the_alert_are_allowed():
    # A host name or path from the alert is kept as-is, whatever its script.
    output = sample_output("HIGH", alert_summary_ja="端末「财务-PC」で脅威が検出されました。")
    assert any(i.startswith("non_japanese_characters") for i in validate_ai_output(output, "HIGH"))
    assert validate_ai_output(output, "HIGH", source_text='{"endpoint_name": "财务-PC"}') == []
