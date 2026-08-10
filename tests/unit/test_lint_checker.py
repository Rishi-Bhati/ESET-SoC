import pytest
from src.models.ai_output import AIOutput, ClientNotificationJa, CThreeNotificationJa, InternalNotificationJa, EngineerNotificationEn
from src.services.ai.lint_checker import lint_ai_output, LintFailureException

def get_base_ai_output() -> AIOutput:
    return AIOutput(
        risk_level="MEDIUM",
        client_notification_ja=ClientNotificationJa(
            summary="通知の要約",
            current_status="現在の状況",
            required_confirmation="特になし"
        ),
        cthree_notification_ja=CThreeNotificationJa(
            summary="要約",
            assessment="アセスメント",
            front_office_notes="メモ",
            draft_client_response="返信案"
        ),
        internal_notification_ja=InternalNotificationJa(
            summary="要約",
            assessment="アセスメント",
            recommended_actions=["対応1"],
            draft_client_response="返信案"
        ),
        engineer_notification_en=EngineerNotificationEn(
            alert_summary="Alert summary",
            assessment="Assessment",
            confirmed_information=["Fact 1"],
            unknown_information=["None"],
            investigation_items=["Item 1"],
            recommended_actions=["Action 1"],
            draft_client_response="Draft response"
        )
    )

def test_lint_pass():
    output = get_base_ai_output()
    # Should not raise exception
    lint_ai_output(output)

def test_lint_fail_english():
    output = get_base_ai_output()
    # Inject prohibited phrase in English
    output.engineer_notification_en.assessment = "We have an infection confirmed on host 01."
    
    with pytest.raises(LintFailureException) as exc_info:
        lint_ai_output(output)
    assert "infection confirmed" in exc_info.value.found_phrases

def test_lint_fail_japanese():
    output = get_base_ai_output()
    # Inject prohibited phrase in Japanese
    output.client_notification_ja.current_status = "端末での感染を確認しました。"
    
    with pytest.raises(LintFailureException) as exc_info:
        lint_ai_output(output)
    assert "感染を確認" in exc_info.value.found_phrases
