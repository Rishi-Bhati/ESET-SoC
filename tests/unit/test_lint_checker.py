import pytest
from src.services.ai.lint_checker import find_prohibited_phrases, lint_ai_output, LintFailureException
from ai_fakes import sample_output


def test_lint_pass():
    lint_ai_output(sample_output("MEDIUM"))


def test_lint_fail_english():
    output = sample_output(engineer_summary_en="We have an infection confirmed on host 01.")
    with pytest.raises(LintFailureException) as exc_info:
        lint_ai_output(output)
    assert "infection confirmed" in exc_info.value.found_phrases


def test_lint_fail_japanese():
    output = sample_output(client_notification_ja="端末での感染を確認しました。")
    with pytest.raises(LintFailureException) as exc_info:
        lint_ai_output(output)
    assert "感染を確認しました" in exc_info.value.found_phrases


@pytest.mark.parametrize("text", [
    "The environment is safe and no further action is required.",
    "現在、環境は安全です。",
    "情報漏えいが確認されました。",
])
def test_safety_and_leakage_claims_are_blocked(text):
    assert find_prohibited_phrases(sample_output(internal_summary_ja=text))


@pytest.mark.parametrize("text", [
    "端末の感染有無を確認してください。",                 # a confirmation request, not a claim
    "現時点で感染が確認されたわけではありません。",        # explicitly negated
    "No infection confirmed at this time; needs confirmation.",
    "Whether data was exfiltrated is Unknown.",
])
def test_cautious_wording_is_not_blocked(text):
    assert find_prohibited_phrases(sample_output(internal_summary_ja=text)) == []


def test_list_fields_are_scanned():
    output = sample_output(recommended_initial_actions_ja=["確認", "隔離成功を報告する"])
    assert "隔離成功" in find_prohibited_phrases(output)
