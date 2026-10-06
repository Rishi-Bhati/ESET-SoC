"""
Post-generation validation of AI output, run before anything is sent to anyone.

Schema conformance (field names, types, no extra keys, risk_level one of the
four values) is already enforced by the provider's structured-output mode and
by Pydantic when the response is parsed. This module checks what a schema
cannot express:

  * risk_level is exactly the level the rule engine computed — the AI may not
    modify it (client requirement #1);
  * no bracketed risk label in the text contradicts it (e.g. a subject line
    reading 【LOW】 on a HIGH alert);
  * every section the notifications are built from is actually filled in;
  * no prohibited claim (confirmed infection/leakage/compromise, "safe") —
    see src/services/ai/lint_checker.py;
  * no Chinese characters: the Japanese text must be written in hiragana,
    katakana and Japanese kanji only. Models writing Japanese occasionally slip
    in a simplified-Chinese form (检 for 検, 应 for 応), which a Japanese client
    reads as a typo at best. A kanji is accepted when it exists in the Japanese
    character set (CP932: JIS X 0208 plus the NEC/IBM extensions used in
    Japanese names); anything else is a Chinese-only form. A character that
    already appears in the alert itself (a file path or host name quoted
    verbatim) is allowed through, since the model was told to keep those as-is.

Any issue blocks the output: the alert is still recorded, and the team gets
the deterministic "AI summary unavailable" notice instead (src/services/email_composer.py).
"""
import re
from src.models.ai_output import AIOutput, RISK_LEVELS
from src.services.ai.lint_checker import find_prohibited_phrases

_REQUIRED_TEXT_FIELDS = (
    "alert_summary_ja", "risk_reason_ja", "client_notification_ja", "internal_summary_ja",
    "engineer_summary_en", "backlog_comment_ja", "email_subject_ja", "email_body_ja",
)
_REQUIRED_LIST_FIELDS = ("recommended_initial_actions_ja", "additional_confirmation_items_ja")
_BRACKETED_LEVEL_RE = re.compile(r"[【\[]\s*(" + "|".join(RISK_LEVELS) + r")\s*[】\]]", re.IGNORECASE)
# CJK Unified Ideographs (+ Extension A, compatibility ideographs, and the
# supplementary-plane extensions).
_IDEOGRAPH_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U0003ffff]")


def _is_japanese_kanji(char: str) -> bool:
    try:
        char.encode("cp932")
        return True
    except UnicodeEncodeError:
        return False


def find_non_japanese_characters(text: str, allowed: str = "") -> list[str]:
    """Ideographs in `text` that are not Japanese kanji, in order, without repeats."""
    found: list[str] = []
    for char in _IDEOGRAPH_RE.findall(text):
        if char not in found and char not in allowed and not _is_japanese_kanji(char):
            found.append(char)
    return found


def validate_ai_output(output: AIOutput, expected_risk_level: str, source_text: str = "") -> list[str]:
    """Human-readable issues; an empty list means the output may be used.

    `source_text` is the alert data the model was given; characters quoted from it
    verbatim are exempt from the Japanese-script check.
    """
    issues: list[str] = []

    if output.risk_level != expected_risk_level:
        issues.append(
            f"risk_level_modified: the model returned {output.risk_level}, "
            f"the rule engine assigned {expected_risk_level}"
        )

    for name in _REQUIRED_TEXT_FIELDS:
        if not getattr(output, name).strip():
            issues.append(f"empty_field: {name}")
    for name in _REQUIRED_LIST_FIELDS:
        if not [item for item in getattr(output, name) if item.strip()]:
            issues.append(f"empty_list: {name}")

    for name in type(output).model_fields:
        value = getattr(output, name)
        texts = value if isinstance(value, list) else [value]
        for text in texts:
            for label in _BRACKETED_LEVEL_RE.findall(str(text)):
                if label.upper() != expected_risk_level:
                    issues.append(f"contradicting_risk_label: {name} contains [{label.upper()}]")
                    break

    for phrase in find_prohibited_phrases(output):
        issues.append(f"prohibited_phrase: {phrase}")

    for name in type(output).model_fields:
        value = getattr(output, name)
        text = "\n".join(value) if isinstance(value, list) else str(value)
        chars = find_non_japanese_characters(text, allowed=source_text)
        if chars:
            issues.append(f"non_japanese_characters: {name} contains {''.join(chars)}")

    return issues
