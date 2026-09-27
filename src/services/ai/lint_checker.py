"""
Prohibited-claim safety lint over AI output.

An exact-phrase backstop behind the system prompt, not a semantic check: it
catches the model asserting what the client's rules say it must never assert —
confirmed infection, confirmed leakage, confirmed compromise, a safe
environment, a resolved incident — in the common English and Japanese forms.

Phrases are deliberately the assertive/completed forms (「感染を確認しました」,
not 「感染を確認」) so a legitimate confirmation request such as
「端末の感染有無を確認してください」 is not blocked, and a match immediately
negated or hedged (「感染が確認されたわけではありません」, "no infection
confirmed", "whether data was exfiltrated is unknown") is skipped.
"""
import re
from typing import Any
from pydantic import BaseModel
import structlog

logger = structlog.get_logger(__name__)

PROHIBITED_PHRASES = [
    # English — confirmed infection / compromise / leakage
    "infection confirmed",
    "confirmed infection",
    "confirmed to be infected",
    "compromise confirmed",
    "confirmed compromise",
    "successfully compromised",
    "system compromised",
    "breach confirmed",
    "data leak confirmed",
    "data leakage confirmed",
    "leakage confirmed",
    "data was exfiltrated",
    "data has been exfiltrated",
    # English — safety / resolution claims
    "environment is safe",
    "system is safe",
    "network is safe",
    "endpoint is safe",
    "safe to ignore",
    "no further action is required",
    "no further action required",
    "no further immediate action",
    "no immediate action is required",
    "no immediate action required",
    "no action is required",
    "no action required",
    "nothing further is required",
    "successfully isolated",
    "resolved successfully",
    "incident resolved",

    # Japanese — confirmed infection / compromise / leakage
    "感染を確認しました",
    "感染が確認されました",
    "感染を確認済み",
    "感染が判明",
    "感染しています",
    "情報漏洩を確認しました",
    "情報漏洩が確認されました",
    "情報漏えいを確認しました",
    "情報漏えいが確認されました",
    "漏洩が発生しました",
    "漏えいが発生しました",
    "侵入を確認しました",
    "侵害を確認しました",
    "侵害が確認されました",
    # Japanese — safety / resolution claims
    "インシデントは解決",
    "解決済み",
    "安全を確認しました",
    "安全が確認されました",
    "環境は安全です",
    "安全な状態です",
    "問題はありません",
    "対応は不要です",
    "隔離成功",
    "駆除成功",
]

_EN_NEGATION_BEFORE = re.compile(r"\b(?:not|no|never|without|whether|if|cannot|can't|isn't|is not|has not|have not)\b[\w\s]{0,12}$", re.IGNORECASE)
_JA_NEGATION_AFTER = re.compile(r"^.{0,4}(?:わけではありません|わけではない|ではありません|ではない|ておりません|ていません|おりません|とは言えません|とは限りません)")


class LintFailureException(Exception):
    """
    Exception raised when AI output violates security phrasing constraints.
    """
    def __init__(self, message: str, found_phrases: list[str]) -> None:
        super().__init__(message)
        self.found_phrases = found_phrases


def _negated(text: str, start: int, end: int, phrase: str) -> bool:
    if phrase.isascii():
        return bool(_EN_NEGATION_BEFORE.search(text[max(0, start - 30):start]))
    return bool(_JA_NEGATION_AFTER.search(text[end:end + 20]))


def _scan_text(value: str, found: list[str]) -> None:
    lowered = value.lower()
    for phrase in PROHIBITED_PHRASES:
        needle = phrase.lower()
        start = lowered.find(needle)
        while start != -1:
            end = start + len(needle)
            if not _negated(lowered, start, end, phrase):
                if phrase not in found:
                    found.append(phrase)
                break
            start = lowered.find(needle, end)


def find_prohibited_phrases(output: Any) -> list[str]:
    """Every prohibited phrase asserted anywhere in the output's text."""
    found: list[str] = []

    def scan(value: Any) -> None:
        if isinstance(value, str):
            _scan_text(value, found)
        elif isinstance(value, list):
            for item in value:
                scan(item)
        elif isinstance(value, dict):
            for item in value.values():
                scan(item)
        elif isinstance(value, BaseModel):
            for name in value.__class__.model_fields:
                scan(getattr(value, name))

    scan(output)
    return found


def lint_ai_output(output: Any) -> None:
    """
    Raises LintFailureException if the output asserts any prohibited claim.
    """
    found_phrases = find_prohibited_phrases(output)
    if found_phrases:
        logger.warning("ai_lint_failed", prohibited_found=found_phrases)
        raise LintFailureException(
            f"AI output safety lint violation: prohibited phrases detected {found_phrases}",
            found_phrases=found_phrases
        )
    logger.info("ai_lint_passed")
