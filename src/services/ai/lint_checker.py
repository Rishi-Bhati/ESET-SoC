from typing import Any
from pydantic import BaseModel
import structlog
from src.models.ai_output import AIOutput

logger = structlog.get_logger(__name__)

# List of forbidden diagnostic assertions that the AI must not make
PROHIBITED_PHRASES = [
    # English
    "infection confirmed",
    "confirmed infection",
    "compromise confirmed",
    "confirmed compromise",
    "breach confirmed",
    "data leak confirmed",
    "leakage confirmed",
    "system compromised",
    "successfully isolated",
    "resolved successfully",
    "incident resolved",
    
    # Japanese
    "感染を確認",
    "情報漏洩を確認",
    "漏洩を確認",
    "侵入を確認",
    "インシデント解決",
    "解決済み",
    "安全を確認",
    "隔離成功",
    "駆除成功"
]

class LintFailureException(Exception):
    """
    Exception raised when AI output violates security phrasing constraints.
    """
    def __init__(self, message: str, found_phrases: list[str]) -> None:
        super().__init__(message)
        self.found_phrases = found_phrases

def lint_ai_output(output: AIOutput) -> None:
    """
    Recursively scans all text attributes within the AIOutput model
    for prohibited speculative security diagnostic statements.
    """
    found_phrases = []
    
    def scan(value: Any) -> None:
        if isinstance(value, str):
            val_lower = value.lower()
            for phrase in PROHIBITED_PHRASES:
                if phrase.lower() in val_lower:
                    found_phrases.append(phrase)
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
    
    if found_phrases:
        logger.warning("ai_lint_failed", prohibited_found=found_phrases)
        raise LintFailureException(
            f"AI output safety lint violation: prohibited phrases detected {found_phrases}",
            found_phrases=found_phrases
        )
        
    logger.info("ai_lint_passed")
