from contextvars import ContextVar
import structlog
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

logger = structlog.get_logger(__name__)

# Per-call-chain log of retry attempts, populated by _log_retry_attempt() below.
# Exists so AI-call instrumentation (src/services/ai/trace_recorder.py) can surface
# retry/backoff activity in an AI trace's timeline without this decorator needing to
# know anything about tracing — callers that don't care can simply ignore it. Uses a
# ContextVar rather than a parameter so retry_api_call()'s public signature is
# unchanged; the same pattern is already used for correlation_id (see
# src/utils/correlation.py).
_retry_log: ContextVar[list | None] = ContextVar("retry_log", default=None)

def get_retry_log() -> list:
    """Returns (creating if needed) the current context's retry-attempt log."""
    log = _retry_log.get()
    if log is None:
        log = []
        _retry_log.set(log)
    return log

def reset_retry_log() -> None:
    """Clears the current context's retry-attempt log before a fresh call."""
    _retry_log.set(None)

def _log_retry_attempt(retry_state):
    """Callback to log retry attempts with structlog."""
    exc = retry_state.outcome.exception() if retry_state.outcome.failed else None
    logger.warning(
        "retry_attempt",
        attempt=retry_state.attempt_number,
        next_delay=retry_state.idle_for,
        error=str(exc) if exc else None,
    )
    get_retry_log().append({
        "attempt": retry_state.attempt_number,
        "next_delay": retry_state.idle_for,
        "error": str(exc) if exc else None,
    })

def retry_api_call(
    max_attempts: int = 3,
    min_delay: float = 1.0,
    max_delay: float = 10.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
):
    """
    Returns a configured tenacity retry decorator for async/sync API calls.
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=min_delay, max=max_delay),
        retry=retry_if_exception_type(exceptions),
        before_sleep=_log_retry_attempt,
        reraise=True,
    )
