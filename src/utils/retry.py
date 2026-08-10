import structlog
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

logger = structlog.get_logger(__name__)

def _log_retry_attempt(retry_state):
    """Callback to log retry attempts with structlog."""
    exc = retry_state.outcome.exception() if retry_state.outcome.failed else None
    logger.warning(
        "retry_attempt",
        attempt=retry_state.attempt_number,
        next_delay=retry_state.idle_for,
        error=str(exc) if exc else None,
    )

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
