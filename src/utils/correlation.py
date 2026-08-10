import uuid
from contextvars import ContextVar
import structlog

# Context variable to hold correlation_id for the current execution context
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")

def generate_correlation_id() -> str:
    """Generates a unique UUID v4 string for request tracing."""
    return str(uuid.uuid4())

def set_correlation_id(correlation_id: str) -> None:
    """Sets the correlation ID in context and binds it to structlog."""
    correlation_id_var.set(correlation_id)
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

def get_correlation_id() -> str:
    """Retrieves the correlation ID of the current context."""
    return correlation_id_var.get()

def clear_correlation_id() -> None:
    """Clears the correlation ID from context."""
    correlation_id_var.set("")
    structlog.contextvars.unbind_contextvars("correlation_id")
