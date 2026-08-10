import logging
import os
import sys
import structlog

def setup_logging(log_level: str = "INFO", log_file: str = "logs/app.log"):
    """
    Configures structlog to output to both console (human-readable) and a JSON file.
    """
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # File handler writes structured JSON logs
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
        )
    )

    # Console handler writes colorized human-readable logs
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.dev.ConsoleRenderer(colors=True),
        )
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Reset any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Helper to get a structlog logger.
    """
    return structlog.get_logger(name)
