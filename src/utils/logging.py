import logging
import logging.handlers
import os
import re
import sys
from urllib.parse import unquote_plus
import structlog

# Anything shaped like a credential carried in a URL query string. The dashboard
# no longer puts its access key in the WebSocket URL (see src/api/dashboard.py),
# but this is the backstop: uvicorn's access log records the full request line,
# run.py gives uvicorn no log config of its own so those lines land in this same
# file, and /dashboard/api/logs serves that file back through the browser. One
# future endpoint that takes a secret in a query parameter would otherwise
# publish it, silently.
_QUERY_VALUE_RE = re.compile(r"(?<![\w%+\-])([\w%+\-]+)=([^&\s]+)")
_SECRET_NAMES = {
    "key", "token", "secret", "password", "passwd", "pwd", "apikey",
    "accesskey", "auth", "authorization", "dashboardaccesskey", "geminiapikey",
    "emailapikey", "emailapisecret", "esetwebhookauthtoken", "xdashboardkey",
}


def _secret_name(name: str) -> bool:
    return unquote_plus(name).lower().replace("_", "").replace("-", "") in _SECRET_NAMES


def redact_secrets(value):
    """Redact credentials in nested log data and URL-encoded query names."""
    if isinstance(value, str):
        return _QUERY_VALUE_RE.sub(
            lambda m: m[1] + "=[REDACTED]" if _secret_name(m[1]) else m[0], value,
        )
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if isinstance(key, str) and _secret_name(key)
            else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item) for item in value]
    return value


def _redact_secrets(_logger, _method, event_dict):
    return redact_secrets(event_dict)

class QuietDashboardAccessFilter(logging.Filter):
    """
    Drops uvicorn access lines for the dashboard's own background traffic —
    successful GETs of /dashboard/api/*, /static/*, / and /health — which the
    dashboard generates every few seconds per open tab and which otherwise
    make up most of the log. Ingest requests, every other method and any
    non-2xx/3xx response still get logged.
    """

    _QUIET_PREFIXES = ("/dashboard/api/", "/static/", "/health")

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name != "uvicorn.access":
            return True
        args = record.args
        # uvicorn: (client_addr, method, full_path, http_version, status_code)
        if not isinstance(args, tuple) or len(args) < 5:
            return True
        method, path, status = args[1], str(args[2]), args[4]
        try:
            ok = 200 <= int(status) < 400
        except (TypeError, ValueError):
            return True
        quiet_path = path == "/" or path.startswith(self._QUIET_PREFIXES)
        return not (method == "GET" and ok and quiet_path)


def setup_logging(
    log_level: str = "INFO",
    log_file: str = "logs/app.log",
    *,
    max_bytes: int = 20_000_000,
    backup_count: int = 5,
    quiet_dashboard_access: bool = True,
):
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
        # Last, so formatted exception messages are covered as well.
        _redact_secrets,
    ]

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # File handler writes structured JSON logs.
    # foreign_pre_chain runs the same redaction over records that came from the
    # stdlib logging API rather than from structlog — which is where uvicorn's
    # access lines (the ones that carry a full request line) arrive.
    # Rotated by size so a long-running deployment cannot fill its volume.
    # src/services/log_reader.py notices the new inode after a rollover.
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8",
    )
    file_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
            foreign_pre_chain=shared_processors,
        )
    )

    # Console handler writes colorized human-readable logs
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            # Colour codes only for a real terminal; container log collectors
            # would otherwise store the escape sequences verbatim.
            processor=structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty()),
            foreign_pre_chain=shared_processors,
        )
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Reset any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    if quiet_dashboard_access:
        noise = QuietDashboardAccessFilter()
        console_handler.addFilter(noise)
        file_handler.addFilter(noise)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Helper to get a structlog logger.
    """
    return structlog.get_logger(name)
