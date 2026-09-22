import io
import json
import logging

import structlog

from src.utils.logging import _redact_secrets, redact_secrets


def test_redacts_encoded_names_nested_values_and_structured_credentials():
    event = {
        "event": 'WebSocket /dashboard/api/ws?%6bey=hidden-ws&limit=20',
        "details": [{"url": "https://example.test/?access%5fkey=hidden-api"}],
        "Authorization": "Bearer hidden-header",
        "error": "token=hidden-error",
        "quoted_key": "GET /ws?key=hidden'quoted-value HTTP/1.1",
    }
    result = redact_secrets(event)
    assert "hidden-" not in json.dumps(result)
    assert "quoted-value" not in json.dumps(result)
    assert "limit=20" in result["event"]
    assert event["Authorization"] == "Bearer hidden-header"  # callers keep their data


def test_foreign_log_formatter_redacts_and_supplies_timestamp_level():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            _redact_secrets,
        ],
    ))
    record = logging.LogRecord("test", logging.WARNING, __file__, 1,
                               "WebSocket /ws?key=hidden-value", (), None)
    handler.handle(record)
    entry = json.loads(stream.getvalue())
    assert entry["level"] == "warning"
    assert entry["timestamp"].endswith("Z")
    assert "hidden-value" not in entry["event"]
