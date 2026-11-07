"""
Size, count and shape limits the ESET Mail worker enforces on POST /api/send
(Email Service src/index.ts, v1.2.x), mirrored here so a message that can never
be accepted is caught BEFORE the request is signed and sent, not discovered as
a 400/413 after the fact.

    attachments             at most 20 per email
    attachment.filename     required, <= 255 chars (CR/LF/NUL are stripped)
    attachment.content      non-empty standard base64 (length % 4 == 0)
    attachment.mimeType     optional string, whitespace stripped, kept to 127 chars
    html / body             <= 900,000 characters
    request body            <= 3 MiB (3 * 1024 * 1024 bytes)
    stored email            html + text + attachments-as-JSON must total
                            <= 1,900,000 bytes (D1 caps a row at 2,000,000).
                            That is roughly 1.4 MB of raw attachment data
                            once base64 and JSON overhead are counted.

The worker has no attachment type allow-list; it auto-detects the MIME type
from the filename when `mimeType` is omitted.

Pure functions, no I/O, no dependence on a particular provider class — the weekly
report uses `message_violation()` to decide whether to attach at all, and the
provider uses `prepare_attachments()` / `check_sizes()` as its final guard.
"""
import base64
import binascii
import json
import re
from typing import Any, Iterable

from src.models.email_message import EmailAttachment, EmailMessage

MAX_ATTACHMENTS = 20
MAX_ATTACHMENT_FILENAME_CHARS = 255
MAX_MIME_TYPE_CHARS = 127
MAX_EMAIL_BODY_CHARS = 900_000
MAX_SEND_BODY_BYTES = 3 * 1024 * 1024
MAX_STORED_EMAIL_BYTES = 1_900_000

_CTRL = re.compile(r"[\r\n\x00]")
_WHITESPACE = re.compile(r"\s+")
_BASE64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
# type/subtype with the characters RFC 6838 allows; anything else is dropped so
# the worker falls back to detecting the type from the filename.
_MIME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$")


class MailLimitError(ValueError):
    """A message the mail service is documented to reject. Always permanent."""


def _clean_filename(name: str) -> str:
    # Path separators are not forbidden by the worker, but a filename is the
    # one attacker-influenced header-ish value in the message, so keep it flat.
    return _CTRL.sub("", name).replace("/", "_").replace("\\", "_").strip()


def prepare_attachments(attachments: Iterable[EmailAttachment]) -> list[dict[str, Any]]:
    """
    Validates attachments against the worker's rules and returns them in the
    wire shape: [{"filename", "content", "mimeType"?}]. `content_type` on our
    model is `mimeType` on the wire. Raises MailLimitError on the first problem.
    """
    items = list(attachments)
    if len(items) > MAX_ATTACHMENTS:
        raise MailLimitError(
            f"Too many attachments ({len(items)}; the mail service allows {MAX_ATTACHMENTS})"
        )
    wire: list[dict[str, Any]] = []
    for i, att in enumerate(items):
        filename = _clean_filename(att.filename or "")
        if not filename:
            raise MailLimitError(f"attachments[{i}] has no filename")
        if len(filename) > MAX_ATTACHMENT_FILENAME_CHARS:
            raise MailLimitError(
                f"attachments[{i}].filename exceeds {MAX_ATTACHMENT_FILENAME_CHARS} characters"
            )
        content = _WHITESPACE.sub("", att.content_base64 or "")
        if not content:
            raise MailLimitError(f"attachments[{i}] ({filename}) is empty")
        if len(content) % 4 != 0 or not _BASE64.match(content):
            raise MailLimitError(f"attachments[{i}] ({filename}) is not valid base64")
        try:
            base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError):
            raise MailLimitError(f"attachments[{i}] ({filename}) is not valid base64") from None
        item: dict[str, Any] = {"filename": filename, "content": content}
        mime = _WHITESPACE.sub("", att.content_type or "")[:MAX_MIME_TYPE_CHARS]
        if mime and _MIME.match(mime):
            item["mimeType"] = mime
        wire.append(item)
    return wire


def _utf8_len(value: str) -> int:
    return len(value.encode("utf-8", "replace"))


def attachments_json_bytes(wire_attachments: list[dict[str, Any]]) -> int:
    """Size of the attachments as the worker stores them (compact JSON, UTF-8)."""
    if not wire_attachments:
        return 0
    return _utf8_len(json.dumps(wire_attachments, separators=(",", ":"), ensure_ascii=False))


def check_sizes(
    body_text: str, wire_attachments: list[dict[str, Any]], request_bytes: int | None = None,
) -> None:
    """
    Raises MailLimitError when the worker would answer 413. `body_text` is
    whatever goes under `html` (or `body`); `request_bytes` is the serialised
    request when known.
    """
    if len(body_text) > MAX_EMAIL_BODY_CHARS:
        raise MailLimitError(
            f"Email body is too large ({len(body_text)} characters; limit {MAX_EMAIL_BODY_CHARS})"
        )
    stored = _utf8_len(body_text) + attachments_json_bytes(wire_attachments)
    if stored > MAX_STORED_EMAIL_BYTES:
        raise MailLimitError(
            f"Email is too large for the mail service: body + base64 attachments are "
            f"{stored} bytes, the limit is {MAX_STORED_EMAIL_BYTES} "
            f"(about 1.4 MB of raw attachment data)"
        )
    if request_bytes is not None and request_bytes > MAX_SEND_BODY_BYTES:
        raise MailLimitError(
            f"Request body is {request_bytes} bytes; the mail service accepts at most "
            f"{MAX_SEND_BODY_BYTES}"
        )


def message_violation(message: EmailMessage) -> str | None:
    """
    None when the message (body + attachments) fits the worker's limits,
    otherwise the reason it would be rejected. Never raises.
    """
    try:
        wire = prepare_attachments(message.attachments)
        check_sizes(message.html or message.body or "", wire)
    except MailLimitError as e:
        return str(e)
    return None
