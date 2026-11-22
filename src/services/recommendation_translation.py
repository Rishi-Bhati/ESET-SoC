"""
Japanese translations of engineer recommendations.

Engineers write recommendations as free text, usually in English. Every other
piece of alert text the platform shows has a Japanese version produced by the AI
provider at pipeline time (ai_output.*_ja), and the language toggle picks between
the stored versions. Recommendations get the same treatment here: the configured
AI provider (BaseAIProvider.translate_to_japanese) produces `body_ja`, stored next
to the untouched `body`. The dashboard and the client portal show body_ja in
Japanese mode; exports carry it in their Japanese column (alert_export) and in
the client-facing fields (client_fields).

When it runs:
  * right after a recommendation is added (run_once(), a background task of the
    recommendations API);
  * every RECOMMENDATION_TRANSLATION_INTERVAL_SECONDS, for anything still without
    a translation: recommendations that existed before this feature, failed
    attempts (up to MAX_ATTEMPTS) and those added while no AI provider was set up.

Technical values are never sent and always come back exactly: URLs, e-mail
addresses, IP addresses, file paths, registry keys, hashes, DOMAIN\\user
references and `code` are replaced with [[Pn]] placeholders before the request
and restored afterwards. A translation whose placeholders do not all come back
exactly once is rejected (status 'failed', retried later), so a garbled
identifier can never be shown in place of the real one.

Text that is already Japanese is copied as is, without an API call.
"""
import asyncio
import re
from collections import defaultdict
from typing import Any

import structlog

from src.config import settings
from src.services.ai import factory as ai_factory
from src.services.ai.base import AIConfigurationError, TranslationError
from src.storage import recommendation_store
from src.utils import events

logger = structlog.get_logger(__name__)

MAX_ATTEMPTS = 5          # per recommendation, then it stays untranslated (shown with a note)
BATCH_SIZE = 10           # recommendations per provider call (always from one alert)
PASS_LIMIT = 200          # recommendations handled per pass

STATUS_DONE = "done"            # xlsx_writer.recommendation_body() relies on this value
STATUS_FAILED = "failed"
STATUS_UNAVAILABLE = "unavailable"

# ------------------------------------------------------------- identifiers

# Order matters: the earlier patterns claim their text first (a URL before the
# IP address or path inside it).
_PROTECT_PATTERNS = [
    re.compile(r"`[^`\n]+`"),                                                    # `code`
    re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s<>\"'）」]+", re.IGNORECASE),       # URLs (incl. defanged)
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),          # e-mail
    re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\s\"'<>|]+"),      # registry keys
    re.compile(r"(?<![\w\\])(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]+"),                   # Windows / UNC paths
    re.compile(r"(?<![\w/:.])/(?:[\w.\-]+/)+[\w.\-]*"),                           # Unix paths (2+ segments)
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2}|:\d{1,5})?\b"),             # IPv4 (+ /cidr or :port)
    re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])"),  # IPv6 (incl. ::)
    re.compile(r"\b[0-9A-Fa-f]{32,128}\b"),                                       # hashes
    re.compile(r"(?<![\w\\:])[A-Za-z][A-Za-z0-9.\-]{0,62}\\[A-Za-z0-9._\-$]{2,64}\b"),  # DOMAIN\user
]
_TRAILING_PUNCT = ".,;:!?)]}'\"、。"
_PLACEHOLDER_RE = re.compile(r"\[\[P(\d+)\]\]")


def protect(text: str) -> tuple[str, list[str]]:
    """(text with identifiers replaced by [[P1]], [[P2]], ... numbered in reading
    order, the identifiers in that order). Where patterns overlap, the earlier
    pattern in _PROTECT_PATTERNS wins (a URL keeps the IP address inside it)."""
    spans: list[tuple[int, int]] = []
    for pattern in _PROTECT_PATTERNS:
        for m in pattern.finditer(text):
            start, value = m.start(), m.group(0)
            if not value.startswith("`"):
                value = value.rstrip(_TRAILING_PUNCT)     # sentence punctuation is not part of it
            end = start + len(value)
            if value and all(end <= s or start >= e for s, e in spans):
                spans.append((start, end))
    out, tokens, pos = [], [], 0
    for start, end in sorted(spans):
        tokens.append(text[start:end])
        out.append(text[pos:start] + f"[[P{len(tokens)}]]")
        pos = end
    out.append(text[pos:])
    return "".join(out), tokens


def restore(text: str, tokens: list[str]) -> str:
    """Puts the identifiers back. Raises ValueError unless every placeholder is
    present exactly once and no unknown one appears."""
    found = [int(n) for n in _PLACEHOLDER_RE.findall(text)]
    if sorted(found) != list(range(1, len(tokens) + 1)):
        raise ValueError(f"placeholders changed by the translation (expected {len(tokens)}, got {found})")
    return _PLACEHOLDER_RE.sub(lambda m: tokens[int(m.group(1)) - 1], text)


# ------------------------------------------------------------- language check

_JA_RE = re.compile(r"[぀-ヿ㐀-䶿一-鿿ｦ-ﾟ]")
_KANA_RE = re.compile(r"[぀-ヿｦ-ﾟ]")
_LATIN_WORD_RE = re.compile(r"[A-Za-z]{2,}")


def looks_japanese(text: str) -> bool:
    """True for text already written in Japanese (identifiers and the odd English
    term aside): it has kana, and Japanese characters outnumber English words'
    letters. Kanji alone is not enough (it could be Chinese)."""
    protected, _ = protect(text or "")
    if not _KANA_RE.search(protected):
        return False
    ja = len(_JA_RE.findall(protected))
    latin = sum(len(w) for w in _LATIN_WORD_RE.findall(protected))
    return ja >= latin


# ------------------------------------------------------------- translating

_lock = asyncio.Lock()


async def _translate_batch(provider: Any, correlation_id: str, recs: list[dict[str, Any]]) -> list[str]:
    """Translates one batch (one alert); stores each outcome. Returns the ids translated."""
    protected = [protect(r["body"]) for r in recs]
    try:
        result = await provider.translate_to_japanese([p[0] for p in protected], correlation_id=correlation_id)
    except TranslationError as exc:
        for r in recs:
            await recommendation_store.set_translation(r["id"], status=STATUS_FAILED)
        logger.warning("recommendation_translation_batch_failed", correlation_id=correlation_id,
                       count=len(recs), error=str(exc))
        return []
    done = []
    for rec, (_, tokens), text in zip(recs, protected, result.translations):
        try:
            body_ja = restore(text, tokens)
        except ValueError as exc:
            await recommendation_store.set_translation(rec["id"], status=STATUS_FAILED)
            logger.warning("recommendation_translation_rejected", id=rec["id"], error=str(exc))
            continue
        await recommendation_store.set_translation(rec["id"], status=STATUS_DONE, body_ja=body_ja,
                                                   model=result.model)
        done.append(rec["id"])
    return done


async def translate_pending(limit: int = PASS_LIMIT) -> dict[str, int]:
    """One pass over recommendations still without a Japanese translation."""
    counts = {"translated": 0, "already_japanese": 0, "failed": 0, "unavailable": 0}
    if not settings.recommendation_translation_enabled:
        return counts
    async with _lock:
        pending = await recommendation_store.needing_translation(limit, MAX_ATTEMPTS)
        if not pending:
            return counts
        touched: dict[str, list[str]] = defaultdict(list)
        to_translate: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for rec in pending:
            if looks_japanese(rec["body"]):
                await recommendation_store.set_translation(rec["id"], status=STATUS_DONE, body_ja=rec["body"],
                                                           model="original (already Japanese)",
                                                           count_attempt=False)
                counts["already_japanese"] += 1
                touched[rec["correlation_id"]].append(rec["id"])
            else:
                to_translate[rec["correlation_id"]].append(rec)

        if to_translate:
            try:
                provider = ai_factory.get_ai_provider()
            except AIConfigurationError as exc:
                provider = None
                logger.warning("recommendation_translation_unavailable", error=str(exc))
            for cid, recs in to_translate.items():
                if provider is None:
                    for r in recs:  # not counted as an attempt: it is retried once a provider is set up
                        await recommendation_store.set_translation(r["id"], status=STATUS_UNAVAILABLE,
                                                                   count_attempt=False)
                    counts["unavailable"] += len(recs)
                    continue
                for start in range(0, len(recs), BATCH_SIZE):
                    batch = recs[start:start + BATCH_SIZE]
                    done = await _translate_batch(provider, cid, batch)
                    counts["translated"] += len(done)
                    counts["failed"] += len(batch) - len(done)
                    touched[cid].extend(done)

    for cid, ids in touched.items():
        if ids:
            await events.emit("recommendation_translated", {"correlation_id": cid, "ids": ids})
    if any(counts.values()):
        logger.info("recommendation_translation_pass", **counts)
    return counts


async def run_once() -> None:
    """One pass that never raises: run as a FastAPI background task right after a
    recommendation is added, and by the loop below."""
    try:
        await translate_pending()
    except Exception as e:  # a background pass must never take anything down with it
        logger.error("recommendation_translation_pass_error", error=str(e))


async def run_translation_loop() -> None:
    """Background loop started with the app: translates whatever is missing
    (existing recommendations on first start, failed and unavailable ones later),
    then sleeps for the configured interval."""
    while True:
        await run_once()
        await asyncio.sleep(settings.recommendation_translation_interval_seconds)
