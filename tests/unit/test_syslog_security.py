import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.config import settings
from src.services import syslog_runtime as runtime


@pytest.mark.parametrize("configured", ["exporter.invalid", "192.0.2.0/99", ", ,"])
def test_invalid_nonempty_allowlist_fails_closed(monkeypatch, configured):
    monkeypatch.setattr(settings, "syslog_allowed_sources", configured)
    assert not runtime.source_allowed(("203.0.113.8", 514))
    assert not runtime.source_allowed(None)


@pytest.mark.parametrize(
    "configured,peer,allowed",
    [
        ("  ", "203.0.113.8", True),
        ("192.0.2.0/24", "192.0.2.10", True),
        ("192.0.2.0/24", "203.0.113.8", False),
        ("typo,192.0.2.10", "192.0.2.10", True),
        ("typo,192.0.2.10", "192.0.2.11", False),
        ("2001:db8::/32", "2001:db8::8", True),
        ("2001:db8::/32", "2001:db9::8", False),
    ],
)
def test_source_allowlist_matches_only_valid_networks(monkeypatch, configured, peer, allowed):
    monkeypatch.setattr(settings, "syslog_allowed_sources", configured)
    assert runtime.source_allowed((peer, 514)) is allowed


def test_json_extraction_handles_nested_payload_and_malformed_frames():
    assert runtime.extract_json_payload('<14> host {"nested":{"value":"}"}} trailing') == {
        "nested": {"value": "}"},
    }
    for frame in ("no JSON", "}}}{{{", '{"broken":}', "{" * 65536):
        assert runtime.extract_json_payload(frame) is None


def test_repeated_opening_braces_do_not_block_event_loop():
    # Legal-sized UDP frames used to trigger quadratic regex backtracking here.
    # Several frames make the regression visible with a generous timing margin.
    started = time.monotonic()
    for _ in range(8):
        assert runtime.extract_json_payload("{" * 65536) is None
    assert time.monotonic() - started < 1.0


def test_udp_rejects_disallowed_and_oversized_frames_before_enqueuing(monkeypatch):
    queue = asyncio.Queue(maxsize=2)
    monkeypatch.setattr(runtime, "_queue", queue)
    monkeypatch.setattr(settings, "syslog_allowed_sources", "192.0.2.1")
    monkeypatch.setattr(settings, "syslog_max_frame_bytes", 16)
    protocol = runtime.UDPProtocol()
    protocol.datagram_received(b'{"ok":true}', ("192.0.2.2", 514))
    protocol.datagram_received(b'{"message":"too long"}', ("192.0.2.1", 514))
    assert queue.empty()
    protocol.datagram_received(b'{"ok":true}', ("192.0.2.1", 514))
    assert queue.get_nowait() == {"ok": True}


async def test_worker_pool_and_pending_queue_are_bounded(monkeypatch):
    queue = asyncio.Queue(maxsize=1)
    monkeypatch.setattr(runtime, "_queue", queue)
    monkeypatch.setattr(runtime, "_dropped_frames", 0)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked_forward(payload):
        entered.set()
        await release.wait()

    monkeypatch.setattr(runtime, "forward_to_api", blocked_forward)
    worker = asyncio.create_task(runtime._worker())
    try:
        runtime._enqueue({"id": 1}, None, "udp")
        await asyncio.wait_for(entered.wait(), timeout=1)
        runtime._enqueue({"id": 2}, None, "udp")
        runtime._enqueue({"id": 3}, None, "udp")
        assert queue.qsize() == 1
        assert runtime._dropped_frames == 1
        release.set()
        await asyncio.wait_for(queue.join(), timeout=1)
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)


def test_rejected_packet_warnings_are_sampled(monkeypatch):
    monkeypatch.setattr(runtime, "_ingress_warning_counts", {})
    logger = Mock()
    monkeypatch.setattr(runtime, "logger", logger)
    for _ in range(201):
        runtime._ingress_warning("syslog_udp_source_rejected", addr=("203.0.113.8", 514))
    assert logger.warning.call_count == 3
    assert logger.warning.call_args.kwargs["count"] == 201


def fake_writer():
    return SimpleNamespace(
        get_extra_info=lambda key: ("192.0.2.1", 514),
        close=Mock(),
        wait_closed=AsyncMock(),
    )


async def test_tcp_connection_limit_refuses_before_reading(monkeypatch):
    monkeypatch.setattr(settings, "syslog_allowed_sources", "")
    monkeypatch.setattr(settings, "syslog_max_tcp_connections", 1)
    monkeypatch.setattr(runtime, "_tcp_connections", 1)
    reader = SimpleNamespace(readline=AsyncMock())
    writer = fake_writer()
    await runtime.handle_tcp_client(reader, writer)
    reader.readline.assert_not_called()
    writer.close.assert_called_once()
    assert runtime._tcp_connections == 1


async def test_stop_cancels_live_tcp_clients_and_releases_connection_count(monkeypatch):
    monkeypatch.setattr(settings, "syslog_allowed_sources", "")
    monkeypatch.setattr(runtime, "_tcp_connections", 0)
    monkeypatch.setattr(runtime, "_tcp_tasks", set())
    monkeypatch.setattr(runtime, "_tcp_writers", set())
    monkeypatch.setattr(runtime, "_workers", [])
    monkeypatch.setattr(runtime, "_queue", None)
    monkeypatch.setattr(runtime, "_client", None)
    entered = asyncio.Event()

    async def blocked_read():
        entered.set()
        await asyncio.Event().wait()

    # StreamWriter objects are hashable, unlike SimpleNamespace.
    writer = Mock()
    writer.get_extra_info.return_value = ("192.0.2.1", 514)
    writer.wait_closed = AsyncMock()
    task = asyncio.create_task(runtime.handle_tcp_client(SimpleNamespace(readline=blocked_read), writer))
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        assert runtime._tcp_connections == 1
        await asyncio.wait_for(runtime.stop(runtime.SyslogHandles()), timeout=1)
        assert task.done()
        assert runtime._tcp_connections == 0
        assert not runtime._tcp_tasks
        assert not runtime._tcp_writers
        writer.close.assert_called()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("oversized", [False, True])
async def test_tcp_idle_or_oversized_frame_is_closed_without_forwarding(monkeypatch, oversized):
    monkeypatch.setattr(settings, "syslog_allowed_sources", "")
    monkeypatch.setattr(settings, "syslog_tcp_idle_timeout_seconds", 0.01)
    monkeypatch.setattr(runtime, "_tcp_connections", 0)
    monkeypatch.setattr(runtime, "_tcp_tasks", set())
    monkeypatch.setattr(runtime, "_tcp_writers", set())
    queue = asyncio.Queue(maxsize=1)
    monkeypatch.setattr(runtime, "_queue", queue)
    reader = asyncio.StreamReader(limit=8)
    if oversized:
        reader.feed_data(b"{" * 16)
    writer = Mock()
    writer.get_extra_info.return_value = ("192.0.2.1", 514)
    writer.wait_closed = AsyncMock()
    await asyncio.wait_for(runtime.handle_tcp_client(reader, writer), timeout=1)
    writer.close.assert_called_once()
    assert queue.empty()
    assert runtime._tcp_connections == 0
    assert not runtime._tcp_writers


async def test_start_refuses_to_replace_an_existing_worker_pool(monkeypatch):
    monkeypatch.setattr(runtime, "_queue", asyncio.Queue(maxsize=1))
    with pytest.raises(RuntimeError, match="already started"):
        await runtime.start()
