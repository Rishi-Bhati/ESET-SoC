"""
Socket-level coverage for src/services/syslog_runtime.py — previously the least-
tested ingestion path in the repo (docs/SOC_LITE_AUDIT.md §12/§16): the embedded
UDP/TCP listeners were implemented but no test bound a real socket and sent a
packet through them. These tests do exactly that, on high (non-privileged) ports
so they run without root/admin, and stub out forward_to_api() so they verify the
listener -> JSON-extraction -> forward hand-off without depending on the running
HTTP server.
"""
import asyncio
import json

from src.config import settings
from src.services import syslog_runtime


async def test_udp_listener_extracts_and_forwards_embedded_json(monkeypatch):
    monkeypatch.setattr(settings, "syslog_host", "127.0.0.1")
    monkeypatch.setattr(settings, "syslog_udp_port", 15514)
    monkeypatch.setattr(settings, "syslog_tcp_port", 15601)

    captured: list[dict] = []

    async def fake_forward(payload: dict) -> None:
        captured.append(payload)

    monkeypatch.setattr(syslog_runtime, "forward_to_api", fake_forward)

    handles = await syslog_runtime.start()
    assert handles.udp_transport is not None, "UDP listener failed to bind on a high, non-privileged port"

    try:
        loop = asyncio.get_running_loop()
        client_transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", 15514)
        )
        message = (
            '<14>1 2026-01-01T00:00:00Z host ESET-PROTECT - - - '
            '{"id":"syslog-udp-test-1","severity":"HIGH","threat_name":"Test/UDP"}'
        )
        client_transport.sendto(message.encode("utf-8"))
        client_transport.close()

        for _ in range(20):
            if captured:
                break
            await asyncio.sleep(0.05)
    finally:
        await syslog_runtime.stop(handles)

    assert captured, "no payload was forwarded within the timeout"
    assert captured[0] == {"id": "syslog-udp-test-1", "severity": "HIGH", "threat_name": "Test/UDP"}


async def test_udp_listener_ignores_frames_with_no_embedded_json(monkeypatch):
    monkeypatch.setattr(settings, "syslog_host", "127.0.0.1")
    monkeypatch.setattr(settings, "syslog_udp_port", 15515)
    monkeypatch.setattr(settings, "syslog_tcp_port", 15602)

    captured: list[dict] = []

    async def fake_forward(payload: dict) -> None:
        captured.append(payload)

    monkeypatch.setattr(syslog_runtime, "forward_to_api", fake_forward)

    handles = await syslog_runtime.start()
    try:
        loop = asyncio.get_running_loop()
        client_transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", 15515)
        )
        client_transport.sendto(b"<14>1 2026-01-01T00:00:00Z host ESET-PROTECT - - - not json at all")
        client_transport.close()
        await asyncio.sleep(0.2)
    finally:
        await syslog_runtime.stop(handles)

    assert captured == []


async def test_tcp_listener_extracts_and_forwards_embedded_json(monkeypatch):
    monkeypatch.setattr(settings, "syslog_host", "127.0.0.1")
    monkeypatch.setattr(settings, "syslog_udp_port", 15516)
    monkeypatch.setattr(settings, "syslog_tcp_port", 15603)

    captured: list[dict] = []

    async def fake_forward(payload: dict) -> None:
        captured.append(payload)

    monkeypatch.setattr(syslog_runtime, "forward_to_api", fake_forward)

    handles = await syslog_runtime.start()
    assert handles.tcp_server is not None, "TCP listener failed to bind on a high, non-privileged port"

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 15603)
        message = (
            '<14>1 2026-01-01T00:00:00Z host ESET-PROTECT - - - '
            '{"id":"syslog-tcp-test-1","severity":"CRITICAL","computer_name":"TCP-HOST"}\n'
        )
        writer.write(message.encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

        for _ in range(20):
            if captured:
                break
            await asyncio.sleep(0.05)
    finally:
        await syslog_runtime.stop(handles)

    assert captured, "no payload was forwarded within the timeout"
    assert captured[0] == {"id": "syslog-tcp-test-1", "severity": "CRITICAL", "computer_name": "TCP-HOST"}
