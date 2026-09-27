import asyncio
import ipaddress
import json
from dataclasses import dataclass
from functools import lru_cache
import httpx
import structlog
from src.config import settings

logger = structlog.get_logger(__name__)

# Frames accepted off the wire and not yet forwarded. Bounded on purpose: these
# listeners are unauthenticated, so this queue bounds pending loopback forwards.
# Pipeline admission must be bounded separately at the HTTP ingestion endpoint:
# its response is sent before the background pipeline has finished.
# When it is full, new frames are DROPPED and counted rather than queued — losing
# syslog frames under attack is strictly better than taking the API process down,
# and the same alert arrives again on ESET's next export.
_queue: asyncio.Queue | None = None
_workers: list[asyncio.Task] = []
_client: httpx.AsyncClient | None = None
# Live TCP connections, for the connection cap.
_tcp_connections = 0
_dropped_frames = 0
_tcp_tasks: set[asyncio.Task] = set()
_tcp_writers: set[asyncio.StreamWriter] = set()
_ingress_warning_counts: dict[str, int] = {}


@lru_cache(maxsize=16)
def _allowed_sources(configured: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parses SYSLOG_ALLOWED_SOURCES into networks. Plain addresses are accepted
    and treated as /32 (or /128). An unparseable entry is logged and skipped
    rather than silently widening the allowlist. Cache parsing so invalid config
    is not logged anew for every incoming packet."""
    nets = []
    for raw in configured.split(","):
        entry = raw.strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.error("syslog_allowlist_entry_invalid", entry=entry)
    return tuple(nets)


def source_allowed(addr: tuple | None) -> bool:
    """True when this peer may feed the listeners. A blank allowlist accepts
    everyone — the documented, deliberately-permissive default for a listener
    that is already behind a network boundary."""
    configured = settings.syslog_allowed_sources.strip()
    if not configured:
        return True
    nets = _allowed_sources(configured)
    # A configured but unusable allowlist must never turn into allow-everyone.
    if not nets:
        return False
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr[0])
    except ValueError:
        return False
    return any(ip in net for net in nets)


def _ingress_warning(event: str, **details) -> None:
    """Sample repetitive packet warnings so rejected traffic cannot fill logs."""
    count = _ingress_warning_counts.get(event, 0) + 1
    _ingress_warning_counts[event] = count
    if count % 100 == 1:
        logger.warning(event, count=count, **details)


def _enqueue(payload: dict, addr: tuple | None, transport: str) -> None:
    """Hands one parsed frame to the worker pool, dropping it if the queue is
    full. Never blocks the protocol callback."""
    global _dropped_frames
    if _queue is None:
        logger.warning("syslog_frame_dropped_not_started", transport=transport)
        return
    try:
        _queue.put_nowait(payload)
    except asyncio.QueueFull:
        _dropped_frames += 1
        # One line per 100 drops: under a flood, logging every drop is itself a
        # denial of service against the log file the dashboard reads.
        if _dropped_frames % 100 == 1:
            logger.warning(
                "syslog_queue_full_dropping", transport=transport, addr=addr,
                dropped_total=_dropped_frames, queue_size=settings.syslog_queue_size,
            )


async def _worker() -> None:
    """Drains the queue, bounding concurrent loopback HTTP forwards."""
    queue = _queue
    assert queue is not None
    while True:
        payload = await queue.get()
        try:
            await forward_to_api(payload)
        except Exception as e:  # a bad frame must never kill the worker
            logger.error("syslog_worker_forward_failed", error=str(e))
        finally:
            queue.task_done()


def extract_json_payload(raw_message: str) -> dict | None:
    """
    Search and extract embedded JSON payload within a syslog message.
    """
    # An unanchored greedy regex retries from every opening brace when there is
    # no closing brace. One legal-size malformed packet could block the shared
    # event loop for seconds. These searches are linear in the frame length.
    start = raw_message.find("{")
    end = raw_message.rfind("}")
    if start < 0 or end < start:
        return None

    try:
        return json.loads(raw_message[start:end + 1])
    except Exception:
        return None


async def forward_to_api(payload: dict) -> None:
    """
    Forwards a parsed syslog payload to the FastAPI webhook endpoint over loopback HTTP.
    """
    url = f"http://127.0.0.1:{settings.app_port}/webhook/syslog"
    headers = {
        "Authorization": f"Bearer {settings.eset_webhook_auth_token}",
        "Content-Type": "application/json"
    }

    # One shared client for the process: a new AsyncClient (and its connection
    # pool and socket) per datagram is how a packet flood becomes FD exhaustion.
    owns_client = _client is None
    client = _client if _client is not None else httpx.AsyncClient()
    try:
        try:
            logger.info("syslog_forwarding_start", url=url)
            response = await client.post(
                url,
                json=payload,
                headers=headers,
                timeout=settings.threat_intel_timeout_seconds
            )
            if response.status_code in (200, 202):
                logger.info(
                    "syslog_forwarding_success",
                    status_code=response.status_code,
                    resp=response.json()
                )
            else:
                logger.error(
                    "syslog_forwarding_error_status",
                    status_code=response.status_code,
                    body=response.text
                )
        except Exception as e:
            logger.error("syslog_forwarding_failed", error=str(e))
    finally:
        # Only close a client we created here as a fallback; the shared one is
        # owned by start()/stop().
        if owns_client:
            await client.aclose()


class UDPProtocol(asyncio.DatagramProtocol):
    """
    Asyncio Datagram Protocol to handle UDP Syslog messages.
    """
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            # UDP source addresses are spoofable, so the allowlist is a cost
            # control and a misconfiguration guard — not an authentication
            # mechanism. It is checked first so a rejected packet costs one
            # comparison and nothing else.
            if not source_allowed(addr):
                _ingress_warning("syslog_udp_source_rejected", addr=addr)
                return
            # Truncate before decoding: an oversized datagram is malformed for
            # this protocol and must not be carried around at full size.
            if len(data) > settings.syslog_max_frame_bytes:
                _ingress_warning("syslog_udp_frame_too_large", addr=addr, size=len(data))
                return

            message = data.decode("utf-8", errors="ignore").strip()
            logger.debug("syslog_udp_received_raw", addr=addr, message=message[:200])

            payload = extract_json_payload(message)
            if payload:
                logger.debug("syslog_udp_json_found", addr=addr)
                _enqueue(payload, addr, "udp")
            else:
                _ingress_warning("syslog_udp_no_json", addr=addr, message_preview=message[:100])
        except Exception as e:
            logger.error("syslog_udp_processing_failed", error=str(e))


async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Handles a TCP client connection for Syslog messages.

    Three bounds, all of them protecting the HTTP API rather than this listener:
    the listeners run inside the API process, so a peer that exhausts file
    descriptors here stops ingest and the dashboard too.
      - a cap on concurrent connections, refused immediately past the limit;
      - an idle timeout, so a peer that connects and never writes is dropped
        instead of holding its descriptor indefinitely;
      - a frame-size limit (applied by start_server's `limit`), so an
        unterminated line cannot be streamed into memory without end.
    """
    global _tcp_connections
    addr = writer.get_extra_info("peername")

    if not source_allowed(addr):
        _ingress_warning("syslog_tcp_source_rejected", addr=addr)
        writer.close()
        return

    if _tcp_connections >= settings.syslog_max_tcp_connections:
        _ingress_warning("syslog_tcp_connection_limit_reached", addr=addr, limit=settings.syslog_max_tcp_connections)
        writer.close()
        return

    _tcp_connections += 1
    task = asyncio.current_task()
    if task is not None:
        _tcp_tasks.add(task)
    _tcp_writers.add(writer)
    logger.info("syslog_tcp_client_connected", addr=addr, open_connections=_tcp_connections)

    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    reader.readline(), timeout=settings.syslog_tcp_idle_timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.info("syslog_tcp_client_idle_timeout", addr=addr)
                break
            except ValueError:
                # start_server's `limit` was exceeded before a newline arrived:
                # the peer is streaming one unbounded "line". Drop the connection
                # rather than trying to resynchronise.
                _ingress_warning("syslog_tcp_frame_too_large", addr=addr)
                break
            if not data:
                break

            message = data.decode("utf-8", errors="ignore").strip()
            if not message:
                continue

            logger.debug("syslog_tcp_received_raw", addr=addr, message=message[:200])
            payload = extract_json_payload(message)
            if payload:
                logger.debug("syslog_tcp_json_found", addr=addr)
                _enqueue(payload, addr, "tcp")
            else:
                _ingress_warning("syslog_tcp_no_json", addr=addr, message_preview=message[:100])

    except Exception as e:
        logger.error("syslog_tcp_client_error", addr=addr, error=str(e))
    finally:
        _tcp_connections -= 1
        _tcp_writers.discard(writer)
        if task is not None:
            _tcp_tasks.discard(task)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        logger.info("syslog_tcp_client_disconnected", addr=addr)


@dataclass
class SyslogHandles:
    """
    Holds the live UDP/TCP server handles so they can be gracefully stopped later.
    Either field may be None if that listener failed to bind (e.g. privileged port
    without root) — this is a non-fatal degraded state, matching prior behavior.
    """
    udp_transport: asyncio.DatagramTransport | None = None
    tcp_server: asyncio.AbstractServer | None = None


async def start() -> SyslogHandles:
    """
    Starts the UDP and TCP syslog listeners using settings from src.config.
    Binding failures (e.g. PermissionError on privileged ports) are logged and
    swallowed rather than raised, so the host process (the API server) keeps running.
    """
    global _queue, _client, _dropped_frames
    if _queue is not None:
        raise RuntimeError("syslog listeners are already started")
    loop = asyncio.get_running_loop()
    handles = SyslogHandles()

    # Stand the worker pool up before either listener binds, so no frame can
    # arrive with nowhere to go.
    _dropped_frames = 0
    _ingress_warning_counts.clear()
    _queue = asyncio.Queue(maxsize=settings.syslog_queue_size)
    _client = httpx.AsyncClient()
    _workers.clear()
    for _ in range(max(1, settings.syslog_workers)):
        _workers.append(asyncio.create_task(_worker()))

    allowlist = settings.syslog_allowed_sources.strip()
    if allowlist:
        logger.info("syslog_source_allowlist_active", sources=allowlist)
    else:
        logger.warning(
            "syslog_source_allowlist_empty",
            tip="SYSLOG_ALLOWED_SOURCES is blank: any host that can reach the syslog "
                "ports can inject alerts, each costing an AI call and a notification. "
                "Set it to the ESET PROTECT exporter address(es), or keep the ports on a "
                "trusted network only.",
        )

    try:
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: UDPProtocol(),
            local_addr=(settings.syslog_host, settings.syslog_udp_port)
        )
        handles.udp_transport = transport
        logger.info("syslog_udp_started", host=settings.syslog_host, port=settings.syslog_udp_port)
    except PermissionError:
        logger.critical(
            "syslog_udp_permission_denied",
            port=settings.syslog_udp_port,
            tip="Ports under 1024 require root/sudo access or iptables mapping."
        )
    except Exception as e:
        logger.error("syslog_udp_failed", error=str(e))

    try:
        tcp_server = await asyncio.start_server(
            handle_tcp_client,
            settings.syslog_host,
            settings.syslog_tcp_port,
            # Bounds the per-connection read buffer: readline() raises ValueError
            # past this instead of growing without limit on an unterminated line.
            limit=settings.syslog_max_frame_bytes,
        )
        handles.tcp_server = tcp_server
        logger.info("syslog_tcp_started", host=settings.syslog_host, port=settings.syslog_tcp_port)
    except PermissionError:
        logger.critical(
            "syslog_tcp_permission_denied",
            port=settings.syslog_tcp_port,
            tip="Ports under 1024 require root/sudo access or iptables mapping."
        )
    except Exception as e:
        logger.error("syslog_tcp_failed", error=str(e))

    if not handles.udp_transport and not handles.tcp_server:
        logger.critical("syslog_server_all_ports_failed")
        await stop(handles)

    return handles


async def stop(handles: SyslogHandles) -> None:
    """
    Gracefully closes any live syslog listener handles, then tears down the
    worker pool and the shared HTTP client. Listeners are closed first so no new
    frame can be enqueued while the workers are being cancelled.
    """
    global _queue, _client
    if handles.udp_transport:
        handles.udp_transport.close()
    if handles.tcp_server:
        handles.tcp_server.close()
    # Closing the server stops accepting but leaves existing connections alive.
    # Close and cancel those handlers before waiting for the server to finish.
    for writer in tuple(_tcp_writers):
        writer.close()
    tasks = tuple(_tcp_tasks)
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    if handles.tcp_server:
        await handles.tcp_server.wait_closed()

    for task in _workers:
        task.cancel()
    if _workers:
        await asyncio.gather(*_workers, return_exceptions=True)
    _workers.clear()
    _queue = None

    if _client is not None:
        await _client.aclose()
        _client = None

    logger.info("syslog_server_stopped", dropped_frames=_dropped_frames)
