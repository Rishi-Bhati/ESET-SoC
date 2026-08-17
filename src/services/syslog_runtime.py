import asyncio
import re
import json
from dataclasses import dataclass
import httpx
import structlog
from src.config import settings

logger = structlog.get_logger(__name__)

JSON_RE = re.compile(r"(\{.*\})")


def extract_json_payload(raw_message: str) -> dict | None:
    """
    Search and extract embedded JSON payload within a syslog message.
    """
    match = JSON_RE.search(raw_message)
    if not match:
        return None

    try:
        return json.loads(match.group(1))
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

    async with httpx.AsyncClient() as client:
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


class UDPProtocol(asyncio.DatagramProtocol):
    """
    Asyncio Datagram Protocol to handle UDP Syslog messages.
    """
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            message = data.decode("utf-8", errors="ignore").strip()
            logger.debug("syslog_udp_received_raw", addr=addr, message=message[:200])

            payload = extract_json_payload(message)
            if payload:
                logger.info("syslog_udp_json_found", addr=addr)
                asyncio.create_task(forward_to_api(payload))
            else:
                logger.warning("syslog_udp_no_json", addr=addr, message_preview=message[:100])
        except Exception as e:
            logger.error("syslog_udp_processing_failed", error=str(e))


async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Handles a TCP client connection for Syslog messages.
    """
    addr = writer.get_extra_info("peername")
    logger.info("syslog_tcp_client_connected", addr=addr)

    try:
        while True:
            data = await reader.readline()
            if not data:
                break

            message = data.decode("utf-8", errors="ignore").strip()
            if not message:
                continue

            logger.debug("syslog_tcp_received_raw", addr=addr, message=message[:200])
            payload = extract_json_payload(message)
            if payload:
                logger.info("syslog_tcp_json_found", addr=addr)
                asyncio.create_task(forward_to_api(payload))
            else:
                logger.warning("syslog_tcp_no_json", addr=addr, message_preview=message[:100])

    except Exception as e:
        logger.error("syslog_tcp_client_error", addr=addr, error=str(e))
    finally:
        writer.close()
        await writer.wait_closed()
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
    loop = asyncio.get_running_loop()
    handles = SyslogHandles()

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
            settings.syslog_tcp_port
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

    return handles


async def stop(handles: SyslogHandles) -> None:
    """
    Gracefully closes any live syslog listener handles.
    """
    if handles.udp_transport:
        handles.udp_transport.close()
    if handles.tcp_server:
        handles.tcp_server.close()
        await handles.tcp_server.wait_closed()
    logger.info("syslog_server_stopped")
