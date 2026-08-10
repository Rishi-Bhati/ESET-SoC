import asyncio
import re
import httpx
import structlog
from src.config import settings
from src.utils.logging import setup_logging

# Simple setup for syslog logger
logger = structlog.get_logger(__name__)

# Regex to find JSON object in the syslog message
JSON_RE = re.compile(r"(\{.*\})")

def extract_json_payload(raw_message: str) -> dict | None:
    """
    Search and extract embedded JSON payload within syslog message.
    """
    match = JSON_RE.search(raw_message)
    if not match:
        return None
        
    try:
        import json
        return json.loads(match.group(1))
    except Exception:
        return None

async def forward_to_api(payload: dict) -> None:
    """
    Forwards parsed syslog payload to the FastAPI webhook endpoint.
    """
    # Build endpoint URL pointing to local FastAPI instance
    url = f"http://127.0.0.1:{settings.app_port}/webhook/syslog"
    headers = {
        "Authorization": f"Bearer {settings.eset_webhook_auth_token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            logger.info("syslog_forwarding_start", url=url)
            # Use settings limits for timeouts
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
                # Fire and forget forwarding in event loop task
                asyncio.create_task(forward_to_api(payload))
            else:
                logger.warning("syslog_udp_no_json", addr=addr, message_preview=message[:100])
        except Exception as e:
            logger.error("syslog_udp_processing_failed", error=str(e))

async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Handles TCP client connection for Syslog messages.
    """
    addr = writer.get_extra_info("peername")
    logger.info("syslog_tcp_client_connected", addr=addr)
    
    try:
        # Read lines from stream (each syslog message is usually newline-terminated)
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

async def main() -> None:
    # Setup structured logging to log to a dedicated syslog file
    setup_logging(settings.log_level, log_file="logs/syslog_server.log")
    logger.info("syslog_server_starting")
    
    loop = asyncio.get_running_loop()
    
    # 1. Start UDP Server
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPProtocol(),
            local_addr=(settings.syslog_host, settings.syslog_udp_port)
        )
        logger.info("syslog_udp_started", host=settings.syslog_host, port=settings.syslog_udp_port)
    except PermissionError:
        logger.critical(
            "syslog_udp_permission_denied", 
            port=settings.syslog_udp_port,
            tip="Ports under 1024 require root/sudo access or iptables mapping."
        )
        transport = None
    except Exception as e:
        logger.error("syslog_udp_failed", error=str(e))
        transport = None

    # 2. Start TCP Server
    tcp_server = None
    try:
        tcp_server = await asyncio.start_server(
            handle_tcp_client,
            settings.syslog_host,
            settings.syslog_tcp_port
        )
        logger.info("syslog_tcp_started", host=settings.syslog_host, port=settings.syslog_tcp_port)
    except PermissionError:
        logger.critical(
            "syslog_tcp_permission_denied", 
            port=settings.syslog_tcp_port,
            tip="Ports under 1024 require root/sudo access or iptables mapping."
        )
    except Exception as e:
        logger.error("syslog_tcp_failed", error=str(e))
        
    if not transport and not tcp_server:
        logger.critical("syslog_server_all_ports_failed")
        return
        
    try:
        # Keep running
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("syslog_server_cancelled")
    finally:
        if transport:
            transport.close()
        if tcp_server:
            tcp_server.close()
            await tcp_server.wait_closed()
        logger.info("syslog_server_stopped")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
