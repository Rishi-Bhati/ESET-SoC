import json
from typing import Any
import structlog
from fastapi import WebSocket

logger = structlog.get_logger(__name__)


class EventBroadcaster:
    """
    Minimal in-process pub/sub for pushing live pipeline events to connected
    dashboard WebSocket clients. All broadcast calls are best-effort: a slow or
    dead client is dropped rather than blocking or failing the caller.
    """

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._clients.add(websocket)
        logger.info("dashboard_ws_connected", total_clients=len(self._clients))

    def disconnect(self, websocket: WebSocket) -> None:
        self._clients.discard(websocket)
        logger.info("dashboard_ws_disconnected", total_clients=len(self._clients))

    async def broadcast(self, event_type: str, data: dict[str, Any]) -> None:
        if not self._clients:
            return

        message = json.dumps({"type": event_type, "data": data}, default=str)
        dead: list[WebSocket] = []

        for client in self._clients:
            try:
                await client.send_text(message)
            except Exception:
                dead.append(client)

        for client in dead:
            self._clients.discard(client)
