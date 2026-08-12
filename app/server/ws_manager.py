"""WebSocket connection manager (see docs/ARCHITECTURE.md §3.5).

Deliberately has no knowledge of HAL state, metrics, or business logic — it
only tracks active connections and broadcasts pre-built messages. This
avoids a circular import between this module and `routes_common.py`
(which owns state-snapshot construction) / `main.py` (which owns the
telemetry background task).
"""

from __future__ import annotations

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        """Send `message` to every active connection.

        Iterates over a *copy* of the connection list (impediment §4.9):
        `disconnect()` mutates the original list, which would corrupt a live
        iteration. Connections that raise on send (abrupt disconnects) are
        removed rather than propagating the exception.
        """
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


# Module-level singleton, shared across the whole process (same pattern as
# `app/hal/hal.py`'s `hal`).
manager = ConnectionManager()
