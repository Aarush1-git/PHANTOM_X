import json
from typing import Dict, List, Any
from fastapi import WebSocket
from uuid import UUID


class WebSocketConnectionManager:
    """Manages active WebSocket connections for live scan streaming and telemetry."""

    def __init__(self):
        # Map scan_id string -> List of WebSockets
        self.active_scan_connections: Dict[str, List[WebSocket]] = {}
        # Global broadcast connections (e.g., live alert feeds)
        self.global_connections: List[WebSocket] = []

    async def connect_scan(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        if scan_id not in self.active_scan_connections:
            self.active_scan_connections[scan_id] = []
        self.active_scan_connections[scan_id].append(websocket)

    def disconnect_scan(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.active_scan_connections:
            if websocket in self.active_scan_connections[scan_id]:
                self.active_scan_connections[scan_id].remove(websocket)
            if not self.active_scan_connections[scan_id]:
                del self.active_scan_connections[scan_id]

    async def connect_global(self, websocket: WebSocket):
        await websocket.accept()
        self.global_connections.append(websocket)

    def disconnect_global(self, websocket: WebSocket):
        if websocket in self.global_connections:
            self.global_connections.remove(websocket)

    async def broadcast_to_scan(self, scan_id: str, message: Dict[str, Any]):
        """Send live progress/finding event to all clients monitoring a scan."""
        if scan_id in self.active_scan_connections:
            payload = json.dumps(message)
            for connection in list(self.active_scan_connections[scan_id]):
                try:
                    await connection.send_text(payload)
                except Exception:
                    self.disconnect_scan(scan_id, connection)

    async def broadcast_global(self, message: Dict[str, Any]):
        """Broadcast event to all dashboard operators."""
        payload = json.dumps(message)
        for connection in list(self.global_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                self.disconnect_global(connection)


ws_manager = WebSocketConnectionManager()

