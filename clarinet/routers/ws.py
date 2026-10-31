"""
clarinet/routers/ws.py
WebSocket endpoint for live alert push to the dashboard.

The server broadcasts a JSON message to all connected clients whenever
a new alert is created by the collector or analytics modules.
"""

import asyncio
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["websocket"])

# All currently connected dashboard clients
_clients: set[WebSocket] = set()


@router.websocket("/ws/alerts")
async def alerts_ws(websocket: WebSocket):
    await websocket.accept()
    _clients.add(websocket)
    try:
        # Keep connection alive; client sends pings
        while True:
            data = await websocket.receive_text()
            # Echo back ping as pong
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        _clients.discard(websocket)


async def broadcast_alert(alert_data: dict[str, Any]) -> None:
    """
    Called from the collector / analytics when a new alert is raised.
    Sends JSON to all connected WebSocket clients.
    """
    message = json.dumps(alert_data)
    dead = set()
    for ws in list(_clients):
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    _clients.difference_update(dead)


def broadcast_alert_sync(alert_data: dict[str, Any]) -> None:
    """
    Thread-safe wrapper for the broadcast — used from APScheduler / collector
    threads which are not running inside an asyncio event loop.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(broadcast_alert(alert_data))
        else:
            loop.run_until_complete(broadcast_alert(alert_data))
    except RuntimeError:
        # No event loop — we're probably running in a test
        pass
