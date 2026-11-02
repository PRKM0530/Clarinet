"""
clarinet/routers/ws.py
WebSocket endpoint for live alert push to the dashboard.

M1 OWNS THIS FILE — do not edit in other branches.

Contracts (C-02):
  - set_event_loop(loop)         — called by the app startup to register the running loop
  - broadcast_alert_sync(data)   — thread-safe, never raises, for use from APScheduler threads
  - broadcast_alert(data)        — async, sends to all authenticated clients

Security:
  - WS connection requires a valid session (F-12 fix)
  - Members see only {type, level} — no full alert text (role-aware broadcast)
  - Heartbeat: clients send "ping", server replies "pong"
"""

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

log = logging.getLogger("clarinet.ws")

router = APIRouter(tags=["websocket"])

# All currently connected dashboard clients mapped to their role
_clients: dict["WebSocket", str] = {}  # websocket → role ("ADMIN" | "MEMBER")

# The running asyncio event loop, set by the app startup (C-02)
_loop: "asyncio.AbstractEventLoop | None" = None


def set_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    """
    Register the running asyncio event loop so that broadcast_alert_sync
    can schedule coroutines from APScheduler / collector threads.
    Call this from app startup before starting the scheduler.
    (C-02 contract)
    """
    global _loop
    _loop = loop


@router.websocket("/ws/alerts")
async def alerts_ws(websocket: WebSocket) -> None:
    """
    WebSocket handler for live alert notifications.
    Requires a valid authenticated session (closes with 4401 if not logged in).
    """
    # Login check before accepting (F-12 fix)
    from clarinet.auth import get_session_user
    from clarinet.database import SessionLocal

    with SessionLocal() as db:
        user = get_session_user(websocket, db)

    if user is None:
        await websocket.close(code=4401)
        return

    role = user.role

    await websocket.accept()
    _clients[websocket] = role
    log.debug("WS connected: user=%s role=%s", user.username, role)

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.debug("WS error: %s", exc)
    finally:
        _clients.pop(websocket, None)


async def broadcast_alert(alert_data: dict[str, Any]) -> None:
    """
    Send alert JSON to all connected clients.
    Admins receive full alert_data; Members receive only {type, level}.
    """
    dead: list["WebSocket"] = []
    for ws, role in list(_clients.items()):
        try:
            if role == "ADMIN":
                payload = json.dumps(alert_data)
            else:
                # Members see only enough to show a badge — not the full message
                payload = json.dumps({
                    "type": alert_data.get("type", "ALERT"),
                    "level": alert_data.get("level", "INFO"),
                })
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _clients.pop(ws, None)


def broadcast_alert_sync(alert_data: dict[str, Any]) -> None:
    """
    Thread-safe wrapper — used from APScheduler / collector threads.
    Uses the registered event loop (set_event_loop); never raises.
    (C-02 contract)
    """
    global _loop
    try:
        loop = _loop
        if loop is not None and loop.is_running():
            asyncio.run_coroutine_threadsafe(broadcast_alert(alert_data), loop)
        else:
            # Fallback: try to get the running loop from the calling thread
            try:
                running = asyncio.get_event_loop()
                if running.is_running():
                    asyncio.run_coroutine_threadsafe(broadcast_alert(alert_data), running)
            except RuntimeError:
                pass  # No loop available (tests etc.) — silently discard
    except Exception as exc:
        log.debug("broadcast_alert_sync failed silently: %s", exc)
