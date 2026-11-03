"""
clarinet/routers/devicespeed.py
Per-device speed test. The device measures itself in its own browser:

  GET  /speed/device/probe/ping   nothing to download, to time the round trip
  GET  /speed/device/probe/down   a block of bytes to download
  POST /speed/device/probe/up     a block of bytes to upload (discarded)
  POST /speed/device/result       the numbers the browser measured, stored for the device it came from

The device is recognised by the address the request comes from, the same way
"This is my device" works. A member can only test (and so only store results for)
a device they own. An administrator can test the device they are using.
"""
import threading

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy.orm import Session

from clarinet.auth import client_ip, get_session_user
from clarinet.core_svc import device_speed
from clarinet.core_svc.accounts import detect_device, is_clarinet_host
from clarinet.database import get_db
from clarinet.models import Device
from clarinet.models.devspeed import DeviceSpeedResult

router = APIRouter(prefix="/speed/device", tags=["device-speed"])

# The computer that runs Clarinet cannot test its link to Clarinet (that would only be the computer talking to
# itself), so for that one device the test measures its own connection to the internet instead.
_host = {"running": False, "error": None}
_host_lock = threading.Lock()

MAX_PROBE_BYTES = 8 * 1024 * 1024
CHUNK = 64 * 1024
NO_STORE = {"Cache-Control": "no-store, no-transform", "Content-Encoding": "identity"}


def _unauthorised():
    return JSONResponse({"error": "Sign in first."}, status_code=401)


def _host_worker(device_id: int, member_id: int) -> None:
    from clarinet.collector.speed_test import _run_speedtest_cli
    from clarinet.database import SessionLocal
    error = None
    try:
        raw = _run_speedtest_cli()
        if raw is None:
            error = ("No speed test tool answered. Install one with: pip install speedtest-cli, "
                     "and check that this computer is online.")
        else:
            with SessionLocal() as db:
                device_speed.record(db, db.get(Device, device_id), member_id,
                                    raw["download_mbps"], raw["upload_mbps"], raw["latency_ms"])
    except device_speed.Refused as refused:
        error = str(refused)
    except Exception:
        error = "The test did not finish."
    with _host_lock:
        _host["running"], _host["error"] = False, error


@router.post("/host-test")
def start_host_test(request: Request, db: Session = Depends(get_db)):
    """Measure the internet connection of the computer that runs Clarinet, for that computer's own device."""
    user = get_session_user(request, db)
    if user is None:
        return _unauthorised()
    ip = client_ip(request)
    if not is_clarinet_host(ip):
        return JSONResponse({"error": "This is only for the computer that runs Clarinet."}, status_code=400)
    device = detect_device(db, ip)
    if device is None or not device_speed.may_measure(user, device):
        return JSONResponse({"error": "Press \"This is my device\" first, so the test can be saved for this computer."},
                            status_code=403)
    with _host_lock:
        if _host["running"]:
            return {"running": True}
        _host["running"], _host["error"] = True, None
    threading.Thread(target=_host_worker, args=(device.device_id, user.member_id), daemon=True).start()
    return {"running": True}


@router.get("/host-test/status")
def host_test_status(request: Request, db: Session = Depends(get_db)):
    if get_session_user(request, db) is None:
        return _unauthorised()
    with _host_lock:
        return dict(_host)


@router.get("/due")
def test_due(request: Request, db: Session = Depends(get_db)):
    """Should the page quietly test the device it is open on? Only the owner's device, and only when its
    last test is older than the interval. The page asks; the server decides, so every tab agrees."""
    user = get_session_user(request, db)
    if user is None:
        return _unauthorised()
    device = detect_device(db, client_ip(request))
    interval = device_speed.test_interval_minutes(db)
    if is_clarinet_host(client_ip(request)) or device is None or not device_speed.may_measure(user, device):
        return {"due": False, "interval_minutes": interval}
    from datetime import datetime, timedelta, timezone
    last = (db.query(DeviceSpeedResult).filter(DeviceSpeedResult.device_id == device.device_id)
            .order_by(DeviceSpeedResult.tested_at.desc()).first())
    if last is None:
        return {"due": True, "interval_minutes": interval}
    stamp = last.tested_at if last.tested_at.tzinfo else last.tested_at.replace(tzinfo=timezone.utc)
    return {"due": datetime.now(timezone.utc) - stamp >= timedelta(minutes=interval), "interval_minutes": interval}


@router.get("/probe/ping")
def probe_ping(request: Request, db: Session = Depends(get_db)):
    if get_session_user(request, db) is None:
        return _unauthorised()
    return Response(status_code=204, headers=NO_STORE)


@router.get("/probe/down")
def probe_down(request: Request, bytes: int = 1_000_000, db: Session = Depends(get_db)):
    if get_session_user(request, db) is None:
        return _unauthorised()
    size = max(1, min(int(bytes), MAX_PROBE_BYTES))

    def blocks():
        left, block = size, b"\0" * CHUNK
        while left > 0:
            part = block if left >= CHUNK else block[:left]
            left -= len(part)
            yield part

    return StreamingResponse(blocks(), media_type="application/octet-stream",
                             headers={**NO_STORE, "Content-Length": str(size)})


@router.post("/probe/up")
async def probe_up(request: Request, db: Session = Depends(get_db)):
    if get_session_user(request, db) is None:
        return _unauthorised()
    received = 0
    async for part in request.stream():
        received += len(part)
        if received > MAX_PROBE_BYTES:
            return JSONResponse({"error": "That is more than a test needs."}, status_code=413)
    return JSONResponse({"received": received}, headers=NO_STORE)


@router.post("/result")
async def store_result(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if user is None:
        return _unauthorised()
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError
    except ValueError:
        return JSONResponse({"error": "The measurement was not valid."}, status_code=400)

    if is_clarinet_host(client_ip(request)):
        return JSONResponse({"error": "Clarinet runs on this computer, so a test here would only measure the computer "
                                      "itself, not your network. Open Clarinet from another device on the network."}, status_code=422)
    device = detect_device(db, client_ip(request))
    if device is None:
        return JSONResponse({"error": "Clarinet does not recognise the device you are using yet. "
                                       "Wait a minute for it to be found, then try again."}, status_code=409)
    if not device_speed.may_measure(user, device):
        return JSONResponse({"error": "This device is not yours. Claim it on the Devices page first."}, status_code=403)
    try:
        row = device_speed.record(db, device, user.member_id, body.get("download_mbps"), body.get("upload_mbps"),
                                  body.get("latency_ms"), body.get("jitter_ms"))
    except device_speed.Refused as refused:
        return JSONResponse({"error": str(refused)}, status_code=422)

    summary = device_speed.summary(db, device)
    from clarinet.core_svc.alerts import raise_alert
    from clarinet.core_svc.device_names import device_name
    from clarinet.models import Alert
    if summary.status in ("slower", "much_slower"):
        why = (f"Its speed was {row.download_mbps:.1f} Mbps; it usually gets about {summary.baseline_mbps:.1f} Mbps."
               if summary.reason == "speed" else
               f"Its delay was {row.latency_ms:.0f} ms; it is usually about {summary.baseline_latency_ms:.0f} ms.")
        raise_alert(db, level="CRITICAL" if summary.status == "much_slower" else "WARNING", type="SLOWDOWN",
                    title=(f"{device_name(device)} is {summary.slowdown_pct}% slower than usual" if summary.reason == "speed"
                           else f"{device_name(device)} has a long delay"),
                    message=why, device_id=device.device_id, cooldown_s=3600)
    elif summary.status == "ok":                       # back to normal: the old alert is no longer true
        db.query(Alert).filter(Alert.type == "SLOWDOWN", Alert.device_id == device.device_id,
                               Alert.status == "OPEN").update({"status": "RESOLVED"})
        db.commit()
    return {"ok": True, "device_id": device.device_id, "result_id": row.result_id,
            "status": summary.status, "slowdown_pct": summary.slowdown_pct}
