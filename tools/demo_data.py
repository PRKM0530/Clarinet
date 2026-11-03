"""Fill a database with a small demonstration network, so every page of Clarinet has something to show.

    python tools/demo_data.py                  creates clarinet_demo.db in the project folder

Then start the application on it (see the README):
    DATABASE_URL=sqlite:///./clarinet_demo.db python run.py          (Linux, macOS, Git Bash)
    $env:DATABASE_URL="sqlite:///./clarinet_demo.db"; python run.py  (Windows PowerShell)

Accounts:  praveen / pw-admin-123 (administrator)   asha / pw-asha-1234, ravi / pw-ravi-1234, meera / pw-meera-123 (members)
The data is invented. Devices and numbers do not describe any real network.
"""
import math
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "clarinet_demo.db"
if DB.exists():
    DB.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{DB.as_posix()}"
os.environ.setdefault("SECRET_KEY", "demo-secret-key")
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from clarinet.auth import hash_password  # noqa: E402
from clarinet.database import Base, SessionLocal, engine  # noqa: E402
import clarinet.models  # noqa: E402,F401
from clarinet.models import (  # noqa: E402
    Alert, AuditLog, Device, Member, PingRecord, PriorityGrant, Settings, SlowdownEvent, SpeedTestResult, TimeRule,
    UsageRecord, Voucher,
)
from clarinet.models.devspeed import DeviceSpeedResult  # noqa: E402
from clarinet.models.security import KnownNetwork, RouterAuditFinding, SeenAccessPoint, TrustedAccessPoint  # noqa: E402
from clarinet.models.traffic import CollectorHeartbeat, UsageActivity  # noqa: E402

Base.metadata.create_all(bind=engine)

random.seed(11)
now = datetime.now(timezone.utc)
with SessionLocal() as db:
    for k, v in {"setup_complete": "true", "network_mode": "FULL", "plan_download_mbps": "100", "plan_upload_mbps": "20",
                 "billing_day": "1", "limit.bytes": str(300 * 1024 ** 3), "timezone": "Asia/Kolkata",
                 "hold_new_devices": "true", "device_test_interval_minutes": "60", "router_ip": "192.168.1.1"}.items():
        db.add(Settings(key=k, value=v))
    praveen = Member(username="praveen", password_hash=hash_password("pw-admin-123"), role="ADMIN")
    asha = Member(username="asha", password_hash=hash_password("pw-asha-1234"), role="MEMBER")
    ravi = Member(username="ravi", password_hash=hash_password("pw-ravi-1234"), role="MEMBER")
    meera = Member(username="meera", password_hash=hash_password("pw-meera-123"), role="MEMBER")
    db.add_all([praveen, asha, ravi, meera])
    db.flush()
    spec = [
        ("A4:83:E7:10:00:01", "192.168.1.11", "Praveen's laptop", "praveen-laptop", "Dell", "APPROVED", praveen, "ph"),
        ("A4:83:E7:10:00:02", "192.168.1.12", "Praveen's phone", "pixel-8", "Google", "APPROVED", praveen, "ph"),
        ("3C:22:FB:20:00:03", "192.168.1.13", "Asha's laptop", "asha-macbook", "Apple", "APPROVED", asha, "lap"),
        ("3C:22:FB:20:00:04", "192.168.1.14", "Asha's phone", "iphone-asha", "Apple", "APPROVED", asha, "ph"),
        ("F0:2F:74:30:00:05", "192.168.1.15", "Ravi's desktop", "ravi-pc", "ASUSTek", "APPROVED", ravi, "pc"),
        ("F0:2F:74:30:00:06", "192.168.1.16", "Ravi's phone", "galaxy-s23", "Samsung", "APPROVED", ravi, "ph"),
        ("B8:27:EB:40:00:07", "192.168.1.17", "Meera's tablet", "ipad-meera", "Apple", "APPROVED", meera, "ph"),
        ("D8:3A:DD:50:00:08", "192.168.1.20", "Living room TV", "bravia-tv", "Sony", "APPROVED", None, "tv"),
        ("B8:27:EB:50:00:09", "192.168.1.21", "Home server", "raspberrypi", "Raspberry Pi", "APPROVED", None, "srv"),
        ("00:1B:A9:50:00:0A", "192.168.1.22", "Hall printer", "brother-hl", "Brother", "APPROVED", None, "pr"),
        ("7C:2F:80:50:00:0B", "192.168.1.30", None, "unknown-esp32", "Espressif", "NEW", None, "iot"),
        ("02:1A:2B:3C:4D:5E", "192.168.1.31", None, None, None, "NEW", None, "ph"),
        ("DC:A6:32:60:00:0C", "192.168.1.40", "Guest tablet", None, "Apple", "GUEST", None, "ph"),
        ("00:11:22:AA:BB:CC", "192.168.1.50", "Old camera", "ipcam", "Hikvision", "BLOCKED", None, "iot"),
    ]
    rows = {}
    for mac, ip, label, host, vendor, state, owner, kind in spec:
        d = Device(mac_address=mac, ip_address=ip, label=label, hostname=host, vendor=vendor, state=state, is_random_mac=(mac.startswith("02")),
                   owner_member_id=owner.member_id if owner else None, first_seen=now - timedelta(days=30), last_seen=now - timedelta(minutes=random.randint(0, 4)))
        db.add(d)
        db.flush()
        rows[mac] = (d, kind)

    # usage by hour (stored in UTC buckets), heavier in the evening in India
    base = {"ph": 90, "lap": 160, "pc": 220, "tv": 380, "srv": 60, "pr": 2, "iot": 1}
    for mac, (d, kind) in rows.items():
        if d.state in ("NEW", "BLOCKED"):
            continue
        for back in range(9):
            day = (now - timedelta(days=back)).date()
            for hour in range(24):
                local_hour = (hour + 5.5) % 24
                weight = 0.15 + 1.0 * math.exp(-((local_hour - 21) ** 2) / 8) + 0.5 * math.exp(-((local_hour - 13) ** 2) / 10)
                size = base[kind] * weight * random.uniform(0.5, 1.5) * 1_000_000
                if back == 0 and hour > now.hour:
                    continue
                db.add(UsageRecord(device_id=d.device_id, date=day.isoformat(), hour=hour, bytes_in=int(size), bytes_out=int(size * random.uniform(0.05, 0.3))))
    mixes = {"lap": {"STREAMING": 4, "BROWSING": 5, "CALLS": 2, "UPDATES": 1}, "ph": {"STREAMING": 5, "BROWSING": 3, "GAMING": 1, "CALLS": 1},
             "pc": {"GAMING": 6, "DOWNLOAD": 3, "STREAMING": 2, "UPDATES": 1}, "tv": {"STREAMING": 10}, "srv": {"UPDATES": 2, "DOWNLOAD": 1}}
    for mac, (d, kind) in rows.items():
        for cat, w in mixes.get(kind, {}).items():
            for back in range(7):
                day = (now - timedelta(days=back)).date().isoformat()
                db.add(UsageActivity(device_id=d.device_id, date=day, hour=14, category=cat, bytes_in=w * 55_000_000, bytes_out=w * 3_000_000))

    # each device's own speed tests: mostly steady, Asha's phone slowed down this evening
    def tests(device, usual, slow=False, spread_min=60):
        for i in range(10):
            t = now - timedelta(minutes=spread_min * (10 - i) + random.randint(-6, 6))
            speed = usual * random.uniform(0.88, 1.08)
            if slow and i >= 8:
                speed = usual * random.uniform(0.42, 0.5)
            db.add(DeviceSpeedResult(device_id=device.device_id, tested_at=t, download_mbps=round(speed, 1), upload_mbps=round(speed * 0.35, 1),
                                     latency_ms=round(random.uniform(4, 9) * (3 if slow and i >= 8 else 1), 1), jitter_ms=round(random.uniform(0.4, 2), 1)))
    tests(rows["A4:83:E7:10:00:01"][0], 410)
    tests(rows["A4:83:E7:10:00:02"][0], 96)
    tests(rows["3C:22:FB:20:00:03"][0], 180)
    tests(rows["3C:22:FB:20:00:04"][0], 64, slow=True)
    tests(rows["F0:2F:74:30:00:05"][0], 940)
    tests(rows["B8:27:EB:40:00:07"][0], 48)

    for i in range(14):
        db.add(SpeedTestResult(tested_at=now - timedelta(hours=6 * i), download_mbps=round(random.choice([94, 91, 97, 88, 62, 95, 93]) * random.uniform(0.97, 1.02), 1),
                               upload_mbps=round(random.choice([18.5, 19, 17.5, 12.4]), 1), latency_ms=random.randint(12, 30), busy=False, server_host="speedtest.net"))
    for minute in range(180, 0, -1):
        t = now - timedelta(minutes=minute)
        for target, host, mean in (("router", "192.168.1.1", 2.5), ("cloudflare", "1.1.1.1", 14), ("google_dns", "8.8.8.8", 18)):
            spike = 3.0 if 60 < minute < 75 else 1.0
            db.add(PingRecord(measured_at=t, target=target, host=host, avg_ms=round(mean * spike * random.uniform(0.8, 1.4), 1), min_ms=mean * 0.8,
                              max_ms=mean * 1.6, packet_loss=0.0, reachable=True))
    for name, secs in (("pinger", 60), ("arp_scanner", 15), ("traffic_counter", 60)):
        db.add(CollectorHeartbeat(collector=name, last_seen=now.replace(tzinfo=None) - timedelta(seconds=random.randint(1, 8)), interval_s=secs, ok=True))

    dev = lambda mac: rows[mac][0]
    for i, (lvl, typ, title, msg, device) in enumerate([
        ("WARNING", "SLOWDOWN", "Asha's phone is 52% slower than usual", "Its speed was 31.4 Mbps; it usually gets about 64.8 Mbps.", dev("3C:22:FB:20:00:04")),
        ("INFO", "NEW_DEVICE", "2 devices found on your network", "These are the devices Clarinet found on its first scan. Open Devices to approve the ones you know.", None),
        ("WARNING", "NEW_DEVICE", "New device detected", "Unknown device 7C:2F:80:30:00:0B (Espressif) joined from 192.168.1.30.", dev("7C:2F:80:50:00:0B")),
        ("CRITICAL", "ARP_SPOOF", "ARP spoofing detected on 192.168.1.1", "IP 192.168.1.1 answered as a different hardware address than before.", None),
        ("WARNING", "FAKE_AP", "Possible fake access point: HomeNet", "Same name as your network but not a trusted access point.", None),
        ("INFO", "DATA_LIMIT_WARN", "Data limit warning", "Used 212.4 GB of 300.0 GB (71%). 9 day(s) remaining.", None)]):
        db.add(Alert(level=lvl, type=typ, title=title, message=msg, device_id=device.device_id if device else None, raised_at=now - timedelta(minutes=17 * (i + 1))))
    db.add(SlowdownEvent(started_at=now - timedelta(days=1, hours=2), ended_at=now - timedelta(days=1, hours=1, minutes=35),
                         causes_json='[{"cause": "ONE_DEVICE_HEAVY", "confidence": "likely", "evidence": "Ravi\'s desktop used 71% of the network.", "suggestion": "Pause large downloads on that device."}]',
                         raw_metrics_json='{"internet_ms": 62, "router_ms": 3, "plan_ratio": 0.58}'))
    db.add(SlowdownEvent(started_at=now - timedelta(days=3, hours=5), ended_at=now - timedelta(days=3, hours=4, minutes=10),
                         causes_json='[{"cause": "PROVIDER_ISSUE", "confidence": "possible", "evidence": "The router answers fast but the internet is slow.", "suggestion": "Wait and check again; contact the provider if it keeps happening."}]'))
    db.add(Voucher(code="K7M2-QX9P", data_cap_mb=2048, status="UNUSED", created_by=praveen.member_id, expires_at=now + timedelta(hours=5)))
    db.add(Voucher(code="T4N8-ZR3W", speed_cap_mbps=10.0, status="USED", created_by=praveen.member_id, expires_at=now + timedelta(minutes=40)))
    db.add(PriorityGrant(device_id=dev("3C:22:FB:20:00:03").device_id, member_id=asha.member_id, decision="PENDING", requested_at=now - timedelta(minutes=9),
                         duration_min=60, reason="Video interview at 6 PM"))
    db.add(TimeRule(device_id=dev("B8:27:EB:40:00:07").device_id, days_json='["Mon","Tue","Wed","Thu","Fri"]', start_time="22:00", end_time="06:30", action="BLOCK", created_by=praveen.member_id, active=True))
    db.add(TimeRule(device_id=dev("F0:2F:74:30:00:05").device_id, days_json='["Sat","Sun"]', start_time="01:00", end_time="07:00", action="RATE_LIMIT", rate_kbps=2000, created_by=praveen.member_id, active=True))
    db.add(TrustedAccessPoint(ssid="HomeNet", bssid="AA:AA:AA:AA:AA:01", label="Router"))
    db.add(SeenAccessPoint(bssid="AA:AA:AA:AA:AA:01", ssid="HomeNet", signal=88, security="WPA2", verdict="OK", first_seen=now, last_seen=now))
    db.add(SeenAccessPoint(bssid="11:22:33:44:55:66", ssid="HomeNet", signal=95, security="Open", verdict="SUSPECT", first_seen=now, last_seen=now,
                           reason="Same name as your network but not a trusted access point, and it has no password"))
    db.add(SeenAccessPoint(bssid="22:33:44:55:66:77", ssid="NeighbourWiFi", signal=40, security="WPA2", verdict="UNKNOWN", first_seen=now, last_seen=now))
    db.add(KnownNetwork(gateway_mac="AA:BB:CC:00:00:01", gateway_ip="192.168.1.1", ssid="HomeNet", label="Learned on first run", trusted=True))
    for sev, title, detail in (("HIGH", "Telnet is open on the router", "Telnet sends passwords in the clear. Turn it off in the router settings."),
                               ("MEDIUM", "UPnP is switched on", "Turn UPnP off unless a game or app needs it."),
                               ("OK", "The router's web page uses HTTPS", "")):
        db.add(RouterAuditFinding(run_id="demo", gateway_ip="192.168.1.1", check="x", severity=sev, title=title, detail=detail))
    for action, target in (("APPROVE_DEVICE", "Asha's laptop"), ("SET_DEVICE_OWNER", "Ravi's desktop"), ("CREATE_VOUCHER", "K7M2-QX9P")):
        db.add(AuditLog(actor_id=praveen.member_id, action=action, target_type="Device", target_id="1", detail_json='{"label": "%s"}' % target))
    db.commit()

print("demo database written to", DB)
print("start it with:  DATABASE_URL=sqlite:///./clarinet_demo.db python run.py")
