"""
Real-host Wi-Fi / network checks (SEC-04, SEC-05). NOT a pytest file: run it once per network you are on.

    python tests/host/hotspot_check.py --step 1 --reset   # on your usual network: learns it, then re-checks
    python tests/host/hotspot_check.py --step 2           # after switching to the phone hotspot
    python tests/host/hotspot_check.py --step 2 --scan-only  # usual network + a lookalike hotspot nearby
    python tests/host/hotspot_check.py --step 3           # after switching back to the usual network

It uses a separate database (~/clarinet-hotspot/hotspot.db), only READS the OS Wi-Fi list (nmcli),
and sends one ping to the default gateway to learn its MAC. It attacks nothing and changes no settings.
"""
import argparse
import os
import sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--step", type=int, required=True)
ap.add_argument("--reset", action="store_true")
ap.add_argument("--scan-only", action="store_true", help="only scan for fake access points; skip the network check")
args = ap.parse_args()

home = Path.home() / "clarinet-hotspot"
home.mkdir(exist_ok=True)
db_file = home / "hotspot.db"
if args.reset and db_file.exists():
    db_file.unlink()
os.environ.update(DATABASE_URL=f"sqlite:///{db_file}", SECRET_KEY="hotspot-check-not-a-secret", APP_ENV="production")
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from clarinet.database import Base, SessionLocal, engine  # noqa: E402
import clarinet.models  # noqa: E402,F401
from clarinet.collector import network_check, wifi_scan  # noqa: E402
from clarinet.models import Alert  # noqa: E402
from clarinet.models.security import KnownNetwork, SeenAccessPoint, TrustedAccessPoint  # noqa: E402

Base.metadata.create_all(bind=engine)
print(f"== step {args.step}; database {db_file}")

cur = wifi_scan.current_connection()
print("connected Wi-Fi:", (cur.ssid, cur.bssid) if cur else None)
info = network_check.current_network()
print("network:", info)

with SessionLocal() as db:
    before = {a.alert_id for a in db.query(Alert)}
    scan = wifi_scan.scan_and_evaluate(db)
    print("wifi scan summary:", scan)
    verdict = None if args.scan_only else network_check.check_and_evaluate(db)
    print("network verdict (1st):", verdict)
    if args.step == 1:
        print("network verdict (2nd, should be KNOWN):", network_check.check_and_evaluate(db))

    print("\ntrusted access points:", [(t.ssid, t.bssid) for t in db.query(TrustedAccessPoint)])
    print("known networks:", [(k.ssid, k.gateway_mac, k.trusted) for k in db.query(KnownNetwork)])
    suspects = db.query(SeenAccessPoint).filter(SeenAccessPoint.verdict == "SUSPECT").all()
    shown = [x for x in suspects if x.ssid != (cur.ssid if cur else None)] if args.step == 2 and args.scan_only else suspects
    print(f"suspect access points ({len(suspects)}; showing {len(shown)} with a name different from the connected one):")
    for s in shown:
        print("  ", s.ssid, s.bssid, "|", s.security or "open", "|", s.reason)
    new = [a for a in db.query(Alert) if a.alert_id not in before]
    print(f"\nalerts raised in this run ({len(new)}):")
    for a in new:
        print("  ", a.level, a.type, "|", a.title)
