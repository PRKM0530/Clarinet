"""
Real router audit against a router YOU OWN (SEC-01, real part). Not a pytest file.

    python tests/host/real_router_audit.py --yes-i-own-this-router

It refuses to run unless the flag is given, uses its own database, and prints the gateway first.
The audit checks 8 TCP ports and UPnP and, only if a web admin page on port 80 or 8080 asks for HTTP Basic
login, tries up to 6 default passwords. Do not point it at a campus, office or ISP router.
"""
import argparse
import os
import sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--yes-i-own-this-router", action="store_true")
args = ap.parse_args()
if not args.yes_i_own_this_router:
    sys.exit("refusing to run: pass --yes-i-own-this-router only for a router you own")

home = Path.home() / "clarinet-hotspot"
home.mkdir(exist_ok=True)
db_file = home / "router_audit.db"
if db_file.exists():
    db_file.unlink()
os.environ.update(DATABASE_URL=f"sqlite:///{db_file}", SECRET_KEY="audit-check-not-a-secret", APP_ENV="production")
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from clarinet.database import Base, SessionLocal, engine  # noqa: E402
import clarinet.models  # noqa: E402,F401
from clarinet.collector import network_check, router_audit  # noqa: E402
from clarinet.models import Alert  # noqa: E402
from clarinet.models.security import RouterAuditFinding  # noqa: E402

Base.metadata.create_all(bind=engine)
gateway = network_check.get_gateway_ip()
print("gateway to be audited:", gateway)
if not gateway:
    sys.exit("no default gateway")

with SessionLocal() as db:
    out = router_audit.run_audit(db)
    print("audit result:", out)
    for f in db.query(RouterAuditFinding).order_by(RouterAuditFinding.severity):
        print(f"  {f.severity:6} {f.check:20} {f.title}")
    for a in db.query(Alert):
        print("alert:", a.level, a.type, "|", a.title)
