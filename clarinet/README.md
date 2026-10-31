# 🎵 Clarinet — Network Monitor & Manager

> A home / small-office network monitoring and management dashboard built
> as a 3rd-year CSE project. Monitors devices, traffic usage, internet speed,
> and enforces time-based access rules.

---

## Tech Stack

| Layer | Tool |
|---|---|
| Language | Python 3.12 |
| Web framework | FastAPI + Uvicorn |
| Templates | Jinja2 |
| Auth | HttpOnly signed session cookie (itsdangerous) + bcrypt |
| Database | SQLite (WAL mode) via SQLAlchemy 2 |
| CSS | Bootstrap 5 (dark) + custom Clarinet theme |
| Charts | Chart.js |
| Real-time | FastAPI WebSockets → toast alerts |
| Scheduler | APScheduler (speed tests, voucher expiry, baselines) |
| Analytics | pandas + NumPy (baselines, fairness policy) |
| Network probing | icmplib (ICMP/ping), dnspython (DNS timing) |
| Device discovery | Scapy ARP scan (Linux / root) |
| Blocking / rules | nftables (Linux) |
| Bandwidth shaping | tc HTB + fq_codel (Linux) |
| Reverse proxy | Caddy (local HTTPS, SYS-3) |
| Process manager | systemd |

---

## Quick Start (Windows / Dev)

```bash
cd clarinet/

# 1. Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/Mac

# 2. Install dependencies
pip install -r requirements.txt

# 3. Edit .env — set a real SECRET_KEY
#    python -c "import secrets; print(secrets.token_hex(32))"

# 4. Download Bootstrap/Chart.js static assets
#    bash clarinet/static/download_assets.sh   (Linux)
#    Or download manually — see download_assets.sh for URLs

# 5. Run
python run.py
```

Then open http://127.0.0.1:8000 — you'll be redirected to the setup wizard.

---

## Production (Ubuntu 24.04)

```bash
sudo bash install.sh
```

The installer:
1. Installs Python 3.12, nftables, iproute2, Caddy
2. Creates the `clarinet` system user
3. Sets up virtualenv + Python packages
4. Downloads static assets offline
5. Installs and starts the systemd service
6. Configures Caddy for local HTTPS at `https://clarinet.local`

---

## Build Phases

| Phase | Status | Description |
|---|---|---|
| 1 | ✅ Done | Skeleton, DB models, auth, setup wizard, login |
| 2 | 🔜 Next | Device discovery (Scapy), WebSocket new-device alerts |
| 3 | 🔜 | Usage accounting and daily summaries |
| 4 | 🔜 | Latency, baseline, slowdown diagnosis |

---

## Project Structure

```
clarinet/
├── run.py                       ← dev entry point
├── requirements.txt
├── .env                         ← secrets & config (DO NOT COMMIT)
├── clarinet.service             ← systemd unit
├── Caddyfile                    ← local HTTPS
├── install.sh                   ← Ubuntu 24.04 installer
└── clarinet/
    ├── __init__.py              ← FastAPI factory
    ├── config.py                ← pydantic-settings
    ├── database.py              ← SQLAlchemy + WAL
    ├── models.py                ← 14 ORM models
    ├── auth.py                  ← session, lockout, bcrypt
    ├── scheduler.py             ← APScheduler jobs
    ├── routers/
    │   ├── auth_routes.py       ← /login /logout
    │   ├── setup_routes.py      ← /setup wizard
    │   ├── dashboard.py         ← /dashboard
    │   ├── devices.py           ← /devices
    │   ├── alerts.py            ← /alerts
    │   ├── usage.py             ← /usage
    │   ├── rules.py             ← /rules
    │   ├── speed.py             ← /speed
    │   ├── guest.py             ← /guest /vouchers
    │   ├── priority.py          ← /priority
    │   ├── security.py          ← /security
    │   ├── settings_routes.py   ← /settings
    │   └── ws.py                ← /ws/alerts WebSocket
    ├── collector/
    │   ├── arp_scanner.py       ← Scapy ARP scan + upsert (Phase 2)
    │   ├── pinger.py            ← ICMP latency (Phase 4)
    │   ├── dns_timer.py         ← DNS timing (Phase 4)
    │   └── speed_test.py        ← speedtest-cli wrapper
    ├── enforcer/
    │   ├── nft_wrapper.py       ← nftables block/unblock
    │   └── tc_wrapper.py        ← HTB rate limiting
    ├── analytics/
    │   ├── baseline.py          ← per-hour normal ranges
    │   ├── diagnosis.py         ← slowdown cause detection
    │   └── fairness.py          ← bandwidth hog detection
    ├── templates/               ← Jinja2 HTML
    └── static/                  ← Bootstrap 5, Chart.js (offline)
```

---

## Database Tables (14)

`Member` · `Device` · `DeviceHistory` · `Alert` · `TimeRule` ·
`RuleException` · `UsageRecord` · `SlowdownEvent` · `Voucher` ·
`PriorityGrant` · `SpeedTestResult` · `Baseline` · `AuditLog` · `Settings`
