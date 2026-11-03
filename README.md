# Clarinet

Clarinet is a home and small-office network monitor with a web dashboard. It shows which devices are on your network, how much each one uses, how fast your internet really is, and why it feels slow when it does. When it runs on your router (or any machine the traffic passes through), it can also block devices, limit their speed, give visitors time-limited guest access and enforce time rules.

It is a single Python application (FastAPI + SQLite) with a built-in scheduler. There is nothing else to install or run: no separate database, no message queue.

## Features

**See your network**
- **Devices.** Every device that joins is discovered automatically (vendor, name, IP, when it was last seen). New devices raise an alert and wait for an administrator to approve them. Devices that change their address, randomised phone addresses and devices with several addresses can be merged into one.
- **Dashboard.** A health badge, the three latency targets (two public servers and your router) as a live chart, today's usage, the people and devices online, and a stream of what is happening.
- **Usage.** Per device and per person: today, the week, the month, split by what the traffic was (streaming, browsing, downloads, and so on). A monthly data limit can be set, with a warning and then a slowdown of the heaviest devices.
- **Reports.** Day and week reports, plus CSV export of usage, devices, alerts and speed tests.

**Know when something is wrong, and why**
- **Speed tests** on a schedule or on demand, compared with the plan you pay for. A one-page report you can send your provider when you are getting less than you pay for.
- **Slowdown detection.** Clarinet learns what is normal for your network and, when things get slow, tells you the most likely cause: your provider, your router, your Wi-Fi, one device using too much, or several devices together. Rule-based and explainable, no black box.
- **Security checks.** Port-scan detection, ARP spoofing detection, fake access point detection, DNS observation, and a router audit (open ports, UPnP, default web login).
- **Alerts** with levels, filters, live delivery to the browser and CSV export.

**Control the network (Full Control mode)**
- **Block and unblock** a device in one click.
- **Per-device speed limits**, and **priority** grants: a person can ask for the full speed for a while, within a daily allowance.
- **Time rules**: for example, block or slow a device between 22:00 and 07:00.
- **Guest vouchers**: short codes that give a visitor internet access (and not the home network) for a set time, then expire by themselves.

**People**
- **Administrators** manage everything. **Members** sign themselves up, claim their own devices ("This is my device", confirmed by an administrator) and see only their own devices, usage and alerts, plus the internet speed and slowdown pages. Someone who asks for administrator access waits for an existing administrator to approve it.
- Sign-in with lockout after repeated wrong passwords, sign-ins that last until you sign out, sign-out everywhere on password reset, an audit log of administrative actions, and a privacy page that says exactly what is collected. A **Purge** button deletes all stored network data.

### Two modes

| Mode | What it does | Where to use it |
|---|---|---|
| **Monitor only** | Watches only. Devices, latency, speed tests, security checks. Never changes the network. | Any machine, including a laptop on your Wi-Fi |
| **Full Control** | Everything above, plus usage counting, blocking, speed limits, vouchers and time rules. | A machine that routes the traffic (Linux, root) |

Full Control has one extra choice, **Keep new devices offline until I approve them**. It suits a guest or shared network: a device nobody has approved gets no internet until an administrator approves it or the person enters a voucher code. It is off by default. (Older installs that were set to the former "Public" mode are read as Full Control with this switch on.)

Features a role or mode cannot use are hidden rather than greyed out, and the pages explain why when it matters. Usage numbers and blocking need Full Control on the machine that carries the traffic; on a laptop you still get devices, latency, speed and security.

## Requirements

- Python **3.12** (3.13 and later are not supported by the pinned libraries).
- Linux for the network features. The app starts on macOS and Windows for development, but discovery, counting and enforcement are Linux only.
- For Full Control: root, `nftables` and `iproute2` (`tc`). The app shows a warning on every page if they are missing.
- Optional: `nmap` and `iperf3` are only used by the test lab.

## Quick start (development)

```bash
git clone https://github.com/PRKM0530/Clarinet.git
cd Clarinet
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install scapy netifaces zeroconf        # Linux: active device scan, names on the network
cp .env.example .env
# put a random key in .env:
python -c "import secrets; print(secrets.token_hex(32))"     # paste as SECRET_KEY=
python run.py
```

Open **http://127.0.0.1:8000**. The first visit shows the setup wizard: choose an administrator name and password (at least 8 characters), a mode, and your internet plan speeds and time zone. Clarinet finds your network connection and router by itself; both can be changed under Settings, then Advanced. Every password box has a show and hide button. Then sign in.

After about 15 seconds the Devices page lists what the machine can see. A speed test runs at start-up.

### Running as root (Linux, for the full feature set)

Raw packet sniffing, the port-scan and DNS observers and Full Control need root. Keep the virtual environment's tools on the path:

```bash
sudo env "PATH=$PATH" PYTHONDONTWRITEBYTECODE=1 "$(which python)" run.py
```

`PYTHONDONTWRITEBYTECODE=1` stops root leaving root-owned cache files in your checkout. Do not use Full Control on a laptop's own Wi-Fi: it adds firewall and traffic-shaping rules to the interface you are using. Use it on a router or in the test lab.

To remove the counting rules the app adds after stopping it:

```bash
sudo nft delete table inet clarinet
```

### Forgot the administrator password

On the machine running the app:

```bash
python -m clarinet.cli reset-password USERNAME
```

It asks for the new password twice, clears any lockout and signs that account out everywhere. Members who forget theirs ask an administrator (Settings, Reset password).

## Configuration

Settings come from `.env` (see `.env.example`) or environment variables. Most can also be changed later in **Settings**; `.env` supplies the starting values the first time the database is created.

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | `change-me` | Signs login cookies. **Required** to be changed in production: the app refuses to start with the example value |
| `APP_ENV` | `development` | `production` hides the API docs and enforces the key check |
| `APP_HOST`, `APP_PORT` | `127.0.0.1`, `8000` | Where the web server listens |
| `DATABASE_URL` | `sqlite:///./clarinet.db` | SQLite file |
| `NETWORK_INTERFACE` | *(automatic)* | Leave unset. Clarinet finds the connection to your router; set it only to force another one |
| `NETWORK_MODE` | `MONITOR` | `MONITOR` or `FULL` |
| `ACTIVE_DISCOVERY` | `auto` | Active ARP scan on top of the passive neighbour table: `auto` (Full Control only), `on`, `off`. Needs root and scapy |
| `PLAN_DOWNLOAD_MBPS`, `PLAN_UPLOAD_MBPS` | `100`, `20` | Your internet plan |
| `BILLING_DAY` | `1` | Day the monthly usage resets |
| `SLOWDOWN_LATENCY_MULTIPLIER` | `3.0` | Latency this many times normal counts as slow |
| `SLOWDOWN_SPEED_THRESHOLD` | `0.70` | A speed test below this share of the plan counts as slow |
| `ALERT_LOCKOUT_ATTEMPTS`, `ALERT_LOCKOUT_MINUTES` | `5`, `5` | Sign-in lockout |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Reverse proxies whose `X-Forwarded-For` may be believed |
| `COOKIE_SECURE` | `false` | Send the cookie over HTTPS only (set `true` behind HTTPS) |

## Deploying on Ubuntu 24.04

```bash
sudo bash deploy/install.sh
```

The script installs the system packages, creates a `clarinet` service user, copies the app to `/opt/clarinet`, builds a virtual environment, creates `/opt/clarinet/.env` with a random `SECRET_KEY` (production mode, HTTPS-only cookie, mode 600; an existing `.env` is kept), installs and starts the systemd service (`deploy/clarinet.service`) and puts Caddy in front for HTTPS (`deploy/Caddyfile`). The service runs a single worker, which is what keeps SQLite safe.

## Project layout

```
clarinet/
  __init__.py          app, middleware, error pages, template filters
  config.py            settings from .env
  auth.py              passwords, sessions, lockout
  routers/             one file per area: devices, usage, alerts, speed, slowdowns,
                       security, guest/vouchers, rules, priority, settings, account, signup, api, ws
  collector/           things that look at the network: ARP scan, pinger, speed test, traffic counter,
                       port-scan / ARP-spoof / DNS / Wi-Fi checks, router audit
  analytics/           baseline, slowdown diagnosis, early warning, fairness score
  enforcer/            nftables and tc wrappers, reconcile (makes the firewall match the database)
  core_svc/            services shared by the pages: accounts, alerts, reports, usage, time zone, exports
  jobs/                scheduled jobs (scan, latency, counting, summaries, expiry, watchdog)
  models/              SQLAlchemy tables
  templates/, static/  pages and assets
  cli.py               recovery command
deploy/                install script, systemd unit, Caddyfile
tests/                 automated tests (see below)
run.py                 development entry point
```

How the parts fit: collectors and scheduled jobs write measurements and alerts into SQLite; the web pages read them. When enforcement is on, a *reconcile* job (every minute, and straight after a click) makes nftables and tc match what the database says, so the database is always the source of truth.

## Development

```bash
pip install pytest httpx
export SECRET_KEY=x APP_HOST=127.0.0.1
python -m pytest tests -q            # all tests that need no root, about 4 minutes
python -m pytest tests/ui_forms -q   # one folder
```

- Tests use a throw-away database and a guard that blocks real network access and host commands, so running them never touches your network.
- Tests that need a real network are in `tests/lab` and are skipped unless run through the lab scripts. The lab is built from Linux network namespaces named `clb-*` and touches nothing outside them:

```bash
sudo bash tests/lab/lab_setup.sh        # build once (needs nmap and iperf3)
sudo bash tests/lab/lab_run_tests.sh    # run the lab tests
sudo bash tests/lab/lab_teardown.sh     # remove the lab
```

- A new route must be added to the table in `tests/access/test_route_matrix.py` (who may open it); a test fails otherwise.
- `tests/ui_forms/` submits every form and follows every link the way a browser does. It is the quickest way to notice a broken page.

## Security notes

- Passwords are stored as bcrypt hashes; sessions are signed cookies backed by a server-side record that sign-out and password resets delete.
- Cross-site form posts are refused. Sign-out is a POST.
- Clarinet reads the network it is installed on. Run its router audit and active scan only on networks you own or manage.
- See the in-app **Privacy** page for what is collected.
