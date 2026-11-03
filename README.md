# Clarinet

Clarinet is a home and small-office network monitor with a web dashboard. It shows which devices are on your network, how much each one uses, how fast your internet really is, and why it feels slow when it does. When it runs on your router (or any machine the traffic passes through), it can also block devices, limit their speed, give visitors time-limited guest access and enforce time rules.

It is a single Python application (FastAPI + SQLite) with a built-in scheduler. There is nothing else to install or run: no separate database, no message queue.

## Features

**See your network**
- **Devices.** Every device that joins is found automatically (vendor, name, IP, when it was last seen). Devices you have approved, named or assigned come first. Each shows what it can do on the network right now ("Has internet", "No internet until approved", and so on). Randomised phone addresses and devices with several addresses can be merged into one.
- **Dashboard.** Devices online, open alerts, usage today, the speed of your own device, a banner when one of your devices is slow, and the latest alerts.
- **Usage.** Today, the week, the month or the billing cycle: totals, charts by day and hour, what the data was used for (streaming, browsing and so on), a per-device table with each device's owner, and CSV export. A monthly data limit can be set and warns at 70, 90 and 100 percent.

**Know when something is wrong, and why**
- **Speed is per device.** Each device tests its own link to Clarinet in its own browser, quietly about every hour while Clarinet is open on it (or on demand), and is compared only with its own earlier tests. A slowdown needs two low tests in a row, at least 25 percent below that device's usual speed, so one unlucky reading never raises an alert. A long delay counts too. Results and alerts are private to the device's owner; an administrator does not see other members' speed.
- **Internet speed at the router** is a separate administrator page (System status, then Internet speed test), compared with the plan you pay for, with a one-page report for your provider.
- **Network slowdowns.** Clarinet learns what is normal for your connection and, when it gets slow, names the most likely cause: your provider, your router, your Wi-Fi, one device using too much, or several together. Rule-based and explainable.
- **Security checks.** Port-scan and ARP-spoofing detection, fake access point detection, and a router audit (open ports, UPnP, default web login). Administrators only.
- **Alerts** with levels and filters, live in the browser, with CSV export. Members see only alerts about their own devices.
- **System status** (administrators): uptime, router and internet reachability, memory, disk, database size, whether each background collector is running, and a list of what works on this computer and what needs Linux.

**Control the network (Full Control mode)**
- **Block and unblock** a device in one click. A new device can be held offline until approved.
- **Priority** grants: a person can ask for full speed for a while, within a daily allowance.
- **Time rules**: for example, block or slow a device between 22:00 and 07:00.
- **Guest vouchers**: short codes that give a visitor internet access (and not the home network) for a set time.

**People**
- **Administrators** manage everything except other members' speed results. **Members** sign themselves up, claim their own devices ("This is my device", confirmed by an administrator) and see only their own devices, usage and alerts. Someone who asks for administrator access waits for an existing administrator to approve it.
- A member who forgets their password resets it on the sign-in page with a **recovery code** they made on My account. No one else, an administrator included, can reset it for them.
- Sign-in with lockout after repeated wrong passwords, sign-ins that last until you sign out, an audit log of administrative actions, and a privacy page that says what is collected. A **Purge** button deletes all stored network data.

### Two modes

| Mode | What it does | Where to use it |
|---|---|---|
| **Monitor only** | Watches only. Devices, latency, speed tests, security checks. Never changes the network. | Any machine, including a laptop on your Wi-Fi |
| **Full Control** | Everything above, plus usage counting, blocking, speed limits, vouchers and time rules. | A machine that routes the traffic (Linux, root) |

Full Control has one extra choice, **Keep new devices offline until I approve them**. It suits a guest or shared network: a device nobody has approved gets no internet until an administrator approves it or the person enters a voucher code. It is off by default. (Older installs that were set to the former "Public" mode are read as Full Control with this switch on.)

Anything that cannot work on the computer Clarinet runs on is marked where it appears, with the reason (for example a "Needs Linux" tag), and is never shown as a made-up number. On a Windows laptop Clarinet finds devices (from the ARP table), counts that laptop's own traffic, checks nearby Wi-Fi, and measures latency and speed. Counting other devices' traffic, watching website lookups, port-scan detection, blocking and limits need Linux on the machine the traffic passes through.

## Requirements

- Python **3.12** (3.13 and later are not supported by the pinned libraries).
- Linux for the full feature set (see above for what a Windows laptop can do). The app starts on macOS too, with fewer features.
- For Full Control: `nftables` and `iproute2` (`tc`), and the right to use them (root, or the capabilities the systemd service grants). The pages say which feature is unavailable if they are missing.
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

Open **http://127.0.0.1:8000**. The first visit shows the setup wizard: choose an administrator name and password (at least 8 characters), a mode, and your internet plan speeds. The time zone comes from your browser, and Clarinet finds your network connection and router by itself (both can be changed under Settings, then Advanced). Then sign in.

To open Clarinet from a phone or another computer, set `APP_HOST=0.0.0.0` in `.env` and use this computer's address. Testing a device's speed has to happen from that other device: a test on the computer running Clarinet would only measure the computer talking to itself, so it is refused.

After about 15 seconds the Devices page lists what the machine can see. A speed test runs at start-up.

### Try it with demo data

To see every page filled in without waiting for real traffic, build an invented demo network and start the app on it:

```bash
python tools/demo_data.py
DATABASE_URL=sqlite:///./clarinet_demo.db python run.py       # PowerShell: $env:DATABASE_URL="sqlite:///./clarinet_demo.db"; python run.py
```

Sign in as `praveen` / `pw-admin-123` (administrator) or `asha` / `pw-asha-1234` (member).

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

It asks for the new password twice, clears any lockout and signs that account out everywhere. Members use their recovery code on the sign-in page instead ("Forgot your password?").

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
| `SLOWDOWN_SPEED_THRESHOLD` | `0.70` | A router speed test below this share of the plan counts as slow |
| `ALERT_LOCKOUT_ATTEMPTS`, `ALERT_LOCKOUT_MINUTES` | `5`, `5` | Sign-in lockout |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Reverse proxies whose `X-Forwarded-For` may be believed |
| `COOKIE_SECURE` | `false` | Send the cookie over HTTPS only (set `true` behind HTTPS) |

## Deploying on Ubuntu 24.04

```bash
sudo bash deploy/install.sh
```

The script installs the system packages, creates a `clarinet` service user, copies the app to `/opt/clarinet`, builds a virtual environment, creates `/opt/clarinet/.env` with a random `SECRET_KEY` (production mode, HTTPS-only cookie, mode 600; an existing `.env` is kept), installs and starts the systemd service (`deploy/clarinet.service`) and puts Caddy in front for HTTPS (`deploy/Caddyfile`). The service runs a single worker, which is what keeps SQLite safe. It runs as the `clarinet` user with `CAP_NET_RAW` and `CAP_NET_ADMIN`, not as root. Caddy forwards each visitor's address in `X-Forwarded-For`, which Clarinet uses to know which device a request comes from, so keep `TRUSTED_PROXIES` as installed.

To reach it afterwards open `https://clarinet.local` (add the server's address to each client's hosts file, or use your local DNS). Back up `/opt/clarinet/clarinet.db` (the whole database) now and then; to update, pull the new code, copy it over `/opt/clarinet`, and run `sudo systemctl restart clarinet`.

## Project layout

```
clarinet/
  __init__.py          app, middleware, error pages, template filters
  config.py            settings from .env
  auth.py              passwords, sessions, lockout
  routers/             one file per area: devices, usage, alerts, speed, slowdowns,
                       security, guest/vouchers, rules, priority, settings, status, account, signup, api, ws
  collector/           things that look at the network: ARP scan, pinger, speed test, traffic counter,
                       port-scan / ARP-spoof / DNS / Wi-Fi checks, router audit
  analytics/           baseline, slowdown diagnosis, early warning
  enforcer/            nftables and tc wrappers, reconcile (makes the firewall match the database)
  core_svc/            services shared by the pages: accounts, alerts, usage, device speed, what works here, time zone, exports
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
python -m pytest tests -q            # all tests that need no root, about 15 minutes
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
