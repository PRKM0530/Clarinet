#!/usr/bin/env bash
# Starts Clarinet INSIDE clb-router, as root, with an isolated database. Needs root:
#   sudo bash tests/lab/lab_run_clarinet.sh          (leave it running; Ctrl+C to stop)
# Listens on 10.77.0.1:8000 (reachable from the lab namespaces only).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LAB=/tmp/clarinet-lab; mkdir -p $LAB/bin; rm -f $LAB/lab.db*
# fake speedtest so no real speed test ever runs
cat > $LAB/bin/speedtest <<'F'
#!/bin/sh
echo '{"download":{"bandwidth":12500000},"upload":{"bandwidth":2500000},"ping":{"latency":12.5},"server":{"host":"fake-lab"}}'
F
chmod +x $LAB/bin/speedtest
cd "$REPO"
exec ip netns exec clb-router env -i PATH="$LAB/bin:/usr/sbin:/usr/bin:/sbin:/bin" HOME=/root \
  PYTHONDONTWRITEBYTECODE=1 SECRET_KEY="$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
  DATABASE_URL="sqlite:///$LAB/lab.db" APP_ENV=production APP_HOST=10.77.0.1 APP_PORT=8000 \
  NETWORK_INTERFACE=br-lan NETWORK_MODE=FULL \
  "${VENV_PY:-$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)/clarinet-venv/bin/python}" run.py
