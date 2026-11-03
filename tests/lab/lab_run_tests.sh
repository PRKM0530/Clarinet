#!/usr/bin/env bash
# Runs the lab tests INSIDE the clb-router namespace as root.   sudo bash tests/lab/lab_run_tests.sh [pytest args]
# Needs the lab from lab_setup.sh. Changes nothing outside clb-* namespaces.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
VENV_PY="${VENV_PY:-$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)/clarinet-venv/bin/python}"
LAB=/tmp/clarinet-lab; mkdir -p $LAB/bin $LAB/home
cat > $LAB/bin/speedtest <<'F'
#!/bin/sh
echo '{"download":{"bandwidth":12500000},"upload":{"bandwidth":2500000},"ping":{"latency":12.5},"server":{"host":"fake-lab"}}'
F
chmod +x $LAB/bin/speedtest
cd "$REPO"
exec ip netns exec clb-router env -i PATH="$LAB/bin:/usr/sbin:/usr/bin:/sbin:/bin" HOME=$LAB/home \
  PYTHONDONTWRITEBYTECODE=1 SECRET_KEY=lab-secret-not-used-elsewhere APP_HOST=127.0.0.1 CLARINET_LAB=1 \
  "$VENV_PY" -m pytest tests/lab -p no:cacheprovider -q -rxX -W ignore "$@"
