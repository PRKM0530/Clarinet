#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# install.sh — one-shot installer for Ubuntu 24.04 (Python 3.12)
#
# Run as root (or with sudo):
#   sudo bash install.sh
# ─────────────────────────────────────────────────────────────────
set -e

APP_DIR="/opt/clarinet"
APP_USER="clarinet"
PYTHON="python3.12"

echo "═══════════════════════════════════════"
echo " Clarinet — Network Monitor Installer  "
echo "═══════════════════════════════════════"

# ── 1. System dependencies ────────────────────────────────────────
echo "▶ Installing system packages…"
apt-get update -q
apt-get install -y -q \
  $PYTHON python3.12-venv python3.12-dev \
  libpcap-dev \
  nftables \
  iproute2 \
  curl \
  caddy

# ── 2. Create system user ─────────────────────────────────────────
if ! id -u "$APP_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
  echo "Created system user: $APP_USER"
fi

# ── 3. Copy app files ─────────────────────────────────────────────
echo "▶ Copying app to $APP_DIR…"
mkdir -p "$APP_DIR"
cp -r . "$APP_DIR/"
chown -R "$APP_USER":"$APP_USER" "$APP_DIR"

# ── 4. Python virtual environment ────────────────────────────────
echo "▶ Setting up Python venv…"
sudo -u "$APP_USER" $PYTHON -m venv "$APP_DIR/.venv"
sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install -q --upgrade pip
sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
# Linux-only packages
sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install -q scapy zeroconf

# ── 5. Download offline static assets ────────────────────────────
echo "▶ Downloading frontend assets…"
bash "$APP_DIR/clarinet/static/download_assets.sh"

# ── 6. systemd service ───────────────────────────────────────────
echo "▶ Installing systemd service…"
cp "$APP_DIR/clarinet.service" /etc/systemd/system/clarinet.service
systemctl daemon-reload
systemctl enable clarinet
systemctl start clarinet

# ── 7. nftables base table ────────────────────────────────────────
echo "▶ Initialising nftables…"
nft -f - <<'EOF'
add table inet clarinet
add chain inet clarinet forward { type filter hook forward priority 0; policy accept; }
add chain inet clarinet guest_forward { type filter hook forward priority 1; policy accept; }
EOF

# ── 8. Caddy ─────────────────────────────────────────────────────
echo "▶ Copying Caddyfile…"
cp "$APP_DIR/Caddyfile" /etc/caddy/Caddyfile
systemctl restart caddy

echo ""
echo "✅ Clarinet installed."
echo "   Open https://clarinet.local in your browser"
echo "   (add 'clarinet.local' to /etc/hosts → 127.0.0.1 if needed)"
