#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# clarinet/static/download_assets.sh
# Downloads Bootstrap 5, Bootstrap Icons, and Chart.js into the
# static/ directory so the dashboard works offline (NFR-19).
#
# Run once from the app/ directory:
#   bash clarinet/static/download_assets.sh
# ─────────────────────────────────────────────────────────────────
set -e
cd "$(dirname "$0")"

BOOTSTRAP_VER="5.3.3"
BSICONS_VER="1.11.3"
CHARTJS_VER="4.4.4"

CSS_DIR="css"
JS_DIR="js"
FONTS_DIR="fonts"

mkdir -p "$CSS_DIR" "$JS_DIR" "$FONTS_DIR"

echo "▶ Downloading Bootstrap $BOOTSTRAP_VER …"
curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap@${BOOTSTRAP_VER}/dist/css/bootstrap.min.css" \
     -o "$CSS_DIR/bootstrap.min.css"
curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap@${BOOTSTRAP_VER}/dist/js/bootstrap.bundle.min.js" \
     -o "$JS_DIR/bootstrap.bundle.min.js"

echo "▶ Downloading Bootstrap Icons $BSICONS_VER …"
curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap-icons@${BSICONS_VER}/font/bootstrap-icons.min.css" \
     -o "$FONTS_DIR/bootstrap-icons.css"
# The icon font files referenced inside the CSS use relative paths
curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap-icons@${BSICONS_VER}/font/fonts/bootstrap-icons.woff2" \
     -o "$FONTS_DIR/fonts/bootstrap-icons.woff2" --create-dirs
curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap-icons@${BSICONS_VER}/font/fonts/bootstrap-icons.woff" \
     -o "$FONTS_DIR/fonts/bootstrap-icons.woff" --create-dirs

echo "▶ Downloading Chart.js $CHARTJS_VER …"
curl -fsSL "https://cdn.jsdelivr.net/npm/chart.js@${CHARTJS_VER}/dist/chart.umd.min.js" \
     -o "$JS_DIR/chart.min.js"

echo "✅ All assets downloaded to $(pwd)"
