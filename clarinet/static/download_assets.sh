#!/usr/bin/env bash
# clarinet/static/download_assets.sh
# Downloads the icon font and Chart.js into static/ so the dashboard works
# offline (NFR-19). The pages themselves never load anything from the internet.
#
# Run once from the repository root:
#   bash clarinet/static/download_assets.sh
set -e
cd "$(dirname "$0")"

BSICONS_VER="1.11.3"
CHARTJS_VER="4.4.4"

JS_DIR="js"
FONTS_DIR="fonts"

mkdir -p "$JS_DIR" "$FONTS_DIR/fonts"

echo "Downloading Bootstrap Icons $BSICONS_VER ..."
curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap-icons@${BSICONS_VER}/font/bootstrap-icons.min.css" \
     -o "$FONTS_DIR/bootstrap-icons.css"
# The icon font files referenced inside the CSS use relative paths
curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap-icons@${BSICONS_VER}/font/fonts/bootstrap-icons.woff2" \
     -o "$FONTS_DIR/fonts/bootstrap-icons.woff2"
curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap-icons@${BSICONS_VER}/font/fonts/bootstrap-icons.woff" \
     -o "$FONTS_DIR/fonts/bootstrap-icons.woff"

echo "Downloading Chart.js $CHARTJS_VER ..."
curl -fsSL "https://cdn.jsdelivr.net/npm/chart.js@${CHARTJS_VER}/dist/chart.umd.min.js" \
     -o "$JS_DIR/chart.min.js"

echo "All assets downloaded to $(pwd)"
