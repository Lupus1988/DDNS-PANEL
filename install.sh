#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/ddns-panel"
VENV_DIR="$APP_DIR/venv"
CONFIG_DIR="$APP_DIR/config"
ETC_DIR="/etc/ddns-panel"
STATE_DIR="/var/lib/ddns-panel"

if [[ $EUID -ne 0 ]]; then
  echo "Bitte als root ausführen: sudo ./install.sh"
  exit 1
fi

if ! command -v apt >/dev/null 2>&1; then
  echo "Dieses Installationsskript unterstützt aktuell nur Debian/Ubuntu mit apt."
  exit 1
fi

echo "[1/8] Pakete installieren"
apt update
apt install -y python3 python3-venv python3-pip curl iproute2 avahi-daemon sqlite3

echo "[2/8] Verzeichnisse anlegen"
mkdir -p "$APP_DIR" "$CONFIG_DIR" "$ETC_DIR" "$STATE_DIR"

echo "[3/8] Dateien kopieren"
cp -r panel lib "$APP_DIR/"
cp scripts/ddns-panel-update.py "$APP_DIR/ddns-panel-update.py"
chmod 700 "$APP_DIR/ddns-panel-update.py"
cp systemd/ddns-panel.service /etc/systemd/system/ddns-panel.service
cp systemd/ddns-panel-update.service /etc/systemd/system/ddns-panel-update.service
cp systemd/ddns-panel-update.timer /etc/systemd/system/ddns-panel-update.timer

echo "[4/8] Standardkonfiguration anlegen"
[[ -f "$CONFIG_DIR/entries.json" ]] || cp example-config/entries.json "$CONFIG_DIR/entries.json"
[[ -f "$CONFIG_DIR/setup.json" ]] || cp example-config/setup.json "$CONFIG_DIR/setup.json"
[[ -f "$ETC_DIR/secrets.json" ]] || printf '{}\n' > "$ETC_DIR/secrets.json"
chmod 600 "$ETC_DIR/secrets.json"

echo "[5/8] Python venv einrichten"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

echo "[6/8] Python-Abhängigkeiten installieren"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install flask

echo "[7/8] systemd laden"
systemctl daemon-reload
systemctl enable ddns-panel.service
systemctl enable ddns-panel-update.timer

echo "[8/8] Dienste starten"
systemctl restart ddns-panel.service
systemctl restart ddns-panel-update.timer

echo
echo "Fertig."
echo "Panel direkt:  http://SERVER-IP:5085"
echo "Panel lokal:   http://ddns.local oder http://ddns.local:5085"
