#!/usr/bin/env bash
# Installs NotMeter for Linux / SteamOS (Steam Deck).
#
#   ./install.sh                  download the latest NotMeter.exe and install
#   ./install.sh path/NotMeter.exe  use an exe you already have
#   ./install.sh --uninstall      remove the capture service (keeps ~/NotMeter)
#
# Run it as your normal user (deck). It asks for sudo only to install the
# capture service. On a Steam Deck set a password first with `passwd`.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${NOTMETER_DIR:-$HOME/NotMeter}"
SERVICE=notmeter-capture
HELPER_DIR=/etc/notmeter
RELEASE_ZIP=https://github.com/Not4You-Dev/NotMeter-Releases/releases/latest/download/NotMeter.zip

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
  die "run this as your normal user, not root (it uses sudo itself)"
fi

if [ "${1:-}" = "--uninstall" ]; then
  say "Removing the $SERVICE service"
  sudo systemctl disable --now "$SERVICE" 2>/dev/null || true
  sudo rm -f "/etc/systemd/system/$SERVICE.service"
  sudo rm -rf "$HELPER_DIR"
  sudo systemctl daemon-reload
  say "Done. $INSTALL_DIR was left in place; delete it yourself if you want."
  exit 0
fi

command -v python3 >/dev/null || die "python3 not found"
command -v sha256sum >/dev/null || die "sha256sum not found"

mkdir -p "$INSTALL_DIR/Plugins/Proton"

# 1. NotMeter.exe
if [ -n "${1:-}" ]; then
  [ -f "$1" ] || die "file not found: $1"
  cp -f "$1" "$INSTALL_DIR/NotMeter.exe"
elif [ ! -f "$INSTALL_DIR/NotMeter.exe" ]; then
  say "Downloading NotMeter"
  tmp="$(mktemp -d)"
  curl -fL --progress-bar -o "$tmp/NotMeter.zip" "$RELEASE_ZIP"
  python3 -I -m zipfile -e "$tmp/NotMeter.zip" "$tmp/x"
  cp -f "$tmp/x/NotMeter.exe" "$INSTALL_DIR/NotMeter.exe"
  rm -rf "$tmp"
else
  say "Keeping existing $INSTALL_DIR/NotMeter.exe"
fi

# 2. Capture plugin. NotMeter checks the DLL against the hash in plugin.json.
say "Installing the Proton capture plugin"
dll="$INSTALL_DIR/Plugins/Proton/NotMeter.Capture.Proton.dll"
cp -f "$REPO_DIR/dist/Plugins/Proton/NotMeter.Capture.Proton.dll" "$dll"
hash="$(sha256sum "$dll" | cut -d' ' -f1)"
cat > "$INSTALL_DIR/Plugins/Proton/plugin.json" <<EOF
{
  "schemaVersion": 1,
  "apiVersion": 1,
  "id": "proton",
  "version": "1.0.0",
  "assemblySha256": "$hash"
}
EOF

# 3. Capture helper as a root service. It lives in /etc (root-owned and kept
#    across SteamOS updates) so a non-root process can't change what root runs.
say "Installing the $SERVICE service (needs sudo)"
sudo install -d -m 755 "$HELPER_DIR"
sudo install -m 755 "$REPO_DIR/linux/notmeter-capture.py" "$HELPER_DIR/notmeter-capture.py"
sudo tee "/etc/systemd/system/$SERVICE.service" >/dev/null <<EOF
[Unit]
Description=NotMeter packet capture helper (replaces Npcap for Proton)
After=network.target

[Service]
ExecStart=/usr/bin/python3 -I $HELPER_DIR/notmeter-capture.py --allow-uid $(id -u)
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
PrivateTmp=yes
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now "$SERVICE"
sleep 1
if systemctl is-active --quiet "$SERVICE"; then
  say "Service is running"
else
  die "service did not start, see: journalctl -u $SERVICE"
fi

cat <<EOF

Done. Last step, in Steam:
  Aion 2 -> Properties -> General -> Launch Options, paste:

  NOTMETER_PROTON_CAPTURE=1 PROTON_REMOTE_DEBUG_CMD="$INSTALL_DIR/NotMeter.exe" %command%

NotMeter will start together with the game, in the same Proton prefix.
Service logs: journalctl -u $SERVICE -f
EOF
