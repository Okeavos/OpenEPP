#!/usr/bin/env bash
# Installs the behaviour sensor (sec-sensord) as a root LaunchDaemon.
#
#   sudo packaging/macos/install_sensord.sh [path/to/sec-sensord]
#   sudo packaging/macos/install_sensord.sh --uninstall
#
# eslogger only works as root and only if the binary has Full Disk Access
# (System Settings > Privacy & Security > Full Disk Access > "+" > /usr/local/libexec/sec/sec-sensord).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LABEL="com.sec.epp.sensord"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
BIN_DIR="/usr/local/libexec/sec"
BIN="$BIN_DIR/sec-sensord"
DATA_DIR="/Library/Application Support/SecEPP"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0 $*" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST" "$BIN"
    rmdir "$BIN_DIR" 2>/dev/null || true
    echo "removed $LABEL (alerts and settings in \"$DATA_DIR\" were kept)"
    exit 0
fi

SRC="${1:-$ROOT/build/src/sensord/sec-sensord}"
if [ ! -x "$SRC" ]; then
    echo "sec-sensord not found: $SRC (build first: cmake --build build)" >&2
    exit 1
fi
if [ ! -x /usr/bin/eslogger ]; then
    echo "warning: /usr/bin/eslogger not found (needs macOS 13 or later); network polling will still work" >&2
fi

launchctl bootout system "$PLIST" 2>/dev/null || true

mkdir -p "$BIN_DIR" "$DATA_DIR"
chmod 755 "$BIN_DIR" "$DATA_DIR"
cp "$SRC" "$BIN"
chown root:wheel "$BIN"
chmod 755 "$BIN"
codesign --force --sign - "$BIN" 2>/dev/null || true

cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN</string>
        <string>--data-dir</string>
        <string>$DATA_DIR</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>/var/log/sec-sensord.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/sec-sensord.err.log</string>
</dict>
</plist>
PLIST_EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"

launchctl bootstrap system "$PLIST"
launchctl kickstart -k "system/$LABEL" 2>/dev/null || true

cat <<MSG
installed: $BIN
data:      $DATA_DIR  (behavior_alerts.tsv, sensor_status.txt, logs/sensord.log)

Next: grant Full Disk Access to $BIN
  System Settings > Privacy & Security > Full Disk Access > "+" (Cmd+Shift+G to type the path)
Then restart the sensor:
  sudo launchctl kickstart -k system/$LABEL
Check it:
  cat "$DATA_DIR/sensor_status.txt"
Note: every rebuild changes the ad-hoc signature, so macOS may ask for the permission again.
MSG
