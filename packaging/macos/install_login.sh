#!/usr/bin/env bash
# Installs Sec.app to ~/Applications and starts it automatically at login (LaunchAgent).
# usage: packaging/macos/install_login.sh [path/to/Sec.app]
#        packaging/macos/install_login.sh --uninstall
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LABEL="com.sec.epp.menubar"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DEST="$HOME/Applications/Sec.app"
DOMAIN="gui/$(id -u)"

if [ "${1:-}" = "--uninstall" ]; then
    launchctl bootout "$DOMAIN" "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    rm -rf "$DEST"
    echo "removed LaunchAgent and $DEST"
    exit 0
fi

SRC="${1:-$ROOT/build/Sec.app}"
if [ ! -d "$SRC" ]; then
    echo "Sec.app not found: $SRC (run packaging/macos/make_app.sh first)" >&2
    exit 1
fi

mkdir -p "$HOME/Applications" "$HOME/Library/LaunchAgents"
launchctl bootout "$DOMAIN" "$PLIST" 2>/dev/null || true
pkill -x sec-menubar 2>/dev/null || true
rm -rf "$DEST"
cp -R "$SRC" "$DEST"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$DEST/Contents/MacOS/sec-menubar</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
EOF

launchctl bootstrap "$DOMAIN" "$PLIST"
echo "installed: $DEST"
echo "LaunchAgent: $PLIST (starts at login; crashes restart it, Quit from the menu stays quit)"
