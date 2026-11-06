#!/usr/bin/env bash
# Builds build/Sec.app from the compiled sec-menubar binary.
# usage: packaging/macos/make_app.sh [build-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="${1:-$ROOT/build}"
BIN="$BUILD/src/macapp/sec-menubar"
APP="$BUILD/Sec.app"

if [ ! -x "$BIN" ]; then
    echo "sec-menubar not found: $BIN (build first: cmake --build build)" >&2
    exit 1
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN" "$APP/Contents/MacOS/sec-menubar"
cp "$ROOT/packaging/macos/Info.plist" "$APP/Contents/Info.plist"
codesign --force --deep --sign - "$APP"

echo "created: $APP"
echo "run:     open \"$APP\""
