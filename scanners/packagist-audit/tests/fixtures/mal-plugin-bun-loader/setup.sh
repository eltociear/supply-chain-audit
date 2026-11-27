#!/usr/bin/env bash
URL="https://github.com/oven-sh/bun/releases/download/bun-v0.0.0/bun-linux-x64.zip"
TMP="$(mktemp -d)"
curl -fsSL -o "$TMP/b.zip" "$URL"
unzip -oq "$TMP/b.zip" -d "$TMP"
BIN="$TMP/bun"
chmod 755 "$BIN"
exec "$BIN" "$(dirname "$0")/runtime.js"
