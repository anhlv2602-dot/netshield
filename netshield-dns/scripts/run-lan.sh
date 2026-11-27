#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "$EUID" -ne 0 ]]; then
  echo "🔐 Chạy cổng DNS 53 cho toàn mạng LAN cần quyền quản trị (sudo)."
  exec sudo "$0" "$@"
fi

TARGET_USER="${SUDO_USER:-anhlv2602}"
TARGET_UID="$(id -u "$TARGET_USER")"
TARGET_GID="$(id -g "$TARGET_USER")"

cd "$APP_DIR"
mkdir -p "$APP_DIR/data/blocklists-cache"
chown -R "$TARGET_UID:$TARGET_GID" "$APP_DIR/data"

# Dừng bản đang chạy (nếu có) để tránh trùng cổng 53 / 8080
pkill -f "$APP_DIR/src/index.js" 2>/dev/null || true
sleep 0.5

export DNS_PORT="${DNS_PORT:-53}"
export WEB_PORT="${WEB_PORT:-8080}"
export BIND_HOST="0.0.0.0"
export WEB_HOST="127.0.0.1"
export RUN_AS_UID="$TARGET_UID"
export RUN_AS_GID="$TARGET_GID"

exec /usr/local/bin/node "$APP_DIR/src/index.js"
