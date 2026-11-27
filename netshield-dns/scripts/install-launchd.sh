#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PLIST_PATH="/Library/LaunchDaemons/com.local.netshield-dns.plist"

if [[ "$EUID" -ne 0 ]]; then
  echo "🔐 Cài dịch vụ tự chạy cùng macOS (LaunchDaemon) cần quyền sudo."
  exec sudo "$0" "$@"
fi

TARGET_USER="${SUDO_USER:-anhlv2602}"
TARGET_UID="$(id -u "$TARGET_USER")"
TARGET_GID="$(id -g "$TARGET_USER")"

mkdir -p "$APP_DIR/data/blocklists-cache"
chown -R "$TARGET_UID:$TARGET_GID" "$APP_DIR/data"

# Dừng tiến trình chạy tay nếu đang chạy
pkill -f "$APP_DIR/src/index.js" 2>/dev/null || true
sleep 0.5

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.local.netshield-dns</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/node</string>
    <string>$APP_DIR/src/index.js</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$APP_DIR</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>DNS_PORT</key>
    <string>53</string>
    <key>WEB_PORT</key>
    <string>8080</string>
    <key>BIND_HOST</key>
    <string>0.0.0.0</string>
    <key>WEB_HOST</key>
    <string>127.0.0.1</string>
    <key>RUN_AS_UID</key>
    <string>$TARGET_UID</string>
    <key>RUN_AS_GID</key>
    <string>$TARGET_GID</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$APP_DIR/data/stdout.log</string>
  <key>StandardErrorPath</key>
  <string>$APP_DIR/data/stderr.log</string>
</dict>
</plist>
EOF

chmod 644 "$PLIST_PATH"
launchctl bootout system "$PLIST_PATH" 2>/dev/null || true
launchctl bootstrap system "$PLIST_PATH"
echo "✅ Đã cài NetShield DNS chạy nền 24/7 trên cổng 53 (tự hạ quyền khỏi root)!"
echo "🔒 Giao diện quản trị CHỈ mở từ máy Mac Mini: http://127.0.0.1:8080"
