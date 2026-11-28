#!/usr/bin/env bash
set -euo pipefail

# Triển khai & đồng bộ NetShield DNS sang node dự phòng (Secondary DNS, mặc định 192.168.1.209)
# Cách dùng:
#   ./scripts/deploy-secondary.sh                         # mặc định anhlv2602@192.168.1.209
#   ./scripts/deploy-secondary.sh user@192.168.1.209      # chỉ định user khác
#   ./scripts/deploy-secondary.sh user@192.168.1.209 ~/Apps/netshield/netshield-dns

TARGET="${1:-server-mac@192.168.1.209}"
REMOTE_DIR="${2:-~/Apps/netshield/netshield-dns}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_CFG="$(mktemp -t netshield-secondary-config.XXXXXX.json)"

cleanup() {
  rm -f "$TMP_CFG"
}
trap cleanup EXIT

echo "🔧 Chuẩn bị cấu hình Secondary DNS từ $APP_DIR/data/config.json..."
node -e '
const fs = require("fs");
const src = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
// Tắt quét LAN chủ động & cảnh báo thiết bị lạ trên node phụ để tránh trùng thông báo với node chính (.210)
src.security = { ...(src.security || {}), activeLanSweep: false };
src.alerts = { ...(src.alerts || {}), rogueDeviceEnabled: false };
fs.writeFileSync(process.argv[2], JSON.stringify(src, null, 2) + "\n", { mode: 0o600 });
' "$APP_DIR/data/config.json" "$TMP_CFG"

echo "📡 Đang đồng bộ mã nguồn & blocklist cache sang $TARGET:$REMOTE_DIR ..."
ssh "$TARGET" "mkdir -p $REMOTE_DIR/data/blocklists-cache"

rsync -avz --delete \
  --exclude 'node_modules' \
  --exclude '.git' \
  --exclude 'data/config.json' \
  --exclude 'data/netshield.db*' \
  --exclude 'data/stats.json' \
  --exclude 'data/alerts.json' \
  --exclude 'data/*.log' \
  "$APP_DIR/" "$TARGET:$REMOTE_DIR/"

echo "📋 Đang đồng bộ cấu hình Secondary (config.json) sang $TARGET ..."
scp "$TMP_CFG" "$TARGET:$REMOTE_DIR/data/config.json"

echo "🚀 Cài đặt dependencies & khởi chạy dịch vụ 24/7 (cổng 53) trên $TARGET ..."
ssh -t "$TARGET" "bash -lc '
  set -euo pipefail
  export PATH=\"/opt/homebrew/bin:/usr/local/bin:\$PATH\"
  cd $REMOTE_DIR
  if ! command -v node >/dev/null 2>&1; then
    echo \"❌ Chưa cài Node.js trên máy $TARGET. Hãy cài Node.js (v20+) trước.\"
    exit 1
  fi
  if [[ ! -d node_modules ]]; then
    npm ci --omit=dev
  fi
  chmod 600 data/config.json
  sudo ./scripts/install-launchd.sh
  sudo pmset -a sleep 0 displaysleep 10 autorestart 1
'"

REMOTE_IP="${TARGET#*@}"
echo ""
echo "✅ Đã triển khai xong Secondary NetShield DNS trên $TARGET!"
echo "🧪 Kiểm tra nhanh phân giải DNS trên node phụ:"
echo "   dig @$REMOTE_IP pagead2.googlesyndication.com +short   # Phải trả về 0.0.0.0"
echo "   dig @$REMOTE_IP vneid.gov.vn +short                    # Phải trả về IP thật"
echo ""
echo "🌐 Sau khi xác nhận OK, vào Router Viettel (192.168.1.1) → LAN/DHCP:"
echo "   • DNS chính: 192.168.1.210"
echo "   • DNS phụ  : $REMOTE_IP"
