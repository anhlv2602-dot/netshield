import { store } from './store.js';
import { blocklistEngine } from './blocklist.js';
import { startDnsServer } from './dns-server.js';
import { startWebServer } from './web-server.js';

const DNS_PORT = Number(process.env.DNS_PORT || 5335);
const WEB_PORT = Number(process.env.WEB_PORT || 8080);
const BIND_HOST = process.env.BIND_HOST || '0.0.0.0';
const WEB_HOST = process.env.WEB_HOST || '127.0.0.1';

function dropRootPrivileges() {
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) return;
  const targetUid = Number(process.env.RUN_AS_UID || process.env.SUDO_UID || 0);
  const targetGid = Number(process.env.RUN_AS_GID || process.env.SUDO_GID || 0);
  if (targetUid > 0 && targetGid > 0) {
    process.setgid(targetGid);
    process.setuid(targetUid);
    console.log(`🔒 Đã hạ quyền tiến trình khỏi root xuống uid=${targetUid}, gid=${targetGid}`);
  }
}

async function main() {
  console.log('🛡️  Đang khởi động NetShield DNS...');
  await store.load();
  const cachedCount = await blocklistEngine.loadFromCache();
  console.log(`📦 Đã nạp ${cachedCount.toLocaleString('vi-VN')} tên miền chặn từ bộ nhớ đệm.`);

  const dnsSrv = await startDnsServer({ host: BIND_HOST, port: DNS_PORT });
  console.log(`🌐 DNS Server đang chạy tại ${dnsSrv.host}:${dnsSrv.port} (UDP + TCP)`);

  // Hạ quyền khỏi root ngay sau khi mở xong cổng 53
  dropRootPrivileges();

  const webSrv = await startWebServer({ host: WEB_HOST, port: WEB_PORT, dnsPort: DNS_PORT });
  console.log(`🖥️  Giao diện quản trị (chỉ máy Mac Mini): http://${webSrv.host}:${webSrv.port}`);

  // Nếu chưa có cache blocklist thì tự tải ngay ở nền
  if (cachedCount === 0) {
    console.log('⬇️  Chưa có danh sách chặn, đang tự động tải ABPVN & OISD...');
    blocklistEngine.refreshAll().then((res) => {
      if (res.updated) {
        console.log(`✅ Đã cập nhật xong ${res.totalDomains.toLocaleString('vi-VN')} tên miền quảng cáo.`);
      }
    });
  }

  // Tự động cập nhật danh sách chặn mỗi 24 giờ
  const refreshTimer = setInterval(() => {
    blocklistEngine.refreshAll().catch(() => {});
  }, 24 * 60 * 60 * 1000);

  const shutdown = async () => {
    console.log('\n🛑 Đang dừng NetShield DNS...');
    clearInterval(refreshTimer);
    await Promise.allSettled([dnsSrv.close(), webSrv.close()]);
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error('❌ Lỗi khởi động:', err.message);
  if (err.code === 'EACCES') {
    console.error('💡 Gợi ý: Cổng 53 yêu cầu quyền quản trị. Hãy chạy bằng: sudo ./scripts/run-lan.sh');
  }
  process.exit(1);
});
