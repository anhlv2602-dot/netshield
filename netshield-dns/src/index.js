import { store } from './store.js';
import { blocklistEngine } from './blocklist.js';
import { startDnsServer, dnsCache } from './dns-server.js';
import { startWebServer } from './web-server.js';
import { deviceDiscovery } from './discovery.js';
import { alertEngine } from './alerts.js';
import { forensicsDb } from './db.js';
import { localDnsLB } from './load-balancer.js';

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
  console.log(
    `🌐 DNS Server đang chạy tại ${dnsSrv.host}:${dnsSrv.port} (UDP + TCP${dnsSrv.ipv6Enabled ? ' + IPv6' : ''})`
  );

  // Hạ quyền khỏi root ngay sau khi mở xong cổng 53
  dropRootPrivileges();

  // Tự động lưu snapshot thống kê 24h mỗi 60 giây (sau khi hạ quyền để file thuộc user thường)
  store.startStatsAutosave(60_000);

  // Khởi chạy bộ máy cảnh báo bảo mật & kho log SQLite (sau khi hạ quyền để file thuộc user thường)
  alertEngine.start(store);
  const dbOk = await forensicsDb.start(store);
  if (dbOk) {
    console.log(`🗄️  SQLite Forensics đang bật (lưu lịch sử ${store.config.storage?.retentionDays || 14} ngày).`);
  }

  const webSrv = await startWebServer({ host: WEB_HOST, port: WEB_PORT, dnsPort: DNS_PORT });
  console.log(`🖥️  Giao diện quản trị (chỉ máy Mac Mini): http://${webSrv.host}:${webSrv.port}`);

  // Khởi chạy bộ kiểm tra sức khỏe TCP/HTTP cho Local DNS Round-Robin
  localDnsLB.startHealthChecks(() => store.config.localRecords || []);

  // Khởi chạy bộ nhận diện thiết bị LAN ở nền (không làm chậm luồng DNS chính)
  deviceDiscovery.start(store, {
    onMigration: () => dnsCache.clear(),
    onDeviceDiscovered: (info) => alertEngine.handleDiscoveredDevice(info),
  });

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
    store.stopStatsAutosave();
    alertEngine.stop();
    forensicsDb.stop();
    localDnsLB.stopHealthChecks();
    deviceDiscovery.stop();
    await Promise.allSettled([
      store.saveStats({ force: true }),
      alertEngine.save(),
      dnsSrv.close(),
      webSrv.close(),
    ]);
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
