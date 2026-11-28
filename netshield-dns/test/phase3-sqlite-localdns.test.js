import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import dnsPacket from 'dns-packet';

const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'netshield-p3-test-'));
process.env.NETSHIELD_DATA_DIR = tmpDataDir;

const { store } = await import('../src/store.js');
const { blocklistEngine } = await import('../src/blocklist.js');
const { resolveLocalDnsRecord } = await import('../src/dns-server.js');
const { forensicsDb } = await import('../src/db.js');
const { startWebServer } = await import('../src/web-server.js');

await store.load();
await blocklistEngine.loadFromCache();
const dbStarted = await forensicsDb.start(store);
assert.equal(dbStarted, true, 'SQLite Forensics phải khởi động thành công trên Node 24');

test.after(async () => {
  forensicsDb.stop();
  await fs.rm(tmpDataDir, { recursive: true, force: true });
});

test('SQLite Forensics: batch write, query filter (severity/blocked/search), CSV export và retention cleanup', async () => {
  store.recordQuery({
    clientIp: '192.168.1.107',
    domain: 'malware-test.example',
    qtype: 'A',
    blocked: true,
    cached: false,
    severity: 'high',
    reason: 'URLHaus Malware',
    latencyMs: 0.3,
  });
  store.recordQuery({
    clientIp: '192.168.1.75',
    domain: 'sg-cloud.ezvizlife.com',
    qtype: 'A',
    blocked: false,
    cached: false,
    severity: 'info',
    rcode: 'NOERROR',
    reason: 'allowed',
    latencyMs: 14.2,
  });

  const highRows = forensicsDb.queryLogs({ severity: 'high', sinceHours: 24 });
  assert.equal(highRows.length, 1);
  assert.equal(highRows[0].domain, 'malware-test.example');

  const searchRows = forensicsDb.queryLogs({ search: 'ezviz', sinceHours: 24 });
  assert.equal(searchRows.length, 1);
  assert.equal(searchRows[0].clientIp, '192.168.1.75');

  const csv = forensicsDb.exportCsv({ sinceHours: 24 });
  assert.ok(csv.startsWith('\uFEFFThoi_gian,'));
  assert.ok(csv.includes('malware-test.example'));
  assert.ok(csv.includes('URLHaus Malware'));

  const stats = await forensicsDb.getStats();
  assert.equal(stats.enabled, true);
  assert.ok(stats.totalRows >= 2);
  assert.ok(stats.dbSizeBytes > 0);

  // Chèn 1 bản ghi cũ 40 ngày trước và kiểm tra cleanup retention 14 ngày
  const oldTs = Date.now() - 40 * 24 * 60 * 60 * 1000;
  forensicsDb.db
    .prepare('INSERT INTO query_logs (ts, client_ip, domain, blocked) VALUES (?, ?, ?, ?)')
    .run(oldTs, '192.168.1.99', 'old-expired.example', 0);
  const deleted = forensicsDb.cleanupOldLogs(14);
  assert.equal(deleted, 1);
});

test('Local DNS Split-Horizon trả lời trực tiếp IP LAN và không rò rỉ truy vấn AAAA ra upstream', () => {
  store.config.localRecords = [
    { domain: 'netshield.lan', ip: '192.168.1.210', ips: ['192.168.1.210'], ttl: 60 },
    { domain: 'cluster.lan', ip: '192.168.1.209', ips: ['192.168.1.209', '192.168.1.210'], ttl: 30 },
  ];

  const qA = { id: 1001, questions: [{ type: 'A', name: 'netshield.lan' }] };
  const respA = dnsPacket.decode(resolveLocalDnsRecord(qA, 'netshield.lan', 'A'));
  assert.equal(respA.rcode, 'NOERROR');
  assert.equal(respA.answers.length, 1);
  assert.equal(respA.answers[0].data, '192.168.1.210');

  // Hỏi AAAA cho bản ghi chỉ có IPv4 -> vẫn trả NOERROR rỗng (không forward ra Internet)
  const qAAAA = { id: 1002, questions: [{ type: 'AAAA', name: 'netshield.lan' }] };
  const respAAAA = dnsPacket.decode(resolveLocalDnsRecord(qAAAA, 'netshield.lan', 'AAAA'));
  assert.equal(respAAAA.rcode, 'NOERROR');
  assert.equal(respAAAA.answers.length, 0);

  // Multi-IP local record
  const qMulti = { id: 1003, questions: [{ type: 'A', name: 'cluster.lan' }] };
  const respMulti = dnsPacket.decode(resolveLocalDnsRecord(qMulti, 'cluster.lan', 'A'));
  assert.equal(respMulti.answers.length, 2);

  // Domain không có trong localRecords -> null
  assert.equal(resolveLocalDnsRecord({ id: 1004, questions: [{ type: 'A', name: 'google.com' }] }, 'google.com', 'A'), null);
});

test('Web API: Backup ẩn Telegram Token, Restore giữ lại Token cũ, và Local DNS CRUD', async () => {
  store.config.alerts.telegramBotToken = 'SECRET-BOT-TOKEN-123';
  await store.save();

  const web = await startWebServer({ host: '127.0.0.1', port: 18081, dnsPort: 5335 });
  try {
    // 1. Export backup mặc định phải che telegramBotToken
    const expRes = await fetch('http://127.0.0.1:18081/api/config/export');
    assert.equal(expRes.status, 200);
    const exported = await expRes.json();
    assert.equal(exported.config.alerts.telegramBotToken, '', 'Export mặc định phải ẩn Telegram Bot Token');

    // 2. Import backup (không có token) -> phải giữ nguyên token cũ trong hệ thống
    exported.config.localRecords = [{ domain: 'printer.lan', ip: '192.168.1.239', ips: ['192.168.1.239'], ttl: 60 }];
    const impRes = await fetch('http://127.0.0.1:18081/api/config/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(exported),
    });
    assert.equal(impRes.status, 200);
    assert.equal(store.config.alerts.telegramBotToken, 'SECRET-BOT-TOKEN-123', 'Import không được xóa mất Token đang có');
    assert.equal(store.config.localRecords[0].domain, 'printer.lan');

    // 3. Local DNS POST + DELETE
    const addRes = await fetch('http://127.0.0.1:18081/api/local-dns', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: 'router.lan', ip: '192.168.1.1' }),
    });
    assert.equal(addRes.status, 200);
    assert.ok(store.config.localRecords.some((r) => r.domain === 'router.lan'));

    const delRes = await fetch('http://127.0.0.1:18081/api/local-dns/router.lan', { method: 'DELETE' });
    assert.equal(delRes.status, 200);
    assert.ok(!store.config.localRecords.some((r) => r.domain === 'router.lan'));
  } finally {
    await web.close();
  }
});
