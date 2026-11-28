import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';

const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'netshield-p2-test-'));
process.env.NETSHIELD_DATA_DIR = tmpDataDir;

const { store, inferBlocklistMeta, DEFAULT_ALERTS_CONFIG } = await import('../src/store.js');
const { blocklistEngine } = await import('../src/blocklist.js');
const { alertEngine } = await import('../src/alerts.js');

await store.load();
await blocklistEngine.loadFromCache();
alertEngine.start(store);

test.after(async () => {
  alertEngine.stop();
  await fs.rm(tmpDataDir, { recursive: true, force: true });
});

test('inferBlocklistMeta phân loại đúng Ads vs Malware/Phishing/Threat Intel', () => {
  assert.deepEqual(inferBlocklistMeta({ id: 'abpvn-hosts', name: 'ABPVN Hosts' }), {
    category: 'ads',
    severity: 'info',
  });
  assert.deepEqual(inferBlocklistMeta({ name: 'Phishing Army', url: 'https://phishing.army/...' }), {
    category: 'phishing',
    severity: 'high',
  });
  assert.deepEqual(inferBlocklistMeta({ name: 'URLHaus Malware (Abuse.ch)' }), {
    category: 'malware',
    severity: 'high',
  });
  assert.deepEqual(inferBlocklistMeta({ name: 'HaGeZi Threat Intelligence (TIF Mini)' }), {
    category: 'threat_intel',
    severity: 'high',
  });
});

test('Zero-Trust Camera/IoT: Audit Mode học không chặn, Enforce Mode khóa cứng ngoài Allowlist', () => {
  store.config.protectionEnabled = true;
  store.config.devices = [
    { id: 'mac:0C:A6:4C:32:77:C1', ip: '192.168.1.75', name: 'Camera Ezviz H80x', groupId: 'camera', mac: '0C:A6:4C:32:77:C1' },
  ];

  // 1. Audit Mode: cho phép đi qua nhưng ghi nhận domain ngoài allowlist
  store.config.clientRules = [
    {
      id: 'rule-cam-audit',
      name: 'Audit Camera',
      targetType: 'group',
      groupId: 'camera',
      ruleMode: 'allowlist_audit',
      enabled: true,
      allowedDomains: ['ezvizlife.com', 'ntp.org'],
      schedule: { enabled: false },
    },
  ];

  const auditOk = blocklistEngine.evaluate('sg-cloud.ezvizlife.com', '192.168.1.75');
  assert.equal(auditOk.blocked, false);

  const auditUnknown = blocklistEngine.evaluate('unknown-c2.example.org', '192.168.1.75');
  assert.equal(auditUnknown.blocked, false, 'Audit mode không được chặn');
  assert.equal(auditUnknown.auditViolation, true);

  const observed = blocklistEngine.getObservedDomainsForGroup('camera');
  assert.ok(observed.some((d) => d.domain === 'sg-cloud.ezvizlife.com'));
  assert.ok(observed.some((d) => d.domain === 'unknown-c2.example.org' && d.allowedByRule === false));

  // 2. Enforce Mode: chỉ cho phép domain trong Allowlist, chặn mọi domain ngoài
  store.config.clientRules[0].ruleMode = 'allowlist_enforce';

  const enfOk = blocklistEngine.evaluate('sg-cloud.ezvizlife.com', '192.168.1.75');
  assert.equal(enfOk.blocked, false);

  const enfBlocked = blocklistEngine.evaluate('unknown-c2.example.org', '192.168.1.75');
  assert.equal(enfBlocked.blocked, true);
  assert.equal(enfBlocked.iotViolation, true);
  assert.equal(enfBlocked.severity, 'medium');
});

test('AlertEngine: phân 2 cấp Rogue Device (MAC thật = high, Private MAC = low, MAC đã lưu = bỏ qua)', () => {
  alertEngine.clearAll();
  store.config.alerts = { ...DEFAULT_ALERTS_CONFIG, enabled: true, rogueDeviceEnabled: true, ignorePrivateMacPush: true };
  store.config.devices = [
    { id: 'mac:D0:11:E5:D2:F6:37', ip: '192.168.1.210', name: 'Mac Mini', groupId: 'computer', mac: 'D0:11:E5:D2:F6:37' },
  ];

  // Thiết bị đã lưu -> không cảnh báo
  const known = alertEngine.handleDiscoveredDevice({
    ip: '192.168.1.210',
    mac: 'D0:11:E5:D2:F6:37',
    isPrivateMac: false,
    isSelf: false,
    isLoopback: false,
    isGateway: false,
    isSharedMac: false,
  });
  assert.equal(known, null);

  // Thiết bị lạ MAC thật -> high
  const rogueReal = alertEngine.handleDiscoveredDevice({
    ip: '192.168.1.99',
    mac: '00:1B:21:AA:BB:CC',
    isPrivateMac: false,
    vendor: 'Intel PC',
    isSelf: false,
    isLoopback: false,
    isGateway: false,
    isSharedMac: false,
  });
  assert.ok(rogueReal);
  assert.equal(rogueReal.type, 'rogue_device');
  assert.equal(rogueReal.severity, 'high');

  // Thiết bị lạ Private MAC -> bỏ qua khi ignorePrivateMacPush=true (tránh làm nhiễu tab Cảnh báo)
  const roguePrivSuppressed = alertEngine.handleDiscoveredDevice({
    ip: '192.168.1.188',
    mac: '0A:11:22:33:44:55',
    isPrivateMac: true,
    isSelf: false,
    isLoopback: false,
    isGateway: false,
    isSharedMac: false,
  });
  assert.equal(roguePrivSuppressed, null);

  // Dedupe vĩnh viễn theo MAC: kể cả khi hết cửa sổ 10 phút cũng không lặp lại cùng 1 MAC lạ
  alertEngine.dedupeMap.clear();
  const dup = alertEngine.handleDiscoveredDevice({
    ip: '192.168.1.99',
    mac: '00:1B:21:AA:BB:CC',
    isPrivateMac: false,
    isSelf: false,
    isLoopback: false,
    isGateway: false,
    isSharedMac: false,
  });
  assert.equal(dup, null);
});

test('AlertEngine: phát hiện Threat Hit, DNS Tunneling và NXDOMAIN Spike', () => {
  alertEngine.clearAll();
  store.config.alerts = {
    ...DEFAULT_ALERTS_CONFIG,
    enabled: true,
    nxdomainThresholdPerMin: 5,
    tunnelingLabelLength: 50,
  };

  // 1. Threat Hit
  store.recordQuery({
    clientIp: '192.168.1.107',
    domain: 'evil-phish.example',
    qtype: 'A',
    blocked: true,
    cached: false,
    severity: 'high',
    reason: 'Phishing Army',
    latencyMs: 0.4,
  });

  // 2. DNS Tunneling (nhãn dài > 50 ký tự)
  const longLabel = 'a'.repeat(58) + '.tunnel.example';
  store.recordQuery({
    clientIp: '192.168.1.107',
    domain: longLabel,
    qtype: 'TXT',
    blocked: false,
    cached: false,
    rcode: 'NOERROR',
    reason: 'allowed',
    latencyMs: 12,
  });

  // 3. NXDOMAIN Spike (>= 5 domain khác nhau trong 60s)
  for (let i = 1; i <= 5; i++) {
    store.recordQuery({
      clientIp: '192.168.1.129',
      domain: `dga-random-${i}.nonexistent.test`,
      qtype: 'A',
      blocked: false,
      cached: false,
      rcode: 'NXDOMAIN',
      reason: 'allowed',
      latencyMs: 15,
    });
  }

  const all = alertEngine.getAlerts();
  assert.ok(all.some((a) => a.type === 'threat_hit' && a.domain === 'evil-phish.example'));
  assert.ok(all.some((a) => a.type === 'dns_anomaly' && /Tunneling/.test(a.title)));
  assert.ok(all.some((a) => a.type === 'dns_anomaly' && /NXDOMAIN/.test(a.title)));

  // Acknowledge flow
  const sumBefore = alertEngine.getSummary();
  assert.ok(sumBefore.unacknowledged >= 3);
  alertEngine.acknowledgeAll();
  assert.equal(alertEngine.getSummary().unacknowledged, 0);
});
