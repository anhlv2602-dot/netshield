import test from 'node:test';
import assert from 'node:assert/strict';
import {
  checkVnImpersonation,
  isDgaLikeDomain,
  DgaTracker,
  BeaconingTracker,
} from '../src/threat-guard.js';
import { store, PROTECTED_WHITELIST, normalizeDomain, inferBlocklistMeta } from '../src/store.js';
import { blocklistEngine } from '../src/blocklist.js';

const WHITELIST_SET = new Set(PROTECTED_WHITELIST.map(normalizeDomain));

test('VN Lookalike Guard: chặn chính xác các mẫu lừa đảo cơ quan Nhà nước, Thuế & Ngân hàng VN', () => {
  const phishingSamples = [
    'vneid-capnhat.xyz',
    'vne1d-vn.com',
    'dichvucong-gdt.online',
    'thuedientu-vn.com',
    'hoadondientu-gdt.top',
    'vietcombank-login.com',
    'vietc0mbank247.com',
    'techcombank-support.vip',
    'mbbank-xacthuc.icu',
    'acb-login.xyz',
    'bidv-smartbanking.click',
    'misa-xacthuc.top',
    'gdt-gov-vn.site',
    'shopee-nhanthuong.shop',
    'momo-nhanqua.online',
    'bocongan-xacminh.com',
  ];

  for (const d of phishingSamples) {
    const res = checkVnImpersonation(d, WHITELIST_SET);
    assert.equal(res.suspicious, true, `Phải phát hiện giả mạo: ${d}`);
    assert.equal(res.severity, 'critical');
  }
});

test('VN Lookalike Guard: KHÔNG chặn nhầm tên miền chính chủ VN và từ tiếng Anh trùng từ khóa ngắn', () => {
  const safeSamples = [
    'vneid.gov.vn',
    'thuedientu.gdt.gov.vn',
    'hoadondientu.gdt.gov.vn',
    'dichvucong.gov.vn',
    'vietcombank.com.vn',
    'ebanking.vietcombank.com.vn',
    'techcombank.com.vn',
    'mbbank.com.vn',
    'acb.com.vn',
    'misa.vn',
    'meinvoice.vn',
    'shopee.vn',
    'momo.vn',
    // Từ tiếng Anh chứa từ khóa ngắn (acb, vib, sapo, shb...)
    'macbook-support.site',
    'vibe-music.online',
    'saponin-shop.xyz',
    'dashboard-app.top',
    // Đuôi chính thống VN luôn miễn trừ
    'portal.edu.vn',
    'vneid-guide.org.vn',
  ];

  for (const d of safeSamples) {
    const res = checkVnImpersonation(d, WHITELIST_SET);
    assert.equal(res.suspicious, false, `Không được chặn nhầm domain hợp pháp: ${d}`);
  }
});

test('blocklistEngine.evaluate tích hợp VN Lookalike Guard theo chế độ block / audit / off', () => {
  const prevProtection = store.config.protectionEnabled;
  const prevMode = store.config.security?.vnImpersonationMode;
  store.config.protectionEnabled = true;
  blocklistEngine.rebuildCustomSets();

  try {
    store.config.security.vnImpersonationMode = 'block';
    const blk = blocklistEngine.evaluate('vneid-capnhat.xyz', '192.168.1.100');
    assert.equal(blk.blocked, true);
    assert.equal(blk.severity, 'critical');

    store.config.security.vnImpersonationMode = 'audit';
    const aud = blocklistEngine.evaluate('vneid-capnhat.xyz', '192.168.1.100');
    assert.equal(aud.blocked, false);
    assert.match(aud.reason, /^Audit:/);

    store.config.security.vnImpersonationMode = 'off';
    const off = blocklistEngine.evaluate('vneid-capnhat.xyz', '192.168.1.100');
    assert.equal(off.blocked, false);
  } finally {
    store.config.protectionEnabled = prevProtection;
    store.config.security.vnImpersonationMode = prevMode;
  }
});

test('DGA Detector & DgaTracker: nhận diện domain sinh ngẫu nhiên và loại trừ Chrome probe / CDN', () => {
  assert.equal(isDgaLikeDomain('xk8q2m9vplz4wr7t.com'), true);
  assert.equal(isDgaLikeDomain('qzxjklmnpvbrtwf9.xyz'), true);

  // Loại trừ Chrome single-label probe, CDN, domain thường
  assert.equal(isDgaLikeDomain('xk8q2m9vplz4wr7t'), false);
  assert.equal(isDgaLikeDomain('vnexpress.net'), false);
  assert.equal(isDgaLikeDomain('e13678.dscb.akamaiedge.net'), false);
  assert.equal(isDgaLikeDomain('1.168.192.in-addr.arpa'), false);
  assert.equal(isDgaLikeDomain('my-long-article-slug-here.com'), false);

  const tracker = new DgaTracker({ threshold: 4 });
  const t0 = 1_700_000_000_000;
  assert.equal(tracker.record('192.168.1.50', 'xk8q2m9vplz4wr7a.com', { nowMs: t0 }), null);
  assert.equal(tracker.record('192.168.1.50', 'qzxjklmnpvbrtwf1.xyz', { nowMs: t0 + 1000 }), null);
  assert.equal(tracker.record('192.168.1.50', 'mnbvcxzlkjhgfds2.top', { nowMs: t0 + 2000 }), null);
  const hit = tracker.record('192.168.1.50', 'wertyuipqsdfghj3.net', { nowMs: t0 + 3000 });
  assert.ok(hit);
  assert.equal(hit.count, 4);
  // Không spam lần 2 trong cùng cửa sổ
  assert.equal(tracker.record('192.168.1.50', 'zxcvbnmlkjhgfdp4.org', { nowMs: t0 + 4000 }), null);
});

test('BeaconingTracker: phát hiện nhịp C2 đều đặn trên computer/mobile, bỏ qua IoT/Camera & giữ trần LRU', () => {
  const tracker = new BeaconingTracker({ minHits: 6, maxEntries: 3 });
  const t0 = 1_700_000_000_000;

  // 1. Nhóm IoT / Camera bị bỏ qua (không báo giả cho Growatt / Samsung TV / Camera)
  for (let i = 0; i < 8; i++) {
    const r = tracker.record('192.168.1.145', 'server.growatt.com', {
      nowMs: t0 + i * 60_000,
      deviceGroup: 'iot',
    });
    assert.equal(r, null);
  }

  // 2. Máy tính gọi đều đặn mỗi 60s tới domain lạ -> phát hiện C2 Beaconing
  let detected = null;
  for (let i = 0; i < 6; i++) {
    detected = tracker.record('192.168.1.107', 'c2-panel.unknown-host.xyz', {
      nowMs: t0 + i * 60_000 + (i % 2) * 400,
      deviceGroup: 'computer',
    });
  }
  assert.ok(detected);
  assert.equal(detected.domain, 'c2-panel.unknown-host.xyz');
  assert.ok(detected.avgIntervalSec >= 59 && detected.avgIntervalSec <= 61);

  // 3. Giới hạn cứng LRU (maxEntries = 3)
  tracker.record('192.168.1.107', 'a.example.org', { nowMs: t0 + 10_000, deviceGroup: 'computer' });
  tracker.record('192.168.1.107', 'b.example.org', { nowMs: t0 + 20_000, deviceGroup: 'computer' });
  tracker.record('192.168.1.107', 'c.example.org', { nowMs: t0 + 30_000, deviceGroup: 'computer' });
  assert.ok(tracker.map.size <= 3);
});

test('inferBlocklistMeta phân loại đúng nguồn NRD', () => {
  const meta = inferBlocklistMeta({ id: 'hagezi-nrd7', name: 'HaGeZi NRD 7 ngày', url: 'https://example.com/nrd7.txt' });
  assert.equal(meta.category, 'nrd');
  assert.equal(meta.severity, 'high');
});
