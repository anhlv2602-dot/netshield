import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import dgram from 'node:dgram';
import dnsPacket from 'dns-packet';

// Cô lập thư mục data để không đụng vào cấu hình production đang chạy cổng 53
const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'netshield-test-'));
process.env.NETSHIELD_DATA_DIR = tmpDataDir;

const { store, DEFAULT_SECURITY_CONFIG } = await import('../src/store.js');
const { blocklistEngine } = await import('../src/blocklist.js');
const {
  isPrivateOrReservedIp,
  inspectUpstreamResponse,
  buildBlockedResponse,
  dnsCache,
  testAllUpstreams,
  startDnsServer,
} = await import('../src/dns-server.js');

await store.load();
await blocklistEngine.loadFromCache();

test.after(async () => {
  await fs.rm(tmpDataDir, { recursive: true, force: true });
});

test('isPrivateOrReservedIp nhận diện chính xác IPv4 & IPv6 nội bộ vs công cộng', () => {
  // Nội bộ / đặc biệt -> true
  for (const ip of [
    '127.0.0.1',
    '10.0.0.1',
    '172.16.0.5',
    '172.31.255.254',
    '192.168.1.1',
    '192.168.1.210',
    '169.254.1.1',
    '100.64.0.1',
    '0.0.0.0',
    '::1',
    '::',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    '::ffff:192.168.1.1',
  ]) {
    assert.equal(isPrivateOrReservedIp(ip), true, `Phải chặn IP nội bộ: ${ip}`);
  }

  // Công cộng -> false
  for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '172.32.0.1', '203.113.131.1', '2606:4700:4700::1111']) {
    assert.equal(isPrivateOrReservedIp(ip), false, `Không được chặn IP công cộng: ${ip}`);
  }
});

test('Anti-Bypass chặn Firefox DoH & Apple Private Relay bằng NXDOMAIN', () => {
  store.config.protectionEnabled = true;
  store.config.security = { ...DEFAULT_SECURITY_CONFIG, antiBypass: true };

  for (const d of ['use-application-dns.net', 'mask.icloud.com', 'mask-h2.icloud.com', '_dns.resolver.arpa']) {
    const dec = blocklistEngine.evaluate(d, '192.168.1.100');
    assert.equal(dec.blocked, true, `Phải chặn ${d}`);
    assert.equal(dec.forceNxdomain, true, `Phải trả NXDOMAIN cho ${d}`);
  }

  // Khi tắt antiBypass thì cho phép
  store.config.security.antiBypass = false;
  const allowed = blocklistEngine.evaluate('use-application-dns.net', '192.168.1.100');
  assert.equal(allowed.blocked, false);
  store.config.security.antiBypass = true;
});

test('DNS Rebinding Guard chặn IP LAN từ upstream nhưng miễn trừ Whitelist & rebindingWhitelist', () => {
  store.config.protectionEnabled = true;
  store.config.security = {
    ...DEFAULT_SECURITY_CONFIG,
    dnsRebindingGuard: true,
    rebindingWhitelist: ['plex.direct'],
  };

  const makeAResp = (name, ip) =>
    dnsPacket.encode({
      type: 'response',
      id: 1234,
      flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
      questions: [{ type: 'A', name }],
      answers: [{ type: 'A', class: 'IN', name, ttl: 120, data: ip }],
    });

  // Domain lạ trả về IP router -> CHẶN
  const rebind = inspectUpstreamResponse(makeAResp('evil-rebind.test', '192.168.1.1'), 'evil-rebind.test', '192.168.1.107');
  assert.equal(rebind.blocked, true);
  assert.equal(rebind.forceNxdomain, true);
  assert.match(rebind.reason, /DNS Rebinding/);

  // Domain nằm trong rebindingWhitelist -> CHO PHÉP
  const plex = inspectUpstreamResponse(makeAResp('192-168-1-50.plex.direct', '192.168.1.50'), '192-168-1-50.plex.direct', '192.168.1.107');
  assert.equal(plex.blocked, false);

  // Domain nằm trong PROTECTED_WHITELIST (Thuế/HĐĐT/Ngân hàng) -> CHO PHÉP
  const gov = inspectUpstreamResponse(makeAResp('test.gdt.gov.vn', '10.0.0.5'), 'test.gdt.gov.vn', '192.168.1.107');
  assert.equal(gov.blocked, false);

  // IP công cộng bình thường -> CHO PHÉP
  const pub = inspectUpstreamResponse(makeAResp('example.com', '93.184.216.34'), 'example.com', '192.168.1.107');
  assert.equal(pub.blocked, false);
  assert.equal(pub.ttl, 120);

  // Windows NCSI IPv6 hợp lệ (đúng cặp dns.msftncsi.com + fd3e:4f5a:5b81::1) -> CHO PHÉP
  const ncsiIpv6Resp = dnsPacket.encode({
    type: 'response',
    id: 1235,
    flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
    questions: [{ type: 'AAAA', name: 'dns.msftncsi.com' }],
    answers: [{ type: 'AAAA', class: 'IN', name: 'dns.msftncsi.com', ttl: 60, data: 'fd3e:4f5a:5b81::1' }],
  });
  const ncsiAllowed = inspectUpstreamResponse(ncsiIpv6Resp, 'dns.msftncsi.com', '192.168.1.244');
  assert.equal(ncsiAllowed.blocked, false);

  // Nhưng dns.msftncsi.com trỏ về IP nội bộ khác (VD modem hijack 192.168.2.1) -> VẪN CHẶN
  const ncsiHijack = inspectUpstreamResponse(makeAResp('dns.msftncsi.com', '192.168.2.1'), 'dns.msftncsi.com', '192.168.1.244');
  assert.equal(ncsiHijack.blocked, true);
  assert.equal(ncsiHijack.forceNxdomain, true);
});

test('CNAME Cloaking Guard chặn domain sạch trỏ CNAME tới tracker bị chặn', () => {
  store.config.protectionEnabled = true;
  store.config.blacklist = ['tracker.evil.test'];
  blocklistEngine.rebuildCustomSets();
  store.config.security = { ...DEFAULT_SECURITY_CONFIG, cnameCloakingGuard: true };

  const cnameResp = dnsPacket.encode({
    type: 'response',
    id: 4321,
    flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
    questions: [{ type: 'A', name: 'metrics.clean-site.test' }],
    answers: [
      { type: 'CNAME', class: 'IN', name: 'metrics.clean-site.test', ttl: 60, data: 'sub.tracker.evil.test' },
      { type: 'A', class: 'IN', name: 'sub.tracker.evil.test', ttl: 60, data: '93.184.216.34' },
    ],
  });

  const res = inspectUpstreamResponse(cnameResp, 'metrics.clean-site.test', '192.168.1.107');
  assert.equal(res.blocked, true);
  assert.match(res.reason, /CNAME Cloaking/);

  // Thiết bị có bypassProtection -> không chặn
  const bypassed = inspectUpstreamResponse(cnameResp, 'metrics.clean-site.test', '192.168.1.107', {
    bypassProtection: true,
  });
  assert.equal(bypassed.blocked, false);
});

test('Serve-Stale Cache giữ bản ghi hết TTL cho tình huống mất upstream', () => {
  dnsCache.clear();
  const sample = Buffer.from([0x12, 0x34, 0x81, 0x80]);
  dnsCache.set('example.com:A', sample, 30);
  // Ép expiresAt lùi về quá khứ nhưng vẫn trong cửa sổ staleUntil 24h
  const entry = dnsCache.map.get('example.com:A');
  entry.expiresAt = Date.now() - 1000;

  assert.equal(dnsCache.get('example.com:A'), null, 'get() phải trả null khi hết TTL tươi');
  assert.deepEqual(dnsCache.getStale('example.com:A'), sample, 'getStale() phải trả buffer dự phòng');
});

test('buildBlockedResponse tôn trọng forceNxdomain ngay cả khi blockResponseMode là zero', () => {
  store.config.blockResponseMode = 'zero';
  const q = {
    id: 0xabcd,
    questions: [{ type: 'A', name: 'use-application-dns.net' }],
  };
  const zeroResp = dnsPacket.decode(buildBlockedResponse(q, { forceNxdomain: false }));
  assert.equal(zeroResp.answers[0]?.data, '0.0.0.0');

  const nxdResp = dnsPacket.decode(buildBlockedResponse(q, { forceNxdomain: true }));
  assert.equal(nxdResp.rcode, 'NXDOMAIN');
  assert.equal(nxdResp.answers.length, 0);
});

test('DoH trực tiếp bằng IP (1.1.1.2 & 9.9.9.9) hoạt động không cần bootstrap DNS', async () => {
  const results = await testAllUpstreams(['https://1.1.1.2/dns-query', 'https://9.9.9.9/dns-query']);
  assert.equal(results.length, 2);
  for (const r of results) {
    assert.equal(r.protocol, 'DoH');
    assert.equal(r.ok, true, `DoH ${r.upstream} thất bại: ${r.error}`);
    assert.ok(r.answers >= 1, `DoH ${r.upstream} không trả bản ghi A`);
  }
});

test('Smoke test DNS Server cô lập trên cổng 15335 (Anti-Bypass + DoH Upstream)', async () => {
  store.config.upstreamDns = ['https://1.1.1.2/dns-query', 'https://9.9.9.9/dns-query'];
  store.config.security = { ...DEFAULT_SECURITY_CONFIG };
  const srv = await startDnsServer({ host: '127.0.0.1', port: 15335 });

  const sendQuery = (name, type = 'A') =>
    new Promise((resolve, reject) => {
      const sock = dgram.createSocket('udp4');
      const reqBuf = dnsPacket.encode({
        type: 'query',
        id: Math.floor(Math.random() * 65535),
        flags: dnsPacket.RECURSION_DESIRED,
        questions: [{ type, name }],
      });
      const timer = setTimeout(() => {
        sock.close();
        reject(new Error('Timeout'));
      }, 4000);
      sock.once('message', (msg) => {
        clearTimeout(timer);
        sock.close();
        resolve(dnsPacket.decode(msg));
      });
      sock.send(reqBuf, 15335, '127.0.0.1');
    });

  try {
    const antiBypassResp = await sendQuery('use-application-dns.net', 'A');
    assert.equal(antiBypassResp.rcode, 'NXDOMAIN');

    const cleanResp = await sendQuery('cloudflare.com', 'A');
    assert.equal(cleanResp.rcode, 'NOERROR');
    assert.ok(cleanResp.answers.length >= 1);
  } finally {
    await srv.close();
  }
});
