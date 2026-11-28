import test from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import dnsPacket from 'dns-packet';
import { store } from '../src/store.js';
import { blocklistEngine } from '../src/blocklist.js';
import {
  startDohServer,
  startDotServer,
  buildIosMobileConfig,
  extractDohClientIp,
} from '../src/encrypted-dns.js';
import { startWebServer } from '../src/web-server.js';

function makeQuery(name, type = 'A', id = 0x1234) {
  return dnsPacket.encode({
    type: 'query',
    id,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name }],
  });
}

function toBase64Url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

test('DoH Server (RFC 8484): POST, GET, /health, validation & client IP extraction', async () => {
  const prevProtection = store.config.protectionEnabled;
  const prevBlacklist = [...(store.config.blacklist || [])];
  const prevLocal = [...(store.config.localRecords || [])];
  const prevSecurity = { ...(store.config.security || {}) };

  store.config.protectionEnabled = true;
  store.config.security = { ...prevSecurity, antiBypass: true };
  store.config.blacklist = ['ads.mobile-test.example'];
  store.config.localRecords = [
    { domain: 'nas.home.lan', ips: ['192.168.1.50'], strategy: 'round_robin', ttl: 60 },
  ];
  blocklistEngine.rebuildCustomSets();

  const doh = await startDohServer({ host: '127.0.0.1', port: 0 });
  const baseUrl = `http://127.0.0.1:${doh.port}`;

  try {
    // 1. Health endpoint
    const healthRes = await fetch(`${baseUrl}/health`);
    assert.equal(healthRes.status, 200);
    const health = await healthRes.json();
    assert.equal(health.ok, true);
    assert.equal(health.endpoint, '/dns-query');

    // 2. POST /dns-query — chặn quảng cáo (trả 0.0.0.0)
    const adQuery = makeQuery('ads.mobile-test.example', 'A', 0x2222);
    const adRes = await fetch(`${baseUrl}/dns-query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'X-Forwarded-For': '10.0.0.99',
      },
      body: adQuery,
    });
    assert.equal(adRes.status, 200);
    assert.equal(adRes.headers.get('content-type'), 'application/dns-message');
    const adDecoded = dnsPacket.decode(Buffer.from(await adRes.arrayBuffer()));
    assert.equal(adDecoded.id, 0x2222);
    assert.equal(adDecoded.answers?.[0]?.data, '0.0.0.0');

    // 3. GET /dns-query?dns=<base64url> — phân giải Local DNS
    const localQuery = makeQuery('nas.home.lan', 'A', 0x3333);
    const localRes = await fetch(`${baseUrl}/dns-query?dns=${toBase64Url(localQuery)}`);
    assert.equal(localRes.status, 200);
    const localDecoded = dnsPacket.decode(Buffer.from(await localRes.arrayBuffer()));
    assert.equal(localDecoded.id, 0x3333);
    assert.equal(localDecoded.answers?.[0]?.data, '192.168.1.50');

    // 4. Validation errors (415, 400, 405)
    const badCt = await fetch(`${baseUrl}/dns-query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    assert.equal(badCt.status, 415);

    const badGet = await fetch(`${baseUrl}/dns-query?dns=!!!invalid!!!`);
    assert.equal(badGet.status, 400);

    const badMethod = await fetch(`${baseUrl}/dns-query`, { method: 'DELETE' });
    assert.equal(badMethod.status, 405);

    // 5. Client IP extraction chỉ tin proxy header từ loopback
    assert.equal(
      extractDohClientIp({
        socket: { remoteAddress: '127.0.0.1' },
        headers: { 'cf-connecting-ip': '113.160.1.2' },
      }),
      '113.160.1.2'
    );
    assert.equal(
      extractDohClientIp({
        socket: { remoteAddress: '203.0.113.5' },
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      }),
      '203.0.113.5'
    );
  } finally {
    await doh.close();
    store.config.protectionEnabled = prevProtection;
    store.config.blacklist = prevBlacklist;
    store.config.localRecords = prevLocal;
    store.config.security = prevSecurity;
    blocklistEngine.rebuildCustomSets();
  }
});

test('DoT Server (RFC 7858): TLS handshake + length-prefixed DNS query', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'netshield-dot-'));
  const keyPath = path.join(tmpDir, 'key.pem');
  const certPath = path.join(tmpDir, 'cert.pem');

  execFileSync('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-keyout',
    keyPath,
    '-out',
    certPath,
    '-days',
    '1',
    '-nodes',
    '-subj',
    '/CN=localhost',
  ], { stdio: 'ignore' });

  const prevBlacklist = [...(store.config.blacklist || [])];
  const prevProtection = store.config.protectionEnabled;
  store.config.protectionEnabled = true;
  store.config.blacklist = ['dot-ad.mobile.test'];
  blocklistEngine.rebuildCustomSets();

  const dot = await startDotServer({ host: '127.0.0.1', port: 0, certPath, keyPath });

  try {
    const queryBuf = makeQuery('dot-ad.mobile.test', 'A', 0x4444);
    const respBuf = await new Promise((resolve, reject) => {
      const sock = tls.connect(
        { host: '127.0.0.1', port: dot.port, rejectUnauthorized: false },
        () => {
          const prefix = Buffer.alloc(2);
          prefix.writeUInt16BE(queryBuf.length, 0);
          sock.write(Buffer.concat([prefix, queryBuf]));
        }
      );
      let acc = Buffer.alloc(0);
      sock.on('data', (chunk) => {
        acc = Buffer.concat([acc, chunk]);
        if (acc.length >= 2) {
          const len = acc.readUInt16BE(0);
          if (acc.length >= 2 + len) {
            const payload = acc.subarray(2, 2 + len);
            sock.end();
            resolve(payload);
          }
        }
      });
      sock.once('error', reject);
    });

    const decoded = dnsPacket.decode(respBuf);
    assert.equal(decoded.id, 0x4444);
    assert.equal(decoded.answers?.[0]?.data, '0.0.0.0');
  } finally {
    await dot.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
    store.config.blacklist = prevBlacklist;
    store.config.protectionEnabled = prevProtection;
    blocklistEngine.rebuildCustomSets();
  }
});

test('iOS .mobileconfig generator & Web API /api/mobile/ios-profile', async () => {
  // 1. Direct DoH profile with SSID exclusion & XML escaping
  const dohXml = buildIosMobileConfig({
    hostname: 'dns.example.com',
    mode: 'doh',
    excludeSsids: ['Home & Office <WiFi>'],
  });
  assert.match(dohXml, /<string>com\.apple\.dnsSettings\.managed<\/string>/);
  assert.match(dohXml, /<string>HTTPS<\/string>/);
  assert.match(dohXml, /<string>https:\/\/dns\.example\.com\/dns-query<\/string>/);
  assert.match(dohXml, /Home &amp; Office &lt;WiFi&gt;/);
  assert.match(dohXml, /<string>Disconnect<\/string>/);
  assert.match(dohXml, /<string>Connect<\/string>/);

  // 2. Direct DoT profile
  const dotXml = buildIosMobileConfig({ hostname: 'dns.example.com', mode: 'dot' });
  assert.match(dotXml, /<string>TLS<\/string>/);
  assert.match(dotXml, /<string>dns\.example\.com<\/string>/);

  // 3. Invalid hostname rejected
  assert.throws(() => buildIosMobileConfig({ hostname: 'not a host!!' }));

  // 4. Web API endpoint
  const web = await startWebServer({
    host: '127.0.0.1',
    port: 0,
    dnsPort: 5335,
    encryptedDnsStatus: { dohRunning: true, dohPort: 8053, dotRunning: false },
  });
  const baseUrl = `http://127.0.0.1:${web.port}`;

  try {
    const okRes = await fetch(`${baseUrl}/api/mobile/ios-profile?hostname=dns.myhome.vn&mode=doh&excludeSsids=MyWiFi`);
    assert.equal(okRes.status, 200);
    assert.match(okRes.headers.get('content-type') || '', /application\/x-apple-aspen-config/);
    const body = await okRes.text();
    assert.match(body, /https:\/\/dns\.myhome\.vn\/dns-query/);
    assert.match(body, /<string>MyWiFi<\/string>/);

    const badRes = await fetch(`${baseUrl}/api/mobile/ios-profile?hostname=bad_host`);
    assert.equal(badRes.status, 400);
  } finally {
    await web.close();
  }
});
