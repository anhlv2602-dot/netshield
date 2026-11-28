import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { startWebServer } from '../src/web-server.js';
import { startDnsServer } from '../src/dns-server.js';
import { normalizeHaSyncConfig } from '../src/ha-sync.js';

function rawHttpRequest({ port, method = 'GET', path = '/', headers = {}, body = '' }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('Web Admin Security: chống CSRF, DNS Rebinding Host header & có đủ Security Headers', async () => {
  const web = await startWebServer({ host: '127.0.0.1', port: 0, dnsPort: 5335 });
  try {
    // 1. Security headers trên trang HTML chính
    const htmlRes = await rawHttpRequest({
      port: web.port,
      method: 'GET',
      path: '/',
      headers: { Host: `127.0.0.1:${web.port}` },
    });
    assert.equal(htmlRes.status, 200);
    assert.equal(htmlRes.headers['x-frame-options'], 'DENY');
    assert.equal(htmlRes.headers['x-content-type-options'], 'nosniff');
    assert.equal(htmlRes.headers['referrer-policy'], 'no-referrer');
    assert.match(htmlRes.headers['content-security-policy'] || '', /frame-ancestors 'none'/);

    // 2. Chặn DNS Rebinding (Host header không phải localhost / 127.0.0.1)
    const rebindRes = await rawHttpRequest({
      port: web.port,
      method: 'GET',
      path: '/api/status',
      headers: { Host: 'evil.attacker.com:8080' },
    });
    assert.equal(rebindRes.status, 403);

    // 3. Chặn CSRF qua Origin khác
    const csrfOrigin = await rawHttpRequest({
      port: web.port,
      method: 'POST',
      path: '/api/protection',
      headers: {
        Host: `127.0.0.1:${web.port}`,
        Origin: 'https://evil-site.com',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ enabled: false }),
    });
    assert.equal(csrfOrigin.status, 403);

    // 4. Chặn CSRF qua Sec-Fetch-Site: cross-site
    const csrfFetch = await rawHttpRequest({
      port: web.port,
      method: 'POST',
      path: '/api/protection',
      headers: {
        Host: `127.0.0.1:${web.port}`,
        'Sec-Fetch-Site': 'cross-site',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ enabled: false }),
    });
    assert.equal(csrfFetch.status, 403);

    // 5. Cho phép curl / HA Sync cục bộ (không có Origin, Host = 127.0.0.1)
    const okCurl = await rawHttpRequest({
      port: web.port,
      method: 'GET',
      path: '/api/status',
      headers: { Host: `127.0.0.1:${web.port}` },
    });
    assert.equal(okCurl.status, 200);
  } finally {
    await web.close();
  }
});

test('HA Sync Config: chặn option injection, ký tự shell & path traversal trên sshKeyPath', () => {
  const dirty = normalizeHaSyncConfig({
    sshKeyPath: '-oProxyCommand=id',
    sshKnownHostsPath: '/tmp/hosts;rm -rf /',
    secondaryAppDir: '../../etc/passwd',
    secondaryHost: '-oEvil',
    secondaryUser: '-root',
  });
  assert.equal(dirty.sshKeyPath, '');
  assert.equal(dirty.sshKnownHostsPath, '');
  assert.equal(dirty.secondaryAppDir, '~/Apps/netshield/netshield-dns');
  assert.equal(dirty.secondaryHost, '192.168.1.209');
  assert.equal(dirty.secondaryUser, 'server-mac');

  const clean = normalizeHaSyncConfig({
    sshKeyPath: '/Users/anhlv2602/.ssh/id_ed25519',
    sshKnownHostsPath: '/Users/anhlv2602/.ssh/known_hosts',
  });
  assert.equal(clean.sshKeyPath, '/Users/anhlv2602/.ssh/id_ed25519');
  assert.equal(clean.sshKnownHostsPath, '/Users/anhlv2602/.ssh/known_hosts');
});

test('TCP DNS Server: ngắt ngay kết nối gửi frame DNS quá lớn (chống DoS bộ đệm)', async () => {
  const srv = await startDnsServer({ host: '127.0.0.1', port: 15337 });
  try {
    const closed = await new Promise((resolve) => {
      const sock = net.connect({ host: '127.0.0.1', port: 15337 }, () => {
        // Gửi header length = 9000 (> 4096)
        const badFrame = Buffer.alloc(16);
        badFrame.writeUInt16BE(9000, 0);
        sock.write(badFrame);
      });
      sock.once('close', () => resolve(true));
      sock.once('error', () => resolve(true));
      setTimeout(() => {
        sock.destroy();
        resolve(false);
      }, 1500);
    });
    assert.equal(closed, true);
  } finally {
    await srv.close();
  }
});
