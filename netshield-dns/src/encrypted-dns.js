import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { handleDnsPayload } from './dns-server.js';

const MAX_DNS_MSG_BYTES = 4096;
const MIN_DNS_MSG_BYTES = 12;
const DOT_IDLE_TIMEOUT_MS = 30_000;
const HOSTNAME_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function isLoopbackAddress(addr = '') {
  const ip = String(addr).trim();
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

export function extractDohClientIp(req) {
  const remote = req.socket?.remoteAddress || '127.0.0.1';
  if (isLoopbackAddress(remote)) {
    const cfIp = req.headers['cf-connecting-ip'];
    if (typeof cfIp === 'string' && cfIp.trim()) return cfIp.trim();
    const realIp = req.headers['x-real-ip'];
    if (typeof realIp === 'string' && realIp.trim()) return realIp.trim();
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) {
      const first = xff.split(',')[0].trim();
      if (first) return first;
    }
  }
  return remote.startsWith('::ffff:') ? remote.slice(7) : remote;
}

export function decodeBase64Url(input) {
  if (typeof input !== 'string' || !input.length) return null;
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(input)) return null;
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + '='.repeat(padLen);
  const buf = Buffer.from(padded, 'base64');
  if (buf.length < MIN_DNS_MSG_BYTES || buf.length > MAX_DNS_MSG_BYTES) return null;
  return buf;
}

function readRawBody(req, maxBytes = MAX_DNS_MSG_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        const err = new Error('DNS payload too large');
        err.statusCode = 413;
        req.destroy();
        reject(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function loadTlsFiles(certPath, keyPath) {
  if (!certPath || !keyPath) return null;
  const [cert, key] = await Promise.all([
    fs.readFile(certPath),
    fs.readFile(keyPath),
  ]);
  return { cert, key };
}

/**
 * Khởi chạy DNS-over-HTTPS (RFC 8484) server chuyên biệt cho thiết bị di động & reverse proxy.
 * - Nếu có certPath + keyPath hợp lệ: chạy HTTPS trực tiếp.
 * - Nếu không có TLS cert: chạy HTTP trên localhost (mặc định 127.0.0.1:8053) để đứng sau
 *   Cloudflare Tunnel / Caddy / Nginx mà KHÔNG lộ giao diện quản trị :8080.
 */
export async function startDohServer({
  host = '127.0.0.1',
  port = 8053,
  endpoint = '/dns-query',
  certPath = '',
  keyPath = '',
} = {}) {
  const tlsOpts = await loadTlsFiles(certPath, keyPath).catch(() => null);
  const tlsEnabled = Boolean(tlsOpts);

  const handler = async (req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://localhost');
      const method = req.method || 'GET';

      if (method === 'GET' && url.pathname === '/health') {
        const payload = JSON.stringify({
          ok: true,
          service: 'netshield-doh',
          protocol: tlsEnabled ? 'https' : 'http',
          endpoint,
        });
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(payload);
        return;
      }

      if (url.pathname !== endpoint) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Not Found');
        return;
      }

      let rawQuery = null;

      if (method === 'POST') {
        const ct = String(req.headers['content-type'] || '').toLowerCase();
        if (!ct.includes('application/dns-message')) {
          res.writeHead(415, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('Unsupported Media Type: expected application/dns-message');
          return;
        }
        rawQuery = await readRawBody(req, MAX_DNS_MSG_BYTES);
        if (rawQuery.length < MIN_DNS_MSG_BYTES) {
          res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('Malformed DNS query');
          return;
        }
      } else if (method === 'GET') {
        const dnsParam = url.searchParams.get('dns') || '';
        rawQuery = decodeBase64Url(dnsParam);
        if (!rawQuery) {
          res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('Invalid or missing base64url dns parameter');
          return;
        }
      } else {
        res.writeHead(405, {
          Allow: 'GET, POST',
          'Content-Type': 'text/plain; charset=utf-8',
        });
        res.end('Method Not Allowed');
        return;
      }

      const clientIp = extractDohClientIp(req);
      const resp = await handleDnsPayload(rawQuery, clientIp);
      if (!resp) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Unable to process DNS payload');
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'application/dns-message',
        'Content-Length': resp.length,
        'Cache-Control': 'max-age=60',
      });
      res.end(resp);
    } catch (err) {
      const code = err?.statusCode || 500;
      if (!res.headersSent) {
        res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8' });
      }
      res.end(code === 413 ? 'Payload Too Large' : 'Internal Server Error');
    }
  };

  const server = tlsEnabled
    ? https.createServer({ cert: tlsOpts.cert, key: tlsOpts.key, minVersion: 'TLSv1.2' }, handler)
    : http.createServer(handler);

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const addr = server.address();
      const actualPort = typeof addr === 'object' && addr ? addr.port : port;
      resolve({
        host,
        port: actualPort,
        endpoint,
        tlsEnabled,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

/**
 * Khởi chạy DNS-over-TLS (RFC 7858) trên cổng 853 (hoặc cổng cấu hình).
 * Chỉ khởi chạy khi có certPath + keyPath hợp lệ.
 */
export async function startDotServer({
  host = '0.0.0.0',
  port = 853,
  certPath = '',
  keyPath = '',
} = {}) {
  const tlsOpts = await loadTlsFiles(certPath, keyPath);
  if (!tlsOpts) {
    throw new Error('DoT yêu cầu chứng chỉ TLS (tlsCertPath và tlsKeyPath hợp lệ).');
  }

  const server = tls.createServer(
    {
      cert: tlsOpts.cert,
      key: tlsOpts.key,
      minVersion: 'TLSv1.2',
    },
    (socket) => {
      socket.setTimeout(DOT_IDLE_TIMEOUT_MS, () => socket.destroy());
      let buffer = Buffer.alloc(0);

      socket.on('data', async (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length > MAX_DNS_MSG_BYTES * 4) {
          socket.destroy();
          return;
        }
        while (buffer.length >= 2) {
          const msgLen = buffer.readUInt16BE(0);
          if (msgLen < MIN_DNS_MSG_BYTES || msgLen > MAX_DNS_MSG_BYTES) {
            socket.destroy();
            return;
          }
          if (buffer.length < msgLen + 2) break;
          const rawQuery = buffer.subarray(2, 2 + msgLen);
          buffer = buffer.subarray(2 + msgLen);

          try {
            const resp = await handleDnsPayload(rawQuery, socket.remoteAddress || '127.0.0.1');
            if (resp && !socket.destroyed) {
              const lenPrefix = Buffer.alloc(2);
              lenPrefix.writeUInt16BE(resp.length, 0);
              socket.write(Buffer.concat([lenPrefix, resp]));
            }
          } catch {
            // Bỏ qua khung lỗi đơn lẻ
          }
        }
      });

      socket.on('error', () => {});
    }
  );

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const addr = server.address();
      const actualPort = typeof addr === 'object' && addr ? addr.port : port;
      resolve({
        host,
        port: actualPort,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

function escapeXml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function normalizePublicHostname(input) {
  const cleaned = String(input || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .replace(/^\.+|\.+$/g, '');
  return HOSTNAME_RE.test(cleaned) ? cleaned : '';
}

/**
 * Tạo hồ sơ cấu hình Apple (.mobileconfig) chuẩn iOS 14+ / iPadOS / macOS
 * sử dụng PayloadType `com.apple.dnsSettings.managed` (DoH hoặc DoT).
 */
export function buildIosMobileConfig({
  hostname,
  mode = 'doh',
  profileName = 'NetShield DNS',
  excludeSsids = [],
  serverAddresses = [],
} = {}) {
  const cleanHost = normalizePublicHostname(hostname);
  if (!cleanHost) {
    throw new Error('Tên miền công khai (hostname) không hợp lệ. Ví dụ: dns.example.com');
  }

  const normalizedMode = mode === 'dot' ? 'dot' : 'doh';
  const cleanSsids = [...new Set((excludeSsids || []).map((s) => String(s || '').trim()).filter(Boolean))];
  const cleanAddrs = [...new Set((serverAddresses || []).map((s) => String(s || '').trim()).filter(Boolean))];

  const rootUuid = crypto.randomUUID().toUpperCase();
  const dnsUuid = crypto.randomUUID().toUpperCase();
  const displayName = `${profileName} (${normalizedMode === 'dot' ? 'DoT' : 'DoH'})`;

  const dnsSettingsEntries =
    normalizedMode === 'dot'
      ? `        <key>DNSProtocol</key>
        <string>TLS</string>
        <key>ServerName</key>
        <string>${escapeXml(cleanHost)}</string>`
      : `        <key>DNSProtocol</key>
        <string>HTTPS</string>
        <key>ServerURL</key>
        <string>https://${escapeXml(cleanHost)}/dns-query</string>`;

  const serverAddressesXml = cleanAddrs.length
    ? `\n        <key>ServerAddresses</key>\n        <array>\n${cleanAddrs
        .map((ip) => `          <string>${escapeXml(ip)}</string>`)
        .join('\n')}\n        </array>`
    : '';

  const onDemandRules = [];
  if (cleanSsids.length > 0) {
    onDemandRules.push(`        <dict>
          <key>Action</key>
          <string>Disconnect</string>
          <key>InterfaceTypeMatch</key>
          <string>WiFi</string>
          <key>SSIDMatch</key>
          <array>
${cleanSsids.map((ssid) => `            <string>${escapeXml(ssid)}</string>`).join('\n')}
          </array>
        </dict>`);
  }
  onDemandRules.push(`        <dict>
          <key>Action</key>
          <string>Connect</string>
        </dict>`);

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
${dnsSettingsEntries}${serverAddressesXml}
      </dict>
      <key>OnDemandRules</key>
      <array>
${onDemandRules.join('\n')}
      </array>
      <key>PayloadDescription</key>
      <string>Chặn quảng cáo &amp; mã độc trên iOS qua ${escapeXml(displayName)}</string>
      <key>PayloadDisplayName</key>
      <string>${escapeXml(displayName)}</string>
      <key>PayloadIdentifier</key>
      <string>com.netshield.dns.settings.${dnsUuid}</string>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key>
      <string>${dnsUuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>ProhibitDisablement</key>
      <false/>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Hồ sơ DNS mã hóa NetShield cho iPhone/iPad (hỗ trợ cả Wi-Fi &amp; 4G/5G)</string>
  <key>PayloadDisplayName</key>
  <string>${escapeXml(displayName)}</string>
  <key>PayloadIdentifier</key>
  <string>com.netshield.dns.profile.${rootUuid}</string>
  <key>PayloadOrganization</key>
  <string>NetShield DNS</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${rootUuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
`;
}
