import dgram from 'node:dgram';
import net from 'node:net';
import dnsPacket from 'dns-packet';
import { store, normalizeDomain } from './store.js';
import { blocklistEngine } from './blocklist.js';

const MAX_CACHE_SIZE = 5000;
const MIN_TTL_SEC = 30;
const MAX_TTL_SEC = 3600;
const UPSTREAM_TIMEOUT_MS = 2500;
const MAX_QPS_PER_IP = Number(process.env.MAX_QPS_PER_IP || 250);

// Chống spam/flood DNS theo từng IP (cửa sổ trượt 1 giây, tự dọn mỗi 30s)
const rateWindows = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateWindows) {
    if (now - entry.windowStart > 5000) {
      rateWindows.delete(ip);
    }
  }
}, 30000).unref();

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateWindows.get(ip);
  if (!entry || now - entry.windowStart >= 1000) {
    rateWindows.set(ip, { windowStart: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_QPS_PER_IP;
}

class DnsCache {
  constructor(maxSize = MAX_CACHE_SIZE) {
    this.maxSize = maxSize;
    this.map = new Map();
  }

  get(key) {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return null;
    }
    // LRU refresh
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.buffer;
  }

  set(key, buffer, ttlSec) {
    const clampedTtl = Math.max(MIN_TTL_SEC, Math.min(MAX_TTL_SEC, ttlSec || 60));
    if (this.map.size >= this.maxSize) {
      const oldestKey = this.map.keys().next().value;
      if (oldestKey) this.map.delete(oldestKey);
    }
    this.map.set(key, {
      buffer,
      expiresAt: Date.now() + clampedTtl * 1000,
    });
  }

  clear() {
    this.map.clear();
  }

  get size() {
    return this.map.size;
  }
}

export const dnsCache = new DnsCache();

function buildBlockedResponse(queryPacket) {
  const q = queryPacket.questions?.[0];
  const mode = store.config.blockResponseMode || 'zero';
  const base = {
    type: 'response',
    id: queryPacket.id,
    flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
    questions: queryPacket.questions,
    answers: [],
  };

  if (!q || mode === 'nxdomain') {
    base.flags |= 3; // NXDOMAIN
    return dnsPacket.encode(base);
  }

  if (q.type === 'A') {
    base.answers.push({
      type: 'A',
      class: 'IN',
      name: q.name,
      ttl: 60,
      data: '0.0.0.0',
    });
  } else if (q.type === 'AAAA') {
    base.answers.push({
      type: 'AAAA',
      class: 'IN',
      name: q.name,
      ttl: 60,
      data: '::',
    });
  } else {
    // Với HTTPS / SVCB / TXT... trả về NXDOMAIN để trình duyệt không bypass
    base.flags |= 3;
  }

  return dnsPacket.encode(base);
}

function forwardUdp(rawQuery, upstreamIp, upstreamPort = 53) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.close();
        reject(new Error(`Upstream ${upstreamIp} timeout`));
      }
    }, UPSTREAM_TIMEOUT_MS);

    socket.once('message', (msg) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        socket.close();
        resolve(msg);
      }
    });

    socket.once('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        socket.close();
        reject(err);
      }
    });

    socket.send(rawQuery, upstreamPort, upstreamIp);
  });
}

async function forwardWithFailover(rawQuery) {
  const upstreams = store.config.upstreamDns?.length ? store.config.upstreamDns : ['1.1.1.1', '8.8.8.8'];
  let lastError = null;
  for (const ip of upstreams) {
    try {
      return await forwardUdp(rawQuery, ip, 53);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error('All upstream DNS failed');
}

function extractMinTtl(responseBuffer) {
  try {
    const decoded = dnsPacket.decode(responseBuffer);
    if (!decoded.answers || decoded.answers.length === 0) return 60;
    let min = MAX_TTL_SEC;
    for (const ans of decoded.answers) {
      if (typeof ans.ttl === 'number' && ans.ttl < min) {
        min = ans.ttl;
      }
    }
    return min;
  } catch {
    return 60;
  }
}

function cleanClientIp(ip) {
  if (!ip) return 'unknown';
  return ip.replace(/^::ffff:/, '');
}

async function handleDnsPayload(rawBuffer, clientIp) {
  const ip = cleanClientIp(clientIp);
  if (isRateLimited(ip)) {
    return null;
  }

  const startMs = performance.now();
  let query;
  try {
    query = dnsPacket.decode(rawBuffer);
  } catch {
    return null;
  }

  const question = query.questions?.[0];
  if (!question) {
    return await forwardWithFailover(rawBuffer);
  }

  const domain = normalizeDomain(question.name);
  const qtype = question.type || 'A';

  // Kiểm tra bộ lọc
  const decision = blocklistEngine.evaluate(domain, ip);
  if (decision.blocked) {
    const resp = buildBlockedResponse(query);
    store.recordQuery({
      clientIp: ip,
      domain,
      qtype,
      blocked: true,
      cached: false,
      reason: decision.reason,
      latencyMs: Number((performance.now() - startMs).toFixed(2)),
    });
    return resp;
  }

  // Kiểm tra Cache
  const cacheKey = `${domain}:${qtype}`;
  const cachedResp = dnsCache.get(cacheKey);
  if (cachedResp) {
    // Gắn lại đúng Transaction ID của gói tin yêu cầu
    const patched = Buffer.from(cachedResp);
    patched.writeUInt16BE(query.id, 0);
    store.recordQuery({
      clientIp: ip,
      domain,
      qtype,
      blocked: false,
      cached: true,
      reason: decision.reason,
      latencyMs: Number((performance.now() - startMs).toFixed(2)),
    });
    return patched;
  }

  // Forward lên Upstream DNS
  try {
    const upstreamResp = await forwardWithFailover(rawBuffer);
    const ttl = extractMinTtl(upstreamResp);
    dnsCache.set(cacheKey, upstreamResp, ttl);

    store.recordQuery({
      clientIp: ip,
      domain,
      qtype,
      blocked: false,
      cached: false,
      reason: decision.reason,
      latencyMs: Number((performance.now() - startMs).toFixed(2)),
    });
    return upstreamResp;
  } catch (err) {
    const servfail = dnsPacket.encode({
      type: 'response',
      id: query.id,
      flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE | 2, // SERVFAIL
      questions: query.questions,
      answers: [],
    });
    store.recordQuery({
      clientIp: ip,
      domain,
      qtype,
      blocked: false,
      cached: false,
      reason: `Lỗi upstream: ${err.message}`,
      latencyMs: Number((performance.now() - startMs).toFixed(2)),
    });
    return servfail;
  }
}

export function startDnsServer({ host = '0.0.0.0', port = 5335 } = {}) {
  return new Promise((resolve, reject) => {
    const udpServer = dgram.createSocket('udp4');
    const tcpServer = net.createServer((socket) => {
      let buffer = Buffer.alloc(0);
      socket.on('data', async (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 2) {
          const msgLen = buffer.readUInt16BE(0);
          if (buffer.length < msgLen + 2) break;
          const rawQuery = buffer.subarray(2, 2 + msgLen);
          buffer = buffer.subarray(2 + msgLen);

          const resp = await handleDnsPayload(rawQuery, socket.remoteAddress);
          if (resp && !socket.destroyed) {
            const lenPrefix = Buffer.alloc(2);
            lenPrefix.writeUInt16BE(resp.length, 0);
            socket.write(Buffer.concat([lenPrefix, resp]));
          }
        }
      });
      socket.on('error', () => {});
    });

    udpServer.on('message', async (msg, rinfo) => {
      try {
        const resp = await handleDnsPayload(msg, rinfo.address);
        if (resp) {
          udpServer.send(resp, rinfo.port, rinfo.address);
        }
      } catch {
        // Bỏ qua gói tin lỗi
      }
    });

    udpServer.once('error', (err) => {
      tcpServer.close();
      reject(err);
    });

    udpServer.bind(port, host, () => {
      tcpServer.listen(port, host, () => {
        resolve({
          host,
          port,
          close: () =>
            new Promise((done) => {
              udpServer.close(() => tcpServer.close(() => done()));
            }),
        });
      });
    });
  });
}
