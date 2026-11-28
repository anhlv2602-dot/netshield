import dgram from 'node:dgram';
import net from 'node:net';
import http2 from 'node:http2';
import dnsPacket from 'dns-packet';
import { store, normalizeDomain } from './store.js';
import { blocklistEngine } from './blocklist.js';
import { upstreamLB, localDnsLB, normalizeUpstreamStrategy } from './load-balancer.js';
import { alertEngine, hasLongDnsLabel } from './alerts.js';

const MAX_CACHE_SIZE = 5000;
const MIN_TTL_SEC = 30;
const MAX_TTL_SEC = 3600;
const STALE_GRACE_MS = 24 * 60 * 60 * 1000; // Serve-Stale tối đa 24h khi mất upstream
const UPSTREAM_TIMEOUT_MS = 2500;
const MAX_QPS_PER_IP = Number(process.env.MAX_QPS_PER_IP || 250);
const CIRCUIT_FAILURE_THRESHOLD = 3;
const CIRCUIT_OPEN_MS = 60 * 1000;

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

// Circuit breaker & thống kê sức khỏe theo từng Upstream
const upstreamHealthMap = new Map();

function getHealthEntry(upstream) {
  let entry = upstreamHealthMap.get(upstream);
  if (!entry) {
    entry = {
      upstream,
      protocol: upstream.startsWith('https://') ? 'DoH' : 'UDP',
      consecutiveFailures: 0,
      openUntil: 0,
      lastLatencyMs: null,
      lastError: null,
      lastOkAt: null,
    };
    upstreamHealthMap.set(upstream, entry);
  }
  return entry;
}

function recordUpstreamSuccess(upstream, latencyMs) {
  const entry = getHealthEntry(upstream);
  entry.consecutiveFailures = 0;
  entry.openUntil = 0;
  entry.lastLatencyMs = Number(latencyMs.toFixed(1));
  entry.lastError = null;
  entry.lastOkAt = new Date().toISOString();
}

function recordUpstreamFailure(upstream, errorMsg) {
  const entry = getHealthEntry(upstream);
  entry.consecutiveFailures += 1;
  entry.lastError = errorMsg;
  if (entry.consecutiveFailures >= CIRCUIT_FAILURE_THRESHOLD) {
    entry.openUntil = Date.now() + CIRCUIT_OPEN_MS;
  }
}

export function getUpstreamHealth() {
  const now = Date.now();
  const configured = store.config.upstreamDns?.length
    ? store.config.upstreamDns
    : ['https://1.1.1.2/dns-query', 'https://9.9.9.9/dns-query', '203.113.131.1'];
  return configured.map((u) => {
    const e = getHealthEntry(u);
    const circuitOpen = e.openUntil > now;
    return {
      upstream: u,
      protocol: u.startsWith('https://') ? 'DoH' : 'UDP',
      status: circuitOpen ? 'circuit_open' : e.lastError && !e.lastOkAt ? 'degraded' : 'healthy',
      consecutiveFailures: e.consecutiveFailures,
      retryInSec: circuitOpen ? Math.ceil((e.openUntil - now) / 1000) : 0,
      lastLatencyMs: e.lastLatencyMs,
      ewmaLatencyMs: upstreamLB.getEwmaLatency(u),
      queries: upstreamLB.getQueryCount(u),
      lastError: e.lastError,
      lastOkAt: e.lastOkAt,
    };
  });
}

export function resetUpstreamHealth() {
  upstreamHealthMap.clear();
  upstreamLB.reset();
}

class DnsCache {
  constructor(maxSize = MAX_CACHE_SIZE) {
    this.maxSize = maxSize;
    this.map = new Map();
  }

  get(key) {
    const entry = this.map.get(key);
    if (!entry) return null;
    const now = Date.now();
    if (now > entry.staleUntil) {
      this.map.delete(key);
      return null;
    }
    if (now > entry.expiresAt) {
      // Đã hết TTL tươi, giữ lại cho Serve-Stale nếu upstream lỗi
      return null;
    }
    // LRU refresh
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.buffer;
  }

  getStale(key) {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.staleUntil) {
      this.map.delete(key);
      return null;
    }
    return entry.buffer;
  }

  set(key, buffer, ttlSec) {
    const clampedTtl = Math.max(MIN_TTL_SEC, Math.min(MAX_TTL_SEC, ttlSec || 60));
    if (this.map.size >= this.maxSize) {
      const oldestKey = this.map.keys().next().value;
      if (oldestKey) this.map.delete(oldestKey);
    }
    const expiresAt = Date.now() + clampedTtl * 1000;
    this.map.set(key, {
      buffer,
      expiresAt,
      staleUntil: expiresAt + STALE_GRACE_MS,
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

/**
 * Kiểm tra IP có thuộc dải nội bộ / loopback / link-local / CGNAT hay không (chống DNS Rebinding)
 */
export function isPrivateOrReservedIp(rawIp) {
  if (!rawIp || typeof rawIp !== 'string') return false;
  let ip = rawIp.trim().toLowerCase();
  if (ip.startsWith('::ffff:')) {
    ip = ip.slice(7);
  }

  // IPv4
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT / Tailscale
    return false;
  }

  // IPv6
  if (net.isIPv6(ip)) {
    if (ip === '::' || ip === '::1') return true;
    const firstHextet = ip.split(':')[0] || '';
    if (/^f[cd][0-9a-f]{2}$/.test(firstHextet)) return true; // fc00::/7 Unique Local
    if (/^fe[89ab][0-9a-f]$/.test(firstHextet)) return true; // fe80::/10 Link-Local
    return false;
  }

  return false;
}

function isRebindingWhitelisted(domain) {
  const list = store.config.security?.rebindingWhitelist || [];
  if (!list.length) return false;
  const parts = domain.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const suffix = parts.slice(i).join('.');
    if (list.includes(suffix)) return true;
  }
  return false;
}

/**
 * Giải mã 1 lần duy nhất phản hồi từ upstream để:
 * 1. Lấy minTTL cho cache
 * 2. Kiểm tra DNS Rebinding (IP private từ upstream công cộng)
 * 3. Kiểm tra CNAME Cloaking (mục tiêu CNAME nằm trong blocklist)
 */
export function inspectUpstreamResponse(responseBuffer, originalDomain, clientIp, { bypassProtection = false } = {}) {
  const result = {
    ttl: 60,
    rcode: 'NOERROR',
    blocked: false,
    forceNxdomain: false,
    severity: 'info',
    reason: null,
  };

  let decoded;
  try {
    decoded = dnsPacket.decode(responseBuffer);
  } catch {
    return result;
  }

  result.rcode = decoded.rcode || 'NOERROR';
  const answers = decoded.answers || [];
  if (answers.length === 0) return result;

  let minTtl = MAX_TTL_SEC;
  for (const ans of answers) {
    if (typeof ans.ttl === 'number' && ans.ttl < minTtl) {
      minTtl = ans.ttl;
    }
  }
  result.ttl = minTtl;

  if (!store.config.protectionEnabled || bypassProtection) {
    return result;
  }

  const sec = store.config.security || {};
  const domainWhitelisted = blocklistEngine.isWhitelisted(originalDomain);

  // 1. Chống DNS Rebinding
  if (sec.dnsRebindingGuard !== false && !domainWhitelisted && !isRebindingWhitelisted(originalDomain)) {
    for (const ans of answers) {
      if ((ans.type === 'A' || ans.type === 'AAAA') && typeof ans.data === 'string') {
        if (isPrivateOrReservedIp(ans.data)) {
          return {
            ttl: minTtl,
            rcode: result.rcode,
            blocked: true,
            forceNxdomain: true,
            severity: 'high',
            reason: `Chống DNS Rebinding (${ans.data})`,
          };
        }
      }
    }
  }

  // 2. Chống CNAME Cloaking
  if (sec.cnameCloakingGuard !== false && !domainWhitelisted) {
    for (const ans of answers) {
      if (ans.type === 'CNAME' && typeof ans.data === 'string') {
        const cnameTarget = normalizeDomain(ans.data);
        if (!cnameTarget || cnameTarget === originalDomain) continue;
        const cnameDecision = blocklistEngine.evaluateCnameTarget(cnameTarget, clientIp);
        if (cnameDecision.blocked) {
          return {
            ttl: minTtl,
            rcode: result.rcode,
            blocked: true,
            forceNxdomain: false,
            severity: cnameDecision.severity || 'info',
            reason: `CNAME Cloaking (${cnameTarget} → ${cnameDecision.reason})`,
          };
        }
      }
    }
  }

  return result;
}

export function buildBlockedResponse(queryPacket, { forceNxdomain = false } = {}) {
  const q = queryPacket.questions?.[0];
  const mode = forceNxdomain ? 'nxdomain' : store.config.blockResponseMode || 'zero';
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

function parseUdpUpstream(entry) {
  // Hỗ trợ '1.1.1.2' hoặc '1.1.1.2:5353'
  const idx = entry.lastIndexOf(':');
  if (idx > 0 && !entry.includes(']') && /^\d+$/.test(entry.slice(idx + 1))) {
    return { host: entry.slice(0, idx), port: Number(entry.slice(idx + 1)) };
  }
  return { host: entry, port: 53 };
}

function forwardUdp(rawQuery, upstreamEntry, { signal } = {}) {
  const { host: upstreamIp, port: upstreamPort } = parseUdpUpstream(upstreamEntry);
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      const err = new Error('Aborted');
      err.name = 'AbortError';
      return reject(err);
    }
    const socket = dgram.createSocket(net.isIPv6(upstreamIp) ? 'udp6' : 'udp4');
    let settled = false;

    const cleanup = () => {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      try {
        socket.close();
      } catch {}
    };

    const onAbort = () => {
      if (!settled) {
        settled = true;
        cleanup();
        const err = new Error('Aborted');
        err.name = 'AbortError';
        reject(err);
      }
    };

    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new Error(`Upstream ${upstreamEntry} timeout`));
      }
    }, UPSTREAM_TIMEOUT_MS);

    socket.once('message', (msg) => {
      if (!settled) {
        settled = true;
        cleanup();
        resolve(msg);
      }
    });

    socket.once('error', (err) => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(err);
      }
    });

    socket.send(rawQuery, upstreamPort, upstreamIp);
  });
}

function forwardDohHttp2(rawQuery, urlStr, { signal } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      const err = new Error('Aborted');
      err.name = 'AbortError';
      return reject(err);
    }
    const u = new URL(urlStr);
    const client = http2.connect(u.origin);
    let settled = false;
    const done = (err, buf) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      try {
        client.close();
      } catch {}
      if (err) reject(err);
      else resolve(buf);
    };

    const onAbort = () => {
      const err = new Error('Aborted');
      err.name = 'AbortError';
      done(err);
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    const timer = setTimeout(() => done(new Error('DoH/H2 timeout')), UPSTREAM_TIMEOUT_MS);
    client.once('error', (err) => done(err));

    const req = client.request({
      ':method': 'POST',
      ':path': `${u.pathname}${u.search}`,
      'content-type': 'application/dns-message',
      accept: 'application/dns-message',
      'content-length': rawQuery.length,
    });

    let status = 0;
    const chunks = [];
    req.on('response', (headers) => {
      status = Number(headers[':status'] || 0);
    });
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('error', (err) => done(err));
    req.on('end', () => {
      if (status !== 200) return done(new Error(`DoH/H2 HTTP ${status}`));
      const buf = Buffer.concat(chunks);
      if (buf.length < 12) return done(new Error('DoH/H2 gói tin không hợp lệ'));
      done(null, buf);
    });
    req.end(rawQuery);
  });
}

const h2RequiredUrls = new Set();

async function forwardDoh(rawQuery, urlStr, { signal } = {}) {
  if (h2RequiredUrls.has(urlStr)) {
    return await forwardDohHttp2(rawQuery, urlStr, { signal });
  }
  const timeoutSignal = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
  const combinedSignal = signal ? AbortSignal.any([timeoutSignal, signal]) : timeoutSignal;
  const res = await fetch(urlStr, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/dns-message',
      Accept: 'application/dns-message',
    },
    body: rawQuery,
    signal: combinedSignal,
  });
  if (res.status === 505) {
    // Một số máy chủ DoH (như Quad9 9.9.9.9) yêu cầu HTTP/2 -> ghi nhớ để không lãng phí 1 round-trip
    h2RequiredUrls.add(urlStr);
    return await forwardDohHttp2(rawQuery, urlStr, { signal });
  }
  if (!res.ok) {
    throw new Error(`DoH HTTP ${res.status}`);
  }
  const arrBuf = await res.arrayBuffer();
  const buf = Buffer.from(arrBuf);
  if (buf.length < 12) {
    throw new Error('DoH trả về gói tin không hợp lệ');
  }
  return buf;
}

export async function forwardSingleUpstream(rawQuery, upstreamEntry, opts = {}) {
  const trimmed = String(upstreamEntry || '').trim();
  if (trimmed.startsWith('https://')) {
    return await forwardDoh(rawQuery, trimmed, opts);
  }
  return await forwardUdp(rawQuery, trimmed, opts);
}

async function forwardWithFailover(rawQuery, coalesceKey = null) {
  const upstreams = store.config.upstreamDns?.length
    ? store.config.upstreamDns
    : ['https://1.1.1.2/dns-query', 'https://9.9.9.9/dns-query', '203.113.131.1'];
  const strategy = normalizeUpstreamStrategy(store.config.upstreamStrategy);
  const now = Date.now();

  return await upstreamLB.forward(rawQuery, {
    upstreams,
    strategy,
    coalesceKey,
    isCircuitOpen: (u) => getHealthEntry(u).openUntil > now,
    forwardSingle: (q, u, opts) => forwardSingleUpstream(q, u, opts),
    onSuccess: (u, ms) => recordUpstreamSuccess(u, ms),
    onFailure: (u, msg) => recordUpstreamFailure(u, msg),
  });
}

export async function testAllUpstreams(list = null) {
  const upstreams = Array.isArray(list) && list.length
    ? list
    : store.config.upstreamDns?.length
      ? store.config.upstreamDns
      : ['https://1.1.1.2/dns-query', 'https://9.9.9.9/dns-query', '203.113.131.1'];

  const probe = dnsPacket.encode({
    type: 'query',
    id: Math.floor(Math.random() * 65535),
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type: 'A', name: 'cloudflare.com' }],
  });

  return await Promise.all(
    upstreams.map(async (u) => {
      const t0 = performance.now();
      const protocol = u.startsWith('https://') ? 'DoH' : 'UDP';
      try {
        const resp = await forwardSingleUpstream(probe, u);
        const latencyMs = Number((performance.now() - t0).toFixed(1));
        const decoded = dnsPacket.decode(resp);
        recordUpstreamSuccess(u, latencyMs);
        return {
          upstream: u,
          protocol,
          ok: true,
          latencyMs,
          answers: (decoded.answers || []).length,
        };
      } catch (err) {
        const error = err.name === 'TimeoutError' ? 'Timeout' : err.message;
        return {
          upstream: u,
          protocol,
          ok: false,
          latencyMs: Number((performance.now() - t0).toFixed(1)),
          error,
        };
      }
    })
  );
}

function cleanClientIp(ip) {
  if (!ip) return 'unknown';
  return ip.replace(/^::ffff:/, '');
}

export function resolveLocalDnsRecord(queryPacket, domain, qtype) {
  const records = store.config.localRecords || [];
  if (!records.length || !domain) return null;
  const pkt = queryPacket?.questions?.length
    ? queryPacket
    : { id: queryPacket?.id || 0, questions: [{ type: qtype || 'A', name: domain }] };
  const resolved = localDnsLB.resolve(pkt, records);
  return resolved ? resolved.buffer : null;
}

export async function handleDnsPayload(rawBuffer, clientIp) {
  const ip = cleanClientIp(clientIp);
  if (isRateLimited(ip)) {
    store.emit('rate_limited', { clientIp: ip, limit: MAX_QPS_PER_IP });
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

  // 0. Local DNS Split-Horizon (trả lời trực tiếp 0ms, không rò rỉ tên miền nội bộ ra Internet)
  const localResp = resolveLocalDnsRecord(query, domain, qtype);
  if (localResp) {
    store.recordQuery({
      clientIp: ip,
      domain,
      qtype,
      blocked: false,
      cached: true,
      rcode: 'NOERROR',
      reason: 'local_dns',
      latencyMs: Number((performance.now() - startMs).toFixed(2)),
    });
    return localResp;
  }

  // 0.5. Kiểm tra Cách ly DNS (Auto-Quarantine / Cách ly thủ công)
  if (store.config.protectionEnabled) {
    const qEntry = alertEngine.isQuarantined(ip);
    if (qEntry) {
      const resp = buildBlockedResponse(query, { forceNxdomain: true });
      store.recordQuery({
        clientIp: ip,
        domain,
        qtype,
        blocked: true,
        cached: false,
        quarantined: true,
        severity: 'high',
        reason: `Đang cách ly DNS (${qEntry.reason})`,
        latencyMs: Number((performance.now() - startMs).toFixed(2)),
      });
      return resp;
    }
  }

  // 1. Kiểm tra bộ lọc (Whitelist, Client/Group Rules, Anti-Bypass, Blacklist, Blocklists)
  const decision = blocklistEngine.evaluate(domain, ip);
  if (decision.blocked) {
    const resp = buildBlockedResponse(query, { forceNxdomain: Boolean(decision.forceNxdomain) });
    store.recordQuery({
      clientIp: ip,
      domain,
      qtype,
      blocked: true,
      cached: false,
      severity: decision.severity || 'info',
      ...(decision.iotViolation ? { iotViolation: true } : {}),
      reason: decision.reason,
      latencyMs: Number((performance.now() - startMs).toFixed(2)),
    });
    return resp;
  }

  const bypassProtection = typeof decision.reason === 'string' && decision.reason.startsWith('bypass:');

  // 1.5. Chặn chủ động nghi vấn DNS Tunneling (nhãn tên miền dài bất thường)
  if (
    store.config.protectionEnabled &&
    !bypassProtection &&
    decision.reason !== 'whitelist' &&
    store.config.security?.blockDnsTunneling === true
  ) {
    const maxLabelLen = Number(store.config.alerts?.tunnelingLabelLength) || 60;
    if (hasLongDnsLabel(domain, maxLabelLen)) {
      const resp = buildBlockedResponse(query, { forceNxdomain: true });
      store.recordQuery({
        clientIp: ip,
        domain,
        qtype,
        blocked: true,
        cached: false,
        severity: 'high',
        reason: 'Chặn nghi vấn DNS Tunneling',
        latencyMs: Number((performance.now() - startMs).toFixed(2)),
      });
      return resp;
    }
  }

  // 2. Kiểm tra Cache tươi
  const cacheKey = `${domain}:${qtype}`;
  const cachedResp = dnsCache.get(cacheKey);
  if (cachedResp) {
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

  // 3. Forward lên Upstream DNS (4 chế độ cân bằng tải + Singleflight + Circuit Breaker)
  try {
    const upstreamResp = await forwardWithFailover(rawBuffer, cacheKey);
    const inspection = inspectUpstreamResponse(upstreamResp, domain, ip, { bypassProtection });

    if (inspection.blocked) {
      const blockedResp = buildBlockedResponse(query, { forceNxdomain: inspection.forceNxdomain });
      store.recordQuery({
        clientIp: ip,
        domain,
        qtype,
        blocked: true,
        cached: false,
        severity: inspection.severity || 'info',
        reason: inspection.reason,
        latencyMs: Number((performance.now() - startMs).toFixed(2)),
      });
      return blockedResp;
    }

    dnsCache.set(cacheKey, upstreamResp, inspection.ttl);

    store.recordQuery({
      clientIp: ip,
      domain,
      qtype,
      blocked: false,
      cached: false,
      rcode: inspection.rcode,
      reason: decision.reason,
      latencyMs: Number((performance.now() - startMs).toFixed(2)),
    });
    return upstreamResp;
  } catch (err) {
    // Serve-Stale Cache khi toàn bộ upstream lỗi
    if (store.config.security?.serveStaleCache !== false) {
      const staleResp = dnsCache.getStale(cacheKey);
      if (staleResp) {
        const patched = Buffer.from(staleResp);
        patched.writeUInt16BE(query.id, 0);
        store.recordQuery({
          clientIp: ip,
          domain,
          qtype,
          blocked: false,
          cached: true,
          reason: 'stale_cache',
          latencyMs: Number((performance.now() - startMs).toFixed(2)),
        });
        return patched;
      }
    }

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

function startOptionalUdp6(port, host) {
  if (store.config.security?.enableIpv6 === false) return Promise.resolve(null);
  const bindAddr6 = host === '127.0.0.1' ? '::1' : '::';
  return new Promise((resolve) => {
    let settled = false;
    try {
      const udp6 = dgram.createSocket({ type: 'udp6', ipv6Only: true });
      udp6.on('message', async (msg, rinfo) => {
        try {
          const resp = await handleDnsPayload(msg, rinfo.address);
          if (resp) {
            udp6.send(resp, rinfo.port, rinfo.address);
          }
        } catch {
          // Bỏ qua gói tin lỗi
        }
      });
      udp6.once('error', () => {
        if (!settled) {
          settled = true;
          try {
            udp6.close();
          } catch {}
          resolve(null);
        }
      });
      udp6.bind(port, bindAddr6, () => {
        if (!settled) {
          settled = true;
          resolve(udp6);
        }
      });
    } catch {
      resolve(null);
    }
  });
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
      tcpServer.listen(port, host, async () => {
        const udp6Server = await startOptionalUdp6(port, host);
        resolve({
          host,
          port,
          ipv6Enabled: Boolean(udp6Server),
          close: () =>
            new Promise((done) => {
              const finishUdp6 = () => {
                if (!udp6Server) return done();
                udp6Server.close(() => done());
              };
              udpServer.close(() => tcpServer.close(() => finishUdp6()));
            }),
        });
      });
    });
  });
}
