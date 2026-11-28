import net from 'node:net';
import http from 'node:http';
import dnsPacket from 'dns-packet';

export const UPSTREAM_STRATEGIES = ['failover', 'round_robin', 'lowest_latency', 'parallel'];
export const LOCAL_RECORD_STRATEGIES = ['round_robin', 'weighted'];

const DEFAULT_LOCAL_TTL = 15;
const MIN_LOCAL_TTL = 1;
const MAX_LOCAL_TTL = 86400;
const EWMA_ALPHA = 0.3;
const LOWEST_LATENCY_PROBE_EVERY = 10;
const DEFAULT_HEALTH_INTERVAL_MS = 15_000;
const DEFAULT_PROBE_TIMEOUT_MS = 1500;
const IMMEDIATE_FAIL_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ECONNRESET']);

function normalizeDomainName(domain) {
  return String(domain || '')
    .trim()
    .toLowerCase()
    .replace(/\.+$/, '');
}

export function normalizeUpstreamStrategy(strategy) {
  const s = String(strategy || '').trim().toLowerCase();
  return UPSTREAM_STRATEGIES.includes(s) ? s : 'failover';
}

export function normalizeLocalRecordStrategy(strategy) {
  const s = String(strategy || '').trim().toLowerCase();
  return LOCAL_RECORD_STRATEGIES.includes(s) ? s : 'round_robin';
}

/**
 * Kiểm tra gói phản hồi DNS có phải lỗi máy chủ upstream (SERVFAIL=2 hoặc REFUSED=5) hay không.
 * Lưu ý: KHÔNG coi NXDOMAIN (3) là lỗi upstream vì tên miền không tồn tại là câu trả lời hợp lệ.
 */
export function isUpstreamErrorRcode(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return false;
  const rcode = buf[3] & 0x0f;
  return rcode === 2 || rcode === 5;
}

function isAbortError(err) {
  return Boolean(err && (err.name === 'AbortError' || err.code === 'ABORT_ERR'));
}

function sanitizeHealthPath(rawPath) {
  const s = String(rawPath || '').trim();
  if (!s) return '';
  if (/\s/.test(s)) {
    throw new Error(`Đường dẫn HTTP health check không hợp lệ: "${s}"`);
  }
  return s.startsWith('/') ? s : `/${s}`;
}

/**
 * Chuẩn hóa & kiểm tra hợp lệ 1 bản ghi Local DNS (tương thích ngược cả { ip }, { ips[] } và { targets[] })
 */
export function normalizeLocalRecord(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Bản ghi Local DNS không hợp lệ');
  }
  const domain = normalizeDomainName(raw.domain);
  if (!domain || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/.test(domain)) {
    throw new Error(`Tên miền nội bộ không hợp lệ: "${raw.domain || ''}"`);
  }

  let rawTargets = [];
  if (Array.isArray(raw.targets) && raw.targets.length > 0) {
    rawTargets = raw.targets;
  } else if (Array.isArray(raw.ips) && raw.ips.length > 0) {
    rawTargets = raw.ips.map((ip) => ({ ip }));
  } else if (typeof raw.ip === 'string' && raw.ip.trim()) {
    rawTargets = raw.ip
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((ip) => ({ ip }));
  }

  const seenIps = new Set();
  const targets = [];

  for (const item of rawTargets) {
    const ip = String(typeof item === 'string' ? item : item?.ip || '').trim();
    if (!ip || net.isIP(ip) === 0) {
      throw new Error(`Địa chỉ IP backend không hợp lệ: "${ip}"`);
    }
    if (seenIps.has(ip)) continue;
    seenIps.add(ip);

    const rawWeight = typeof item === 'object' ? Number(item.weight) : 1;
    const weight = Number.isFinite(rawWeight) ? Math.max(1, Math.min(100, Math.round(rawWeight))) : 1;

    const rawPort =
      typeof item === 'object' && item.healthPort !== '' && item.healthPort != null
        ? Number(item.healthPort)
        : null;
    let healthPort = null;
    if (rawPort !== null) {
      if (!Number.isInteger(rawPort) || rawPort < 1 || rawPort > 65535) {
        throw new Error(`Cổng health check không hợp lệ cho ${ip}: "${item.healthPort}"`);
      }
      healthPort = rawPort;
    }

    const healthPath = typeof item === 'object' ? sanitizeHealthPath(item.healthPath) : '';
    targets.push({ ip, weight, healthPort, ...(healthPath ? { healthPath } : {}) });
  }

  if (targets.length === 0) {
    throw new Error('Cần ít nhất 1 địa chỉ IP backend hợp lệ');
  }

  const rawTtl = Number(raw.ttl);
  const ttl = Number.isFinite(rawTtl)
    ? Math.max(MIN_LOCAL_TTL, Math.min(MAX_LOCAL_TTL, Math.round(rawTtl)))
    : DEFAULT_LOCAL_TTL;

  const ips = targets.map((t) => t.ip);
  return {
    domain,
    ip: ips[0],
    ips,
    ttl,
    strategy: normalizeLocalRecordStrategy(raw.strategy),
    singleAnswer: Boolean(raw.singleAnswer),
    enabled: raw.enabled !== false,
    targets,
  };
}

/**
 * Bộ cân bằng tải cho các Upstream DNS:
 * - 4 chế độ: failover, round_robin, lowest_latency (EWMA), parallel (AbortSignal + lọc SERVFAIL/REFUSED)
 * - In-flight Singleflight coalescing theo coalesceKey để chống bão truy vấn trùng
 */
export class UpstreamLoadBalancer {
  constructor() {
    this.rrCursor = 0;
    this.latencyQueryCount = 0;
    this.ewmaLatencyMs = new Map();
    this.selectionCounts = new Map();
    this.inflight = new Map(); // coalesceKey -> Promise<Buffer>
  }

  recordLatency(upstream, latencyMs) {
    const prev = this.ewmaLatencyMs.get(upstream);
    const next = prev == null ? latencyMs : EWMA_ALPHA * latencyMs + (1 - EWMA_ALPHA) * prev;
    this.ewmaLatencyMs.set(upstream, Number(next.toFixed(2)));
  }

  getEwmaLatency(upstream) {
    return this.ewmaLatencyMs.get(upstream) ?? null;
  }

  getQueryCount(upstream) {
    return this.selectionCounts.get(upstream) || 0;
  }

  getStats() {
    const out = {};
    for (const [u, count] of this.selectionCounts) {
      out[u] = {
        queries: count,
        ewmaLatencyMs: this.ewmaLatencyMs.get(u) ?? null,
      };
    }
    return out;
  }

  reset() {
    this.rrCursor = 0;
    this.latencyQueryCount = 0;
    this.ewmaLatencyMs.clear();
    this.selectionCounts.clear();
    this.inflight.clear();
  }

  _bumpSelection(upstream) {
    this.selectionCounts.set(upstream, (this.selectionCounts.get(upstream) || 0) + 1);
  }

  selectOrderedUpstreams(upstreams, strategy, isCircuitOpen = () => false) {
    const mode = normalizeUpstreamStrategy(strategy);
    const healthy = [];
    const openCircuit = [];
    for (const u of upstreams) {
      if (isCircuitOpen(u)) openCircuit.push(u);
      else healthy.push(u);
    }

    if (healthy.length === 0) {
      return { healthy: [], openCircuit, ordered: [...upstreams] };
    }

    let orderedHealthy;
    if (mode === 'round_robin') {
      const start = this.rrCursor % healthy.length;
      this.rrCursor = (this.rrCursor + 1) >>> 0;
      orderedHealthy = [...healthy.slice(start), ...healthy.slice(0, start)];
    } else if (mode === 'lowest_latency') {
      orderedHealthy = [...healthy].sort((a, b) => {
        const la = this.ewmaLatencyMs.has(a) ? this.ewmaLatencyMs.get(a) : -1;
        const lb = this.ewmaLatencyMs.has(b) ? this.ewmaLatencyMs.get(b) : -1;
        return la - lb;
      });
      this.latencyQueryCount = (this.latencyQueryCount + 1) >>> 0;
      if (orderedHealthy.length > 1 && this.latencyQueryCount % LOWEST_LATENCY_PROBE_EVERY === 0) {
        const probeIdx =
          1 + ((Math.floor(this.latencyQueryCount / LOWEST_LATENCY_PROBE_EVERY) - 1) % (orderedHealthy.length - 1));
        const [probe] = orderedHealthy.splice(probeIdx, 1);
        orderedHealthy.unshift(probe);
      }
    } else {
      orderedHealthy = healthy;
    }

    return {
      healthy: orderedHealthy,
      openCircuit,
      ordered: [...orderedHealthy, ...openCircuit],
    };
  }

  async _executeForward(
    rawQuery,
    {
      upstreams,
      strategy = 'failover',
      isCircuitOpen = () => false,
      forwardSingle,
      onSuccess = () => {},
      onFailure = () => {},
    }
  ) {
    const mode = normalizeUpstreamStrategy(strategy);
    const { healthy, openCircuit, ordered } = this.selectOrderedUpstreams(upstreams, mode, isCircuitOpen);

    if (mode === 'parallel') {
      const candidates = healthy.length > 0 ? healthy : upstreams;
      const controller = new AbortController();
      try {
        const winner = await Promise.any(
          candidates.map(async (upstream) => {
            const t0 = performance.now();
            try {
              const resp = await forwardSingle(rawQuery, upstream, { signal: controller.signal });
              if (isUpstreamErrorRcode(resp)) {
                const rcode = resp[3] & 0x0f;
                throw new Error(rcode === 2 ? 'SERVFAIL' : 'REFUSED');
              }
              const elapsed = performance.now() - t0;
              this.recordLatency(upstream, elapsed);
              onSuccess(upstream, elapsed);
              return { resp, upstream };
            } catch (err) {
              if (isAbortError(err) || controller.signal.aborted) {
                throw err;
              }
              const msg = err?.name === 'TimeoutError' ? 'Timeout' : err?.message || String(err);
              onFailure(upstream, msg);
              throw new Error(`${upstream}: ${msg}`);
            }
          })
        );
        // Hủy ngay các truy vấn thua để giải phóng socket/fetch
        controller.abort();
        this._bumpSelection(winner.upstream);
        return winner.resp;
      } catch (aggErr) {
        controller.abort();
        if (healthy.length > 0 && openCircuit.length > 0) {
          let lastError = null;
          for (const upstream of openCircuit) {
            const t0 = performance.now();
            try {
              const resp = await forwardSingle(rawQuery, upstream);
              if (isUpstreamErrorRcode(resp)) {
                const rcode = resp[3] & 0x0f;
                const msg = rcode === 2 ? 'SERVFAIL' : 'REFUSED';
                onFailure(upstream, msg);
                lastError = new Error(`${upstream}: ${msg}`);
                continue;
              }
              const elapsed = performance.now() - t0;
              this.recordLatency(upstream, elapsed);
              onSuccess(upstream, elapsed);
              this._bumpSelection(upstream);
              return resp;
            } catch (err) {
              const msg = err?.name === 'TimeoutError' ? 'Timeout' : err?.message || String(err);
              onFailure(upstream, msg);
              lastError = new Error(`${upstream}: ${msg}`);
            }
          }
          throw lastError || new Error('All upstream DNS failed');
        }
        const firstErr = aggErr?.errors?.[0];
        throw firstErr || new Error('All upstream DNS failed');
      }
    }

    // Tuần tự theo thứ tự đã chọn (failover | round_robin | lowest_latency)
    let lastError = null;
    for (const upstream of ordered) {
      const t0 = performance.now();
      try {
        const resp = await forwardSingle(rawQuery, upstream);
        if (isUpstreamErrorRcode(resp)) {
          const rcode = resp[3] & 0x0f;
          const msg = rcode === 2 ? 'SERVFAIL' : 'REFUSED';
          onFailure(upstream, msg);
          lastError = new Error(`${upstream}: ${msg}`);
          continue;
        }
        const elapsed = performance.now() - t0;
        this.recordLatency(upstream, elapsed);
        onSuccess(upstream, elapsed);
        this._bumpSelection(upstream);
        return resp;
      } catch (err) {
        const msg = err?.name === 'TimeoutError' ? 'Timeout' : err?.message || String(err);
        onFailure(upstream, msg);
        lastError = new Error(`${upstream}: ${msg}`);
      }
    }
    throw lastError || new Error('All upstream DNS failed');
  }

  async forward(rawQuery, opts) {
    const coalesceKey = opts?.coalesceKey;
    if (!coalesceKey) {
      return await this._executeForward(rawQuery, opts);
    }

    let pending = this.inflight.get(coalesceKey);
    const isOwner = !pending;
    if (isOwner) {
      pending = this._executeForward(rawQuery, opts).finally(() => {
        if (this.inflight.get(coalesceKey) === pending) {
          this.inflight.delete(coalesceKey);
        }
      });
      this.inflight.set(coalesceKey, pending);
    }

    const baseResp = await pending;
    if (isOwner || !Buffer.isBuffer(baseResp) || baseResp.length < 2 || rawQuery.length < 2) {
      return baseResp;
    }
    // Clone & gắn lại đúng Transaction ID của client chờ gộp
    const cloned = Buffer.from(baseResp);
    cloned[0] = rawQuery[0];
    cloned[1] = rawQuery[1];
    return cloned;
  }
}

/**
 * Kiểm tra cổng TCP của backend nội bộ
 */
export function probeTcpEndpoint(ip, port, timeoutMs = DEFAULT_PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    let settled = false;
    const socket = net.createConnection({ host: ip, port });

    const done = (ok, error = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.destroy();
      } catch {}
      resolve({
        ok,
        latencyMs: ok ? Number((performance.now() - t0).toFixed(1)) : null,
        error,
      });
    };

    const timer = setTimeout(() => done(false, 'Timeout'), timeoutMs);
    socket.once('connect', () => done(true, null));
    socket.once('error', (err) => done(false, err.code || err.message || 'TCP error'));
  });
}

/**
 * Kiểm tra HTTP GET (2xx/3xx, không follow redirect) khi target có khai báo healthPath
 */
export function probeHttpEndpoint(ip, port, healthPath, timeoutMs = DEFAULT_PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    let settled = false;
    const req = http.request(
      {
        host: ip,
        port,
        path: healthPath,
        method: 'GET',
        timeout: timeoutMs,
        headers: { 'User-Agent': 'NetShield-HealthCheck/1.0', Connection: 'close' },
      },
      (res) => {
        res.resume(); // xả body
        const ok = res.statusCode >= 200 && res.statusCode < 400;
        done(ok, ok ? null : `HTTP ${res.statusCode}`);
      }
    );

    const done = (ok, error = null) => {
      if (settled) return;
      settled = true;
      try {
        req.destroy();
      } catch {}
      resolve({
        ok,
        latencyMs: ok ? Number((performance.now() - t0).toFixed(1)) : null,
        error,
      });
    };

    req.once('timeout', () => done(false, 'Timeout'));
    req.once('error', (err) => done(false, err.code || err.message || 'HTTP error'));
    req.end();
  });
}

/**
 * Bộ cân bằng tải DNS Round-Robin nội bộ + TCP/HTTP Health Check tự loại IP chết (chống flapping)
 */
export class LocalDnsLoadBalancer {
  constructor({
    probeFn = probeTcpEndpoint,
    httpProbeFn = probeHttpEndpoint,
    probeTimeoutMs = DEFAULT_PROBE_TIMEOUT_MS,
    timeoutFailureThreshold = 2,
  } = {}) {
    this.probeFn = probeFn;
    this.httpProbeFn = httpProbeFn;
    this.probeTimeoutMs = probeTimeoutMs;
    this.timeoutFailureThreshold = timeoutFailureThreshold;
    this.rrCursors = new Map();
    this.weightedState = new Map();
    this.healthMap = new Map();
    this.timer = null;
    this._getRecords = null;
  }

  _healthKey(ip, port, healthPath = '') {
    return `${ip}:${port}${healthPath || ''}`;
  }

  _extractTargets(record) {
    if (Array.isArray(record?.targets) && record.targets.length > 0) {
      return record.targets;
    }
    const rawIps =
      Array.isArray(record?.ips) && record.ips.length > 0
        ? record.ips
        : record?.ip
          ? [record.ip]
          : [];
    return rawIps
      .filter((ip) => typeof ip === 'string' && net.isIP(ip) !== 0)
      .map((ip) => ({ ip, weight: 1, healthPort: null }));
  }

  isTargetHealthy(target) {
    if (!target.healthPort) return true;
    const entry = this.healthMap.get(this._healthKey(target.ip, target.healthPort, target.healthPath));
    if (!entry) return true;
    return entry.ok;
  }

  getTargetHealth(target) {
    if (!target.healthPort) {
      return {
        status: 'unchecked',
        ok: true,
        latencyMs: null,
        error: null,
        lastCheckedAt: null,
      };
    }
    const entry = this.healthMap.get(this._healthKey(target.ip, target.healthPort, target.healthPath));
    if (!entry) {
      return {
        status: 'pending',
        ok: true,
        latencyMs: null,
        error: null,
        lastCheckedAt: null,
      };
    }
    return {
      status: entry.ok ? 'healthy' : 'unhealthy',
      ok: entry.ok,
      latencyMs: entry.latencyMs,
      error: entry.error,
      consecutiveFailures: entry.consecutiveFailures,
      lastCheckedAt: entry.lastCheckedAt,
    };
  }

  annotateRecordsWithHealth(records = []) {
    return (records || []).map((rec) => {
      const targets = this._extractTargets(rec);
      return {
        ...rec,
        strategy: normalizeLocalRecordStrategy(rec.strategy),
        singleAnswer: Boolean(rec.singleAnswer),
        enabled: rec.enabled !== false,
        targets: targets.map((t) => ({
          ...t,
          health: this.getTargetHealth(t),
        })),
      };
    });
  }

  async runHealthChecks(records = []) {
    const endpoints = new Map();
    for (const rec of records || []) {
      if (rec?.enabled === false) continue;
      for (const t of this._extractTargets(rec)) {
        if (t?.ip && t?.healthPort) {
          const key = this._healthKey(t.ip, t.healthPort, t.healthPath);
          endpoints.set(key, { ip: t.ip, port: t.healthPort, healthPath: t.healthPath || '' });
        }
      }
    }

    for (const key of this.healthMap.keys()) {
      if (!endpoints.has(key)) {
        this.healthMap.delete(key);
      }
    }

    if (endpoints.size === 0) return;

    await Promise.all(
      Array.from(endpoints.entries()).map(async ([key, { ip, port, healthPath }]) => {
        const res = healthPath
          ? await this.httpProbeFn(ip, port, healthPath, this.probeTimeoutMs)
          : await this.probeFn(ip, port, this.probeTimeoutMs);
        const prev = this.healthMap.get(key);
        const failures = res.ok ? 0 : (prev?.consecutiveFailures || 0) + 1;

        // Chống flapping: ECONNREFUSED/HTTP 5xx loại ngay; Timeout cần >= timeoutFailureThreshold lần liên tiếp
        let ok = res.ok;
        if (!res.ok) {
          const isImmediate =
            IMMEDIATE_FAIL_CODES.has(res.error) ||
            (typeof res.error === 'string' && res.error.startsWith('HTTP '));
          if (!isImmediate && failures < this.timeoutFailureThreshold) {
            ok = prev ? prev.ok : true;
          }
        }

        this.healthMap.set(key, {
          ok,
          latencyMs: res.latencyMs,
          error: res.error,
          lastCheckedAt: new Date().toISOString(),
          consecutiveFailures: failures,
        });
      })
    );
  }

  startHealthChecks(getRecordsFn, intervalMs = DEFAULT_HEALTH_INTERVAL_MS) {
    this.stopHealthChecks();
    this._getRecords = getRecordsFn;
    this.runHealthChecks(this._getRecords?.() || []).catch(() => {});
    this.timer = setInterval(() => {
      this.runHealthChecks(this._getRecords?.() || []).catch(() => {});
    }, intervalMs);
    this.timer.unref();
  }

  stopHealthChecks() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  triggerImmediateCheck(records) {
    return this.runHealthChecks(records || this._getRecords?.() || []);
  }

  reset() {
    this.rrCursors.clear();
    this.weightedState.clear();
    this.healthMap.clear();
  }

  _orderTargets(domain, qtype, targets, strategy) {
    if (targets.length <= 1) return targets;
    const key = `${domain}:${qtype}`;

    if (strategy === 'weighted') {
      let state = this.weightedState.get(key);
      if (!state) {
        state = new Map();
        this.weightedState.set(key, state);
      }
      let totalWeight = 0;
      let bestTarget = targets[0];
      let bestWeight = -Infinity;

      for (const t of targets) {
        const w = Math.max(1, Number(t.weight) || 1);
        totalWeight += w;
        const cur = (state.get(t.ip) || 0) + w;
        state.set(t.ip, cur);
        if (cur > bestWeight) {
          bestWeight = cur;
          bestTarget = t;
        }
      }
      state.set(bestTarget.ip, (state.get(bestTarget.ip) || 0) - totalWeight);

      const activeSet = new Set(targets.map((t) => t.ip));
      for (const ip of state.keys()) {
        if (!activeSet.has(ip)) state.delete(ip);
      }

      const rest = targets.filter((t) => t.ip !== bestTarget.ip);
      return [bestTarget, ...rest];
    }

    const cursor = (this.rrCursors.get(key) || 0) % targets.length;
    this.rrCursors.set(key, (cursor + 1) >>> 0);
    return [...targets.slice(cursor), ...targets.slice(0, cursor)];
  }

  resolve(queryPacket, records = []) {
    const q = queryPacket?.questions?.[0];
    if (!q || !Array.isArray(records) || records.length === 0) return null;

    const domain = normalizeDomainName(q.name);
    const record = records.find((r) => r?.enabled !== false && normalizeDomainName(r.domain) === domain);
    if (!record) return null;

    const qtype = q.type || 'A';
    const baseFlags =
      dnsPacket.RECURSION_DESIRED |
      dnsPacket.RECURSION_AVAILABLE |
      dnsPacket.AUTHORITATIVE_ANSWER;

    if (qtype !== 'A' && qtype !== 'AAAA') {
      const buffer = dnsPacket.encode({
        type: 'response',
        id: queryPacket.id,
        flags: baseFlags,
        questions: queryPacket.questions,
        answers: [],
      });
      return { buffer, domain, ips: [], healthyCount: 0, totalCount: 0 };
    }

    const allTargets = this._extractTargets(record);
    const familyTargets = allTargets.filter((t) =>
      qtype === 'A' ? net.isIPv4(t.ip) : net.isIPv6(t.ip)
    );

    if (familyTargets.length === 0) {
      const buffer = dnsPacket.encode({
        type: 'response',
        id: queryPacket.id,
        flags: baseFlags,
        questions: queryPacket.questions,
        answers: [],
      });
      return { buffer, domain, ips: [], healthyCount: 0, totalCount: 0 };
    }

    const healthyTargets = familyTargets.filter((t) => this.isTargetHealthy(t));
    const activeTargets = healthyTargets.length > 0 ? healthyTargets : familyTargets;
    const ordered = this._orderTargets(domain, qtype, activeTargets, normalizeLocalRecordStrategy(record.strategy));
    const finalTargets = record.singleAnswer ? [ordered[0]] : ordered;
    const ttl = Math.max(MIN_LOCAL_TTL, Math.min(MAX_LOCAL_TTL, Number(record.ttl) || DEFAULT_LOCAL_TTL));

    const answers = finalTargets.map((t) => ({
      type: qtype,
      class: 'IN',
      name: q.name,
      ttl,
      data: t.ip,
    }));

    const buffer = dnsPacket.encode({
      type: 'response',
      id: queryPacket.id,
      flags: baseFlags,
      questions: queryPacket.questions,
      answers,
    });

    return {
      buffer,
      domain,
      ips: finalTargets.map((t) => t.ip),
      healthyCount: healthyTargets.length,
      totalCount: familyTargets.length,
    };
  }
}

export const upstreamLB = new UpstreamLoadBalancer();
export const localDnsLB = new LocalDnsLoadBalancer();
