import net from 'node:net';
import dnsPacket from 'dns-packet';

export const UPSTREAM_STRATEGIES = ['failover', 'round_robin', 'lowest_latency', 'parallel'];
export const LOCAL_RECORD_STRATEGIES = ['round_robin', 'weighted'];

const DEFAULT_LOCAL_TTL = 15;
const MIN_LOCAL_TTL = 1;
const MAX_LOCAL_TTL = 300;
const EWMA_ALPHA = 0.3;
const LOWEST_LATENCY_PROBE_EVERY = 10;
const DEFAULT_HEALTH_INTERVAL_MS = 15_000;
const DEFAULT_TCP_TIMEOUT_MS = 1500;

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
 * Chuẩn hóa & kiểm tra hợp lệ 1 bản ghi Local DNS Round-Robin
 */
export function normalizeLocalRecord(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Bản ghi Local DNS không hợp lệ');
  }
  const domain = normalizeDomainName(raw.domain);
  if (!domain || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/.test(domain)) {
    throw new Error(`Tên miền nội bộ không hợp lệ: "${raw.domain || ''}"`);
  }

  const rawTargets = Array.isArray(raw.targets) ? raw.targets : [];
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

    const rawPort = typeof item === 'object' && item.healthPort !== '' && item.healthPort != null
      ? Number(item.healthPort)
      : null;
    let healthPort = null;
    if (rawPort !== null) {
      if (!Number.isInteger(rawPort) || rawPort < 1 || rawPort > 65535) {
        throw new Error(`Cổng health check không hợp lệ cho ${ip}: "${item.healthPort}"`);
      }
      healthPort = rawPort;
    }

    targets.push({ ip, weight, healthPort });
  }

  if (targets.length === 0) {
    throw new Error('Cần ít nhất 1 địa chỉ IP backend hợp lệ');
  }

  const rawTtl = Number(raw.ttl);
  const ttl = Number.isFinite(rawTtl)
    ? Math.max(MIN_LOCAL_TTL, Math.min(MAX_LOCAL_TTL, Math.round(rawTtl)))
    : DEFAULT_LOCAL_TTL;

  return {
    domain,
    ttl,
    strategy: normalizeLocalRecordStrategy(raw.strategy),
    enabled: raw.enabled !== false,
    targets,
  };
}

/**
 * Bộ cân bằng tải cho các Upstream DNS (4 chế độ: failover, round_robin, lowest_latency, parallel)
 */
export class UpstreamLoadBalancer {
  constructor() {
    this.rrCursor = 0;
    this.latencyQueryCount = 0;
    this.ewmaLatencyMs = new Map();
    this.selectionCounts = new Map();
  }

  recordLatency(upstream, latencyMs) {
    const prev = this.ewmaLatencyMs.get(upstream);
    const next = prev == null ? latencyMs : EWMA_ALPHA * latencyMs + (1 - EWMA_ALPHA) * prev;
    this.ewmaLatencyMs.set(upstream, Number(next.toFixed(2)));
  }

  getEwmaLatency(upstream) {
    return this.ewmaLatencyMs.get(upstream) ?? null;
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
      // Định kỳ thăm dò 1 upstream khác để cập nhật lại độ trễ thực tế
      this.latencyQueryCount = (this.latencyQueryCount + 1) >>> 0;
      if (orderedHealthy.length > 1 && this.latencyQueryCount % LOWEST_LATENCY_PROBE_EVERY === 0) {
        const probeIdx = 1 + ((Math.floor(this.latencyQueryCount / LOWEST_LATENCY_PROBE_EVERY) - 1) % (orderedHealthy.length - 1));
        const [probe] = orderedHealthy.splice(probeIdx, 1);
        orderedHealthy.unshift(probe);
      }
    } else {
      // failover hoặc parallel (parallel sẽ gửi đồng thời toàn bộ healthy)
      orderedHealthy = healthy;
    }

    return {
      healthy: orderedHealthy,
      openCircuit,
      ordered: [...orderedHealthy, ...openCircuit],
    };
  }

  async forward(
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
      try {
        const winner = await Promise.any(
          candidates.map(async (upstream) => {
            const t0 = performance.now();
            try {
              const resp = await forwardSingle(rawQuery, upstream);
              const elapsed = performance.now() - t0;
              this.recordLatency(upstream, elapsed);
              onSuccess(upstream, elapsed);
              return { resp, upstream };
            } catch (err) {
              const msg = err?.name === 'TimeoutError' ? 'Timeout' : err?.message || String(err);
              onFailure(upstream, msg);
              throw new Error(`${upstream}: ${msg}`);
            }
          })
        );
        this._bumpSelection(winner.upstream);
        return winner.resp;
      } catch (aggErr) {
        // Nếu toàn bộ healthy đều lỗi và còn upstream đang mở circuit -> thử half-open tuần tự
        if (healthy.length > 0 && openCircuit.length > 0) {
          let lastError = null;
          for (const upstream of openCircuit) {
            const t0 = performance.now();
            try {
              const resp = await forwardSingle(rawQuery, upstream);
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
}

/**
 * Kiểm tra cổng TCP của backend nội bộ
 */
export function probeTcpEndpoint(ip, port, timeoutMs = DEFAULT_TCP_TIMEOUT_MS) {
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
 * Bộ cân bằng tải DNS Round-Robin nội bộ + TCP Health Check tự loại IP chết
 */
export class LocalDnsLoadBalancer {
  constructor({ probeFn = probeTcpEndpoint, tcpTimeoutMs = DEFAULT_TCP_TIMEOUT_MS } = {}) {
    this.probeFn = probeFn;
    this.tcpTimeoutMs = tcpTimeoutMs;
    this.rrCursors = new Map(); // key: `${domain}:${qtype}` -> number
    this.weightedState = new Map(); // key: `${domain}:${qtype}` -> Map<ip, currentWeight>
    this.healthMap = new Map(); // key: `${ip}:${port}` -> { ok, latencyMs, error, lastCheckedAt, consecutiveFailures }
    this.timer = null;
    this._getRecords = null;
  }

  _healthKey(ip, port) {
    return `${ip}:${port}`;
  }

  isTargetHealthy(target) {
    if (!target.healthPort) return true;
    const entry = this.healthMap.get(this._healthKey(target.ip, target.healthPort));
    // Chưa probe lần nào thì tạm coi là khỏe để không chặn ngay lúc mới thêm
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
    const entry = this.healthMap.get(this._healthKey(target.ip, target.healthPort));
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
      lastCheckedAt: entry.lastCheckedAt,
    };
  }

  annotateRecordsWithHealth(records = []) {
    return records.map((rec) => ({
      ...rec,
      targets: (rec.targets || []).map((t) => ({
        ...t,
        health: this.getTargetHealth(t),
      })),
    }));
  }

  async runHealthChecks(records = []) {
    const endpoints = new Map();
    for (const rec of records) {
      if (!rec?.enabled) continue;
      for (const t of rec.targets || []) {
        if (t?.ip && t?.healthPort) {
          endpoints.set(this._healthKey(t.ip, t.healthPort), { ip: t.ip, port: t.healthPort });
        }
      }
    }

    // Dọn các endpoint không còn trong cấu hình
    for (const key of this.healthMap.keys()) {
      if (!endpoints.has(key)) {
        this.healthMap.delete(key);
      }
    }

    if (endpoints.size === 0) return;

    await Promise.all(
      Array.from(endpoints.entries()).map(async ([key, { ip, port }]) => {
        const res = await this.probeFn(ip, port, this.tcpTimeoutMs);
        const prev = this.healthMap.get(key);
        this.healthMap.set(key, {
          ok: res.ok,
          latencyMs: res.latencyMs,
          error: res.error,
          lastCheckedAt: new Date().toISOString(),
          consecutiveFailures: res.ok ? 0 : (prev?.consecutiveFailures || 0) + 1,
        });
      })
    );
  }

  startHealthChecks(getRecordsFn, intervalMs = DEFAULT_HEALTH_INTERVAL_MS) {
    this.stopHealthChecks();
    this._getRecords = getRecordsFn;
    // Chạy kiểm tra lần đầu ngay ở nền
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
      // Smooth Weighted Round-Robin (kiểu Nginx)
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

      // Dọn IP cũ không còn trong danh sách active
      const activeSet = new Set(targets.map((t) => t.ip));
      for (const ip of state.keys()) {
        if (!activeSet.has(ip)) state.delete(ip);
      }

      const rest = targets.filter((t) => t.ip !== bestTarget.ip);
      return [bestTarget, ...rest];
    }

    // Round-Robin chuẩn: xoay phần tử đầu tiên mỗi lượt
    const cursor = (this.rrCursors.get(key) || 0) % targets.length;
    this.rrCursors.set(key, (cursor + 1) >>> 0);
    return [...targets.slice(cursor), ...targets.slice(0, cursor)];
  }

  /**
   * Trả về { buffer, domain, ips, healthyCount, totalCount } nếu khớp Local DNS record,
   * hoặc null nếu không khớp (để đi tiếp luồng blocklist/cache/upstream bình thường).
   */
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
      // Domain nội bộ nhưng hỏi loại bản ghi khác (HTTPS/SVCB/TXT...) -> trả NODATA, không leak ra upstream
      const buffer = dnsPacket.encode({
        type: 'response',
        id: queryPacket.id,
        flags: baseFlags,
        questions: queryPacket.questions,
        answers: [],
      });
      return { buffer, domain, ips: [], healthyCount: 0, totalCount: 0 };
    }

    const familyTargets = (record.targets || []).filter((t) =>
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
    // Nếu toàn bộ target chết -> fallback trả toàn bộ để tránh mất phân giải hoàn toàn
    const activeTargets = healthyTargets.length > 0 ? healthyTargets : familyTargets;
    const ordered = this._orderTargets(domain, qtype, activeTargets, record.strategy);
    const ttl = Math.max(MIN_LOCAL_TTL, Math.min(MAX_LOCAL_TTL, Number(record.ttl) || DEFAULT_LOCAL_TTL));

    const answers = ordered.map((t) => ({
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
      ips: ordered.map((t) => t.ip),
      healthyCount: healthyTargets.length,
      totalCount: familyTargets.length,
    };
  }
}

export const upstreamLB = new UpstreamLoadBalancer();
export const localDnsLB = new LocalDnsLoadBalancer();
