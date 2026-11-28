import fs from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DATA_DIR } from './store.js';
import { deviceDiscovery } from './discovery.js';

const DB_PATH = path.join(DATA_DIR, 'netshield.db');
const FLUSH_INTERVAL_MS = 3000;
const BATCH_FLUSH_SIZE = 100;
const MAX_PENDING = 5000;
const CLEANUP_INTERVAL_MS = 6 * 60 * 60 * 1000;

function csvEscape(val) {
  const s = String(val ?? '');
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

class ForensicsDb {
  constructor() {
    this.db = null;
    this.store = null;
    this.enabled = false;
    this.pending = [];
    this._insertStmt = null;
    this._flushTimer = null;
    this._cleanupTimer = null;
    this._onQuery = null;
  }

  async start(store) {
    this.store = store;
    if (store.config.storage?.sqliteEnabled === false) {
      this.enabled = false;
      return false;
    }

    try {
      await fs.mkdir(DATA_DIR, { recursive: true });
      this.db = new DatabaseSync(DB_PATH);
      this.db.exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        CREATE TABLE IF NOT EXISTS query_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          client_ip TEXT NOT NULL,
          client_mac TEXT DEFAULT '',
          domain TEXT NOT NULL,
          qtype TEXT DEFAULT 'A',
          blocked INTEGER NOT NULL DEFAULT 0,
          cached INTEGER NOT NULL DEFAULT 0,
          severity TEXT DEFAULT 'info',
          rcode TEXT DEFAULT '',
          reason TEXT DEFAULT '',
          latency_ms REAL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_qlogs_ts ON query_logs(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_qlogs_client ON query_logs(client_ip, ts DESC);
        CREATE INDEX IF NOT EXISTS idx_qlogs_severity ON query_logs(severity, ts DESC);
      `);

      // Khóa quyền file DB chỉ cho user sở hữu đọc/ghi
      await fs.chmod(DB_PATH, 0o600).catch(() => {});

      this._insertStmt = this.db.prepare(`
        INSERT INTO query_logs (ts, client_ip, client_mac, domain, qtype, blocked, cached, severity, rcode, reason, latency_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      this.enabled = true;

      this._onQuery = (record) => {
        this.enqueue(record);
      };
      store.on('query', this._onQuery);

      this._flushTimer = setInterval(() => this.flush(), FLUSH_INTERVAL_MS);
      this._flushTimer.unref?.();

      this.cleanupOldLogs();
      this._cleanupTimer = setInterval(() => this.cleanupOldLogs(), CLEANUP_INTERVAL_MS);
      this._cleanupTimer.unref?.();

      return true;
    } catch (err) {
      console.error('⚠️  Không thể khởi tạo SQLite Forensics (fallback chạy RAM):', err.message);
      this.enabled = false;
      this.db = null;
      return false;
    }
  }

  enqueue(record) {
    if (!this.enabled || !record) return;
    if (this.pending.length >= MAX_PENDING) {
      this.pending.shift();
    }
    const ts = record.timestamp ? Date.parse(record.timestamp) || Date.now() : Date.now();
    const mac = deviceDiscovery.getMacForIp(record.clientIp) || '';
    this.pending.push({
      ts,
      clientIp: record.clientIp || '',
      clientMac: mac,
      domain: record.domain || '',
      qtype: record.qtype || 'A',
      blocked: record.blocked ? 1 : 0,
      cached: record.cached ? 1 : 0,
      severity: record.severity || 'info',
      rcode: record.rcode || '',
      reason: record.reason || '',
      latencyMs: Number(record.latencyMs) || 0,
    });
    if (this.pending.length >= BATCH_FLUSH_SIZE) {
      this.flush();
    }
  }

  flush() {
    if (!this.enabled || !this.db || !this._insertStmt || this.pending.length === 0) return 0;
    const batch = this.pending.splice(0, this.pending.length);
    try {
      this.db.exec('BEGIN IMMEDIATE');
      for (const r of batch) {
        this._insertStmt.run(
          r.ts,
          r.clientIp,
          r.clientMac,
          r.domain,
          r.qtype,
          r.blocked,
          r.cached,
          r.severity,
          r.rcode,
          r.reason,
          r.latencyMs
        );
      }
      this.db.exec('COMMIT');
      return batch.length;
    } catch {
      try {
        this.db.exec('ROLLBACK');
      } catch {}
      return 0;
    }
  }

  cleanupOldLogs(retentionDaysOverride = null) {
    if (!this.enabled || !this.db) return 0;
    const days = Math.max(
      1,
      Math.min(90, Number(retentionDaysOverride || this.store?.config?.storage?.retentionDays || 14))
    );
    const cutoffMs = Date.now() - days * 24 * 60 * 60 * 1000;
    try {
      const res = this.db.prepare('DELETE FROM query_logs WHERE ts < ?').run(cutoffMs);
      return Number(res.changes || 0);
    } catch {
      return 0;
    }
  }

  queryLogs({ limit = 200, search = '', filter = 'all', severity = '', clientIp = '', sinceHours = 24 } = {}) {
    if (!this.enabled || !this.db) return null;
    this.flush();

    const clauses = [];
    const params = [];

    if (sinceHours > 0) {
      clauses.push('ts >= ?');
      params.push(Date.now() - sinceHours * 60 * 60 * 1000);
    }
    if (filter === 'blocked') clauses.push('blocked = 1');
    if (filter === 'allowed') clauses.push('blocked = 0');
    if (severity && ['high', 'medium', 'info'].includes(severity)) {
      clauses.push('severity = ?');
      params.push(severity);
    }
    if (clientIp) {
      clauses.push('client_ip = ?');
      params.push(clientIp);
    }
    if (search) {
      const like = `%${search.toLowerCase()}%`;
      clauses.push('(LOWER(domain) LIKE ? OR LOWER(client_ip) LIKE ? OR LOWER(reason) LIKE ?)');
      params.push(like, like, like);
    }

    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const safeLimit = Math.max(1, Math.min(5000, Number(limit) || 200));
    const sql = `SELECT id, ts, client_ip, client_mac, domain, qtype, blocked, cached, severity, rcode, reason, latency_ms FROM query_logs ${where} ORDER BY ts DESC LIMIT ?`;
    params.push(safeLimit);

    const rows = this.db.prepare(sql).all(...params);
    return rows.map((r) => ({
      id: `db-${r.id}`,
      timestamp: new Date(r.ts).toISOString(),
      clientIp: r.client_ip,
      clientMac: r.client_mac,
      domain: r.domain,
      qtype: r.qtype,
      blocked: Boolean(r.blocked),
      cached: Boolean(r.cached),
      severity: r.severity || 'info',
      rcode: r.rcode || '',
      reason: r.reason || '',
      latencyMs: r.latency_ms,
    }));
  }

  exportCsv(opts = {}) {
    const rows = this.queryLogs({ ...opts, limit: Math.min(10000, Number(opts.limit) || 5000) }) || [];
    const header = ['Thoi_gian', 'IP_Thiet_bi', 'MAC', 'Ten_mien', 'Loai', 'Trang_thai', 'Muc_do', 'Ly_do', 'Do_tre_ms'];
    const lines = [header.join(',')];
    for (const r of rows) {
      lines.push(
        [
          r.timestamp,
          r.clientIp,
          r.clientMac || '',
          r.domain,
          r.qtype,
          r.blocked ? 'BLOCKED' : r.cached ? 'CACHED' : 'ALLOWED',
          r.severity || 'info',
          r.reason || '',
          r.latencyMs ?? 0,
        ]
          .map(csvEscape)
          .join(',')
      );
    }
    return '\uFEFF' + lines.join('\r\n');
  }

  async getStats() {
    const retentionDays = Number(this.store?.config?.storage?.retentionDays || 14);
    if (!this.enabled || !this.db) {
      return { enabled: false, totalRows: 0, dbSizeBytes: 0, retentionDays };
    }
    this.flush();
    let totalRows = 0;
    let dbSizeBytes = 0;
    try {
      const row = this.db.prepare('SELECT COUNT(*) AS cnt FROM query_logs').get();
      totalRows = Number(row?.cnt || 0);
      const st = await fs.stat(DB_PATH);
      dbSizeBytes = st.size;
    } catch {}
    return { enabled: true, totalRows, dbSizeBytes, retentionDays };
  }

  stop() {
    if (this.store && this._onQuery) {
      this.store.off('query', this._onQuery);
      this._onQuery = null;
    }
    if (this._flushTimer) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer);
      this._cleanupTimer = null;
    }
    this.flush();
    if (this.db) {
      try {
        this.db.close();
      } catch {}
      this.db = null;
    }
    this.enabled = false;
  }
}

export const forensicsDb = new ForensicsDb();
