import { spawn } from 'node:child_process';
import { CACHE_DIR, DEFAULT_HA_SYNC_CONFIG } from './store.js';

const HOST_SAFE_RE = /^[a-zA-Z0-9._:-]{1,128}$/;
const USER_SAFE_RE = /^[a-zA-Z0-9._-]{1,64}$/;
const DIR_SAFE_RE = /^[a-zA-Z0-9._~/-]{1,256}$/;

function runProcess(cmd, args, { stdinText = null, timeoutMs = 15_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        PATH: `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:${process.env.PATH || ''}`,
      },
    });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill('SIGKILL');
      } catch {}
      reject(new Error(`Timeout sau ${Math.round(timeoutMs / 1000)}s khi chạy ${cmd}`));
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      if (stdout.length < 256_000) stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
      if (stderr.length < 64_000) stderr += chunk.toString('utf8');
    });

    child.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });

    child.once('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code === 0) {
        resolve({ stdout, stderr, code });
      } else {
        const msg = (stderr || stdout || `exit code ${code}`).trim().slice(0, 300);
        reject(new Error(`${cmd} thất bại (${code}): ${msg}`));
      }
    });

    if (stdinText !== null) {
      child.stdin.end(stdinText, 'utf8');
    } else {
      child.stdin.end();
    }
  });
}

/**
 * Kiểm tra hợp lệ & đóng gói payload cấu hình an toàn gửi sang Secondary Node:
 * - Chặn lan truyền cấu hình hỏng (bắt buộc có >= 1 upstreamDns hợp lệ).
 * - Ép cứng haSync.enabled = false (chặn 100% vòng lặp sync).
 * - Ép cứng activeLanSweep = false & rogueDeviceEnabled = false (tránh báo trùng Telegram).
 */
export function buildSecondaryPayload(config) {
  if (!config || typeof config !== 'object') {
    throw new Error('Cấu hình nguồn không hợp lệ');
  }
  if (!Array.isArray(config.upstreamDns) || config.upstreamDns.filter(Boolean).length === 0) {
    throw new Error('Cấu hình nguồn thiếu upstreamDns hợp lệ — từ chối đồng bộ để bảo vệ node phụ');
  }

  const clone = structuredClone(config);
  clone.haSync = {
    ...DEFAULT_HA_SYNC_CONFIG,
    enabled: false,
    autoSyncOnSave: false,
  };
  clone.security = {
    ...(clone.security || {}),
    activeLanSweep: false,
  };
  clone.alerts = {
    ...(clone.alerts || {}),
    rogueDeviceEnabled: false,
    telegramBotToken: '',
  };
  return clone;
}

export function normalizeHaSyncConfig(raw = {}) {
  const merged = { ...DEFAULT_HA_SYNC_CONFIG, ...(raw && typeof raw === 'object' ? raw : {}) };
  const secondaryHost = String(merged.secondaryHost || '').trim();
  const secondaryUser = String(merged.secondaryUser || '').trim();
  const secondaryAppDir = String(merged.secondaryAppDir || '').trim();
  return {
    enabled: Boolean(merged.enabled),
    autoSyncOnSave: merged.autoSyncOnSave !== false,
    debounceSec: Math.max(2, Math.min(300, Number(merged.debounceSec) || 5)),
    healthCheckIntervalSec: Math.max(15, Math.min(3600, Number(merged.healthCheckIntervalSec) || 60)),
    secondaryHost: HOST_SAFE_RE.test(secondaryHost) ? secondaryHost : DEFAULT_HA_SYNC_CONFIG.secondaryHost,
    secondaryUser: USER_SAFE_RE.test(secondaryUser) ? secondaryUser : DEFAULT_HA_SYNC_CONFIG.secondaryUser,
    secondaryAppDir: DIR_SAFE_RE.test(secondaryAppDir) ? secondaryAppDir : DEFAULT_HA_SYNC_CONFIG.secondaryAppDir,
    sshKeyPath: String(merged.sshKeyPath || '').trim(),
    sshKnownHostsPath: String(merged.sshKnownHostsPath || '').trim(),
    alertOnOffline: merged.alertOnOffline !== false,
  };
}

export function buildSshArgs(cfg) {
  const args = [
    '-o',
    'BatchMode=yes',
    '-o',
    'ConnectTimeout=4',
    '-o',
    'ServerAliveInterval=3',
    '-o',
    'ServerAliveCountMax=2',
    '-o',
    'StrictHostKeyChecking=accept-new',
  ];
  if (cfg.sshKeyPath) {
    args.push('-i', cfg.sshKeyPath, '-o', 'IdentitiesOnly=yes');
  }
  if (cfg.sshKnownHostsPath) {
    args.push('-o', `UserKnownHostsFile=${cfg.sshKnownHostsPath}`);
  }
  return args;
}

class HASyncManager {
  constructor({ runner = runProcess } = {}) {
    this.runner = runner;
    this.store = null;
    this.alertEngine = null;
    this.debounceTimer = null;
    this.healthTimer = null;
    this.isSyncing = false;
    this.pendingSync = false;
    this.consecutiveHealthFailures = 0;
    this.offlineAlertSent = false;
    this.onConfigSaved = () => this.scheduleSync();
    this.status = {
      state: 'idle', // 'idle' | 'syncing' | 'ok' | 'error'
      lastSyncAt: null,
      lastSyncDurationMs: null,
      lastSyncTrigger: null,
      lastError: null,
      syncCount: 0,
      secondaryHealthy: null, // null | true | false
      secondaryBlockedDomains: null,
      lastHealthCheckAt: null,
      lastHealthError: null,
    };
  }

  getConfig() {
    return normalizeHaSyncConfig(this.store?.config?.haSync || {});
  }

  getStatus() {
    return {
      ...this.status,
      isSyncing: this.isSyncing,
      config: this.getConfig(),
    };
  }

  start(storeRef, alertEngineRef = null) {
    this.stop();
    this.store = storeRef;
    this.alertEngine = alertEngineRef;
    this.store.on('config_saved', this.onConfigSaved);
    this._resetHealthTimer();
    const cfg = this.getConfig();
    if (cfg.enabled) {
      // Kiểm tra sức khỏe ngay khi khởi động (không chặn luồng khởi động)
      this.checkSecondaryHealth().catch(() => {});
    }
  }

  stop() {
    if (this.store) {
      this.store.off('config_saved', this.onConfigSaved);
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }
  }

  reconfigure() {
    this._resetHealthTimer();
  }

  _resetHealthTimer() {
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }
    const cfg = this.getConfig();
    if (!cfg.enabled) return;
    this.healthTimer = setInterval(() => {
      this.checkSecondaryHealth().catch(() => {});
    }, cfg.healthCheckIntervalSec * 1000);
    if (typeof this.healthTimer.unref === 'function') {
      this.healthTimer.unref();
    }
  }

  scheduleSync() {
    const cfg = this.getConfig();
    if (!cfg.enabled || !cfg.autoSyncOnSave) return;
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      this.syncNow({ syncBlocklistCache: false, trigger: 'auto' }).catch(() => {});
    }, cfg.debounceSec * 1000);
    if (typeof this.debounceTimer.unref === 'function') {
      this.debounceTimer.unref();
    }
  }

  async syncNow({ syncBlocklistCache = true, trigger = 'manual' } = {}) {
    if (!this.store) {
      return { ok: false, error: 'HASyncManager chưa được khởi động' };
    }
    const cfg = this.getConfig();
    if (trigger === 'auto' && !cfg.enabled) {
      return { ok: false, skipped: true, reason: 'haSync disabled' };
    }

    if (this.isSyncing) {
      this.pendingSync = true;
      return { ok: true, queued: true };
    }

    this.isSyncing = true;
    this.status.state = 'syncing';
    const startMs = performance.now();

    try {
      const payload = buildSecondaryPayload(this.store.config);
      const target = `${cfg.secondaryUser}@${cfg.secondaryHost}`;
      const sshArgs = buildSshArgs(cfg);

      if (syncBlocklistCache) {
        const sshCmd = ['ssh', ...sshArgs].join(' ');
        await this.runner(
          'rsync',
          [
            '-az',
            '--delete',
            '-e',
            sshCmd,
            `${CACHE_DIR}/`,
            `${target}:${cfg.secondaryAppDir}/data/blocklists-cache/`,
          ],
          { timeoutMs: 25_000 }
        );
      }

      const remoteImportCmd =
        "curl -sS -f --max-time 10 -X POST -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8080/api/config/import";
      const { stdout } = await this.runner(
        'ssh',
        [...sshArgs, target, remoteImportCmd],
        { stdinText: JSON.stringify(payload), timeoutMs: 15_000 }
      );

      let parsedResp = null;
      try {
        parsedResp = JSON.parse(stdout);
      } catch {}

      if (parsedResp && parsedResp.ok !== true) {
        throw new Error(parsedResp.error || 'Node phụ trả về phản hồi không hợp lệ');
      }

      const durationMs = Math.round(performance.now() - startMs);
      this.status.state = 'ok';
      this.status.lastSyncAt = new Date().toISOString();
      this.status.lastSyncDurationMs = durationMs;
      this.status.lastSyncTrigger = trigger;
      this.status.lastError = null;
      this.status.syncCount += 1;
      this.status.secondaryHealthy = true;
      this.status.lastHealthError = null;
      this.consecutiveHealthFailures = 0;
      this.offlineAlertSent = false;

      return { ok: true, durationMs, trigger, remote: parsedResp };
    } catch (err) {
      const durationMs = Math.round(performance.now() - startMs);
      this.status.state = 'error';
      this.status.lastSyncDurationMs = durationMs;
      this.status.lastSyncTrigger = trigger;
      this.status.lastError = err.message;
      return { ok: false, error: err.message, durationMs };
    } finally {
      this.isSyncing = false;
      if (this.pendingSync) {
        this.pendingSync = false;
        this.syncNow({ syncBlocklistCache: false, trigger: 'auto' }).catch(() => {});
      }
    }
  }

  async checkSecondaryHealth() {
    if (!this.store) return { ok: false, error: 'Chưa khởi động' };
    const cfg = this.getConfig();
    const target = `${cfg.secondaryUser}@${cfg.secondaryHost}`;
    const sshArgs = buildSshArgs(cfg);
    const wasOffline = this.status.secondaryHealthy === false;

    try {
      const { stdout } = await this.runner(
        'ssh',
        [...sshArgs, target, 'curl -sS -f --max-time 4 http://127.0.0.1:8080/api/status'],
        { timeoutMs: 8_000 }
      );
      const data = JSON.parse(stdout);
      this.consecutiveHealthFailures = 0;
      this.offlineAlertSent = false;
      this.status.secondaryHealthy = true;
      this.status.secondaryBlockedDomains = Number(data.totalBlockedDomains || 0);
      this.status.lastHealthCheckAt = new Date().toISOString();
      this.status.lastHealthError = null;

      // Tự đồng bộ lại khi node phụ vừa hồi phục từ trạng thái offline
      if (wasOffline && cfg.enabled) {
        this.syncNow({ syncBlocklistCache: true, trigger: 'recovery' }).catch(() => {});
      }

      return {
        ok: true,
        secondaryHealthy: true,
        totalBlockedDomains: this.status.secondaryBlockedDomains,
      };
    } catch (err) {
      this.consecutiveHealthFailures += 1;
      this.status.lastHealthCheckAt = new Date().toISOString();
      this.status.lastHealthError = err.message;

      // Chống flapping: cần 2 lần liên tiếp lỗi mới đánh dấu offline & gửi 1 cảnh báo duy nhất
      if (this.consecutiveHealthFailures >= 2) {
        this.status.secondaryHealthy = false;
        if (cfg.alertOnOffline && !this.offlineAlertSent && this.alertEngine?.createAlert) {
          this.offlineAlertSent = true;
          this.alertEngine.createAlert({
            type: 'ha_secondary_offline',
            severity: 'high',
            title: `DNS dự phòng (${cfg.secondaryHost}) đang ngoại tuyến`,
            message: `Không thể kết nối tới Secondary Node ${cfg.secondaryHost} sau ${this.consecutiveHealthFailures} lần kiểm tra: ${err.message}`,
            clientIp: cfg.secondaryHost,
            reason: 'HA Secondary Offline',
            push: true,
            fingerprint: `ha_offline|${cfg.secondaryHost}`,
          });
        }
      }

      return { ok: false, secondaryHealthy: this.status.secondaryHealthy, error: err.message };
    }
  }
}

export { HASyncManager };
export const haSyncManager = new HASyncManager();
