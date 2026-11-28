import fs from 'node:fs/promises';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { DATA_DIR, DEFAULT_ALERTS_CONFIG } from './store.js';
import { deviceDiscovery, normalizeMac } from './discovery.js';

const ALERTS_PATH = path.join(DATA_DIR, 'alerts.json');
const MAX_ALERTS = 500;
const DEDUPE_WINDOW_MS = 10 * 60 * 1000; // 10 phút chống spam cùng 1 sự kiện
const NXDOMAIN_WINDOW_MS = 60 * 1000; // Cửa sổ 60 giây phát hiện DGA/NXDOMAIN spike
const PUSH_TIMEOUT_MS = 5000;

function formatDeviceLabel(ip, mac, devices = []) {
  const dev = deviceDiscovery.resolveDeviceForIp(ip, devices);
  if (dev?.name) return `${dev.name} (${ip || dev.ip || mac})`;
  if (mac) return `${ip || 'LAN'} [${mac}]`;
  return ip || 'unknown';
}

function hasLongDnsLabel(domain, maxLabelLen = 60) {
  if (!domain) return false;
  if (domain.length > 150) return true;
  const labels = domain.split('.');
  for (const lbl of labels) {
    if (lbl.length > maxLabelLen) return true;
  }
  return false;
}

class AlertEngine extends EventEmitter {
  constructor() {
    super();
    this.store = null;
    this.alerts = [];
    this.dedupeMap = new Map(); // fingerprint -> lastTriggeredMs
    this.nxdomainMap = new Map(); // clientIp -> { windowStart, domains: Set<string> }
    this._saveTimer = null;
    this._saving = false;
    this._onQuery = null;
    this._onRateLimited = null;
  }

  _cfg() {
    return {
      ...DEFAULT_ALERTS_CONFIG,
      ...(this.store?.config?.alerts || {}),
    };
  }

  async load() {
    try {
      const raw = await fs.readFile(ALERTS_PATH, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        this.alerts = parsed.slice(0, MAX_ALERTS);
      }
    } catch {
      this.alerts = [];
    }
  }

  _scheduleSave() {
    if (this._saveTimer) return;
    this._saveTimer = setTimeout(() => {
      this._saveTimer = null;
      this.save().catch(() => {});
    }, 1500);
    this._saveTimer.unref?.();
  }

  async save() {
    if (this._saving) return;
    this._saving = true;
    try {
      await fs.mkdir(DATA_DIR, { recursive: true });
      const tmpPath = `${ALERTS_PATH}.tmp`;
      await fs.writeFile(tmpPath, JSON.stringify(this.alerts.slice(0, MAX_ALERTS), null, 2), {
        encoding: 'utf8',
        mode: 0o600,
      });
      await fs.rename(tmpPath, ALERTS_PATH);
    } catch {
      // Không để lỗi I/O ảnh hưởng luồng DNS
    } finally {
      this._saving = false;
    }
  }

  start(store) {
    this.store = store;
    this.load().catch(() => {});

    this._onQuery = (record) => {
      try {
        this.handleQuery(record);
      } catch {
        // Không để lỗi cảnh báo làm gián đoạn DNS
      }
    };
    this._onRateLimited = ({ clientIp, limit }) => {
      try {
        this.handleRateLimit(clientIp, limit);
      } catch {}
    };

    store.on('query', this._onQuery);
    store.on('rate_limited', this._onRateLimited);
  }

  stop() {
    if (this.store && this._onQuery) {
      this.store.off('query', this._onQuery);
      this._onQuery = null;
    }
    if (this.store && this._onRateLimited) {
      this.store.off('rate_limited', this._onRateLimited);
      this._onRateLimited = null;
    }
    if (this._saveTimer) {
      clearTimeout(this._saveTimer);
      this._saveTimer = null;
    }
  }

  _isDuplicate(fingerprint) {
    const now = Date.now();
    const last = this.dedupeMap.get(fingerprint);
    if (last && now - last < DEDUPE_WINDOW_MS) {
      return true;
    }
    this.dedupeMap.set(fingerprint, now);
    if (this.dedupeMap.size > 2000) {
      for (const [k, ts] of this.dedupeMap) {
        if (now - ts >= DEDUPE_WINDOW_MS) this.dedupeMap.delete(k);
      }
    }
    return false;
  }

  createAlert({ type, severity = 'medium', title, message, clientIp = '', mac = '', domain = '', reason = '', push = true, fingerprint = '' }) {
    const cfg = this._cfg();
    if (!cfg.enabled) return null;

    const fp = fingerprint || `${type}|${mac || clientIp}|${domain || title}`;
    if (this._isDuplicate(fp)) return null;

    const alert = {
      id: `alt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toISOString(),
      type,
      severity,
      title,
      message,
      clientIp,
      mac,
      domain,
      reason,
      acknowledged: false,
    };

    this.alerts.unshift(alert);
    if (this.alerts.length > MAX_ALERTS) {
      this.alerts.length = MAX_ALERTS;
    }
    this._scheduleSave();
    this.emit('alert', alert);

    if (push) {
      this._dispatchExternal(alert, cfg).catch(() => {});
    }
    return alert;
  }

  handleQuery(record) {
    const cfg = this._cfg();
    if (!cfg.enabled || !record) return;

    const devices = this.store?.config?.devices || [];
    const clientIp = record.clientIp || '';
    const domain = record.domain || '';
    const mac = deviceDiscovery.getMacForIp(clientIp) || '';
    const devLabel = formatDeviceLabel(clientIp, mac, devices);

    // 1. Chạm Threat Intelligence / Malware / Phishing / DNS Rebinding
    if (cfg.threatHitEnabled && record.blocked && record.severity === 'high') {
      const rLow = String(record.reason || '').toLowerCase();
      let title = 'Chặn truy cập Nguy hiểm';
      if (rLow.includes('rebinding')) title = 'Chặn tấn công DNS Rebinding';
      else if (rLow.includes('phish')) title = 'Chặn trang Lừa đảo (Phishing)';
      else if (rLow.includes('urlhaus') || rLow.includes('malware')) title = 'Chặn tên miền Mã độc (Malware)';
      else if (rLow.includes('tif') || rLow.includes('threat')) title = 'Chặn tên miền Độc hại (Threat Intel)';

      this.createAlert({
        type: 'threat_hit',
        severity: 'high',
        title,
        message: `${devLabel} đã gọi tới ${domain} (${record.reason || 'Threat Intel'})`,
        clientIp,
        mac,
        domain,
        reason: record.reason || '',
        push: true,
        fingerprint: `threat_hit|${clientIp}|${domain}`,
      });
    }

    // 2. Vi phạm Zero-Trust Allowlist của Camera / IoT
    if (record.blocked && record.iotViolation) {
      this.createAlert({
        type: 'iot_violation',
        severity: 'medium',
        title: 'Camera / IoT gọi domain ngoài danh sách cho phép',
        message: `${devLabel} đã bị chặn khi gọi ${domain} (${record.reason || 'Zero-Trust IoT'})`,
        clientIp,
        mac,
        domain,
        reason: record.reason || '',
        push: true,
        fingerprint: `iot_violation|${clientIp}|${domain}`,
      });
    }

    // 3. Phát hiện bất thường (DNS Tunneling & NXDOMAIN Spike)
    if (cfg.anomalyEnabled) {
      const maxLabelLen = Number(cfg.tunnelingLabelLength) || 60;
      if (hasLongDnsLabel(domain, maxLabelLen)) {
        this.createAlert({
          type: 'dns_anomaly',
          severity: 'high',
          title: 'Nghi vấn DNS Tunneling (tên miền dài bất thường)',
          message: `${devLabel} truy vấn tên miền dài ${domain.length} ký tự: ${domain.slice(0, 90)}…`,
          clientIp,
          mac,
          domain,
          reason: 'DNS Tunneling suspicion',
          push: true,
          fingerprint: `tunnel|${clientIp}|${domain.split('.').slice(-2).join('.')}`,
        });
      }

      if (!record.blocked && record.rcode === 'NXDOMAIN') {
        const now = Date.now();
        let entry = this.nxdomainMap.get(clientIp);
        if (!entry || now - entry.windowStart >= NXDOMAIN_WINDOW_MS) {
          entry = { windowStart: now, domains: new Set() };
          this.nxdomainMap.set(clientIp, entry);
        }
        entry.domains.add(domain);
        const threshold = Number(cfg.nxdomainThresholdPerMin) || 30;
        if (entry.domains.size >= threshold) {
          this.createAlert({
            type: 'dns_anomaly',
            severity: 'high',
            title: 'Bùng phát NXDOMAIN bất thường (Nghi vấn DGA / Botnet)',
            message: `${devLabel} phát sinh ${entry.domains.size} tên miền không tồn tại trong 60 giây (mới nhất: ${domain})`,
            clientIp,
            mac,
            domain,
            reason: `NXDOMAIN spike (${entry.domains.size}/min)`,
            push: true,
            fingerprint: `nxdomain_spike|${clientIp}`,
          });
        }
      }
    }
  }

  handleRateLimit(clientIp, limit) {
    const cfg = this._cfg();
    if (!cfg.enabled || !cfg.anomalyEnabled) return;
    const devices = this.store?.config?.devices || [];
    const mac = deviceDiscovery.getMacForIp(clientIp) || '';
    const devLabel = formatDeviceLabel(clientIp, mac, devices);
    this.createAlert({
      type: 'dns_anomaly',
      severity: 'medium',
      title: 'Phát hiện bão truy vấn DNS (Rate-Limit)',
      message: `${devLabel} vượt ngưỡng ${limit} truy vấn/giây và đang bị giới hạn`,
      clientIp,
      mac,
      reason: `Rate limit > ${limit} QPS`,
      push: true,
      fingerprint: `rate_limit|${clientIp}`,
    });
  }

  /**
   * Kiểm tra thiết bị lạ từ kết quả quét ARP/mDNS:
   * - MAC thật (non-private OUI) chưa có trong config.devices -> mức 'high', đẩy Telegram ngay
   * - Private MAC chưa lưu -> mức 'low', chỉ ghi nhận trên UI (tránh spam điện thoại khách)
   */
  handleDiscoveredDevice(info) {
    const cfg = this._cfg();
    if (!cfg.enabled || !cfg.rogueDeviceEnabled || !info) return null;
    if (info.isSelf || info.isLoopback || info.isGateway || info.isSharedMac) return null;

    const mac = normalizeMac(info.mac);
    if (!mac) return null;

    const savedDevices = this.store?.config?.devices || [];
    const known = savedDevices.some((d) => normalizeMac(d.mac) === mac || (info.ip && d.ip === info.ip && !d.mac));
    if (known) return null;

    const isPriv = Boolean(info.isPrivateMac);
    const shouldPush = !(isPriv && cfg.ignorePrivateMacPush !== false);
    const label = info.suggestedName || info.hostname || info.vendor || 'Chưa xác định';

    return this.createAlert({
      type: 'rogue_device',
      severity: isPriv ? 'low' : 'high',
      title: isPriv ? 'Thiết bị mới (Private Wi-Fi MAC)' : 'Phát hiện thiết bị lạ vào mạng LAN',
      message: `${label} — IP: ${info.ip || '?'}, MAC: ${mac}${info.vendor ? ` (${info.vendor})` : ''}`,
      clientIp: info.ip || '',
      mac,
      reason: isPriv ? 'Private MAC chưa duyệt' : 'MAC thật chưa có trong danh sách thiết bị',
      push: shouldPush,
      fingerprint: `rogue_device|${mac}`,
    });
  }

  async _dispatchExternal(alert, cfg) {
    const icon = alert.severity === 'high' ? '🚨' : alert.severity === 'medium' ? '⚠️' : 'ℹ️';
    const text = `${icon} [NetShield DNS] ${alert.title}\n${alert.message}\nThời gian: ${new Date(alert.timestamp).toLocaleString('vi-VN')}`;

    const tasks = [];
    if (cfg.telegramBotToken && cfg.telegramChatId) {
      tasks.push(this._sendTelegram(cfg.telegramBotToken, cfg.telegramChatId, text));
    }
    if (cfg.webhookUrl && /^https?:\/\//i.test(cfg.webhookUrl)) {
      tasks.push(this._sendWebhook(cfg.webhookUrl, { text, alert }));
    }
    if (tasks.length > 0) {
      await Promise.allSettled(tasks);
    }
  }

  async _sendTelegram(botToken, chatId, text) {
    const url = `https://api.telegram.org/bot${encodeURIComponent(botToken)}/sendMessage`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        disable_web_page_preview: true,
      }),
      signal: AbortSignal.timeout(PUSH_TIMEOUT_MS),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`Telegram HTTP ${res.status}: ${body.slice(0, 120)}`);
    }
    return true;
  }

  async _sendWebhook(webhookUrl, payload) {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(PUSH_TIMEOUT_MS),
    });
    if (!res.ok) {
      throw new Error(`Webhook HTTP ${res.status}`);
    }
    return true;
  }

  async sendTestNotification(overrideCfg = {}) {
    const cfg = { ...this._cfg(), ...overrideCfg };
    const text = `🛡️ [NetShield DNS] Kiểm tra kết nối cảnh báo thành công!\nThời gian: ${new Date().toLocaleString('vi-VN')}`;
    const results = [];

    if (cfg.telegramBotToken && cfg.telegramChatId) {
      try {
        await this._sendTelegram(cfg.telegramBotToken, cfg.telegramChatId, text);
        results.push({ channel: 'Telegram', ok: true });
      } catch (err) {
        results.push({ channel: 'Telegram', ok: false, error: err.message });
      }
    }
    if (cfg.webhookUrl && /^https?:\/\//i.test(cfg.webhookUrl)) {
      try {
        await this._sendWebhook(cfg.webhookUrl, { text, test: true });
        results.push({ channel: 'Webhook', ok: true });
      } catch (err) {
        results.push({ channel: 'Webhook', ok: false, error: err.message });
      }
    }
    if (results.length === 0) {
      return { ok: false, error: 'Chưa cấu hình Telegram Bot Token/Chat ID hoặc Webhook URL' };
    }
    return { ok: results.every((r) => r.ok), results };
  }

  getAlerts({ limit = 100, unacknowledgedOnly = false } = {}) {
    let list = this.alerts;
    if (unacknowledgedOnly) {
      list = list.filter((a) => !a.acknowledged);
    }
    return list.slice(0, limit);
  }

  getSummary() {
    let unacknowledged = 0;
    let highUnacknowledged = 0;
    for (const a of this.alerts) {
      if (!a.acknowledged) {
        unacknowledged += 1;
        if (a.severity === 'high') highUnacknowledged += 1;
      }
    }
    return {
      total: this.alerts.length,
      unacknowledged,
      highUnacknowledged,
      recent: this.alerts.slice(0, 8),
    };
  }

  acknowledge(id) {
    const item = this.alerts.find((a) => a.id === id);
    if (!item) return false;
    item.acknowledged = true;
    this._scheduleSave();
    return true;
  }

  acknowledgeAll() {
    for (const a of this.alerts) a.acknowledged = true;
    this._scheduleSave();
    return true;
  }

  clearAll() {
    this.alerts = [];
    this.dedupeMap.clear();
    this._scheduleSave();
  }
}

export const alertEngine = new AlertEngine();
