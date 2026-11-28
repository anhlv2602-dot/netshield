import fs from 'node:fs/promises';
import path from 'node:path';
import { CACHE_DIR, PROTECTED_WHITELIST, SERVICE_PRESETS, normalizeDomain, store } from './store.js';
import { deviceDiscovery, normalizeMac } from './discovery.js';

const DOMAIN_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

/**
 * Parse nhiều định dạng blocklist phổ biến:
 * - Hosts file: 0.0.0.0 ads.example.com / 127.0.0.1 ads.example.com
 * - Adblock: ||ads.example.com^
 * - Plain domain list: ads.example.com
 */
export function parseBlocklistText(text) {
  const domains = new Set();
  const lines = text.split(/\r?\n/);

  for (let rawLine of lines) {
    let line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('!') || line.startsWith('[')) {
      continue;
    }

    // Bỏ comment cuối dòng
    const hashIdx = line.indexOf('#');
    if (hashIdx !== -1) line = line.slice(0, hashIdx).trim();
    if (!line) continue;

    // Định dạng AdBlock: ||example.com^
    if (line.startsWith('||')) {
      if (line.includes('$') && !line.endsWith('$important')) continue;
      let d = line.slice(2).split('^')[0].split('/')[0].trim().toLowerCase();
      if (d && DOMAIN_REGEX.test(d)) {
        domains.add(d);
      }
      continue;
    }

    // Bỏ qua rule ngoại lệ AdBlock
    if (line.startsWith('@@')) continue;

    // Định dạng Hosts: 0.0.0.0 domain1 domain2
    const parts = line.split(/\s+/);
    if (parts.length >= 2 && (parts[0] === '0.0.0.0' || parts[0] === '127.0.0.1' || parts[0] === '::' || parts[0] === '::1')) {
      for (let i = 1; i < parts.length; i++) {
        const d = normalizeDomain(parts[i]);
        if (d && d !== 'localhost' && d !== 'localhost.localdomain' && DOMAIN_REGEX.test(d)) {
          domains.add(d);
        }
      }
      continue;
    }

    // Định dạng plain domain
    if (parts.length === 1) {
      const d = normalizeDomain(parts[0]);
      if (d && d !== 'localhost' && DOMAIN_REGEX.test(d)) {
        domains.add(d);
      }
    }
  }

  return domains;
}

function getDomainSuffixes(domain) {
  const parts = domain.split('.');
  const list = [];
  for (let i = 0; i < parts.length - 1; i++) {
    list.push(parts.slice(i).join('.'));
  }
  return list;
}

function isTimeInSchedule(schedule, now) {
  if (!schedule || !schedule.enabled) return true;

  // Kiểm tra thứ trong tuần (0 = CN, 1 = T2 ... 6 = T7)
  if (Array.isArray(schedule.days) && schedule.days.length > 0) {
    if (!schedule.days.includes(now.getDay())) return false;
  }

  const [sh, sm] = (schedule.start || '00:00').split(':').map(Number);
  const [eh, em] = (schedule.end || '23:59').split(':').map(Number);
  const curMin = now.getHours() * 60 + now.getMinutes();
  const startMin = sh * 60 + sm;
  const endMin = eh * 60 + em;

  if (startMin <= endMin) {
    return curMin >= startMin && curMin <= endMin;
  }
  // Hỗ trợ khung giờ qua đêm (ví dụ 22:00 - 06:00)
  return curMin >= startMin || curMin <= endMin;
}

class BlocklistEngine {
  constructor() {
    this.whitelistSet = new Set();
    this.blacklistSet = new Set();
    // Map domain -> tên blocklist nguồn đầu tiên
    this.blocklistMap = new Map();
    this.isUpdating = false;
  }

  rebuildCustomSets() {
    this.whitelistSet = new Set([
      ...PROTECTED_WHITELIST.map(normalizeDomain),
      ...(store.config.whitelist || []).map(normalizeDomain),
    ].filter(Boolean));
    this.blacklistSet = new Set(
      (store.config.blacklist || []).map(normalizeDomain).filter(Boolean)
    );
  }

  async loadFromCache() {
    this.rebuildCustomSets();
    const nextMap = new Map();

    for (const list of store.config.blocklists) {
      if (!list.enabled) continue;
      const cacheFile = path.join(CACHE_DIR, `${list.id}.txt`);
      try {
        const content = await fs.readFile(cacheFile, 'utf8');
        const lines = content.split('\n');
        let count = 0;
        for (const line of lines) {
          const d = line.trim();
          if (!d) continue;
          count += 1;
          if (!nextMap.has(d)) {
            nextMap.set(d, list.name);
          }
        }
        list.count = count;
      } catch {
        // Chưa có cache, sẽ tải ở bước refresh
      }
    }

    this.blocklistMap = nextMap;
    return this.blocklistMap.size;
  }

  async refreshOne(list) {
    await fs.mkdir(CACHE_DIR, { recursive: true });
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 20000);
      const res = await fetch(list.url, {
        signal: controller.signal,
        headers: { 'User-Agent': 'NetShield-DNS/1.0' },
      });
      clearTimeout(timer);

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const text = await res.text();
      const parsed = parseBlocklistText(text);
      if (parsed.size === 0) {
        throw new Error('Không tìm thấy tên miền hợp lệ trong file (sai định dạng hoặc link rỗng)');
      }
      const cacheFile = path.join(CACHE_DIR, `${list.id}.txt`);
      await fs.writeFile(cacheFile, [...parsed].join('\n'), 'utf8');

      list.count = parsed.size;
      list.lastUpdated = new Date().toISOString();
      list.lastError = null;
      return { id: list.id, ok: true, count: parsed.size };
    } catch (err) {
      list.lastError = err.name === 'AbortError' ? 'Quá thời gian chờ (Timeout)' : err.message;
      return { id: list.id, ok: false, error: list.lastError };
    }
  }

  async refreshById(id) {
    const list = store.config.blocklists.find((b) => b.id === id);
    if (!list) return { ok: false, error: 'Không tìm thấy nguồn' };
    const res = await this.refreshOne(list);
    await store.save();
    const totalDomains = await this.loadFromCache();
    return { ...res, totalDomains };
  }

  async refreshAll() {
    if (this.isUpdating) return { updated: false, message: 'Đang cập nhật danh sách...' };
    this.isUpdating = true;
    const results = [];

    try {
      for (const list of store.config.blocklists) {
        if (!list.enabled) continue;
        results.push(await this.refreshOne(list));
      }

      await store.save();
      const totalDomains = await this.loadFromCache();
      return { updated: true, totalDomains, results };
    } finally {
      this.isUpdating = false;
    }
  }

  getTotalBlockedDomains() {
    return this.blocklistMap.size + this.blacklistSet.size;
  }

  evaluate(rawDomain, clientIp, now = new Date()) {
    const domain = normalizeDomain(rawDomain);
    if (!domain) {
      return { blocked: false, reason: 'invalid' };
    }

    if (!store.config.protectionEnabled) {
      return { blocked: false, reason: 'protection_paused' };
    }

    const suffixes = getDomainSuffixes(domain);

    // 1. Whitelist luôn ưu tiên cao nhất
    for (const s of suffixes) {
      if (this.whitelistSet.has(s)) {
        return { blocked: false, reason: 'whitelist' };
      }
    }

    // 2. Quy tắc theo thiết bị (ưu tiên khớp theo MAC qua ARP, fallback IP) hoặc Nhóm thiết bị & Khung giờ
    const clientMac = deviceDiscovery.getMacForIp(clientIp);
    const clientDevice = deviceDiscovery.resolveDeviceForIp(clientIp, store.config.devices || []);
    for (const rule of store.config.clientRules || []) {
      if (!rule.enabled) continue;
      let targetMatches = false;
      let targetLabel = rule.name || rule.clientIp || clientIp;

      if (rule.targetType === 'group' && rule.groupId) {
        targetMatches = Boolean(clientDevice && clientDevice.groupId === rule.groupId);
        if (targetMatches) {
          const grp = (store.config.deviceGroups || []).find((g) => g.id === rule.groupId);
          targetLabel = rule.name || (grp ? `Nhóm ${grp.name}` : rule.groupId);
        }
      } else {
        const ruleMac = normalizeMac(rule.clientIp);
        targetMatches =
          rule.clientIp === '*' ||
          rule.clientIp === clientIp ||
          Boolean(clientMac && ruleMac && ruleMac === clientMac);
      }
      if (!targetMatches) continue;

      if (rule.bypassProtection) {
        return { blocked: false, reason: `bypass:${targetLabel}` };
      }

      if (!isTimeInSchedule(rule.schedule, now)) {
        continue;
      }

      // Chặn toàn bộ Internet theo khung giờ cho thiết bị / nhóm này
      if (rule.blockAllInternet) {
        return { blocked: true, reason: `Khóa mạng: ${targetLabel}` };
      }

      // Chặn theo nhóm dịch vụ nhanh (TikTok, Facebook, YouTube...)
      for (const svcKey of rule.blockedServices || []) {
        const preset = SERVICE_PRESETS[svcKey];
        if (!preset) continue;
        for (const s of suffixes) {
          if (preset.domains.includes(s)) {
            return { blocked: true, reason: `Dịch vụ (${preset.label}): ${targetLabel}` };
          }
        }
      }

      // Chặn theo danh sách domain riêng của thiết bị / nhóm
      for (const customD of rule.blockedDomains || []) {
        const norm = normalizeDomain(customD);
        if (norm && suffixes.includes(norm)) {
          return { blocked: true, reason: `Chặn riêng: ${targetLabel}` };
        }
      }
    }

    // 3. Blacklist tùy chỉnh toàn mạng
    for (const s of suffixes) {
      if (this.blacklistSet.has(s)) {
        return { blocked: true, reason: 'Blacklist tùy chỉnh' };
      }
    }

    // 4. Blocklist tự động
    for (const s of suffixes) {
      const sourceName = this.blocklistMap.get(s);
      if (sourceName) {
        return { blocked: true, reason: sourceName };
      }
    }

    return { blocked: false, reason: 'allowed' };
  }
}

export const blocklistEngine = new BlocklistEngine();
