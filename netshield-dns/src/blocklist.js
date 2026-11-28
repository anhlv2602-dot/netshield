import fs from 'node:fs/promises';
import path from 'node:path';
import {
  ANTI_BYPASS_DOMAINS,
  CACHE_DIR,
  PROTECTED_WHITELIST,
  SERVICE_PRESETS,
  inferBlocklistMeta,
  normalizeDomain,
  store,
} from './store.js';
import { deviceDiscovery, normalizeMac } from './discovery.js';

const ANTI_BYPASS_SET = new Set(ANTI_BYPASS_DOMAINS.map(normalizeDomain));

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
    // Map domain -> { name, category, severity }
    this.blocklistMap = new Map();
    // Map groupId -> Map<domain, { count, lastSeen, allowedByRule }>
    this.observedByGroup = new Map();
    this.isUpdating = false;
  }

  _recordObservedForGroup(groupId, domain, allowedByRule = true) {
    if (!groupId || !domain) return;
    let map = this.observedByGroup.get(groupId);
    if (!map) {
      map = new Map();
      this.observedByGroup.set(groupId, map);
    }
    const existing = map.get(domain);
    if (existing) {
      existing.count += 1;
      existing.lastSeen = new Date().toISOString();
      existing.allowedByRule = allowedByRule;
      return;
    }
    if (map.size >= 300) {
      const oldest = map.keys().next().value;
      if (oldest) map.delete(oldest);
    }
    map.set(domain, { count: 1, lastSeen: new Date().toISOString(), allowedByRule });
  }

  getObservedDomainsForGroup(groupId) {
    const map = this.observedByGroup.get(groupId);
    if (!map) return [];
    return [...map.entries()]
      .map(([domain, meta]) => ({ domain, ...meta }))
      .sort((a, b) => b.count - a.count);
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
      const isMixedAdList = /stevenblack|oisd|abpvn|adguard/i.test(`${list.id || ''} ${list.name || ''}`);
      const meta = isMixedAdList ? { category: 'ads', severity: 'info' } : inferBlocklistMeta(list);
      const cacheFile = path.join(CACHE_DIR, `${list.id}.txt`);
      try {
        const content = await fs.readFile(cacheFile, 'utf8');
        const lines = content.split('\n');
        let count = 0;
        for (const line of lines) {
          const d = line.trim();
          if (!d) continue;
          count += 1;
          const prev = nextMap.get(d);
          // Ưu tiên nâng mức nghiêm trọng lên 'high' nếu domain xuất hiện trong nguồn Malware/Phishing/TIF
          if (!prev || (prev.severity !== 'high' && meta.severity === 'high')) {
            nextMap.set(d, { name: list.name, category: meta.category, severity: meta.severity });
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

  isWhitelisted(rawDomain) {
    const domain = normalizeDomain(rawDomain);
    if (!domain) return false;
    for (const s of getDomainSuffixes(domain)) {
      if (this.whitelistSet.has(s)) return true;
    }
    return false;
  }

  evaluateCnameTarget(rawCname, clientIp) {
    if (!store.config.protectionEnabled) {
      return { blocked: false, reason: 'protection_paused' };
    }
    const domain = normalizeDomain(rawCname);
    if (!domain) return { blocked: false, reason: 'invalid' };
    const suffixes = getDomainSuffixes(domain);
    for (const s of suffixes) {
      if (this.whitelistSet.has(s)) {
        return { blocked: false, reason: 'whitelist' };
      }
    }
    for (const s of suffixes) {
      if (this.blacklistSet.has(s)) {
        return { blocked: true, reason: 'Blacklist tùy chỉnh' };
      }
    }
    for (const s of suffixes) {
      const hit = this.blocklistMap.get(s);
      if (hit) {
        return { blocked: true, reason: hit.name, severity: hit.severity, category: hit.category };
      }
    }
    return { blocked: false, reason: 'allowed' };
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

    // 0. Chống vượt mặt DNS (Firefox DoH canary, Apple iCloud Private Relay, DDR, và Public DoH/DoT resolvers)
    // Đặt trước Whitelist suffix để không bị 'icloud.com' miễn trừ 'mask.icloud.com',
    // nhưng vẫn tôn trọng nếu người dùng whitelist đích danh chính domain DoH/canary đó.
    if (
      store.config.security?.antiBypass !== false &&
      suffixes.some((s) => ANTI_BYPASS_SET.has(s)) &&
      !this.whitelistSet.has(domain)
    ) {
      return {
        blocked: true,
        forceNxdomain: true,
        severity: 'medium',
        reason: 'Chống vượt mặt DNS (Anti-Bypass)',
      };
    }

    const clientMac = deviceDiscovery.getMacForIp(clientIp);
    const clientDevice = deviceDiscovery.resolveDeviceForIp(clientIp, store.config.devices || []);
    if (clientDevice?.groupId) {
      this._recordObservedForGroup(clientDevice.groupId, domain, true);
    }

    // 1. Whitelist luôn ưu tiên cao nhất
    for (const s of suffixes) {
      if (this.whitelistSet.has(s)) {
        return { blocked: false, reason: 'whitelist' };
      }
    }

    // 2. Quy tắc theo thiết bị (ưu tiên khớp theo MAC qua ARP, fallback IP) hoặc Nhóm thiết bị & Khung giờ
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

      // Chế độ Zero-Trust Allowlist-Only (Audit hoặc Enforce) cho Camera / IoT
      if (rule.ruleMode === 'allowlist_audit' || rule.ruleMode === 'allowlist_enforce') {
        const allowSet = new Set((rule.allowedDomains || []).map(normalizeDomain).filter(Boolean));
        const inAllowlist = suffixes.some((s) => allowSet.has(s));
        if (!inAllowlist) {
          if (clientDevice?.groupId) {
            this._recordObservedForGroup(clientDevice.groupId, domain, false);
          }
          if (rule.ruleMode === 'allowlist_enforce') {
            return {
              blocked: true,
              severity: 'medium',
              iotViolation: true,
              reason: `Zero-Trust IoT (${targetLabel})`,
            };
          }
          // Chế độ allowlist_audit: ghi nhận để học, KHÔNG chặn
          return {
            blocked: false,
            auditViolation: true,
            reason: `Audit IoT (ngoài Allowlist): ${targetLabel}`,
          };
        }
        // Nằm trong Allowlist hợp lệ -> tiếp tục kiểm tra Threat Intel/Blocklist bên dưới
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
      const hit = this.blocklistMap.get(s);
      if (hit) {
        return { blocked: true, reason: hit.name, severity: hit.severity, category: hit.category };
      }
    }

    return { blocked: false, reason: 'allowed' };
  }
}

export const blocklistEngine = new BlocklistEngine();
