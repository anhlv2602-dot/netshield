import fs from 'node:fs/promises';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import { deviceDiscovery, normalizeMac } from './discovery.js';
import { normalizeUpstreamStrategy, normalizeLocalRecord } from './load-balancer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(__dirname, '..');
export const DATA_DIR = process.env.NETSHIELD_DATA_DIR
  ? path.resolve(process.env.NETSHIELD_DATA_DIR)
  : path.join(ROOT_DIR, 'data');
export const CACHE_DIR = path.join(DATA_DIR, 'blocklists-cache');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
const STATS_PATH = path.join(DATA_DIR, 'stats.json');
const HOUR_MS = 60 * 60 * 1000;
const BANDWIDTH_DEDUPE_WINDOW_MS = 30 * 1000;

export const SERVICE_PRESETS = {
  tiktok: {
    label: 'TikTok',
    domains: ['tiktok.com', 'tiktokcdn.com', 'tiktokv.com', 'musical.ly', 'byteoversea.com', 'ibytedtos.com'],
  },
  facebook: {
    label: 'Facebook',
    domains: ['facebook.com', 'fbcdn.net', 'fb.com', 'fbsbx.com', 'messenger.com'],
  },
  youtube: {
    label: 'YouTube',
    domains: ['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com'],
  },
  instagram: {
    label: 'Instagram',
    domains: ['instagram.com', 'cdninstagram.com'],
  },
  shopee: {
    label: 'Shopee',
    domains: ['shopee.vn', 'shopee.com', 'shopeemobile.com'],
  },
  gaming: {
    label: 'Game (Roblox/Steam/Garena)',
    domains: ['roblox.com', 'rbxcdn.com', 'steampowered.com', 'steamcommunity.com', 'garena.vn', 'garena.com', 'riotgames.com'],
  },
};

export const PROTECTED_WHITELIST = [
  // Cơ quan Nhà nước, Thuế (GDT), BHXH, Hải quan, ĐKDN, VNeID
  'localhost',
  'gov.vn',
  'gdt.gov.vn',
  'thuedientu.gdt.gov.vn',
  'hoadondientu.gdt.gov.vn',
  'tracuuhoadon.gdt.gov.vn',
  'vneid.gov.vn',
  'rootca.gov.vn',
  'neac.gov.vn',

  // Hóa đơn điện tử (HĐĐT) & Phần mềm Kế toán
  'misa.vn',
  'misa.com.vn',
  'meinvoice.vn',
  'amis.vn',
  'sinvoice.vn',
  'viettel.vn',
  'viettel.com.vn',
  'vnpt-invoice.com.vn',
  'vnpt.vn',
  'vnpt.com.vn',
  'ehoadon.vn',
  'bkav.com.vn',
  'bkav.vn',
  'ivan.vn',
  'easyinvoice.vn',
  'easyinvoice.com.vn',
  'softdreams.vn',
  'minvoice.vn',
  'minvoice.com.vn',
  'cyberbill.vn',
  'cybers.vn',
  'cyberlotus.com',
  'fast.com.vn',
  'einvoice.vn',
  'thaison.vn',
  'thaison.com.vn',
  'efy.com.vn',
  'efy.vn',
  'ihoadon.vn',
  'fpt.com.vn',
  'mobifoneinvoice.vn',
  'hilo.com.vn',
  'matbao.in',
  'matbao.net',
  'vietinvoice.vn',
  'newinvoice.vn',
  'smartvas.vn',
  'vnpayinvoice.vn',
  'wininvoice.vn',
  'hoadonviet.vn',
  'xcyber.vn',
  'tax24.com.vn',
  'ts24.com.vn',
  'ts24.vn',
  'nhantokhai.vn',
  'tvan.vn',
  'esoc.vn',
  'kiotviet.vn',
  'sapo.vn',
  'haravan.com',
  'nhanh.vn',

  // Chữ ký số (CA), OCSP/CRL & Timestamp (TSA)
  'viettel-ca.vn',
  'vnpt-ca.vn',
  'bkavca.vn',
  'bkav-ca.vn',
  'fpt-ca.vn',
  'newca.vn',
  'fastca.vn',
  'vinca.vn',
  'efyca.vn',
  'easyca.vn',
  'nacencomm.vn',
  'ca2.vn',
  'smartsign.com.vn',
  'vina-ca.vn',
  'intrustca.vn',
  'safe-ca.com',
  'trustca.vn',
  'hilo-ca.vn',
  'ica.com.vn',
  'oneca.vn',
  'nca.vn',
  'mobifoneca.vn',
  'digicert.com',
  'sectigo.com',
  'globalsign.com',
  'entrust.net',
  'letsencrypt.org',

  // Ngân hàng Việt Nam & Cổng thanh toán (NAPAS / VNPAY / VietQR)
  'vietcombank.com.vn',
  'techcombank.com.vn',
  'techcombank.com',
  'mbbank.com.vn',
  'mb.com.vn',
  'bidv.com.vn',
  'vietinbank.vn',
  'agribank.com.vn',
  'acb.com.vn',
  'vpbank.com.vn',
  'tpb.vn',
  'tpbank.vn',
  'sacombank.com.vn',
  'sacombank.vn',
  'hdbank.com.vn',
  'vib.com.vn',
  'shb.com.vn',
  'seabank.com.vn',
  'ocb.com.vn',
  'msb.com.vn',
  'eximbank.com.vn',
  'lpbank.com.vn',
  'lienvietpostbank.com.vn',
  'namabank.com.vn',
  'abbank.vn',
  'bacabank.com.vn',
  'vietcapitalbank.com.vn',
  'bvbank.net.vn',
  'ncb-bank.vn',
  'pvcombank.com.vn',
  'scb.com.vn',
  'vietabank.com.vn',
  'kienlongbank.com',
  'pgbank.com.vn',
  'saigonbank.com.vn',
  'baovietbank.vn',
  'co-opbank.com.vn',
  'shinhan.com.vn',
  'woori.com.vn',
  'hsbc.com.vn',
  'sc.com',
  'uob.com.vn',
  'publicbank.com.vn',
  'cimb.com.vn',
  'timo.vn',
  'cake.vn',
  'tnex.com.vn',
  'napas.com.vn',
  'vnpay.vn',
  'vnpayment.vn',
  'vietqr.io',
  'vietqr.net',
  'momo.vn',
  'zalopay.vn',
  'onepay.vn',
];

export const IOT_ALLOWLIST_PRESETS = {
  camera_ezviz: {
    label: 'Camera Ezviz / Hikvision',
    domains: ['ezvizlife.com', 'ezviz.com', 'ezvizru.com', 'hik-connect.com', 'ys7.com', 'ntp.org', 'pool.ntp.org', 'time.google.com'],
  },
  camera_dahua_imou: {
    label: 'Camera Dahua / Imou',
    domains: ['imoulife.com', 'easy4ipcloud.com', 'easy4ip.com', 'dahuasecurity.com', 'lechange.cn', 'ntp.org', 'pool.ntp.org'],
  },
  iot_smarthome: {
    label: 'SmartHome (ESP / Tuya / Hunonic)',
    domains: ['hunonic.com', 'hunonic.vn', 'tuyaus.com', 'tuyaeu.com', 'tuyacn.com', 'tuya.com', 'espressif.com', 'ntp.org', 'pool.ntp.org'],
  },
  iot_printer: {
    label: 'Máy in (Brother / Canon)',
    domains: ['brother.com', 'canon.com', 'canon.jp', 'ntp.org', 'pool.ntp.org'],
  },
};

export const DEFAULT_ALERTS_CONFIG = {
  enabled: true,
  rogueDeviceEnabled: true,
  ignorePrivateMacPush: true,
  threatHitEnabled: true,
  anomalyEnabled: true,
  nxdomainThresholdPerMin: 30,
  tunnelingLabelLength: 60,
  telegramBotToken: '',
  telegramChatId: '',
  webhookUrl: '',
};

export function inferBlocklistMeta(list) {
  const explicit = String(list?.category || '').toLowerCase();
  if (['malware', 'phishing', 'threat_intel', 'ads'].includes(explicit)) {
    return {
      category: explicit,
      severity: explicit === 'ads' ? 'info' : 'high',
    };
  }
  const haystack = `${list?.id || ''} ${list?.name || ''} ${list?.url || ''}`.toLowerCase();
  if (haystack.includes('phish')) return { category: 'phishing', severity: 'high' };
  if (haystack.includes('urlhaus') || haystack.includes('malware')) return { category: 'malware', severity: 'high' };
  if (haystack.includes('tif') || haystack.includes('threat') || haystack.includes('botnet')) {
    return { category: 'threat_intel', severity: 'high' };
  }
  return { category: 'ads', severity: 'info' };
}

export const ANTI_BYPASS_DOMAINS = [
  'use-application-dns.net', // Firefox DoH canary
  'mask.icloud.com',         // Apple iCloud Private Relay
  'mask-h2.icloud.com',      // Apple iCloud Private Relay (HTTP/2)
  '_dns.resolver.arpa',      // DDR (Discovery of Designated Resolvers)
];

export const DEFAULT_SECURITY_CONFIG = {
  dnsRebindingGuard: true,
  cnameCloakingGuard: true,
  antiBypass: true,
  serveStaleCache: true,
  enableIpv6: true,
  rebindingWhitelist: [],
};

export const DEFAULT_STORAGE_CONFIG = {
  sqliteEnabled: true,
  retentionDays: 14,
};

export const DEFAULT_CONFIG = {
  protectionEnabled: true,
  upstreamDns: [
    'https://1.1.1.2/dns-query',
    'https://9.9.9.9/dns-query',
    '203.113.131.1',
  ],
  upstreamStrategy: 'failover', // 'failover' | 'round_robin' | 'lowest_latency' | 'parallel'
  blockResponseMode: 'zero', // 'zero' (0.0.0.0 / ::) hoặc 'nxdomain'
  security: { ...DEFAULT_SECURITY_CONFIG },
  alerts: { ...DEFAULT_ALERTS_CONFIG },
  storage: { ...DEFAULT_STORAGE_CONFIG },
  localRecords: [],
  blocklists: [
    {
      id: 'abpvn-hosts',
      name: 'ABPVN Hosts (Quảng cáo Việt Nam)',
      url: 'https://abpvn.com/android/abpvn.txt',
      enabled: true,
      count: 0,
      lastUpdated: null,
    },
    {
      id: 'oisd-small',
      name: 'OISD Small (Quảng cáo & Tracker quốc tế)',
      url: 'https://small.oisd.nl/domainswild2',
      enabled: true,
      count: 0,
      lastUpdated: null,
    },
    {
      id: 'adguard-dns',
      name: 'AdGuard DNS Filter',
      url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
      enabled: false,
      count: 0,
      lastUpdated: null,
    },
    {
      id: 'stevenblack-ads',
      name: 'StevenBlack Unified (Ads + Malware)',
      url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
      enabled: false,
      count: 0,
      lastUpdated: null,
    },
  ],
  whitelist: [
    'localhost',
    'gov.vn',
    'gdt.gov.vn',
    'misa.vn',
    'meinvoice.vn',
    'sinvoice.vn',
    'vnpt-invoice.com.vn',
    'ehoadon.vn',
    'bkav.com.vn',
    'viettel-ca.vn',
    'vnpt-ca.vn',
    'efy.com.vn',
    'apple.com',
    'icloud.com',
    'vietcombank.com.vn',
    'techcombank.com.vn',
    'mbbank.com.vn',
    'bidv.com.vn',
    'vietinbank.vn',
    'acb.com.vn',
  ],
  blacklist: [],
  deviceGroups: [
    {
      id: 'camera',
      name: 'Camera an ninh',
      icon: '📷',
      description: 'Camera IP, đầu ghi NVR/DVR',
    },
    {
      id: 'computer',
      name: 'Máy tính / Laptop',
      icon: '💻',
      description: 'PC văn phòng, Mac, Laptop',
    },
    {
      id: 'mobile',
      name: 'Thiết bị di động',
      icon: '📱',
      description: 'Điện thoại, máy tính bảng',
    },
    {
      id: 'iot',
      name: 'Thiết bị IoT',
      icon: '🔌',
      description: 'Smart TV, ổ cắm, cảm biến, máy in mạng',
    },
  ],
  devices: [],
  clientRules: [],
};

export function normalizeDomain(input) {
  if (!input || typeof input !== 'string') return '';
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/^\.+|\.+$/g, '');
}

export const BANDWIDTH_CATEGORIES = {
  video_ad: { label: 'Quảng cáo Video / Rich Media', bytesPerQuery: 750 * 1024 },
  service_rule: { label: 'Dịch vụ chặn theo quy tắc', bytesPerQuery: 500 * 1024 },
  display_ad: { label: 'Quảng cáo Banner / Display', bytesPerQuery: 180 * 1024 },
  tracker: { label: 'Tracker / Telemetry / Log', bytesPerQuery: 25 * 1024 },
};

const TRACKER_DOMAIN_RE =
  /(^|[.-])(collector|logs?|logging|telemetry|metrics|analytics|googletagmanager|tagmanager|pixel|beacon|track|tracking|events|customerevents|ichnaea|crashlytics|sentry|clarity|hotjar|mixpanel|amplitude|appsflyer|adjust|branch|trellian|scorecardresearch|quantserve|adtrafficquality|newrelic|datadog|stats?|ping|report|diag|diagnostic)([.-]|$)/i;

const VIDEO_AD_DOMAIN_RE =
  /(imasdk|vungle|unityads|applovin|adcolony|pangle|mintegral|googlevideo|tiktokcdn|taboola|outbrain|mgid|videoad|video-ad|admedia|vast|vpaid|ytimg|mopub|fyber|ironsrc|supersonicads)/i;

export function estimateSavedBandwidth(domain, reason = '') {
  if (typeof reason === 'string' && (reason.startsWith('Dịch vụ (') || reason.startsWith('Khóa mạng:'))) {
    return { category: 'service_rule', bytes: BANDWIDTH_CATEGORIES.service_rule.bytesPerQuery };
  }
  const d = String(domain || '').toLowerCase();
  if (TRACKER_DOMAIN_RE.test(d)) {
    return { category: 'tracker', bytes: BANDWIDTH_CATEGORIES.tracker.bytesPerQuery };
  }
  if (VIDEO_AD_DOMAIN_RE.test(d)) {
    return { category: 'video_ad', bytes: BANDWIDTH_CATEGORIES.video_ad.bytesPerQuery };
  }
  return { category: 'display_ad', bytes: BANDWIDTH_CATEGORIES.display_ad.bytesPerQuery };
}

class Store extends EventEmitter {
  constructor() {
    super();
    this.config = structuredClone(DEFAULT_CONFIG);
    this.logs = [];
    this.maxLogs = 1500;
    this.recentSavedDedupe = new Map();
    this._statsDirty = false;
    this._statsSaveTimer = null;
    this._savingStats = false;
    this.stats = {
      startedAt: Date.now(),
      totalQueries: 0,
      blockedQueries: 0,
      cachedQueries: 0,
      savedBytesTotal: 0,
      savedByCategory: Object.fromEntries(
        Object.keys(BANDWIDTH_CATEGORIES).map((k) => [k, { count: 0, bytes: 0 }])
      ),
      byDomainBlocked: new Map(),
      byClient: new Map(),
      hourlyMap: new Map(),
    };
  }

  async load() {
    await fs.mkdir(CACHE_DIR, { recursive: true });
    try {
      const raw = await fs.readFile(CONFIG_PATH, 'utf8');
      const parsed = JSON.parse(raw);
      this.config = {
        ...structuredClone(DEFAULT_CONFIG),
        ...parsed,
        whitelist: Array.isArray(parsed.whitelist) ? parsed.whitelist : DEFAULT_CONFIG.whitelist,
        blacklist: Array.isArray(parsed.blacklist) ? parsed.blacklist : [],
        blocklists: Array.isArray(parsed.blocklists) ? parsed.blocklists : DEFAULT_CONFIG.blocklists,
        deviceGroups: Array.isArray(parsed.deviceGroups) ? parsed.deviceGroups : structuredClone(DEFAULT_CONFIG.deviceGroups),
        devices: Array.isArray(parsed.devices)
          ? parsed.devices
              .filter((d) => d && (d.mac || d.ip))
              .map((d) => {
                const mac = normalizeMac(d.mac);
                const ip = (d.ip || '').trim();
                const id = d.id || (mac ? `mac:${mac}` : `ip:${ip}`);
                return {
                  id,
                  ip,
                  name: (d.name || '').trim(),
                  groupId: (d.groupId || '').trim(),
                  ...(mac ? { mac } : {}),
                };
              })
          : [],
        clientRules: Array.isArray(parsed.clientRules) ? parsed.clientRules : [],
        security: {
          ...DEFAULT_SECURITY_CONFIG,
          ...(parsed.security && typeof parsed.security === 'object' ? parsed.security : {}),
          rebindingWhitelist: Array.isArray(parsed.security?.rebindingWhitelist)
            ? parsed.security.rebindingWhitelist.map(normalizeDomain).filter(Boolean)
            : [],
        },
        alerts: {
          ...DEFAULT_ALERTS_CONFIG,
          ...(parsed.alerts && typeof parsed.alerts === 'object' ? parsed.alerts : {}),
        },
        storage: {
          ...DEFAULT_STORAGE_CONFIG,
          ...(parsed.storage && typeof parsed.storage === 'object' ? parsed.storage : {}),
        },
        upstreamStrategy: normalizeUpstreamStrategy(parsed.upstreamStrategy),
        localRecords: Array.isArray(parsed.localRecords)
          ? parsed.localRecords
              .map((r) => {
                try {
                  return normalizeLocalRecord(r);
                } catch {
                  return null;
                }
              })
              .filter(Boolean)
          : [],
      };
    } catch {
      await this.save();
    }
    await this.loadStats();
    return this.config;
  }

  async loadStats() {
    try {
      const raw = await fs.readFile(STATS_PATH, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return;

      const nowEpoch = Math.floor(Date.now() / HOUR_MS);
      const minEpoch = nowEpoch - 23;

      if (Number.isFinite(parsed.startedAt)) this.stats.startedAt = parsed.startedAt;
      if (Number.isFinite(parsed.totalQueries)) this.stats.totalQueries = Math.max(0, parsed.totalQueries);
      if (Number.isFinite(parsed.blockedQueries)) this.stats.blockedQueries = Math.max(0, parsed.blockedQueries);
      if (Number.isFinite(parsed.cachedQueries)) this.stats.cachedQueries = Math.max(0, parsed.cachedQueries);
      if (Number.isFinite(parsed.savedBytesTotal)) this.stats.savedBytesTotal = Math.max(0, parsed.savedBytesTotal);

      if (parsed.savedByCategory && typeof parsed.savedByCategory === 'object') {
        for (const key of Object.keys(BANDWIDTH_CATEGORIES)) {
          const item = parsed.savedByCategory[key];
          if (item && typeof item === 'object') {
            this.stats.savedByCategory[key] = {
              count: Number.isFinite(item.count) ? Math.max(0, item.count) : 0,
              bytes: Number.isFinite(item.bytes) ? Math.max(0, item.bytes) : 0,
            };
          }
        }
      }

      if (Array.isArray(parsed.byDomainBlocked)) {
        this.stats.byDomainBlocked.clear();
        for (const [domain, s] of parsed.byDomainBlocked) {
          if (!domain || !s || typeof s !== 'object') continue;
          this.stats.byDomainBlocked.set(domain, {
            count: Number.isFinite(s.count) ? Math.max(0, s.count) : 0,
            savedBytes: Number.isFinite(s.savedBytes) ? Math.max(0, s.savedBytes) : 0,
            category: typeof s.category === 'string' ? s.category : 'display_ad',
          });
        }
      }

      if (Array.isArray(parsed.byClient)) {
        this.stats.byClient.clear();
        for (const [ip, s] of parsed.byClient) {
          if (!ip || !s || typeof s !== 'object') continue;
          this.stats.byClient.set(ip, {
            total: Number.isFinite(s.total) ? Math.max(0, s.total) : 0,
            blocked: Number.isFinite(s.blocked) ? Math.max(0, s.blocked) : 0,
            savedBytes: Number.isFinite(s.savedBytes) ? Math.max(0, s.savedBytes) : 0,
            lastSeen: typeof s.lastSeen === 'string' ? s.lastSeen : new Date().toISOString(),
          });
        }
      }

      if (Array.isArray(parsed.hourly)) {
        this.stats.hourlyMap.clear();
        for (const item of parsed.hourly) {
          if (!item || !Number.isFinite(item.hourEpoch)) continue;
          if (item.hourEpoch < minEpoch || item.hourEpoch > nowEpoch) continue;
          this.stats.hourlyMap.set(item.hourEpoch, {
            total: Number.isFinite(item.total) ? Math.max(0, item.total) : 0,
            blocked: Number.isFinite(item.blocked) ? Math.max(0, item.blocked) : 0,
            savedBytes: Number.isFinite(item.savedBytes) ? Math.max(0, item.savedBytes) : 0,
          });
        }
      }
    } catch {
      // Chưa có stats.json hoặc file hỏng -> bắt đầu sạch, không ghi file trước khi dropRootPrivileges
    }
  }

  async saveStats({ force = false } = {}) {
    if ((!force && !this._statsDirty) || this._savingStats) return;
    this._savingStats = true;
    try {
      const nowEpoch = Math.floor(Date.now() / HOUR_MS);
      const minEpoch = nowEpoch - 23;
      const hourly = [];
      for (const [hourEpoch, bucket] of this.stats.hourlyMap.entries()) {
        if (hourEpoch >= minEpoch && hourEpoch <= nowEpoch) {
          hourly.push({
            hourEpoch,
            total: bucket.total,
            blocked: bucket.blocked,
            savedBytes: bucket.savedBytes,
          });
        }
      }

      const topDomains = [...this.stats.byDomainBlocked.entries()]
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 200);
      const topClients = [...this.stats.byClient.entries()]
        .sort((a, b) => b[1].total - a[1].total)
        .slice(0, 200);

      const payload = {
        version: 1,
        savedAt: new Date().toISOString(),
        startedAt: this.stats.startedAt,
        totalQueries: this.stats.totalQueries,
        blockedQueries: this.stats.blockedQueries,
        cachedQueries: this.stats.cachedQueries,
        savedBytesTotal: this.stats.savedBytesTotal,
        savedByCategory: this.stats.savedByCategory,
        byDomainBlocked: topDomains,
        byClient: topClients,
        hourly,
      };

      await fs.mkdir(DATA_DIR, { recursive: true });
      const tmpPath = `${STATS_PATH}.tmp`;
      await fs.writeFile(tmpPath, JSON.stringify(payload), 'utf8');
      await fs.rename(tmpPath, STATS_PATH);
      this._statsDirty = false;
    } catch (err) {
      console.error('⚠️  Không thể lưu thống kê ra stats.json:', err.message);
    } finally {
      this._savingStats = false;
    }
  }

  startStatsAutosave(intervalMs = 60_000) {
    this.stopStatsAutosave();
    this._statsSaveTimer = setInterval(() => {
      this.saveStats().catch(() => {});
    }, intervalMs);
    this._statsSaveTimer.unref?.();
  }

  stopStatsAutosave() {
    if (this._statsSaveTimer) {
      clearInterval(this._statsSaveTimer);
      this._statsSaveTimer = null;
    }
  }

  async save() {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const tmpPath = `${CONFIG_PATH}.tmp`;
    await fs.writeFile(tmpPath, JSON.stringify(this.config, null, 2), { encoding: 'utf8', mode: 0o600 });
    await fs.rename(tmpPath, CONFIG_PATH);
  }

  recordQuery(entry) {
    const nowMs = Date.now();
    const now = new Date(nowMs);
    const hourEpoch = Math.floor(nowMs / HOUR_MS);

    let saved = null;
    let savedBytes = 0;
    let bandwidthDeduplicated = false;
    if (entry.blocked) {
      saved = estimateSavedBandwidth(entry.domain, entry.reason);
      const dedupeKey = `${entry.clientIp || ''}|${entry.domain || ''}`;
      const lastSavedAt = this.recentSavedDedupe.get(dedupeKey) || 0;
      if (nowMs - lastSavedAt >= BANDWIDTH_DEDUPE_WINDOW_MS) {
        savedBytes = saved.bytes;
        this.recentSavedDedupe.set(dedupeKey, nowMs);
      } else {
        bandwidthDeduplicated = true;
      }
      if (this.recentSavedDedupe.size > 4000) {
        const cutoff = nowMs - BANDWIDTH_DEDUPE_WINDOW_MS;
        for (const [k, ts] of this.recentSavedDedupe) {
          if (ts < cutoff) this.recentSavedDedupe.delete(k);
        }
      }
    }

    const record = {
      id: `${nowMs}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: now.toISOString(),
      ...entry,
      ...(saved
        ? {
            savedBytes,
            category: saved.category,
            ...(bandwidthDeduplicated ? { bandwidthDeduplicated: true } : {}),
          }
        : {}),
    };

    this.logs.unshift(record);
    if (this.logs.length > this.maxLogs) {
      this.logs.length = this.maxLogs;
    }

    let hourBucket = this.stats.hourlyMap.get(hourEpoch);
    if (!hourBucket) {
      hourBucket = { total: 0, blocked: 0, savedBytes: 0 };
      this.stats.hourlyMap.set(hourEpoch, hourBucket);
      const minEpoch = hourEpoch - 23;
      for (const ep of this.stats.hourlyMap.keys()) {
        if (ep < minEpoch) this.stats.hourlyMap.delete(ep);
      }
    }

    this.stats.totalQueries += 1;
    hourBucket.total += 1;
    if (entry.cached) {
      this.stats.cachedQueries += 1;
    }
    if (entry.blocked && saved) {
      this.stats.blockedQueries += 1;
      this.stats.savedBytesTotal += savedBytes;
      hourBucket.blocked += 1;
      hourBucket.savedBytes += savedBytes;

      const catStat = this.stats.savedByCategory[saved.category];
      if (catStat) {
        catStat.count += 1;
        catStat.bytes += savedBytes;
      }

      const domStat = this.stats.byDomainBlocked.get(entry.domain) || {
        count: 0,
        savedBytes: 0,
        category: saved.category,
      };
      domStat.count += 1;
      domStat.savedBytes += savedBytes;
      this.stats.byDomainBlocked.set(entry.domain, domStat);
    }

    const clientStat = this.stats.byClient.get(entry.clientIp) || {
      total: 0,
      blocked: 0,
      savedBytes: 0,
      lastSeen: record.timestamp,
    };
    clientStat.total += 1;
    if (entry.blocked && saved) {
      clientStat.blocked += 1;
      clientStat.savedBytes += savedBytes;
    }
    clientStat.lastSeen = record.timestamp;
    this.stats.byClient.set(entry.clientIp, clientStat);

    this._statsDirty = true;
    this.emit('query', record);
  }

  getSummary() {
    const topBlockedDomains = [...this.stats.byDomainBlocked.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 12)
      .map(([domain, s]) => ({
        domain,
        count: s.count,
        savedBytes: s.savedBytes,
        category: s.category,
      }));

    const groupMap = new Map();
    for (const g of this.config.deviceGroups || []) {
      groupMap.set(g.id, g);
    }

    const savedDevices = this.config.devices || [];

    const clientNames = new Map();
    for (const rule of this.config.clientRules) {
      if (rule.clientIp && rule.name) {
        clientNames.set(rule.clientIp, rule.name);
      }
    }

    const topClients = [...this.stats.byClient.entries()]
      .sort((a, b) => b[1].total - a[1].total)
      .slice(0, 20)
      .map(([ip, s]) => {
        const dev = deviceDiscovery.resolveDeviceForIp(ip, savedDevices);
        const grp = dev?.groupId ? groupMap.get(dev.groupId) : null;
        const mac = dev?.mac || deviceDiscovery.getMacForIp(ip) || '';
        return {
          ip,
          mac,
          deviceId: dev?.id || '',
          name: dev?.name || clientNames.get(ip) || (mac ? clientNames.get(mac) || '' : ''),
          groupId: grp?.id || '',
          groupName: grp?.name || '',
          groupIcon: grp?.icon || '',
          total: s.total,
          blocked: s.blocked,
          savedBytes: s.savedBytes,
          lastSeen: s.lastSeen,
        };
      });

    // Thống kê tổng hợp theo từng nhóm thiết bị
    const groupStatsMap = new Map();
    for (const g of this.config.deviceGroups || []) {
      groupStatsMap.set(g.id, {
        id: g.id,
        name: g.name,
        icon: g.icon || '📁',
        description: g.description || '',
        deviceCount: 0,
        activeCount: 0,
        total: 0,
        blocked: 0,
        savedBytes: 0,
      });
    }
    for (const d of savedDevices) {
      const gs = d.groupId ? groupStatsMap.get(d.groupId) : null;
      if (!gs) continue;
      gs.deviceCount += 1;
    }
    const activeDevicesByGroup = new Map();
    for (const [ip, cs] of this.stats.byClient.entries()) {
      const dev = deviceDiscovery.resolveDeviceForIp(ip, savedDevices);
      const gs = dev?.groupId ? groupStatsMap.get(dev.groupId) : null;
      if (!gs) continue;
      if (!activeDevicesByGroup.has(gs.id)) activeDevicesByGroup.set(gs.id, new Set());
      activeDevicesByGroup.get(gs.id).add(dev.id || dev.mac || dev.ip);
      gs.total += cs.total;
      gs.blocked += cs.blocked;
      gs.savedBytes += cs.savedBytes;
    }
    for (const [gid, set] of activeDevicesByGroup.entries()) {
      const gs = groupStatsMap.get(gid);
      if (gs) gs.activeCount = set.size;
    }
    const groupStats = [...groupStatsMap.values()];

    const nowEpoch = Math.floor(Date.now() / HOUR_MS);
    const hourly = [];
    for (let i = 23; i >= 0; i--) {
      const ep = nowEpoch - i;
      const d = new Date(ep * HOUR_MS);
      const bucket = this.stats.hourlyMap.get(ep);
      hourly.push({
        hour: d.getHours(),
        hourEpoch: ep,
        timestamp: d.toISOString(),
        dateKey: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`,
        isCurrent: i === 0,
        total: bucket ? bucket.total : 0,
        blocked: bucket ? bucket.blocked : 0,
        savedBytes: bucket ? bucket.savedBytes : 0,
      });
    }

    return {
      startedAt: this.stats.startedAt,
      totalQueries: this.stats.totalQueries,
      blockedQueries: this.stats.blockedQueries,
      cachedQueries: this.stats.cachedQueries,
      blockRate:
        this.stats.totalQueries > 0
          ? Number(((this.stats.blockedQueries / this.stats.totalQueries) * 100).toFixed(1))
          : 0,
      bandwidth: {
        totalSavedBytes: this.stats.savedBytesTotal,
        avgSavedBytesPerBlocked:
          this.stats.blockedQueries > 0
            ? Math.round(this.stats.savedBytesTotal / this.stats.blockedQueries)
            : 0,
        byCategory: Object.entries(BANDWIDTH_CATEGORIES).map(([key, meta]) => ({
          key,
          label: meta.label,
          bytesPerQuery: meta.bytesPerQuery,
          count: this.stats.savedByCategory[key].count,
          bytes: this.stats.savedByCategory[key].bytes,
        })),
        methodology:
          'Ước tính từ truy vấn DNS bị chặn theo nhóm nội dung (Video/Rich Media ~750 KB, Quy tắc dịch vụ ~500 KB, Banner/Display ~180 KB, Tracker/Telemetry ~25 KB), có khử trùng lặp retry cùng thiết bị + tên miền trong 30 giây.',
      },
      topBlockedDomains,
      topClients,
      groupStats,
      hourly,
    };
  }
}

export const store = new Store();
