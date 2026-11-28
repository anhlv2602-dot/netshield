import fs from 'node:fs/promises';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import { deviceDiscovery, normalizeMac } from './discovery.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(__dirname, '..');
export const DATA_DIR = path.join(ROOT_DIR, 'data');
export const CACHE_DIR = path.join(DATA_DIR, 'blocklists-cache');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');

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

export const DEFAULT_CONFIG = {
  protectionEnabled: true,
  upstreamDns: ['1.1.1.1', '8.8.8.8'],
  blockResponseMode: 'zero', // 'zero' (0.0.0.0 / ::) hoặc 'nxdomain'
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
      hourly: new Array(24).fill(0).map(() => ({ total: 0, blocked: 0, savedBytes: 0, dateKey: null })),
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
      };
    } catch {
      await this.save();
    }
    return this.config;
  }

  async save() {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const tmpPath = `${CONFIG_PATH}.tmp`;
    await fs.writeFile(tmpPath, JSON.stringify(this.config, null, 2), 'utf8');
    await fs.rename(tmpPath, CONFIG_PATH);
  }

  recordQuery(entry) {
    const now = new Date();
    const hour = now.getHours();
    const dateKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
    const saved = entry.blocked ? estimateSavedBandwidth(entry.domain, entry.reason) : null;
    const record = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: now.toISOString(),
      ...entry,
      ...(saved ? { savedBytes: saved.bytes, category: saved.category } : {}),
    };

    this.logs.unshift(record);
    if (this.logs.length > this.maxLogs) {
      this.logs.length = this.maxLogs;
    }

    const hourBucket = this.stats.hourly[hour];
    if (hourBucket.dateKey !== dateKey) {
      hourBucket.total = 0;
      hourBucket.blocked = 0;
      hourBucket.savedBytes = 0;
      hourBucket.dateKey = dateKey;
    }

    this.stats.totalQueries += 1;
    hourBucket.total += 1;
    if (entry.cached) {
      this.stats.cachedQueries += 1;
    }
    if (entry.blocked && saved) {
      this.stats.blockedQueries += 1;
      this.stats.savedBytesTotal += saved.bytes;
      hourBucket.blocked += 1;
      hourBucket.savedBytes += saved.bytes;

      const catStat = this.stats.savedByCategory[saved.category];
      if (catStat) {
        catStat.count += 1;
        catStat.bytes += saved.bytes;
      }

      const domStat = this.stats.byDomainBlocked.get(entry.domain) || {
        count: 0,
        savedBytes: 0,
        category: saved.category,
      };
      domStat.count += 1;
      domStat.savedBytes += saved.bytes;
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
      clientStat.savedBytes += saved.bytes;
    }
    clientStat.lastSeen = record.timestamp;
    this.stats.byClient.set(entry.clientIp, clientStat);

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
          'Ước tính từ số truy vấn DNS bị chặn theo nhóm nội dung (Video/Rich Media ~750 KB, Quy tắc dịch vụ ~500 KB, Banner/Display ~180 KB, Tracker/Telemetry ~25 KB).',
      },
      topBlockedDomains,
      topClients,
      groupStats,
      hourly: this.stats.hourly.map(({ total, blocked, savedBytes }) => ({ total, blocked, savedBytes })),
    };
  }
}

export const store = new Store();
