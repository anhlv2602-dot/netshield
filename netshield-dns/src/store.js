import fs from 'node:fs/promises';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';

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
      byDomainBlocked: new Map(),
      byClient: new Map(),
      hourly: new Array(24).fill(0).map(() => ({ total: 0, blocked: 0 })),
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
    const record = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: now.toISOString(),
      ...entry,
    };

    this.logs.unshift(record);
    if (this.logs.length > this.maxLogs) {
      this.logs.length = this.maxLogs;
    }

    this.stats.totalQueries += 1;
    this.stats.hourly[hour].total += 1;
    if (entry.cached) {
      this.stats.cachedQueries += 1;
    }
    if (entry.blocked) {
      this.stats.blockedQueries += 1;
      this.stats.hourly[hour].blocked += 1;
      this.stats.byDomainBlocked.set(
        entry.domain,
        (this.stats.byDomainBlocked.get(entry.domain) || 0) + 1
      );
    }

    const clientStat = this.stats.byClient.get(entry.clientIp) || { total: 0, blocked: 0, lastSeen: record.timestamp };
    clientStat.total += 1;
    if (entry.blocked) clientStat.blocked += 1;
    clientStat.lastSeen = record.timestamp;
    this.stats.byClient.set(entry.clientIp, clientStat);

    this.emit('query', record);
  }

  getSummary() {
    const topBlockedDomains = [...this.stats.byDomainBlocked.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12)
      .map(([domain, count]) => ({ domain, count }));

    const clientNames = new Map();
    for (const rule of this.config.clientRules) {
      if (rule.clientIp && rule.name) {
        clientNames.set(rule.clientIp, rule.name);
      }
    }

    const topClients = [...this.stats.byClient.entries()]
      .sort((a, b) => b[1].total - a[1].total)
      .slice(0, 15)
      .map(([ip, s]) => ({
        ip,
        name: clientNames.get(ip) || '',
        total: s.total,
        blocked: s.blocked,
        lastSeen: s.lastSeen,
      }));

    return {
      startedAt: this.stats.startedAt,
      totalQueries: this.stats.totalQueries,
      blockedQueries: this.stats.blockedQueries,
      cachedQueries: this.stats.cachedQueries,
      blockRate:
        this.stats.totalQueries > 0
          ? Number(((this.stats.blockedQueries / this.stats.totalQueries) * 100).toFixed(1))
          : 0,
      topBlockedDomains,
      topClients,
      hourly: this.stats.hourly,
    };
  }
}

export const store = new Store();
