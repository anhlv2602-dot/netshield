import { normalizeDomain } from './store.js';

// Đuôi tên miền rủi ro cao thường dùng trong các chiến dịch lừa đảo tại Việt Nam
const RISKY_TLDS = new Set([
  'xyz', 'top', 'vip', 'icu', 'click', 'online', 'site', 'shop', 'buzz',
  'club', 'cfd', 'sbs', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'cc', 'live',
  'store', 'fun', 'work', 'pro', 'info', 'lat', 'bond', 'quest', 'rest',
]);

// Đuôi tên miền chính thống tại Việt Nam luôn được miễn trừ khỏi luật Lookalike
const TRUSTED_VN_SUFFIXES = ['gov.vn', 'edu.vn', 'org.vn'];

// Từ khóa mồi nhử lừa đảo phổ biến tại Việt Nam
const LURE_TOKENS = new Set([
  'login', 'signin', 'verify', 'xacthuc', 'capnhat', 'hotro', 'support',
  'tructuyen', 'nhanqua', 'quatang', 'thuong', 'nhanthuong', 'congthongtin',
  'apk', 'download', 'tai', 'taive', 'update', 'baomat', 'security', 'account',
  'taikhoan', 'khachhang', 'cskh', 'dichvu', 'online', 'portal', 'app', 'web',
  'check', 'tra', 'tracuu', 'nopthue', 'hoanthue', 'giahan', 'khoa', 'mokhoa',
  '247', 'vn', 'gov', 'bank', 'banking', 'ebanking', 'smartbanking', 'digibank',
]);

// Nhóm 1: Thương hiệu / cơ quan tên DÀI đặc trưng duy nhất tại VN
// -> Chỉ cần xuất hiện (kể cả biến thể leetspeak 0->o, 1->i, 3->e) ngoài domain chính chủ là chặn trên MỌI đuôi (.com, .net, .xyz...)
const LONG_VN_BRANDS = [
  { key: 'vneid', label: 'VNeID', official: ['vneid.gov.vn', 'gov.vn'] },
  { key: 'dichvucong', label: 'Dịch vụ công', official: ['dichvucong.gov.vn', 'gov.vn'] },
  { key: 'thuedientu', label: 'Thuế điện tử (GDT)', official: ['thuedientu.gdt.gov.vn', 'gdt.gov.vn', 'gov.vn'] },
  { key: 'hoadondientu', label: 'Hóa đơn điện tử (GDT)', official: ['hoadondientu.gdt.gov.vn', 'gdt.gov.vn', 'gov.vn'] },
  { key: 'baohiemxahoi', label: 'Bảo hiểm xã hội', official: ['baohiemxahoi.gov.vn', 'gov.vn'] },
  { key: 'bocongan', label: 'Bộ Công an', official: ['bocongan.gov.vn', 'mps.gov.vn', 'gov.vn'] },
  { key: 'vietcombank', label: 'Vietcombank', official: ['vietcombank.com.vn'] },
  { key: 'techcombank', label: 'Techcombank', official: ['techcombank.com.vn', 'techcombank.com'] },
  { key: 'vietinbank', label: 'VietinBank', official: ['vietinbank.vn'] },
  { key: 'agribank', label: 'Agribank', official: ['agribank.com.vn'] },
  { key: 'sacombank', label: 'Sacombank', official: ['sacombank.com.vn', 'sacombank.vn'] },
  { key: 'mbbank', label: 'MB Bank', official: ['mbbank.com.vn', 'mb.com.vn'] },
  { key: 'vpbank', label: 'VPBank', official: ['vpbank.com.vn'] },
  { key: 'tpbank', label: 'TPBank', official: ['tpbank.vn', 'tpb.vn'] },
  { key: 'hdbank', label: 'HDBank', official: ['hdbank.com.vn'] },
  { key: 'seabank', label: 'SeABank', official: ['seabank.com.vn'] },
  { key: 'namabank', label: 'Nam A Bank', official: ['namabank.com.vn'] },
  { key: 'bacabank', label: 'Bac A Bank', official: ['bacabank.com.vn'] },
  { key: 'eximbank', label: 'Eximbank', official: ['eximbank.com.vn'] },
  { key: 'zalopay', label: 'ZaloPay', official: ['zalopay.vn'] },
  { key: 'meinvoice', label: 'MISA meInvoice', official: ['meinvoice.vn', 'misa.vn', 'misa.com.vn'] },
];

// Nhóm 2: Thương hiệu tên NGẮN (<= 4-6 ký tự dễ trùng từ tiếng Anh)
// -> BẮT BUỘC khớp nguyên token (tách theo '.' và '-') VÀ đi kèm dấu hiệu mồi nhử hoặc TLD rủi ro
const SHORT_VN_BRANDS = [
  { key: 'gdt', label: 'Tổng cục Thuế (GDT)', official: ['gdt.gov.vn', 'gov.vn'] },
  { key: 'bhxh', label: 'Bảo hiểm xã hội', official: ['baohiemxahoi.gov.vn', 'gov.vn'] },
  { key: 'acb', label: 'ACB Bank', official: ['acb.com.vn'] },
  { key: 'bidv', label: 'BIDV', official: ['bidv.com.vn'] },
  { key: 'vib', label: 'VIB Bank', official: ['vib.com.vn'] },
  { key: 'shb', label: 'SHB Bank', official: ['shb.com.vn'] },
  { key: 'ocb', label: 'OCB Bank', official: ['ocb.com.vn'] },
  { key: 'msb', label: 'MSB Bank', official: ['msb.com.vn'] },
  { key: 'momo', label: 'MoMo', official: ['momo.vn'] },
  { key: 'vnpay', label: 'VNPAY', official: ['vnpay.vn', 'vnpayment.vn', 'vnpayinvoice.vn'] },
  { key: 'napas', label: 'NAPAS', official: ['napas.com.vn'] },
  { key: 'misa', label: 'MISA', official: ['misa.vn', 'misa.com.vn', 'meinvoice.vn', 'amis.vn'] },
  { key: 'bkav', label: 'Bkav', official: ['bkav.com.vn', 'bkav.vn', 'bkavca.vn', 'bkav-ca.vn'] },
  { key: 'vnpt', label: 'VNPT', official: ['vnpt.vn', 'vnpt.com.vn', 'vnpt-invoice.com.vn', 'vnpt-ca.vn'] },
  { key: 'viettel', label: 'Viettel', official: ['viettel.vn', 'viettel.com.vn', 'viettel-ca.vn', 'sinvoice.vn'] },
  { key: 'sapo', label: 'Sapo', official: ['sapo.vn'] },
  { key: 'kiotviet', label: 'KiotViet', official: ['kiotviet.vn'] },
  { key: 'shopee', label: 'Shopee', official: ['shopee.vn', 'shopee.com', 'shopeemobile.com', 'shopee.io'] },
];

const SAFE_DGA_SUFFIXES = [
  'gov.vn', 'edu.vn', 'org.vn', 'com.vn', 'vn',
  'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'usercontent.goog',
  'apple.com', 'icloud.com', 'aaplimg.com', 'apple-dns.net', 'akadns.net', 'akamaiedge.net',
  'cloudfront.net', 'amazonaws.com', 'azureedge.net', 'fastly.net', 'cloudflare.com',
  'facebook.com', 'fbcdn.net', 'microsoft.com', 'windows.com', 'live.com', 'office.com',
  'ntp.org', 'in-addr.arpa', 'ip6.arpa', 'local', 'lan',
];

function matchesAnySuffix(domain, suffixes) {
  for (const s of suffixes) {
    if (domain === s || domain.endsWith(`.${s}`)) return true;
  }
  return false;
}

function normalizeLeetspeak(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'i')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's');
}

function getDomainTokens(domain) {
  // Bỏ TLD cuối cùng khi tách token để tránh khớp nhầm TLD
  const labels = domain.split('.');
  const bodyLabels = labels.length > 1 ? labels.slice(0, -1) : labels;
  const tokens = [];
  for (const lbl of bodyLabels) {
    for (const part of lbl.split('-')) {
      if (part) tokens.push(part);
    }
  }
  return { labels, bodyLabels, tokens, tld: labels[labels.length - 1] || '' };
}

/**
 * Kiểm tra tên miền có dấu hiệu giả mạo thương hiệu / cơ quan Nhà nước / ngân hàng Việt Nam hay không.
 * Trả về { suspicious: boolean, brand?: string, reason?: string, severity?: 'critical' }
 */
export function checkVnImpersonation(rawDomain, whitelistSet = null) {
  const domain = normalizeDomain(rawDomain);
  if (!domain || !domain.includes('.')) return { suspicious: false };

  // 1. Miễn trừ tuyệt đối đuôi chính thống VN & whitelist
  if (matchesAnySuffix(domain, TRUSTED_VN_SUFFIXES)) return { suspicious: false };
  if (whitelistSet && whitelistSet.size > 0) {
    const parts = domain.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      if (whitelistSet.has(parts.slice(i).join('.'))) return { suspicious: false };
    }
  }

  const { labels, bodyLabels, tokens, tld } = getDomainTokens(domain);
  const bodyJoined = bodyLabels.join('.');
  const leetBody = normalizeLeetspeak(bodyJoined);
  const hasPunycode = labels.some((l) => l.startsWith('xn--'));
  const isRiskyTld = RISKY_TLDS.has(tld);
  const hasLureToken = tokens.some((t) => LURE_TOKENS.has(t));
  const hasFakeGovPattern = /(^|[.-])(gov-vn|com-vn|govvn|chinhphu-vn)([.-]|$)/.test(bodyJoined);

  // 2. Nhóm thương hiệu dài đặc trưng VN (khớp cả leetspeak trên MỌI TLD nếu không phải domain chính chủ)
  for (const brand of LONG_VN_BRANDS) {
    if (matchesAnySuffix(domain, brand.official)) continue;
    if (bodyJoined.includes(brand.key) || leetBody.includes(brand.key)) {
      return {
        suspicious: true,
        brand: brand.label,
        severity: 'critical',
        reason: `Giả mạo thương hiệu VN (${brand.label})`,
      };
    }
  }

  // 3. Nhóm thương hiệu ngắn (bắt buộc khớp nguyên token + có dấu hiệu mồi nhử / TLD rủi ro / giả gov-vn / punycode)
  for (const brand of SHORT_VN_BRANDS) {
    if (matchesAnySuffix(domain, brand.official)) continue;
    const exactTokenHit = tokens.includes(brand.key);
    if (!exactTokenHit) continue;

    if (isRiskyTld || hasLureToken || hasFakeGovPattern || hasPunycode) {
      return {
        suspicious: true,
        brand: brand.label,
        severity: 'critical',
        reason: `Giả mạo thương hiệu VN (${brand.label})`,
      };
    }
  }

  // 4. Giả mạo cấu trúc gov-vn.* không thuộc gov.vn
  if (hasFakeGovPattern) {
    return {
      suspicious: true,
      brand: 'Cơ quan Nhà nước VN',
      severity: 'critical',
      reason: 'Giả mạo tên miền cơ quan Nhà nước (gov-vn)',
    };
  }

  return { suspicious: false };
}

/**
 * Tính Shannon Entropy (bit/ký tự) của chuỗi.
 */
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Nhận diện tên miền có dấu hiệu sinh tự động bởi mã độc (DGA - Domain Generation Algorithm).
 * Loại trừ: single-label (Chrome startup probe), PTR, DKIM, domain CDN/hợp lệ, nhãn quá ngắn.
 */
export function isDgaLikeDomain(rawDomain) {
  const domain = normalizeDomain(rawDomain);
  if (!domain || !domain.includes('.')) return false; // Loại trừ Chrome single-label probe
  if (domain.includes('._domainkey.') || matchesAnySuffix(domain, SAFE_DGA_SUFFIXES)) {
    return false;
  }

  const labels = domain.split('.');
  if (labels.length < 2) return false;
  const sld = labels[labels.length - 2];

  // Bỏ qua nhãn ngắn, nhãn chứa nhiều dấu gạch ngang (thường là tên bài viết/slug), hoặc punycode
  if (!sld || sld.length < 13 || sld.length > 50 || sld.startsWith('xn--') || sld.includes('-')) {
    return false;
  }
  if (!/^[a-z0-9]+$/.test(sld)) return false;

  const entropy = shannonEntropy(sld);
  const vowels = (sld.match(/[aeiouy]/g) || []).length;
  const digits = (sld.match(/[0-9]/g) || []).length;
  const vowelRatio = vowels / sld.length;
  const digitRatio = digits / sld.length;
  const maxConsonantRun = Math.max(0, ...(sld.match(/[bcdfghjklmnpqrstvwxz]+/g) || ['']).map((s) => s.length));

  // DGA điển hình: entropy cao (>= 3.65) + thiếu nguyên âm hoặc chuỗi phụ âm dài / trộn số dày
  if (entropy >= 3.65 && (vowelRatio < 0.22 || maxConsonantRun >= 6 || digitRatio >= 0.3)) {
    return true;
  }
  if (entropy >= 3.95 && sld.length >= 16) {
    return true;
  }
  return false;
}

/**
 * Theo dõi hành vi C2 Beaconing (gọi lặp lại theo chu kỳ đều đặn bất thường)
 * với giới hạn cứng LRU (maxEntries = 2000) để không rò rỉ RAM khi chạy 24/7.
 */
export class BeaconingTracker {
  constructor({
    maxEntries = 2000,
    windowMs = 30 * 60 * 1000,
    minHits = 8,
    minIntervalMs = 10_000,
    maxCv = 0.12,
  } = {}) {
    this.maxEntries = maxEntries;
    this.windowMs = windowMs;
    this.minHits = minHits;
    this.minIntervalMs = minIntervalMs;
    this.maxCv = maxCv;
    this.map = new Map(); // `${clientIp}|${domain}` -> { times: number[], lastAlertAt: number }
  }

  record(clientIp, rawDomain, { nowMs = Date.now(), deviceGroup = '', whitelistSet = null } = {}) {
    if (!clientIp || !rawDomain) return null;
    // Bỏ qua IoT / Camera / Router vốn có nhịp heartbeat cố định
    if (deviceGroup === 'iot' || deviceGroup === 'camera') return null;

    const domain = normalizeDomain(rawDomain);
    if (!domain || !domain.includes('.') || matchesAnySuffix(domain, SAFE_DGA_SUFFIXES)) {
      return null;
    }
    if (whitelistSet && whitelistSet.size > 0) {
      const parts = domain.split('.');
      for (let i = 0; i < parts.length - 1; i++) {
        if (whitelistSet.has(parts.slice(i).join('.'))) return null;
      }
    }

    const key = `${clientIp}|${domain}`;
    let entry = this.map.get(key);
    if (entry) {
      // Refresh LRU position
      this.map.delete(key);
      this.map.set(key, entry);
    } else {
      if (this.map.size >= this.maxEntries) {
        const oldestKey = this.map.keys().next().value;
        if (oldestKey) this.map.delete(oldestKey);
      }
      entry = { times: [], lastAlertAt: 0 };
      this.map.set(key, entry);
    }

    // Lọc các mốc nằm trong cửa sổ windowMs & tránh gom các truy vấn A/AAAA song song cách nhau < 2s
    const cutoff = nowMs - this.windowMs;
    entry.times = entry.times.filter((t) => t >= cutoff);
    const lastTs = entry.times[entry.times.length - 1] || 0;
    if (nowMs - lastTs < 2000) return null;

    entry.times.push(nowMs);
    if (entry.times.length > 16) {
      entry.times.shift();
    }

    if (entry.times.length < this.minHits) return null;
    if (nowMs - entry.lastAlertAt < this.windowMs) return null;

    const intervals = [];
    for (let i = 1; i < entry.times.length; i++) {
      intervals.push(entry.times[i] - entry.times[i - 1]);
    }
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (mean < this.minIntervalMs) return null;

    const variance = intervals.reduce((acc, v) => acc + (v - mean) ** 2, 0) / intervals.length;
    const stddev = Math.sqrt(variance);
    const cv = stddev / mean;

    if (cv <= this.maxCv) {
      entry.lastAlertAt = nowMs;
      return {
        clientIp,
        domain,
        hits: entry.times.length,
        avgIntervalSec: Number((mean / 1000).toFixed(1)),
        cv: Number(cv.toFixed(3)),
      };
    }

    return null;
  }

  cleanup(nowMs = Date.now()) {
    const cutoff = nowMs - this.windowMs;
    for (const [key, entry] of this.map) {
      const last = entry.times[entry.times.length - 1] || 0;
      if (last < cutoff) this.map.delete(key);
    }
  }
}

/**
 * Theo dõi bùng phát truy vấn DGA theo từng thiết bị LAN (cửa sổ 5 phút, giới hạn LRU).
 */
export class DgaTracker {
  constructor({ windowMs = 5 * 60 * 1000, threshold = 5, maxClients = 500 } = {}) {
    this.windowMs = windowMs;
    this.threshold = threshold;
    this.maxClients = maxClients;
    this.map = new Map(); // clientIp -> { windowStart, domains: Set<string>, alerted: boolean }
  }

  record(clientIp, rawDomain, { nowMs = Date.now() } = {}) {
    if (!clientIp || !isDgaLikeDomain(rawDomain)) return null;
    const domain = normalizeDomain(rawDomain);

    let entry = this.map.get(clientIp);
    if (!entry || nowMs - entry.windowStart > this.windowMs) {
      if (!entry && this.map.size >= this.maxClients) {
        const oldest = this.map.keys().next().value;
        if (oldest) this.map.delete(oldest);
      }
      entry = { windowStart: nowMs, domains: new Set(), alerted: false };
      this.map.set(clientIp, entry);
    }

    entry.domains.add(domain);
    if (!entry.alerted && entry.domains.size >= this.threshold) {
      entry.alerted = true;
      return {
        clientIp,
        count: entry.domains.size,
        samples: [...entry.domains].slice(0, 5),
      };
    }
    return null;
  }
}
