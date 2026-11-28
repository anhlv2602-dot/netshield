import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import dgram from 'node:dgram';
import os from 'node:os';
import dnsPacket from 'dns-packet';

const execFileAsync = promisify(execFile);

const EXEC_TIMEOUT_MS = 1200;
const PTR_TIMEOUT_MS = 400;
const HOSTNAME_CACHE_TTL_MS = 10 * 60 * 1000;
const ARP_REFRESH_MS = 60 * 1000;
const PERIODIC_SCAN_MS = 10 * 60 * 1000;
const DEBOUNCE_SCAN_MS = 2500;
const MAX_TRACKED_IPS = 250;
const MAX_DOMAINS_PER_IP = 80;
const PTR_CONCURRENCY = 6;

/**
 * Bảng OUI tinh gọn (offline, 0ms, không gửi dữ liệu ra Internet)
 * Định dạng key: 'XX:XX:XX' (in hoa, đủ 2 ký tự mỗi octet)
 * Giá trị: { vendor: string, hintGroup?: 'camera'|'computer'|'mobile'|'iot'|'network' }
 */
const OUI_TABLE = {
  // Apple
  '00:1C:B3': { vendor: 'Apple' },
  '04:0C:CE': { vendor: 'Apple' },
  '0C:4D:E9': { vendor: 'Apple' },
  '14:10:9F': { vendor: 'Apple' },
  '18:E7:F4': { vendor: 'Apple' },
  '20:C9:D0': { vendor: 'Apple' },
  '24:A0:74': { vendor: 'Apple' },
  '28:CF:E9': { vendor: 'Apple' },
  '34:36:3B': { vendor: 'Apple' },
  '38:C9:86': { vendor: 'Apple' },
  '3C:07:54': { vendor: 'Apple' },
  '40:6C:8F': { vendor: 'Apple' },
  '44:D8:84': { vendor: 'Apple' },
  '48:D7:05': { vendor: 'Apple' },
  '50:EA:D6': { vendor: 'Apple' },
  '54:26:96': { vendor: 'Apple' },
  '5C:F9:38': { vendor: 'Apple' },
  '60:03:08': { vendor: 'Apple' },
  '64:B9:E8': { vendor: 'Apple' },
  '68:5B:35': { vendor: 'Apple' },
  '6C:40:08': { vendor: 'Apple' },
  '70:56:81': { vendor: 'Apple' },
  '78:31:C1': { vendor: 'Apple' },
  '7C:D1:C3': { vendor: 'Apple' },
  '80:E6:50': { vendor: 'Apple' },
  '84:38:35': { vendor: 'Apple' },
  '88:66:5A': { vendor: 'Apple' },
  '8C:85:90': { vendor: 'Apple' },
  '90:72:40': { vendor: 'Apple' },
  '98:01:A7': { vendor: 'Apple' },
  '98:60:CA': { vendor: 'Apple' },
  '9C:20:7B': { vendor: 'Apple' },
  'A4:5E:60': { vendor: 'Apple' },
  'A8:66:7F': { vendor: 'Apple' },
  'AC:BC:32': { vendor: 'Apple' },
  'B0:34:95': { vendor: 'Apple' },
  'B8:E8:56': { vendor: 'Apple' },
  'BC:52:B7': { vendor: 'Apple' },
  'C0:CE:CD': { vendor: 'Apple' },
  'C4:2C:03': { vendor: 'Apple' },
  'C8:2A:14': { vendor: 'Apple' },
  'CC:08:E0': { vendor: 'Apple' },
  'D0:03:4B': { vendor: 'Apple' },
  'D4:9A:20': { vendor: 'Apple' },
  'D8:30:62': { vendor: 'Apple' },
  'DC:2B:2A': { vendor: 'Apple' },
  'E0:AC:CB': { vendor: 'Apple' },
  'E4:CE:8F': { vendor: 'Apple' },
  'E8:80:2E': { vendor: 'Apple' },
  'EC:35:86': { vendor: 'Apple' },
  'F0:18:98': { vendor: 'Apple' },
  'F4:5C:89': { vendor: 'Apple' },
  'F8:1E:DF': { vendor: 'Apple' },
  'FC:25:3F': { vendor: 'Apple' },

  // Samsung
  '00:12:47': { vendor: 'Samsung', hintGroup: 'mobile' },
  '00:16:32': { vendor: 'Samsung', hintGroup: 'mobile' },
  '08:D4:2B': { vendor: 'Samsung', hintGroup: 'mobile' },
  '10:1D:C0': { vendor: 'Samsung', hintGroup: 'mobile' },
  '18:3A:2D': { vendor: 'Samsung', hintGroup: 'mobile' },
  '24:4B:81': { vendor: 'Samsung', hintGroup: 'mobile' },
  '34:23:BA': { vendor: 'Samsung', hintGroup: 'mobile' },
  '38:AA:3C': { vendor: 'Samsung', hintGroup: 'mobile' },
  '40:0E:85': { vendor: 'Samsung', hintGroup: 'mobile' },
  '50:CC:F8': { vendor: 'Samsung', hintGroup: 'mobile' },
  '5C:0A:5B': { vendor: 'Samsung', hintGroup: 'mobile' },
  '64:B3:10': { vendor: 'Samsung', hintGroup: 'mobile' },
  '78:47:1D': { vendor: 'Samsung', hintGroup: 'mobile' },
  '84:25:DB': { vendor: 'Samsung', hintGroup: 'mobile' },
  '94:35:0A': { vendor: 'Samsung', hintGroup: 'mobile' },
  'A0:82:1F': { vendor: 'Samsung', hintGroup: 'mobile' },
  'B4:79:A7': { vendor: 'Samsung', hintGroup: 'mobile' },
  'BC:14:85': { vendor: 'Samsung', hintGroup: 'mobile' },
  'C4:73:1E': { vendor: 'Samsung', hintGroup: 'mobile' },
  'CC:07:AB': { vendor: 'Samsung', hintGroup: 'mobile' },
  'D0:22:BE': { vendor: 'Samsung', hintGroup: 'mobile' },
  'E4:7C:F9': { vendor: 'Samsung', hintGroup: 'mobile' },
  'F0:25:B7': { vendor: 'Samsung', hintGroup: 'mobile' },
  'FC:03:9F': { vendor: 'Samsung' },

  // Xiaomi / Redmi / Mi IoT
  '04:CF:8C': { vendor: 'Xiaomi' },
  '14:F6:5A': { vendor: 'Xiaomi' },
  '28:6C:07': { vendor: 'Xiaomi' },
  '34:CE:00': { vendor: 'Xiaomi' },
  '50:64:2B': { vendor: 'Xiaomi' },
  '58:44:98': { vendor: 'Xiaomi' },
  '64:09:80': { vendor: 'Xiaomi' },
  '64:B4:73': { vendor: 'Xiaomi' },
  '74:23:44': { vendor: 'Xiaomi' },
  '78:11:DC': { vendor: 'Xiaomi' },
  '7C:1D:D9': { vendor: 'Xiaomi' },
  '8C:BE:BE': { vendor: 'Xiaomi' },
  '98:FA:E3': { vendor: 'Xiaomi' },
  'B0:E2:35': { vendor: 'Xiaomi' },
  'C4:0B:CB': { vendor: 'Xiaomi' },
  'D4:97:0B': { vendor: 'Xiaomi' },
  'F0:B4:29': { vendor: 'Xiaomi' },
  'F8:A4:5F': { vendor: 'Xiaomi' },

  // Oppo / Realme / OnePlus / Vivo / Huawei
  '1C:77:F6': { vendor: 'OPPO', hintGroup: 'mobile' },
  '2C:5B:B8': { vendor: 'OPPO', hintGroup: 'mobile' },
  '58:C6:F0': { vendor: 'OPPO', hintGroup: 'mobile' },
  'A4:3D:78': { vendor: 'OPPO', hintGroup: 'mobile' },
  'BC:3A:EA': { vendor: 'OPPO', hintGroup: 'mobile' },
  'C0:9F:05': { vendor: 'OPPO', hintGroup: 'mobile' },
  '38:A4:ED': { vendor: 'Xiaomi / Redmi', hintGroup: 'mobile' },
  '48:43:7C': { vendor: 'Huawei', hintGroup: 'mobile' },
  '70:8C:B6': { vendor: 'Huawei' },
  '88:CF:98': { vendor: 'Huawei' },
  'CC:A2:23': { vendor: 'Huawei' },
  'E0:24:7F': { vendor: 'Huawei' },
  '10:F6:81': { vendor: 'Vivo', hintGroup: 'mobile' },
  '6C:5C:14': { vendor: 'Vivo', hintGroup: 'mobile' },

  // Camera: Hikvision / Ezviz / Dahua / Imou / KBVision / Yoosee / Reolink
  '00:12:12': { vendor: 'Hikvision', hintGroup: 'camera' },
  '18:68:CB': { vendor: 'Hikvision', hintGroup: 'camera' },
  '28:57:BE': { vendor: 'Hikvision', hintGroup: 'camera' },
  '44:19:B6': { vendor: 'Hikvision', hintGroup: 'camera' },
  '4C:BD:8F': { vendor: 'Hikvision', hintGroup: 'camera' },
  '54:C4:15': { vendor: 'Hikvision', hintGroup: 'camera' },
  '64:DB:8B': { vendor: 'Hikvision', hintGroup: 'camera' },
  '80:7C:62': { vendor: 'Hikvision', hintGroup: 'camera' },
  'A4:14:37': { vendor: 'Hikvision', hintGroup: 'camera' },
  'BC:AD:28': { vendor: 'Hikvision', hintGroup: 'camera' },
  'C0:56:E3': { vendor: 'Hikvision', hintGroup: 'camera' },
  'C4:2F:90': { vendor: 'Hikvision', hintGroup: 'camera' },
  'E0:CA:3C': { vendor: 'Ezviz / Hikvision', hintGroup: 'camera' },
  '68:6D:BC': { vendor: 'Ezviz', hintGroup: 'camera' },
  '14:A7:8B': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  '38:AF:29': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  '3C:EF:8C': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  '4C:11:BF': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  '54:46:17': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  '6C:1C:71': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  '74:C9:29': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  '90:02:A9': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  'A0:BD:1D': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  'B4:4C:3B': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  'BC:32:5F': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  'E0:50:8B': { vendor: 'Dahua / Imou', hintGroup: 'camera' },
  'EC:71:DB': { vendor: 'Reolink', hintGroup: 'camera' },

  // IoT: Espressif (Tuya / SmartHome), Tuya, Shelly, Sonoff, LG, Sony, Máy in
  '18:FE:34': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '24:0A:C4': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '24:6F:28': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '30:AE:A4': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '3C:71:BF': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '40:F5:20': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '48:3F:DA': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '50:02:91': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '5C:CF:7F': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '60:01:94': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '68:C6:3A': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '7C:9E:BD': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '84:0D:8E': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '84:CC:A8': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '94:B9:7E': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  'A4:CF:12': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  'B4:E6:2D': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  'BC:DD:C2': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  'C4:4F:33': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  'CC:50:E3': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  'DC:4F:22': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  'EC:FA:BC': { vendor: 'Espressif (IoT)', hintGroup: 'iot' },
  '10:D5:61': { vendor: 'Tuya Smart', hintGroup: 'iot' },
  'D8:F1:5B': { vendor: 'Tuya / Espressif', hintGroup: 'iot' },
  '00:E0:91': { vendor: 'LG Electronics', hintGroup: 'iot' },
  '14:C9:13': { vendor: 'LG Smart TV', hintGroup: 'iot' },
  '38:8C:50': { vendor: 'LG Electronics', hintGroup: 'iot' },
  '64:99:5D': { vendor: 'LG Electronics', hintGroup: 'iot' },
  'A8:23:FE': { vendor: 'LG Electronics', hintGroup: 'iot' },
  '00:1D:BA': { vendor: 'Sony', hintGroup: 'iot' },
  '30:F9:ED': { vendor: 'Sony', hintGroup: 'iot' },
  'AC:9B:0A': { vendor: 'Sony', hintGroup: 'iot' },
  '00:1E:8F': { vendor: 'Canon Printer', hintGroup: 'iot' },
  '18:0C:AC': { vendor: 'Canon Printer', hintGroup: 'iot' },
  '00:26:AB': { vendor: 'Epson Printer', hintGroup: 'iot' },
  '44:D2:44': { vendor: 'Epson Printer', hintGroup: 'iot' },
  'B8:27:EB': { vendor: 'Raspberry Pi', hintGroup: 'iot' },
  'DC:A6:32': { vendor: 'Raspberry Pi', hintGroup: 'iot' },
  'E4:5F:01': { vendor: 'Raspberry Pi', hintGroup: 'iot' },

  // Router / Mesh / Network (VNPT, Viettel, FPT, TP-Link, Asus, Ubiquiti, MikroTik)
  '24:0B:2A': { vendor: 'VNPT Technology', hintGroup: 'network' },
  'A4:F4:C2': { vendor: 'VNPT Technology', hintGroup: 'network' },
  '00:1D:0F': { vendor: 'TP-Link', hintGroup: 'network' },
  '14:CC:20': { vendor: 'TP-Link', hintGroup: 'network' },
  '50:C7:BF': { vendor: 'TP-Link', hintGroup: 'network' },
  '54:AF:97': { vendor: 'TP-Link', hintGroup: 'network' },
  '60:32:B1': { vendor: 'TP-Link', hintGroup: 'network' },
  '74:DA:88': { vendor: 'TP-Link', hintGroup: 'network' },
  '98:DA:C4': { vendor: 'TP-Link', hintGroup: 'network' },
  'B0:BE:76': { vendor: 'TP-Link', hintGroup: 'network' },
  'C0:25:E9': { vendor: 'TP-Link', hintGroup: 'network' },
  'D8:07:B6': { vendor: 'TP-Link', hintGroup: 'network' },
  'E8:94:F6': { vendor: 'TP-Link', hintGroup: 'network' },
  'F4:F2:6D': { vendor: 'TP-Link', hintGroup: 'network' },
  '04:D4:C4': { vendor: 'ASUS', hintGroup: 'network' },
  '1C:87:2C': { vendor: 'ASUS', hintGroup: 'network' },
  '2C:FD:A1': { vendor: 'ASUS' },
  '38:D5:47': { vendor: 'ASUS', hintGroup: 'network' },
  '50:46:5D': { vendor: 'ASUS' },
  '74:D0:2B': { vendor: 'ASUS' },
  '00:15:6D': { vendor: 'Ubiquiti', hintGroup: 'network' },
  '18:E8:29': { vendor: 'Ubiquiti', hintGroup: 'network' },
  '74:83:C2': { vendor: 'Ubiquiti', hintGroup: 'network' },
  'B4:FB:E4': { vendor: 'Ubiquiti', hintGroup: 'network' },
  '4C:5E:0C': { vendor: 'MikroTik', hintGroup: 'network' },
  '64:D1:54': { vendor: 'MikroTik', hintGroup: 'network' },
  'D4:CA:6D': { vendor: 'MikroTik', hintGroup: 'network' },
  '00:19:C6': { vendor: 'ZTE', hintGroup: 'network' },
  '34:4B:50': { vendor: 'ZTE', hintGroup: 'network' },
  'C8:64:C7': { vendor: 'ZTE', hintGroup: 'network' },
  '48:57:02': { vendor: 'Huawei Router', hintGroup: 'network' },
  'D4:6A:A8': { vendor: 'Huawei Router', hintGroup: 'network' },

  // PC / Laptop (Intel, Realtek, Dell, HP, Lenovo)
  '00:14:22': { vendor: 'Dell', hintGroup: 'computer' },
  '18:03:73': { vendor: 'Dell', hintGroup: 'computer' },
  '34:17:EB': { vendor: 'Dell', hintGroup: 'computer' },
  '54:BF:64': { vendor: 'Dell', hintGroup: 'computer' },
  'B8:2A:72': { vendor: 'Dell', hintGroup: 'computer' },
  '00:21:5A': { vendor: 'HP', hintGroup: 'computer' },
  '3C:D9:2B': { vendor: 'HP', hintGroup: 'computer' },
  '6C:3B:E5': { vendor: 'HP', hintGroup: 'computer' },
  '94:57:A5': { vendor: 'HP', hintGroup: 'computer' },
  '00:21:86': { vendor: 'Lenovo', hintGroup: 'computer' },
  '54:EE:75': { vendor: 'Lenovo', hintGroup: 'computer' },
  '8C:16:45': { vendor: 'Lenovo', hintGroup: 'computer' },
  'C8:5B:76': { vendor: 'Lenovo', hintGroup: 'computer' },
  '00:1B:21': { vendor: 'Intel PC', hintGroup: 'computer' },
  '34:13:E8': { vendor: 'Intel PC', hintGroup: 'computer' },
  '48:51:B7': { vendor: 'Intel PC', hintGroup: 'computer' },
  '60:57:18': { vendor: 'Intel PC', hintGroup: 'computer' },
  '80:86:F2': { vendor: 'Intel PC', hintGroup: 'computer' },
  'A4:4C:C8': { vendor: 'Dell / Intel', hintGroup: 'computer' },
  '00:E0:4C': { vendor: 'Realtek PC', hintGroup: 'computer' },
  '52:54:00': { vendor: 'Máy ảo (QEMU/VM)', hintGroup: 'computer' },
  '00:0C:29': { vendor: 'VMware', hintGroup: 'computer' },
};

// Mẫu domain hành vi (Behavioral DNS Fingerprinting)
const CAMERA_DOMAIN_RE =
  /(^|\.)(imoulife\.com|easy4ipcloud\.com|easy4ip\.com|ezvizlife\.com|ezvizru\.com|ezviz\.com|hik-connect\.com|hikvision\.com|dahuasecurity\.com|lechange\.cn|ycc365|v380|reolink\.com|xmeye\.net|ipc365|cloudlinks\.cn)$/i;
const GENERAL_SOCIAL_WEB_RE =
  /(^|\.)(facebook\.com|fbcdn\.net|tiktok\.com|tiktokv\.com|youtube\.com|instagram\.com|zalo\.me|shopee\.vn|lazada\.vn|vnexpress\.net|dantri\.com\.vn|reddit\.com|x\.com|twitter\.com)$/i;
const APPLE_DOMAIN_RE = /(^|\.)(apple\.com|icloud\.com|mzstatic\.com|aaplimg\.com|apple-dns\.net|icloud-content\.com)$/i;
const MAC_SPECIFIC_RE = /(^|\.)(swscan\.apple\.com|swcdn\.apple\.com|mesu\.apple\.com|gdmf\.apple\.com|github\.com|githubusercontent\.com|npmjs\.org|homebrew\.sh|formulae\.brew\.sh|vscode-cdn\.net)$/i;
const MOBILE_APP_RE = /(^|\.)(appsflyer\.com|adjust\.com|branch\.io|grab\.com|momo\.vn|zaloapp\.com|push\.apple\.com|mtalk\.google\.com|connectivitycheck\.gstatic\.com|android\.googleapis\.com)$/i;
const WINDOWS_DOMAIN_RE = /(^|\.)(windowsupdate\.com|msftconnecttest\.com|msftncsi\.com|update\.microsoft\.com|telemetry\.microsoft\.com|windows\.com|office\.com|live\.com)$/i;
const ANDROID_DOMAIN_RE = /(^|\.)(connectivitycheck\.gstatic\.com|android\.googleapis\.com|mtalk\.google\.com|miui\.com|xiaomi\.net|samsungcloud\.com|heytapmobi\.com|heytapdl\.com|oppomobile\.com)$/i;
const IOT_DOMAIN_RE = /(^|\.)(tuyaus\.com|tuyaeu\.com|tuyacn\.com|tuya\.com|smartlife|lgsmartad\.com|lgtvsdp\.com|samsungcloudsolution\.com|samsungqbe\.com|miot-spec\.org|espressif\.com|shelly\.cloud|sonoff)$/i;

export function normalizeMac(raw) {
  if (!raw || typeof raw !== 'string') return '';
  const cleaned = raw.trim().toLowerCase();
  if (!cleaned || cleaned === '(incomplete)' || cleaned === 'ff:ff:ff:ff:ff:ff') return '';
  const parts = cleaned.split(':');
  if (parts.length !== 6) return '';
  const normalized = [];
  for (const p of parts) {
    if (!/^[0-9a-f]{1,2}$/.test(p)) return '';
    normalized.push(p.padStart(2, '0').toUpperCase());
  }
  const mac = normalized.join(':');
  if (mac === '00:00:00:00:00:00' || mac === 'FF:FF:FF:FF:FF:FF') return '';
  return mac;
}

export function isPrivateMac(mac) {
  if (!mac || mac.length < 2) return false;
  const firstOctet = parseInt(mac.slice(0, 2), 16);
  if (Number.isNaN(firstOctet)) return false;
  // Bit 1 (0x02) = Locally Administered Address (iOS/Android Private Wi-Fi)
  return (firstOctet & 0x02) !== 0;
}

export function lookupVendor(mac) {
  if (!mac || mac.length < 8) return null;
  if (isPrivateMac(mac)) return null;
  const prefix = mac.slice(0, 8);
  return OUI_TABLE[prefix] || null;
}

function getLocalLanIps() {
  const set = new Set();
  const ifaces = os.networkInterfaces();
  for (const addrs of Object.values(ifaces)) {
    for (const addr of addrs || []) {
      if (addr.family === 'IPv4' && !addr.internal) {
        set.add(addr.address);
      }
    }
  }
  return set;
}

async function getDefaultGateway() {
  try {
    if (process.platform === 'darwin') {
      const { stdout } = await execFileAsync('route', ['-n', 'get', 'default'], { timeout: EXEC_TIMEOUT_MS });
      const m = stdout.match(/gateway:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
      return m ? m[1] : '';
    }
    if (process.platform === 'linux') {
      const { stdout } = await execFileAsync('ip', ['route', 'show', 'default'], { timeout: EXEC_TIMEOUT_MS });
      const m = stdout.match(/default via\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
      return m ? m[1] : '';
    }
  } catch {
    // Bỏ qua nếu không đọc được gateway
  }
  return '';
}

async function readArpTable() {
  const byIp = new Map();
  const macToIps = new Map();
  try {
    const { stdout } = await execFileAsync('arp', ['-an'], { timeout: EXEC_TIMEOUT_MS });
    const lines = stdout.split(/\r?\n/);
    for (const line of lines) {
      // macOS & Linux: ? (192.168.1.83) at 54:46:17:df:e:1 on en1 ifscope [ethernet]
      const m = line.match(/\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+(\S+)/);
      if (!m) continue;
      const ip = m[1];
      const mac = normalizeMac(m[2]);
      const iface = m[3];
      if (!mac) continue;
      byIp.set(ip, { mac, iface });
      if (!macToIps.has(mac)) macToIps.set(mac, new Set());
      macToIps.get(mac).add(ip);
    }
  } catch {
    // Bỏ qua nếu arp lỗi
  }

  // Shared MAC: cùng 1 MAC xuất hiện ở >= 2 IP cùng lúc (Wi-Fi Repeater / Proxy ARP)
  const sharedMacs = new Set();
  for (const [mac, ips] of macToIps.entries()) {
    if (ips.size >= 2) sharedMacs.add(mac);
  }
  return { byIp, sharedMacs };
}

function ipToReverseArpa(ip) {
  const parts = String(ip || '').split('.');
  if (parts.length !== 4 || parts.some((p) => !/^\d+$/.test(p))) return '';
  return `${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`;
}

function queryPtr(ip, targetHost, targetPort, timeoutMs = PTR_TIMEOUT_MS) {
  const arpa = ipToReverseArpa(ip);
  if (!arpa) return Promise.resolve('');

  return new Promise((resolve) => {
    let settled = false;
    let sock;
    let timer;

    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (sock) {
        try {
          sock.close();
        } catch {
          // ignore
        }
      }
      resolve(value || '');
    };

    try {
      sock = dgram.createSocket('udp4');
      const queryBuf = dnsPacket.encode({
        type: 'query',
        id: targetPort === 5353 ? 0 : Math.floor(Math.random() * 65535),
        flags: targetPort === 5353 ? 0 : dnsPacket.RECURSION_DESIRED,
        questions: [{ type: 'PTR', name: arpa }],
      });

      sock.on('error', () => finish(''));
      sock.on('message', (msg) => {
        try {
          const decoded = dnsPacket.decode(msg);
          const ans = (decoded.answers || []).find((a) => a.type === 'PTR' && typeof a.data === 'string');
          if (ans?.data) {
            const clean = ans.data.replace(/\.+$/, '').trim();
            if (clean) return finish(clean);
          }
        } catch {
          // ignore malformed packet
        }
      });

      timer = setTimeout(() => finish(''), timeoutMs);
      sock.send(queryBuf, targetPort, targetHost, (err) => {
        if (err) finish('');
      });
    } catch {
      finish('');
    }
  });
}

async function resolveHostname(ip, gatewayIp, localIps) {
  const tasks = [queryPtr(ip, '224.0.0.251', 5353, PTR_TIMEOUT_MS)];
  if (gatewayIp && gatewayIp !== ip && !localIps.has(gatewayIp)) {
    tasks.push(queryPtr(ip, gatewayIp, 53, PTR_TIMEOUT_MS));
  }
  const results = await Promise.all(tasks);
  for (const name of results) {
    if (name && name.toLowerCase() !== ip.toLowerCase()) {
      return name;
    }
  }
  return '';
}

function inferFromHostname(hostname) {
  if (!hostname) return null;
  const h = hostname.toLowerCase().replace(/\.local$/, '');
  if (/(macbook|imac|mac-mini|macmini|mac-studio|mac-pro|desktop-|laptop-|thinkpad|dell-|hp-|pc-)/i.test(h)) {
    return { groupId: 'computer', label: 'Máy tính', reason: `Hostname: ${hostname}` };
  }
  if (/(iphone|ipad|galaxy|redmi|poco|xiaomi|oppo|vivo|realme|pixel|android)/i.test(h)) {
    return { groupId: 'mobile', label: 'Di động', reason: `Hostname: ${hostname}` };
  }
  if (/(cam|camera|ipc|nvr|dvr|ezviz|imou|hikvision|dahua)/i.test(h)) {
    return { groupId: 'camera', label: 'Camera', reason: `Hostname: ${hostname}` };
  }
  if (/(tv|bravia|webos|tizen|printer|canon|epson|brother|homepod|chromecast|esp-|tuya)/i.test(h)) {
    return { groupId: 'iot', label: 'IoT', reason: `Hostname: ${hostname}` };
  }
  return null;
}

function analyzeDomains(domainSet) {
  if (!domainSet || domainSet.size === 0) return null;

  let cameraHits = 0;
  let socialHits = 0;
  let appleHits = 0;
  let macHits = 0;
  let mobileHits = 0;
  let windowsHits = 0;
  let androidHits = 0;
  let iotHits = 0;

  for (const d of domainSet) {
    if (CAMERA_DOMAIN_RE.test(d)) cameraHits += 1;
    if (GENERAL_SOCIAL_WEB_RE.test(d)) socialHits += 1;
    if (APPLE_DOMAIN_RE.test(d)) appleHits += 1;
    if (MAC_SPECIFIC_RE.test(d)) macHits += 1;
    if (MOBILE_APP_RE.test(d)) mobileHits += 1;
    if (WINDOWS_DOMAIN_RE.test(d)) windowsHits += 1;
    if (ANDROID_DOMAIN_RE.test(d)) androidHits += 1;
    if (IOT_DOMAIN_RE.test(d)) iotHits += 1;
  }

  // Camera: gọi domain hãng camera nhưng KHÔNG duyệt web/mạng xã hội (tránh nhận nhầm điện thoại cài app xem camera)
  if (cameraHits > 0 && socialHits === 0 && appleHits === 0 && windowsHits === 0) {
    return {
      groupId: 'camera',
      nameHint: 'Camera IP',
      confidence: 88,
      reason: 'DNS: domain hãng Camera (không có web/MXH)',
    };
  }

  // IoT chuyên dụng (Tuya / Smart TV) không duyệt web phổ thông
  if (iotHits > 0 && socialHits === 0 && windowsHits === 0 && appleHits === 0) {
    return {
      groupId: 'iot',
      nameHint: 'Thiết bị IoT / Smart TV',
      confidence: 82,
      reason: 'DNS: dịch vụ IoT / Smart TV',
    };
  }

  // Windows PC
  if (windowsHits >= 2 || (windowsHits >= 1 && macHits > 0)) {
    return {
      groupId: 'computer',
      nameHint: 'Máy tính Windows',
      confidence: 84,
      reason: 'DNS: Microsoft / Windows Update',
    };
  }

  // Apple Mac vs Apple Mobile
  if (appleHits > 0) {
    if (macHits > 0) {
      return {
        groupId: 'computer',
        nameHint: 'Máy tính Mac',
        confidence: 82,
        reason: 'DNS: Apple + dịch vụ macOS/Dev',
      };
    }
    if (mobileHits > 0) {
      return {
        groupId: 'mobile',
        nameHint: 'iPhone / iPad',
        confidence: 78,
        reason: 'DNS: Apple / iCloud + ứng dụng di động',
      };
    }
    return {
      groupId: '',
      nameHint: 'Thiết bị Apple',
      confidence: 65,
      reason: 'DNS: Apple / iCloud',
    };
  }

  // Android
  if (androidHits > 0) {
    return {
      groupId: 'mobile',
      nameHint: 'Điện thoại Android',
      confidence: 78,
      reason: 'DNS: dịch vụ Android',
    };
  }

  return null;
}

class DeviceDiscovery {
  constructor() {
    this.store = null;
    this.onMigrationCallback = null;
    this.domainsByIp = new Map(); // ip -> Set<domain>
    this.hostnameCache = new Map(); // ip -> { hostname, fetchedAt }
    this.discovered = new Map(); // ip -> info object
    this.ipToMac = new Map(); // ip -> normalized MAC (non-shared)
    this.macToIp = new Map(); // normalized MAC (non-shared) -> latest ip
    this.sharedMacs = new Set(); // MAC xuất hiện ở >= 2 IP cùng lúc (Repeater/Proxy ARP)
    this.gatewayIp = '';
    this.localIps = new Set();
    this.isScanning = false;
    this.isRefreshingArp = false;
    this.lastScanAt = null;
    this.debounceTimer = null;
    this.arpTimer = null;
    this.periodicTimer = null;
    this._onQuery = null;
  }

  start(store, { onMigration } = {}) {
    this.store = store;
    this.onMigrationCallback = onMigration || null;

    // Nạp lịch sử domain từ logs hiện có (nếu có)
    for (const log of store.logs || []) {
      this._recordDomain(log.clientIp, log.domain);
    }

    this._onQuery = (record) => {
      if (!record?.clientIp || !record?.domain) return;
      const isNewIp = !this.discovered.has(record.clientIp);
      this._recordDomain(record.clientIp, record.domain);
      if (isNewIp) {
        this._scheduleScan();
      }
    };
    store.on('query', this._onQuery);

    // Quét lần đầu ở nền (không chặn khởi động DNS)
    this.scanAll({ force: false }).catch(() => {});

    // Làm mới nhanh bảng ARP mỗi 60s (~5ms, 0 gói tin mạng) để ánh xạ IP ↔ MAC luôn chính xác
    this.arpTimer = setInterval(() => {
      this.refreshArpFast().catch(() => {});
    }, ARP_REFRESH_MS);
    this.arpTimer.unref();

    this.periodicTimer = setInterval(() => {
      this.scanAll({ force: false }).catch(() => {});
    }, PERIODIC_SCAN_MS);
    this.periodicTimer.unref();
  }

  stop() {
    if (this.store && this._onQuery) {
      this.store.off('query', this._onQuery);
      this._onQuery = null;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    if (this.arpTimer) {
      clearInterval(this.arpTimer);
      this.arpTimer = null;
    }
    if (this.periodicTimer) {
      clearInterval(this.periodicTimer);
      this.periodicTimer = null;
    }
  }

  _updateArpMaps(arpByIp, sharedMacs) {
    this.sharedMacs = sharedMacs;
    const nextIpToMac = new Map();
    const nextMacToIp = new Map();
    for (const [ip, entry] of arpByIp.entries()) {
      if (!entry?.mac || sharedMacs.has(entry.mac)) continue;
      nextIpToMac.set(ip, entry.mac);
      nextMacToIp.set(entry.mac, ip);
    }
    this.ipToMac = nextIpToMac;
    this.macToIp = nextMacToIp;
  }

  /**
   * Tra MAC nhanh O(1) từ bộ nhớ cho luồng DNS chính (trả '' nếu không có hoặc là Shared MAC sau Repeater)
   */
  getMacForIp(ip) {
    if (!ip) return '';
    return this.ipToMac.get(ip) || '';
  }

  getIpForMac(mac) {
    const norm = normalizeMac(mac);
    if (!norm || this.sharedMacs.has(norm)) return '';
    return this.macToIp.get(norm) || '';
  }

  /**
   * Tìm thiết bị đã lưu ưu tiên theo MAC trước, fallback theo IP khi không có MAC hoặc sau Repeater
   */
  resolveDeviceForIp(clientIp, devices = []) {
    if (!clientIp || !Array.isArray(devices) || devices.length === 0) return null;
    const mac = this.getMacForIp(clientIp);
    if (mac) {
      const byMac = devices.find((d) => d.mac && normalizeMac(d.mac) === mac);
      if (byMac) return byMac;
    }
    // Fallback theo IP (chỉ khớp nếu thiết bị đó chưa bị gắn cố định cho một MAC khác)
    return (
      devices.find((d) => {
        if (d.ip !== clientIp) return false;
        if (mac && d.mac && normalizeMac(d.mac) !== mac) return false;
        return true;
      }) || null
    );
  }

  async refreshArpFast() {
    if (this.isRefreshingArp || this.isScanning) return;
    this.isRefreshingArp = true;
    try {
      const arp = await readArpTable();
      this._updateArpMaps(arp.byIp, arp.sharedMacs);
      await this._reconcileSavedDevicesByMac(arp.byIp, arp.sharedMacs);
    } finally {
      this.isRefreshingArp = false;
    }
  }

  _recordDomain(ip, domain) {
    if (!ip || !domain) return;
    let set = this.domainsByIp.get(ip);
    if (!set) {
      if (this.domainsByIp.size >= MAX_TRACKED_IPS) {
        const oldest = this.domainsByIp.keys().next().value;
        if (oldest) this.domainsByIp.delete(oldest);
      }
      set = new Set();
      this.domainsByIp.set(ip, set);
    }
    if (set.size < MAX_DOMAINS_PER_IP) {
      set.add(domain.toLowerCase());
    }
  }

  _scheduleScan() {
    if (this.debounceTimer) return;
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      this.scanAll({ force: false }).catch(() => {});
    }, DEBOUNCE_SCAN_MS);
    this.debounceTimer.unref();
  }

  async _resolveHostnamesBatch(ips, force) {
    const now = Date.now();
    const toQuery = [];
    for (const ip of ips) {
      if (ip === '127.0.0.1' || ip === '::1') continue;
      const cached = this.hostnameCache.get(ip);
      if (!force && cached && now - cached.fetchedAt < HOSTNAME_CACHE_TTL_MS) continue;
      toQuery.push(ip);
    }

    // Giới hạn đồng thời để không tạo nhiều socket UDP cùng lúc
    for (let i = 0; i < toQuery.length; i += PTR_CONCURRENCY) {
      const batch = toQuery.slice(i, i + PTR_CONCURRENCY);
      await Promise.all(
        batch.map(async (ip) => {
          const hostname = await resolveHostname(ip, this.gatewayIp, this.localIps);
          this.hostnameCache.set(ip, { hostname, fetchedAt: Date.now() });
        })
      );
    }
  }

  async _reconcileSavedDevicesByMac(arpByIp, sharedMacs) {
    if (!this.store || !Array.isArray(this.store.config.devices)) return false;

    const savedByIp = new Map();
    for (const d of this.store.config.devices) {
      if (d.ip) savedByIp.set(d.ip, d);
    }

    // Xây bản đồ MAC -> IP mới nhất (mọi MAC hợp lệ không bị Repeater/Proxy ARP dùng chung)
    const uniqueMacToIp = new Map();
    for (const [ip, entry] of arpByIp.entries()) {
      if (!entry.mac || sharedMacs.has(entry.mac)) continue;
      uniqueMacToIp.set(entry.mac, ip);
    }

    let changed = false;
    for (const dev of this.store.config.devices) {
      const devMac = normalizeMac(dev.mac);
      // Nếu thiết bị đã lưu chưa có MAC nhưng hiện đang ở đúng IP có MAC không bị dùng chung → tự gắn MAC
      if (!devMac) {
        const currentArp = dev.ip ? arpByIp.get(dev.ip) : null;
        if (currentArp?.mac && !sharedMacs.has(currentArp.mac)) {
          dev.mac = currentArp.mac;
          dev.id = `mac:${currentArp.mac}`;
          changed = true;
        }
        continue;
      }

      if (dev.mac !== devMac) {
        dev.mac = devMac;
        changed = true;
      }
      if (!dev.id) {
        dev.id = `mac:${devMac}`;
        changed = true;
      }

      if (sharedMacs.has(devMac)) continue;

      const currentIpForMac = uniqueMacToIp.get(devMac);
      if (!currentIpForMac || currentIpForMac === dev.ip) continue;

      // Chỉ di chuyển IP nếu IP mới chưa bị gắn cho thiết bị đã lưu khác
      const existingAtNewIp = savedByIp.get(currentIpForMac);
      if (existingAtNewIp && existingAtNewIp !== dev) continue;

      // Và IP cũ không còn trỏ tới MAC này nữa
      const oldIpArp = dev.ip ? arpByIp.get(dev.ip) : null;
      if (oldIpArp?.mac === devMac) continue;

      if (dev.ip) savedByIp.delete(dev.ip);
      dev.ip = currentIpForMac;
      savedByIp.set(currentIpForMac, dev);
      changed = true;
    }

    if (changed) {
      await this.store.save();
      if (typeof this.onMigrationCallback === 'function') {
        this.onMigrationCallback();
      }
    }
    return changed;
  }

  _synthesizeInfo(ip, arpEntry, sharedMacs) {
    const isLoopback = ip === '127.0.0.1' || ip === '::1';
    const isGateway = Boolean(this.gatewayIp && ip === this.gatewayIp);
    const isSelf = this.localIps.has(ip);

    const mac = arpEntry?.mac || '';
    const privateMac = mac ? isPrivateMac(mac) : false;
    const sharedMac = mac ? sharedMacs.has(mac) : false;
    const oui = mac && !privateMac ? lookupVendor(mac) : null;
    const hostname = this.hostnameCache.get(ip)?.hostname || '';
    const cleanHost = hostname.replace(/\.local$/i, '');

    const reasons = [];
    let suggestedName = '';
    let suggestedGroupId = '';
    let confidence = 0;

    if (isLoopback) {
      return {
        ip,
        mac: '',
        isPrivateMac: false,
        isSharedMac: false,
        isGateway: false,
        isSelf: true,
        isLoopback: true,
        hostname: 'localhost',
        vendor: 'Localhost',
        suggestedName: 'Máy chủ NetShield (Localhost)',
        suggestedGroupId: 'computer',
        confidence: 100,
        reasons: ['Địa chỉ nội bộ máy chạy NetShield'],
      };
    }

    if (isSelf) {
      const hostLabel = cleanHost || os.hostname().replace(/\.local$/i, '');
      reasons.push('IP của chính máy chạy NetShield');
      if (hostname) reasons.push(`mDNS: ${hostname}`);
      return {
        ip,
        mac,
        isPrivateMac: privateMac,
        isSharedMac: sharedMac,
        isGateway: false,
        isSelf: true,
        isLoopback: false,
        hostname: hostname || os.hostname(),
        vendor: 'Apple / Host',
        suggestedName: `Máy chủ NetShield (${hostLabel})`,
        suggestedGroupId: 'computer',
        confidence: 98,
        reasons,
      };
    }

    if (isGateway) {
      reasons.push('Default Gateway (Router chính)');
      if (oui?.vendor) reasons.push(`MAC: ${oui.vendor}`);
      return {
        ip,
        mac,
        isPrivateMac: privateMac,
        isSharedMac: sharedMac,
        isGateway: true,
        isSelf: false,
        isLoopback: false,
        hostname,
        vendor: oui?.vendor || '',
        suggestedName: oui?.vendor ? `Router ${oui.vendor}` : 'Router / Gateway',
        suggestedGroupId: 'iot',
        confidence: 96,
        reasons,
      };
    }

    // Thu thập các bằng chứng
    if (hostname) reasons.push(`mDNS/PTR: ${hostname}`);
    if (oui?.vendor) reasons.push(`MAC: ${oui.vendor}`);
    if (privateMac) reasons.push('MAC ẩn (Private Wi-Fi)');
    if (sharedMac) reasons.push('MAC dùng chung (sau Repeater/Mesh)');

    const hostHint = inferFromHostname(hostname);
    const dnsHint = analyzeDomains(this.domainsByIp.get(ip));
    if (dnsHint?.reason) reasons.push(dnsHint.reason);

    // Ưu tiên tên gợi ý: Hostname thật > DNS Hint + Vendor > Vendor > DNS Hint
    if (cleanHost) {
      suggestedName = cleanHost;
      confidence = Math.max(confidence, 90);
    } else if (oui?.vendor && dnsHint?.nameHint) {
      suggestedName =
        dnsHint.nameHint.toLowerCase().includes(oui.vendor.toLowerCase())
          ? dnsHint.nameHint
          : `${dnsHint.nameHint} (${oui.vendor})`;
      confidence = Math.max(confidence, Math.min(95, dnsHint.confidence + 8));
    } else if (oui?.vendor) {
      suggestedName = oui.hintGroup === 'camera' ? `Camera ${oui.vendor}` : oui.vendor;
      confidence = Math.max(confidence, oui.hintGroup === 'camera' ? 88 : 72);
    } else if (dnsHint?.nameHint) {
      suggestedName = dnsHint.nameHint;
      confidence = Math.max(confidence, dnsHint.confidence);
    }

    // Ưu tiên nhóm gợi ý: Hostname > OUI Camera/IoT/Computer > DNS Behavioral > OUI Mobile
    if (hostHint?.groupId) {
      suggestedGroupId = hostHint.groupId;
    } else if (oui?.hintGroup && oui.hintGroup !== 'network') {
      suggestedGroupId = oui.hintGroup;
    } else if (dnsHint?.groupId) {
      suggestedGroupId = dnsHint.groupId;
    } else if (oui?.hintGroup === 'network') {
      suggestedGroupId = 'iot';
    }

    return {
      ip,
      mac,
      isPrivateMac: privateMac,
      isSharedMac: sharedMac,
      isGateway: false,
      isSelf: false,
      isLoopback: false,
      hostname,
      vendor: oui?.vendor || '',
      suggestedName,
      suggestedGroupId,
      confidence,
      reasons,
    };
  }

  async scanAll({ force = false } = {}) {
    if (this.isScanning) return this.getAllDiscovered();
    this.isScanning = true;
    try {
      this.localIps = getLocalLanIps();
      const [gatewayIp, arp] = await Promise.all([getDefaultGateway(), readArpTable()]);
      if (gatewayIp) this.gatewayIp = gatewayIp;
      this._updateArpMaps(arp.byIp, arp.sharedMacs);

      // Tự động cập nhật IP cho các thiết bị đã lưu theo MAC (trừ Shared MAC sau Repeater)
      await this._reconcileSavedDevicesByMac(arp.byIp, arp.sharedMacs);

      // Tập hợp tất cả IP cần nhận diện (đang hoạt động + đã lưu)
      const ipSet = new Set();
      if (this.store) {
        for (const ip of this.store.stats.byClient.keys()) ipSet.add(ip);
        for (const dev of this.store.config.devices || []) {
          if (dev.ip) ipSet.add(dev.ip);
        }
      }
      // Bổ sung IP cùng dải LAN trong ARP (chỉ subnet /24 khớp máy chạy NetShield để tránh rác link-local 169.254.x.x)
      const lanPrefixes = new Set([...this.localIps].map((ip) => ip.split('.').slice(0, 3).join('.')));
      for (const ip of arp.byIp.keys()) {
        const prefix = ip.split('.').slice(0, 3).join('.');
        if (lanPrefixes.has(prefix)) ipSet.add(ip);
      }

      const ips = [...ipSet];
      await this._resolveHostnamesBatch(ips, force);

      for (const ip of ips) {
        const info = this._synthesizeInfo(ip, arp.byIp.get(ip), arp.sharedMacs);
        this.discovered.set(ip, info);
      }

      this.lastScanAt = new Date().toISOString();
      return this.getAllDiscovered();
    } finally {
      this.isScanning = false;
    }
  }

  getDeviceInfo(ip) {
    return this.discovered.get(ip) || null;
  }

  getAllDiscovered() {
    const out = {};
    for (const [ip, info] of this.discovered.entries()) {
      out[ip] = info;
    }
    return out;
  }
}

export const deviceDiscovery = new DeviceDiscovery();
