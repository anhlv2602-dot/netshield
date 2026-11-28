import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  ROOT_DIR,
  SERVICE_PRESETS,
  IOT_ALLOWLIST_PRESETS,
  DEFAULT_SECURITY_CONFIG,
  DEFAULT_ALERTS_CONFIG,
  DEFAULT_STORAGE_CONFIG,
  DEFAULT_ENCRYPTED_DNS_CONFIG,
  DEFAULT_HA_SYNC_CONFIG,
  normalizeDomain,
  store,
} from './store.js';
import { blocklistEngine } from './blocklist.js';
import { dnsCache, getUpstreamHealth, resetUpstreamHealth, testAllUpstreams } from './dns-server.js';
import { buildIosMobileConfig, normalizePublicHostname } from './encrypted-dns.js';
import { haSyncManager, normalizeHaSyncConfig } from './ha-sync.js';
import { checkVnImpersonation, isDgaLikeDomain } from './threat-guard.js';
import { deviceDiscovery, normalizeMac } from './discovery.js';
import { alertEngine } from './alerts.js';
import { forensicsDb } from './db.js';
import {
  UPSTREAM_STRATEGIES,
  normalizeUpstreamStrategy,
  normalizeLocalRecord,
  localDnsLB,
} from './load-balancer.js';

const PUBLIC_DIR = path.join(ROOT_DIR, 'public');

function getLanIps() {
  const ifaces = os.networkInterfaces();
  const ips = [];
  for (const [name, addrs] of Object.entries(ifaces)) {
    for (const addr of addrs || []) {
      if (addr.family === 'IPv4' && !addr.internal) {
        ips.push({ iface: name, ip: addr.address });
      }
    }
  }
  return ips;
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

async function readJsonBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 1024 * 1024) throw new Error('Payload too large');
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8').trim();
  return text ? JSON.parse(text) : {};
}

function isLocalClient(req) {
  const ip = (req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  return ip === '127.0.0.1' || ip === '::1';
}

export function startWebServer({
  host = '127.0.0.1',
  port = 8080,
  dnsPort = 5335,
  encryptedDnsStatus = null,
} = {}) {
  const sseClients = new Set();

  const onQuery = (record) => {
    if (sseClients.size === 0) return;
    const payload = `data: ${JSON.stringify(record)}\n\n`;
    for (const res of sseClients) {
      try {
        res.write(payload);
      } catch {
        sseClients.delete(res);
      }
    }
  };
  store.on('query', onQuery);

  const server = http.createServer(async (req, res) => {
    if (host === '127.0.0.1' && !isLocalClient(req)) {
      return sendJson(res, 403, { error: 'Chỉ cho phép truy cập trang quản trị từ máy Mac Mini (localhost)' });
    }
    try {
      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const pathname = url.pathname;
      const method = req.method;

      // 1. SSE Live Logs
      if (method === 'GET' && pathname === '/api/logs/stream') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
        });
        res.write(': connected\n\n');
        sseClients.add(res);
        req.on('close', () => sseClients.delete(res));
        return;
      }

      // 2. Status & Stats
      if (method === 'GET' && pathname === '/api/status') {
        return sendJson(res, 200, {
          dnsPort,
          webPort: port,
          lanIps: getLanIps(),
          encryptedDnsStatus,
          haSyncStatus: haSyncManager.getStatus(),
          cacheSize: dnsCache.size,
          totalBlockedDomains: blocklistEngine.getTotalBlockedDomains(),
          isUpdatingBlocklists: blocklistEngine.isUpdating,
          summary: store.getSummary(),
          config: store.config,
          upstreamHealth: getUpstreamHealth(),
          upstreamStrategies: UPSTREAM_STRATEGIES,
          localRecordsHealth: localDnsLB.annotateRecordsWithHealth(store.config.localRecords || []),
          alertsSummary: alertEngine.getSummary(),
          dbStats: await forensicsDb.getStats(),
          servicePresets: SERVICE_PRESETS,
          iotAllowlistPresets: IOT_ALLOWLIST_PRESETS,
          discoveredDevices: deviceDiscovery.getAllDiscovered(),
          lastDiscoveryScanAt: deviceDiscovery.lastScanAt,
        });
      }

      // 2b. Security Alerts API
      if (method === 'GET' && pathname === '/api/alerts') {
        const limit = Math.min(500, Number(url.searchParams.get('limit')) || 100);
        const unack = url.searchParams.get('unacknowledged') === '1';
        return sendJson(res, 200, {
          items: alertEngine.getAlerts({ limit, unacknowledgedOnly: unack }),
          summary: alertEngine.getSummary(),
        });
      }

      if (method === 'POST' && pathname === '/api/alerts/ack-all') {
        alertEngine.acknowledgeAll();
        return sendJson(res, 200, { ok: true, summary: alertEngine.getSummary() });
      }

      if (method === 'POST' && pathname === '/api/alerts/test') {
        const body = await readJsonBody(req);
        const override = {};
        if (typeof body.telegramBotToken === 'string' && body.telegramBotToken.trim()) {
          override.telegramBotToken = body.telegramBotToken.trim();
        }
        if (typeof body.telegramChatId === 'string' && body.telegramChatId.trim()) {
          override.telegramChatId = body.telegramChatId.trim();
        }
        if (typeof body.webhookUrl === 'string' && body.webhookUrl.trim()) {
          override.webhookUrl = body.webhookUrl.trim();
        }
        const result = await alertEngine.sendTestNotification(override);
        return sendJson(res, result.ok ? 200 : 400, result);
      }

      if (method === 'POST' && pathname.startsWith('/api/alerts/') && pathname.endsWith('/ack')) {
        const parts = pathname.split('/');
        const id = parts[parts.length - 2];
        alertEngine.acknowledge(id);
        return sendJson(res, 200, { ok: true, summary: alertEngine.getSummary() });
      }

      if (method === 'DELETE' && pathname === '/api/alerts') {
        alertEngine.clearAll();
        return sendJson(res, 200, { ok: true, summary: alertEngine.getSummary() });
      }

      // 2c. DNS Quarantine API (cách ly tạm thời thiết bị bất thường)
      if (method === 'GET' && pathname === '/api/quarantine') {
        return sendJson(res, 200, { items: alertEngine.getQuarantinedClients() });
      }

      if (method === 'POST' && pathname === '/api/quarantine') {
        const body = await readJsonBody(req);
        const ip = String(body.ip || '').trim();
        if (!ip) return sendJson(res, 400, { error: 'Thiếu địa chỉ IP cần cách ly' });
        const entry = alertEngine.quarantineClient(ip, {
          reason: String(body.reason || 'Cách ly thủ công bởi quản trị viên').slice(0, 120),
          durationMin: Number(body.durationMin) || store.config.security?.quarantineDurationMin || 15,
        });
        if (!entry) {
          return sendJson(res, 400, { error: 'Không thể cách ly IP loopback, chính máy chủ NetShield hoặc Router gateway' });
        }
        return sendJson(res, 200, { ok: true, entry, items: alertEngine.getQuarantinedClients() });
      }

      if (method === 'DELETE' && pathname.startsWith('/api/quarantine/')) {
        const ip = decodeURIComponent(pathname.slice('/api/quarantine/'.length)).trim();
        const removed = alertEngine.unquarantineClient(ip);
        return sendJson(res, 200, { ok: removed, items: alertEngine.getQuarantinedClients() });
      }

      // 3. Query logs (hỗ trợ cả RAM trực tiếp & lịch sử dài hạn SQLite + Xuất CSV)
      if (method === 'GET' && pathname === '/api/logs/export.csv') {
        const search = (url.searchParams.get('search') || '').trim().toLowerCase();
        const filter = url.searchParams.get('filter') || 'all';
        const severity = (url.searchParams.get('severity') || '').trim();
        const sinceHours = Number(url.searchParams.get('sinceHours') || 24);
        const csv = forensicsDb.enabled
          ? forensicsDb.exportCsv({ search, filter, severity, sinceHours, limit: 10000 })
          : '\uFEFFThoi_gian,IP_Thiet_bi,Ten_mien,Loai,Trang_thai,Muc_do,Ly_do,Do_tre_ms\r\n' +
            store.logs
              .map((i) =>
                [
                  i.timestamp,
                  i.clientIp,
                  i.domain,
                  i.qtype,
                  i.blocked ? 'BLOCKED' : i.cached ? 'CACHED' : 'ALLOWED',
                  i.severity || 'info',
                  `"${String(i.reason || '').replace(/"/g, '""')}"`,
                  i.latencyMs ?? 0,
                ].join(',')
              )
              .join('\r\n');
        const dateTag = new Date().toISOString().slice(0, 10);
        res.writeHead(200, {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="netshield-logs-${dateTag}.csv"`,
          'Cache-Control': 'no-store',
        });
        res.end(csv);
        return;
      }

      if (method === 'GET' && pathname === '/api/logs') {
        const limit = Math.min(2000, Number(url.searchParams.get('limit')) || 150);
        const search = (url.searchParams.get('search') || '').trim().toLowerCase();
        const filter = url.searchParams.get('filter') || 'all'; // all | blocked | allowed
        const severity = (url.searchParams.get('severity') || '').trim(); // '' | high | medium | info
        const source = (url.searchParams.get('source') || 'live').trim(); // live | db
        const sinceHours = Number(url.searchParams.get('sinceHours') || 0);

        if ((source === 'db' || sinceHours > 0) && forensicsDb.enabled) {
          const dbItems = forensicsDb.queryLogs({
            limit,
            search,
            filter,
            severity,
            sinceHours: sinceHours > 0 ? sinceHours : 24,
          });
          return sendJson(res, 200, { items: dbItems || [], source: 'db' });
        }

        let items = store.logs;
        if (filter === 'blocked') items = items.filter((i) => i.blocked);
        if (filter === 'allowed') items = items.filter((i) => !i.blocked);
        if (severity) items = items.filter((i) => (i.severity || 'info') === severity);
        if (search) {
          items = items.filter(
            (i) =>
              i.domain.includes(search) ||
              i.clientIp.includes(search) ||
              (i.reason || '').toLowerCase().includes(search)
          );
        }
        return sendJson(res, 200, { items: items.slice(0, limit), source: 'live' });
      }

      // 4. Toggle global protection
      if (method === 'POST' && pathname === '/api/protection') {
        const body = await readJsonBody(req);
        store.config.protectionEnabled = Boolean(body.enabled);
        await store.save();
        dnsCache.clear();
        return sendJson(res, 200, { protectionEnabled: store.config.protectionEnabled });
      }

      // 5. Whitelist / Blacklist
      if (pathname === '/api/lists/whitelist' || pathname === '/api/lists/blacklist') {
        const listKey = pathname.endsWith('whitelist') ? 'whitelist' : 'blacklist';
        const oppositeKey = listKey === 'whitelist' ? 'blacklist' : 'whitelist';
        const body = await readJsonBody(req);
        const domain = normalizeDomain(body.domain);
        if (!domain) return sendJson(res, 400, { error: 'Tên miền không hợp lệ' });

        if (method === 'POST') {
          if (!store.config[listKey].includes(domain)) {
            store.config[listKey].unshift(domain);
          }
          // Gỡ khỏi danh sách đối lập nếu có
          store.config[oppositeKey] = store.config[oppositeKey].filter((d) => d !== domain);
        } else if (method === 'DELETE') {
          store.config[listKey] = store.config[listKey].filter((d) => d !== domain);
        }
        await store.save();
        blocklistEngine.rebuildCustomSets();
        dnsCache.clear();
        return sendJson(res, 200, {
          whitelist: store.config.whitelist,
          blacklist: store.config.blacklist,
        });
      }

      // 5b. Kiểm tra nhanh 1 tên miền xem đang bị chặn hay cho phép
      if (method === 'GET' && pathname === '/api/check') {
        const domain = normalizeDomain(url.searchParams.get('domain') || '');
        const clientIp = (url.searchParams.get('clientIp') || '127.0.0.1').trim();
        if (!domain) return sendJson(res, 400, { error: 'Vui lòng nhập tên miền cần kiểm tra' });
        const decision = blocklistEngine.evaluate(domain, clientIp);
        const vnImpersonation = checkVnImpersonation(domain, blocklistEngine.whitelistSet);
        const dgaLike = isDgaLikeDomain(domain);
        return sendJson(res, 200, { domain, clientIp, ...decision, vnImpersonation, dgaLike });
      }

      // 6. Blocklists management
      if (method === 'POST' && pathname === '/api/blocklists/refresh') {
        const result = await blocklistEngine.refreshAll();
        dnsCache.clear();
        return sendJson(res, 200, result);
      }

      if (method === 'POST' && pathname === '/api/blocklists') {
        const body = await readJsonBody(req);
        const name = (body.name || '').trim();
        const urlStr = (body.url || '').trim();
        if (!name || !/^https?:\/\//i.test(urlStr)) {
          return sendJson(res, 400, { error: 'Cần nhập tên và đường dẫn HTTP/HTTPS hợp lệ' });
        }
        const id = `custom-${Date.now()}`;
        const item = {
          id,
          name,
          url: urlStr,
          enabled: true,
          count: 0,
          lastUpdated: null,
          lastError: null,
        };
        store.config.blocklists.push(item);
        await store.save();
        // Tự động tải và xác minh nguồn vừa thêm ngay lập tức
        const refreshResult = await blocklistEngine.refreshById(id);
        dnsCache.clear();
        return sendJson(res, 200, { blocklists: store.config.blocklists, refreshResult });
      }

      if (method === 'POST' && pathname.startsWith('/api/blocklists/') && pathname.endsWith('/refresh')) {
        const parts = pathname.split('/');
        const id = parts[parts.length - 2];
        const refreshResult = await blocklistEngine.refreshById(id);
        dnsCache.clear();
        return sendJson(res, 200, { blocklists: store.config.blocklists, refreshResult });
      }

      if (pathname.startsWith('/api/blocklists/')) {
        const id = pathname.split('/').pop();
        if (method === 'PATCH') {
          const body = await readJsonBody(req);
          const item = store.config.blocklists.find((b) => b.id === id);
          if (!item) return sendJson(res, 404, { error: 'Không tìm thấy blocklist' });
          if (typeof body.enabled === 'boolean') item.enabled = body.enabled;
          await store.save();
          // Nếu vừa bật và chưa có dữ liệu thì tự động tải luôn
          let refreshResult = null;
          if (item.enabled && (!item.count || !item.lastUpdated)) {
            refreshResult = await blocklistEngine.refreshById(id);
          } else {
            await blocklistEngine.loadFromCache();
          }
          dnsCache.clear();
          return sendJson(res, 200, { blocklists: store.config.blocklists, refreshResult });
        }
        if (method === 'DELETE') {
          store.config.blocklists = store.config.blocklists.filter((b) => b.id !== id);
          await store.save();
          await blocklistEngine.loadFromCache();
          dnsCache.clear();
          return sendJson(res, 200, { blocklists: store.config.blocklists });
        }
      }

      // 7a. Device Groups management (Camera, Máy tính, Di động, IoT...)
      if (method === 'POST' && pathname === '/api/groups') {
        const body = await readJsonBody(req);
        const name = (body.name || '').trim();
        if (!name) return sendJson(res, 400, { error: 'Cần nhập tên nhóm thiết bị' });

        if (!Array.isArray(store.config.deviceGroups)) store.config.deviceGroups = [];
        const id = (body.id || '').trim() || `group-${Date.now()}`;
        const group = {
          id,
          name,
          icon: (body.icon || '📁').trim().slice(0, 4),
          description: (body.description || '').trim(),
        };

        const idx = store.config.deviceGroups.findIndex((g) => g.id === id);
        if (idx >= 0) store.config.deviceGroups[idx] = group;
        else store.config.deviceGroups.push(group);

        await store.save();
        return sendJson(res, 200, { deviceGroups: store.config.deviceGroups });
      }

      if (method === 'GET' && pathname.startsWith('/api/groups/') && pathname.endsWith('/observed-domains')) {
        const parts = pathname.split('/');
        const id = decodeURIComponent(parts[parts.length - 2] || '');
        return sendJson(res, 200, {
          groupId: id,
          domains: blocklistEngine.getObservedDomainsForGroup(id),
        });
      }

      if (method === 'DELETE' && pathname.startsWith('/api/groups/')) {
        const id = decodeURIComponent(pathname.slice('/api/groups/'.length));
        store.config.deviceGroups = (store.config.deviceGroups || []).filter((g) => g.id !== id);
        for (const dev of store.config.devices || []) {
          if (dev.groupId === id) dev.groupId = '';
        }
        store.config.clientRules = (store.config.clientRules || []).filter(
          (r) => !(r.targetType === 'group' && r.groupId === id)
        );
        await store.save();
        dnsCache.clear();
        return sendJson(res, 200, {
          deviceGroups: store.config.deviceGroups,
          devices: store.config.devices,
          clientRules: store.config.clientRules,
        });
      }

      // 7b. Devices (gán IP thiết bị vào nhóm + đặt tên gợi nhớ + quét nhận diện LAN)
      if (method === 'POST' && pathname === '/api/devices/scan') {
        const discoveredDevices = await deviceDiscovery.scanAll({ force: true });
        return sendJson(res, 200, {
          discoveredDevices,
          lastDiscoveryScanAt: deviceDiscovery.lastScanAt,
          devices: store.config.devices,
        });
      }

      if (method === 'POST' && pathname === '/api/devices/apply-suggestions') {
        const body = await readJsonBody(req);
        const items = Array.isArray(body.items) ? body.items : [];
        if (!Array.isArray(store.config.devices)) store.config.devices = [];
        const validGroups = new Set((store.config.deviceGroups || []).map((g) => g.id));
        let applied = 0;

        for (const item of items) {
          let ip = (item?.ip || '').trim();
          let mac = normalizeMac(item?.mac);
          if (!mac && ip) mac = deviceDiscovery.getMacForIp(ip);
          if (!ip && mac) ip = deviceDiscovery.getIpForMac(mac);

          const name = (item?.name || '').trim();
          const groupId = validGroups.has((item?.groupId || '').trim()) ? item.groupId.trim() : '';
          if ((!mac && !ip) || (!name && !groupId)) continue;

          const id = mac ? `mac:${mac}` : `ip:${ip}`;
          const idx = store.config.devices.findIndex(
            (d) => d.id === id || (mac && d.mac && normalizeMac(d.mac) === mac) || (ip && d.ip === ip)
          );
          if (idx >= 0) {
            const cur = store.config.devices[idx];
            const finalMac = mac || normalizeMac(cur.mac);
            const finalIp = ip || cur.ip || '';
            store.config.devices[idx] = {
              id: finalMac ? `mac:${finalMac}` : `ip:${finalIp}`,
              ip: finalIp,
              name: cur.name || name,
              groupId: cur.groupId || groupId,
              ...(finalMac ? { mac: finalMac } : {}),
            };
          } else {
            store.config.devices.push({
              id,
              ip,
              name,
              groupId,
              ...(mac ? { mac } : {}),
            });
          }
          applied += 1;
        }

        if (applied > 0) {
          await store.save();
          dnsCache.clear();
        }
        return sendJson(res, 200, { applied, devices: store.config.devices });
      }

      if (method === 'POST' && pathname === '/api/devices') {
        const body = await readJsonBody(req);
        const rawIp = (body.ip || '').trim();
        const rawMac = (body.mac || '').trim();

        // Hỗ trợ nhập thẳng địa chỉ MAC vào ô IP thủ công
        let mac = normalizeMac(rawMac) || normalizeMac(rawIp);
        let ip = normalizeMac(rawIp) ? '' : rawIp;
        if (!mac && ip) mac = deviceDiscovery.getMacForIp(ip);
        if (!ip && mac) ip = deviceDiscovery.getIpForMac(mac);

        if (!mac && !ip) {
          return sendJson(res, 400, { error: 'Cần nhập địa chỉ MAC hoặc IP thiết bị hợp lệ' });
        }

        const groupId = (body.groupId || '').trim();
        if (groupId && !(store.config.deviceGroups || []).some((g) => g.id === groupId)) {
          return sendJson(res, 400, { error: 'Nhóm thiết bị không tồn tại' });
        }

        if (!Array.isArray(store.config.devices)) store.config.devices = [];
        const name = (body.name || '').trim();
        const id = mac ? `mac:${mac}` : `ip:${ip}`;
        const idx = store.config.devices.findIndex(
          (d) =>
            d.id === id ||
            (mac && d.mac && normalizeMac(d.mac) === mac) ||
            (!mac && ip && d.ip === ip) ||
            (ip && d.ip === ip && !d.mac)
        );
        const existing = idx >= 0 ? store.config.devices[idx] : null;
        const finalMac = mac || normalizeMac(existing?.mac);
        const finalIp = ip || existing?.ip || '';
        const entry = {
          id: finalMac ? `mac:${finalMac}` : `ip:${finalIp}`,
          ip: finalIp,
          name,
          groupId,
          ...(finalMac ? { mac: finalMac } : {}),
        };
        if (idx >= 0) store.config.devices[idx] = entry;
        else store.config.devices.push(entry);

        await store.save();
        dnsCache.clear();
        return sendJson(res, 200, { devices: store.config.devices });
      }

      if (method === 'DELETE' && pathname.startsWith('/api/devices/')) {
        const key = decodeURIComponent(pathname.slice('/api/devices/'.length)).trim();
        const keyMac = normalizeMac(key);
        store.config.devices = (store.config.devices || []).filter(
          (d) => d.id !== key && d.ip !== key && (!keyMac || normalizeMac(d.mac) !== keyMac)
        );
        await store.save();
        dnsCache.clear();
        return sendJson(res, 200, { devices: store.config.devices });
      }

      // 7c. Client Rules & Schedules (hỗ trợ cả IP lẻ và Nhóm thiết bị)
      if (method === 'POST' && pathname === '/api/clients') {
        const body = await readJsonBody(req);
        const targetType = body.targetType === 'group' ? 'group' : 'ip';
        const groupId = targetType === 'group' ? (body.groupId || '').trim() : '';
        const clientIp = targetType === 'ip' ? (body.clientIp || '').trim() : '';

        if (targetType === 'group') {
          if (!groupId || !(store.config.deviceGroups || []).some((g) => g.id === groupId)) {
            return sendJson(res, 400, { error: 'Vui lòng chọn nhóm thiết bị hợp lệ' });
          }
        } else if (!clientIp) {
          return sendJson(res, 400, { error: 'Cần nhập địa chỉ IP thiết bị (hoặc * cho toàn mạng)' });
        }

        const grp = targetType === 'group' ? store.config.deviceGroups.find((g) => g.id === groupId) : null;
        const ruleMode = ['block', 'allowlist_audit', 'allowlist_enforce'].includes(body.ruleMode)
          ? body.ruleMode
          : 'block';
        const rule = {
          id: body.id || `rule-${Date.now()}`,
          name: (body.name || (grp ? `Quy tắc ${grp.name}` : clientIp)).trim(),
          targetType,
          groupId,
          clientIp,
          ruleMode,
          enabled: body.enabled !== false,
          bypassProtection: Boolean(body.bypassProtection),
          blockAllInternet: Boolean(body.blockAllInternet),
          blockedServices: Array.isArray(body.blockedServices) ? body.blockedServices : [],
          blockedDomains: Array.isArray(body.blockedDomains)
            ? body.blockedDomains.map(normalizeDomain).filter(Boolean)
            : [],
          allowedDomains: Array.isArray(body.allowedDomains)
            ? [...new Set(body.allowedDomains.map(normalizeDomain).filter(Boolean))]
            : [],
          schedule: {
            enabled: Boolean(body.schedule?.enabled),
            start: body.schedule?.start || '08:00',
            end: body.schedule?.end || '17:30',
            days: Array.isArray(body.schedule?.days) ? body.schedule.days.map(Number) : [1, 2, 3, 4, 5],
          },
        };

        const idx = store.config.clientRules.findIndex((r) => r.id === rule.id);
        if (idx >= 0) store.config.clientRules[idx] = rule;
        else store.config.clientRules.push(rule);

        await store.save();
        dnsCache.clear();
        return sendJson(res, 200, { clientRules: store.config.clientRules });
      }

      if (method === 'DELETE' && pathname.startsWith('/api/clients/')) {
        const id = pathname.split('/').pop();
        store.config.clientRules = store.config.clientRules.filter((r) => r.id !== id);
        await store.save();
        dnsCache.clear();
        return sendJson(res, 200, { clientRules: store.config.clientRules });
      }

      // 8a. Local DNS Split-Horizon & Round-Robin Load Balancing (tên miền nội bộ *.lan)
      if (method === 'POST' && pathname === '/api/local-dns/check-health') {
        await localDnsLB.triggerImmediateCheck(store.config.localRecords || []);
        return sendJson(res, 200, {
          localRecordsHealth: localDnsLB.annotateRecordsWithHealth(store.config.localRecords || []),
        });
      }

      if (method === 'POST' && pathname === '/api/local-dns') {
        const body = await readJsonBody(req);
        let rec;
        try {
          rec = normalizeLocalRecord(body);
        } catch (err) {
          return sendJson(res, 400, { error: err.message });
        }
        if (!Array.isArray(store.config.localRecords)) store.config.localRecords = [];
        const prevDomain = body.previousDomain ? normalizeDomain(body.previousDomain) : '';
        if (prevDomain && prevDomain !== rec.domain) {
          store.config.localRecords = store.config.localRecords.filter(
            (r) => normalizeDomain(r.domain) !== prevDomain
          );
        }
        const idx = store.config.localRecords.findIndex((r) => normalizeDomain(r.domain) === rec.domain);
        if (idx >= 0) store.config.localRecords[idx] = rec;
        else store.config.localRecords.push(rec);
        await store.save();
        dnsCache.clear();
        localDnsLB.triggerImmediateCheck(store.config.localRecords).catch(() => {});
        return sendJson(res, 200, {
          localRecords: store.config.localRecords,
          localRecordsHealth: localDnsLB.annotateRecordsWithHealth(store.config.localRecords),
        });
      }

      if (method === 'DELETE' && pathname.startsWith('/api/local-dns/')) {
        const domain = normalizeDomain(decodeURIComponent(pathname.slice('/api/local-dns/'.length)));
        store.config.localRecords = (store.config.localRecords || []).filter(
          (r) => normalizeDomain(r.domain) !== domain
        );
        await store.save();
        dnsCache.clear();
        return sendJson(res, 200, {
          localRecords: store.config.localRecords,
          localRecordsHealth: localDnsLB.annotateRecordsWithHealth(store.config.localRecords),
        });
      }

      // 8b. Backup / Restore cấu hình (mặc định che Telegram Bot Token khi xuất)
      if (method === 'GET' && pathname === '/api/config/export') {
        const includeSecrets = url.searchParams.get('includeSecrets') === '1';
        const copy = structuredClone(store.config);
        if (!includeSecrets && copy.alerts) {
          copy.alerts.telegramBotToken = '';
        }
        const payload = {
          exportedAt: new Date().toISOString(),
          version: 1,
          secretsIncluded: includeSecrets,
          config: copy,
        };
        const dateTag = new Date().toISOString().slice(0, 10);
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Disposition': `attachment; filename="netshield-backup-${dateTag}.json"`,
          'Cache-Control': 'no-store',
        });
        res.end(JSON.stringify(payload, null, 2));
        return;
      }

      if (method === 'POST' && pathname === '/api/config/import') {
        const body = await readJsonBody(req);
        const incoming = body.config && typeof body.config === 'object' ? body.config : body;
        if (!incoming || typeof incoming !== 'object' || !Array.isArray(incoming.upstreamDns)) {
          return sendJson(res, 400, { error: 'File sao lưu không hợp lệ (thiếu cấu trúc cấu hình NetShield)' });
        }
        // Tự động sao lưu config.prev.json trước khi ghi đè để dễ khôi phục
        await store.backupCurrentConfig();
        const prevToken = store.config.alerts?.telegramBotToken || '';
        const mergedAlerts = {
          ...DEFAULT_ALERTS_CONFIG,
          ...(incoming.alerts && typeof incoming.alerts === 'object' ? incoming.alerts : {}),
        };
        if (!mergedAlerts.telegramBotToken && prevToken) {
          mergedAlerts.telegramBotToken = prevToken;
        }
        store.config = {
          ...store.config,
          ...incoming,
          security: {
            ...DEFAULT_SECURITY_CONFIG,
            ...(incoming.security && typeof incoming.security === 'object' ? incoming.security : {}),
          },
          alerts: mergedAlerts,
          storage: {
            ...DEFAULT_STORAGE_CONFIG,
            ...(incoming.storage && typeof incoming.storage === 'object' ? incoming.storage : {}),
          },
          haSync: normalizeHaSyncConfig(
            incoming.haSync && typeof incoming.haSync === 'object'
              ? incoming.haSync
              : store.config.haSync || DEFAULT_HA_SYNC_CONFIG
          ),
          upstreamStrategy: normalizeUpstreamStrategy(
            incoming.upstreamStrategy ?? store.config.upstreamStrategy
          ),
          localRecords: Array.isArray(incoming.localRecords)
            ? incoming.localRecords
                .map((r) => {
                  try {
                    return normalizeLocalRecord(r);
                  } catch {
                    return null;
                  }
                })
                .filter(Boolean)
            : store.config.localRecords || [],
        };
        await store.save();
        await blocklistEngine.loadFromCache();
        dnsCache.clear();
        resetUpstreamHealth();
        localDnsLB.triggerImmediateCheck(store.config.localRecords).catch(() => {});
        return sendJson(res, 200, { ok: true, devicesCount: store.config.devices?.length || 0 });
      }

      // 8. Settings
      if (method === 'POST' && pathname === '/api/settings/test-upstreams') {
        const body = await readJsonBody(req);
        const list = Array.isArray(body.upstreamDns)
          ? body.upstreamDns.map((s) => String(s || '').trim()).filter(Boolean)
          : null;
        const results = await testAllUpstreams(list);
        return sendJson(res, 200, { results, upstreamHealth: getUpstreamHealth() });
      }

      if (method === 'POST' && pathname === '/api/settings') {
        const body = await readJsonBody(req);
        if (Array.isArray(body.upstreamDns) && body.upstreamDns.length > 0) {
          store.config.upstreamDns = body.upstreamDns.map((s) => String(s || '').trim()).filter(Boolean);
          resetUpstreamHealth();
        }
        if (typeof body.upstreamStrategy === 'string' && UPSTREAM_STRATEGIES.includes(body.upstreamStrategy)) {
          store.config.upstreamStrategy = body.upstreamStrategy;
        }
        if (body.blockResponseMode === 'zero' || body.blockResponseMode === 'nxdomain') {
          store.config.blockResponseMode = body.blockResponseMode;
        }
        if (body.security && typeof body.security === 'object') {
          const cur = { ...DEFAULT_SECURITY_CONFIG, ...(store.config.security || {}) };
          for (const key of [
            'dnsRebindingGuard',
            'cnameCloakingGuard',
            'antiBypass',
            'blockDnsTunneling',
            'dgaBeaconingGuard',
            'autoQuarantineOnAnomaly',
            'activeLanSweep',
            'serveStaleCache',
            'enableIpv6',
          ]) {
            if (typeof body.security[key] === 'boolean') {
              cur[key] = body.security[key];
            }
          }
          if (['block', 'audit', 'off'].includes(body.security.vnImpersonationMode)) {
            cur.vnImpersonationMode = body.security.vnImpersonationMode;
          }
          if (Number.isFinite(Number(body.security.quarantineDurationMin))) {
            cur.quarantineDurationMin = Math.max(1, Math.min(1440, Number(body.security.quarantineDurationMin)));
          }
          if (Array.isArray(body.security.rebindingWhitelist)) {
            cur.rebindingWhitelist = [...new Set(body.security.rebindingWhitelist.map(normalizeDomain).filter(Boolean))];
          }
          store.config.security = cur;
        }
        if (body.alerts && typeof body.alerts === 'object') {
          const curA = { ...DEFAULT_ALERTS_CONFIG, ...(store.config.alerts || {}) };
          for (const key of ['enabled', 'rogueDeviceEnabled', 'ignorePrivateMacPush', 'threatHitEnabled', 'anomalyEnabled']) {
            if (typeof body.alerts[key] === 'boolean') curA[key] = body.alerts[key];
          }
          if (Number.isFinite(Number(body.alerts.nxdomainThresholdPerMin))) {
            curA.nxdomainThresholdPerMin = Math.max(5, Math.min(500, Number(body.alerts.nxdomainThresholdPerMin)));
          }
          if (Number.isFinite(Number(body.alerts.tunnelingLabelLength))) {
            curA.tunnelingLabelLength = Math.max(30, Math.min(120, Number(body.alerts.tunnelingLabelLength)));
          }
          if (typeof body.alerts.telegramBotToken === 'string') {
            curA.telegramBotToken = body.alerts.telegramBotToken.trim();
          }
          if (typeof body.alerts.telegramChatId === 'string') {
            curA.telegramChatId = body.alerts.telegramChatId.trim();
          }
          if (typeof body.alerts.webhookUrl === 'string') {
            curA.webhookUrl = body.alerts.webhookUrl.trim();
          }
          store.config.alerts = curA;
        }
        if (body.storage && typeof body.storage === 'object') {
          const curS = { ...DEFAULT_STORAGE_CONFIG, ...(store.config.storage || {}) };
          if (Number.isFinite(Number(body.storage.retentionDays))) {
            curS.retentionDays = Math.max(1, Math.min(90, Number(body.storage.retentionDays)));
          }
          if (typeof body.storage.sqliteEnabled === 'boolean') {
            curS.sqliteEnabled = body.storage.sqliteEnabled;
          }
          store.config.storage = curS;
          forensicsDb.cleanupOldLogs(curS.retentionDays);
        }
        if (body.encryptedDns && typeof body.encryptedDns === 'object') {
          const curE = { ...DEFAULT_ENCRYPTED_DNS_CONFIG, ...(store.config.encryptedDns || {}) };
          if (typeof body.encryptedDns.dohEnabled === 'boolean') {
            curE.dohEnabled = body.encryptedDns.dohEnabled;
          }
          if (typeof body.encryptedDns.dotEnabled === 'boolean') {
            curE.dotEnabled = body.encryptedDns.dotEnabled;
          }
          if (typeof body.encryptedDns.dohHost === 'string' && body.encryptedDns.dohHost.trim()) {
            curE.dohHost = body.encryptedDns.dohHost.trim();
          }
          if (Number.isFinite(Number(body.encryptedDns.dohPort))) {
            curE.dohPort = Math.max(1, Math.min(65535, Number(body.encryptedDns.dohPort)));
          }
          if (Number.isFinite(Number(body.encryptedDns.dotPort))) {
            curE.dotPort = Math.max(1, Math.min(65535, Number(body.encryptedDns.dotPort)));
          }
          if (typeof body.encryptedDns.publicHostname === 'string') {
            const rawHost = body.encryptedDns.publicHostname.trim();
            curE.publicHostname = rawHost ? normalizePublicHostname(rawHost) || curE.publicHostname : '';
          }
          if (typeof body.encryptedDns.tlsCertPath === 'string') {
            curE.tlsCertPath = body.encryptedDns.tlsCertPath.trim();
          }
          if (typeof body.encryptedDns.tlsKeyPath === 'string') {
            curE.tlsKeyPath = body.encryptedDns.tlsKeyPath.trim();
          }
          if (Array.isArray(body.encryptedDns.iosExcludeSsids)) {
            curE.iosExcludeSsids = [
              ...new Set(body.encryptedDns.iosExcludeSsids.map((s) => String(s || '').trim()).filter(Boolean)),
            ];
          }
          store.config.encryptedDns = curE;
        }
        if (body.haSync && typeof body.haSync === 'object') {
          store.config.haSync = normalizeHaSyncConfig({
            ...(store.config.haSync || {}),
            ...body.haSync,
          });
          haSyncManager.reconfigure();
        }
        if (body.clearCache) {
          dnsCache.clear();
        }
        await store.save();
        return sendJson(res, 200, {
          config: store.config,
          cacheSize: dnsCache.size,
          upstreamHealth: getUpstreamHealth(),
        });
      }

      // 8b. Tải hồ sơ DNS mã hóa Apple (.mobileconfig) cho iOS / iPadOS / macOS
      if (method === 'GET' && pathname === '/api/mobile/ios-profile') {
        const enc = store.config.encryptedDns || {};
        const hostname = url.searchParams.get('hostname') || enc.publicHostname || '';
        const mode = url.searchParams.get('mode') === 'dot' ? 'dot' : 'doh';
        const excludeParam = url.searchParams.get('excludeSsids');
        const excludeSsids =
          excludeParam !== null
            ? excludeParam.split(',').map((s) => s.trim()).filter(Boolean)
            : enc.iosExcludeSsids || [];
        const addrsParam = url.searchParams.get('serverAddresses') || '';
        const serverAddresses = addrsParam.split(',').map((s) => s.trim()).filter(Boolean);
        try {
          const xml = buildIosMobileConfig({
            hostname,
            mode,
            excludeSsids,
            serverAddresses,
          });
          res.writeHead(200, {
            'Content-Type': 'application/x-apple-aspen-config; charset=utf-8',
            'Content-Disposition': `attachment; filename="netshield-dns-${mode}.mobileconfig"`,
            'Cache-Control': 'no-store',
          });
          res.end(xml);
          return;
        } catch (err) {
          return sendJson(res, 400, { error: err.message });
        }
      }

      // 8c. HA Secondary Sync API (đồng bộ nóng sang .209 & kiểm tra sức khỏe)
      if (method === 'POST' && pathname === '/api/ha/sync') {
        const body = await readJsonBody(req).catch(() => ({}));
        const syncBlocklistCache = body.syncBlocklistCache !== false;
        const result = await haSyncManager.syncNow({ syncBlocklistCache, trigger: 'manual' });
        return sendJson(res, result.ok ? 200 : 502, {
          ...result,
          haSyncStatus: haSyncManager.getStatus(),
        });
      }

      if (method === 'POST' && pathname === '/api/ha/health') {
        const result = await haSyncManager.checkSecondaryHealth();
        return sendJson(res, 200, {
          ...result,
          haSyncStatus: haSyncManager.getStatus(),
        });
      }

      // 9. Static UI
      if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
        const html = await fs.readFile(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
      }

      sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
      sendJson(res, 500, { error: err.message });
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const addr = server.address();
      const actualPort = typeof addr === 'object' && addr ? addr.port : port;
      resolve({
        host,
        port: actualPort,
        close: () =>
          new Promise((done) => {
            store.off('query', onQuery);
            for (const client of sseClients) client.end();
            sseClients.clear();
            server.close(() => done());
          }),
      });
    });
  });
}
