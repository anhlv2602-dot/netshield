import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { ROOT_DIR, SERVICE_PRESETS, normalizeDomain, store } from './store.js';
import { blocklistEngine } from './blocklist.js';
import { dnsCache } from './dns-server.js';

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

export function startWebServer({ host = '127.0.0.1', port = 8080, dnsPort = 5335 } = {}) {
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
          cacheSize: dnsCache.size,
          totalBlockedDomains: blocklistEngine.getTotalBlockedDomains(),
          isUpdatingBlocklists: blocklistEngine.isUpdating,
          summary: store.getSummary(),
          config: store.config,
          servicePresets: SERVICE_PRESETS,
        });
      }

      // 3. Query logs
      if (method === 'GET' && pathname === '/api/logs') {
        const limit = Math.min(500, Number(url.searchParams.get('limit')) || 150);
        const search = (url.searchParams.get('search') || '').trim().toLowerCase();
        const filter = url.searchParams.get('filter') || 'all'; // all | blocked | allowed

        let items = store.logs;
        if (filter === 'blocked') items = items.filter((i) => i.blocked);
        if (filter === 'allowed') items = items.filter((i) => !i.blocked);
        if (search) {
          items = items.filter(
            (i) =>
              i.domain.includes(search) ||
              i.clientIp.includes(search) ||
              (i.reason || '').toLowerCase().includes(search)
          );
        }
        return sendJson(res, 200, { items: items.slice(0, limit) });
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
        return sendJson(res, 200, { domain, clientIp, ...decision });
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

      // 7. Client Rules & Schedules
      if (method === 'POST' && pathname === '/api/clients') {
        const body = await readJsonBody(req);
        const clientIp = (body.clientIp || '').trim();
        if (!clientIp) return sendJson(res, 400, { error: 'Cần nhập địa chỉ IP thiết bị (hoặc * cho toàn mạng)' });

        const rule = {
          id: body.id || `rule-${Date.now()}`,
          name: (body.name || clientIp).trim(),
          clientIp,
          enabled: body.enabled !== false,
          bypassProtection: Boolean(body.bypassProtection),
          blockAllInternet: Boolean(body.blockAllInternet),
          blockedServices: Array.isArray(body.blockedServices) ? body.blockedServices : [],
          blockedDomains: Array.isArray(body.blockedDomains)
            ? body.blockedDomains.map(normalizeDomain).filter(Boolean)
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

      // 8. Settings
      if (method === 'POST' && pathname === '/api/settings') {
        const body = await readJsonBody(req);
        if (Array.isArray(body.upstreamDns) && body.upstreamDns.length > 0) {
          store.config.upstreamDns = body.upstreamDns.map((s) => s.trim()).filter(Boolean);
        }
        if (body.blockResponseMode === 'zero' || body.blockResponseMode === 'nxdomain') {
          store.config.blockResponseMode = body.blockResponseMode;
        }
        if (body.clearCache) {
          dnsCache.clear();
        }
        await store.save();
        return sendJson(res, 200, { config: store.config, cacheSize: dnsCache.size });
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
      resolve({
        host,
        port,
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
