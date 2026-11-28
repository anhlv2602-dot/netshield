import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  HASyncManager,
  buildSecondaryPayload,
  buildSshArgs,
  normalizeHaSyncConfig,
} from '../src/ha-sync.js';

test('buildSecondaryPayload: ép cứng chống vòng lặp sync, chống spam Telegram & từ chối config hỏng', () => {
  const src = {
    upstreamDns: ['https://1.1.1.2/dns-query'],
    haSync: { enabled: true, autoSyncOnSave: true, secondaryHost: '192.168.1.209' },
    security: { activeLanSweep: true, antiBypass: true },
    alerts: { rogueDeviceEnabled: true, telegramBotToken: 'secret-token-123' },
  };
  const out = buildSecondaryPayload(src);

  assert.equal(out.haSync.enabled, false);
  assert.equal(out.haSync.autoSyncOnSave, false);
  assert.equal(out.security.activeLanSweep, false);
  assert.equal(out.security.antiBypass, true);
  assert.equal(out.alerts.rogueDeviceEnabled, false);
  assert.equal(out.alerts.telegramBotToken, '');

  // Không mutate object gốc
  assert.equal(src.haSync.enabled, true);
  assert.equal(src.alerts.telegramBotToken, 'secret-token-123');

  // Từ chối cấu hình hỏng (thiếu upstreamDns)
  assert.throws(() => buildSecondaryPayload({ upstreamDns: [] }), /upstreamDns/);
});

test('buildSshArgs: truyền tường minh key & timeout cho môi trường LaunchDaemon', () => {
  const cfg = normalizeHaSyncConfig({
    sshKeyPath: '/Users/anhlv2602/.ssh/id_ed25519',
    sshKnownHostsPath: '/Users/anhlv2602/.ssh/known_hosts',
  });
  const args = buildSshArgs(cfg);
  assert.ok(args.includes('BatchMode=yes'));
  assert.ok(args.includes('ConnectTimeout=4'));
  assert.ok(args.includes('-i'));
  assert.ok(args.includes('/Users/anhlv2602/.ssh/id_ed25519'));
  assert.ok(args.includes('UserKnownHostsFile=/Users/anhlv2602/.ssh/known_hosts'));
});

test('HASyncManager: sync nóng qua rsync + ssh curl & giám sát chống flapping + tự đồng bộ khi hồi phục', async () => {
  const calls = [];
  const alerts = [];
  let healthShouldFail = false;

  const mockRunner = async (cmd, args, opts) => {
    calls.push({ cmd, args, stdinText: opts?.stdinText || null });
    if (cmd === 'ssh' && args.some((a) => String(a).includes('/api/status'))) {
      if (healthShouldFail) throw new Error('Connection timed out');
      return { stdout: JSON.stringify({ totalBlockedDomains: 604793 }), stderr: '', code: 0 };
    }
    if (cmd === 'ssh' && args.some((a) => String(a).includes('/api/config/import'))) {
      return { stdout: JSON.stringify({ ok: true, devicesCount: 10 }), stderr: '', code: 0 };
    }
    return { stdout: '', stderr: '', code: 0 };
  };

  const fakeStore = new EventEmitter();
  fakeStore.config = {
    upstreamDns: ['https://1.1.1.2/dns-query'],
    haSync: {
      enabled: true,
      autoSyncOnSave: true,
      debounceSec: 2,
      healthCheckIntervalSec: 3600,
      secondaryHost: '192.168.1.209',
      secondaryUser: 'server-mac',
      alertOnOffline: true,
    },
    security: { activeLanSweep: true },
    alerts: { rogueDeviceEnabled: true, telegramBotToken: 'tok' },
  };
  const fakeAlertEngine = {
    recordAlert: (a) => alerts.push(a),
  };

  const mgr = new HASyncManager({ runner: mockRunner });
  mgr.start(fakeStore, fakeAlertEngine);

  try {
    // 1. Sync thủ công kèm blocklist cache
    const res = await mgr.syncNow({ syncBlocklistCache: true, trigger: 'manual' });
    assert.equal(res.ok, true);
    assert.equal(mgr.getStatus().state, 'ok');
    assert.equal(mgr.getStatus().syncCount, 1);

    const importCall = calls.find((c) => c.cmd === 'ssh' && c.stdinText);
    assert.ok(importCall);
    const sent = JSON.parse(importCall.stdinText);
    assert.equal(sent.haSync.enabled, false);
    assert.equal(sent.security.activeLanSweep, false);

    // 2. Chống flapping: lỗi 1 lần chưa báo offline, lỗi lần 2 mới báo 1 lần duy nhất
    healthShouldFail = true;
    await mgr.checkSecondaryHealth();
    assert.equal(alerts.length, 0);

    await mgr.checkSecondaryHealth();
    assert.equal(mgr.getStatus().secondaryHealthy, false);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].type, 'ha_secondary_offline');

    // Lỗi lần 3 không spam thêm cảnh báo
    await mgr.checkSecondaryHealth();
    assert.equal(alerts.length, 1);

    // 3. Hồi phục từ offline -> online tự động kích hoạt recovery sync
    healthShouldFail = false;
    const prevSyncCount = mgr.getStatus().syncCount;
    await mgr.checkSecondaryHealth();
    // Chờ microtask recovery sync hoàn tất
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(mgr.getStatus().secondaryHealthy, true);
    assert.equal(mgr.getStatus().syncCount, prevSyncCount + 1);
    assert.equal(mgr.getStatus().lastSyncTrigger, 'recovery');
  } finally {
    mgr.stop();
  }
});
