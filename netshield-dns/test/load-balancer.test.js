import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dnsPacket from 'dns-packet';
import {
  UpstreamLoadBalancer,
  LocalDnsLoadBalancer,
  normalizeLocalRecord,
  probeTcpEndpoint,
} from '../src/load-balancer.js';

function makeQuery(domain, type = 'A', id = 1234) {
  return dnsPacket.decode(
    dnsPacket.encode({
      type: 'query',
      id,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type, name: domain }],
    })
  );
}

describe('UpstreamLoadBalancer (4 chế độ)', () => {
  const upstreams = ['u1', 'u2', 'u3'];
  const dummyQuery = Buffer.from([0x00, 0x01]);

  it('failover: luôn ưu tiên upstream khỏe đầu tiên, chỉ chuyển khi lỗi hoặc circuit mở', async () => {
    const lb = new UpstreamLoadBalancer();
    const called = [];

    for (let i = 0; i < 3; i++) {
      const resp = await lb.forward(dummyQuery, {
        upstreams,
        strategy: 'failover',
        forwardSingle: async (_q, u) => {
          called.push(u);
          return Buffer.from(u);
        },
      });
      assert.equal(resp.toString(), 'u1');
    }
    assert.deepEqual(called, ['u1', 'u1', 'u1']);

    // Khi u1 mở circuit -> chuyển sang u2
    const resp2 = await lb.forward(dummyQuery, {
      upstreams,
      strategy: 'failover',
      isCircuitOpen: (u) => u === 'u1',
      forwardSingle: async (_q, u) => Buffer.from(u),
    });
    assert.equal(resp2.toString(), 'u2');
  });

  it('round_robin: xoay vòng chia đều qua các upstream khỏe và bỏ qua circuit mở', async () => {
    const lb = new UpstreamLoadBalancer();
    const picks = [];

    for (let i = 0; i < 6; i++) {
      const resp = await lb.forward(dummyQuery, {
        upstreams,
        strategy: 'round_robin',
        forwardSingle: async (_q, u) => Buffer.from(u),
      });
      picks.push(resp.toString());
    }
    assert.deepEqual(picks, ['u1', 'u2', 'u3', 'u1', 'u2', 'u3']);

    // Khi u2 mở circuit -> chỉ xoay giữa u1 và u3
    const picksWithOpen = [];
    for (let i = 0; i < 4; i++) {
      const resp = await lb.forward(dummyQuery, {
        upstreams,
        strategy: 'round_robin',
        isCircuitOpen: (u) => u === 'u2',
        forwardSingle: async (_q, u) => Buffer.from(u),
      });
      picksWithOpen.push(resp.toString());
    }
    assert.deepEqual(picksWithOpen, ['u1', 'u3', 'u1', 'u3']);
  });

  it('lowest_latency: ưu tiên upstream có EWMA thấp nhất và định kỳ thăm dò lại upstream khác', async () => {
    const lb = new UpstreamLoadBalancer();
    lb.recordLatency('u1', 80);
    lb.recordLatency('u2', 12);
    lb.recordLatency('u3', 45);

    const picks = [];
    for (let i = 0; i < 10; i++) {
      const resp = await lb.forward(dummyQuery, {
        upstreams,
        strategy: 'lowest_latency',
        forwardSingle: async (_q, u) => Buffer.from(u),
      });
      picks.push(resp.toString());
    }
    // 9 truy vấn đầu đi vào u2 (nhanh nhất), truy vấn thứ 10 thăm dò upstream khác
    assert.deepEqual(picks.slice(0, 9), Array(9).fill('u2'));
    assert.notEqual(picks[9], 'u2');
  });

  it('parallel: gửi đồng thời và trả về gói từ upstream phản hồi nhanh nhất', async () => {
    const lb = new UpstreamLoadBalancer();
    const delays = { u1: 90, u2: 15, u3: 60 };
    const started = [];

    const resp = await lb.forward(dummyQuery, {
      upstreams,
      strategy: 'parallel',
      forwardSingle: async (_q, u) => {
        started.push(u);
        await new Promise((r) => setTimeout(r, delays[u]));
        return Buffer.from(u);
      },
    });

    assert.equal(resp.toString(), 'u2');
    assert.deepEqual(started.sort(), ['u1', 'u2', 'u3']);
  });

  it('parallel: fallback sang openCircuit nếu toàn bộ healthy đều lỗi', async () => {
    const lb = new UpstreamLoadBalancer();
    const resp = await lb.forward(dummyQuery, {
      upstreams: ['u1', 'u2'],
      strategy: 'parallel',
      isCircuitOpen: (u) => u === 'u2',
      forwardSingle: async (_q, u) => {
        if (u === 'u1') throw new Error('boom');
        return Buffer.from('recovered-u2');
      },
    });
    assert.equal(resp.toString(), 'recovered-u2');
  });
});

describe('LocalDnsLoadBalancer (Round-Robin, Weighted & TCP Health Check)', () => {
  it('normalizeLocalRecord kiểm tra & chuẩn hóa đúng dữ liệu đầu vào', () => {
    const rec = normalizeLocalRecord({
      domain: ' App.LAN. ',
      ttl: 10,
      strategy: 'weighted',
      targets: [
        { ip: '192.168.1.10', weight: 3, healthPort: 80 },
        { ip: '192.168.1.10', weight: 1, healthPort: 80 }, // duplicate bị bỏ
        { ip: '192.168.1.11', weight: 1, healthPort: '' },
      ],
    });
    assert.equal(rec.domain, 'app.lan');
    assert.equal(rec.ttl, 10);
    assert.equal(rec.strategy, 'weighted');
    assert.equal(rec.targets.length, 2);
    assert.equal(rec.targets[0].healthPort, 80);
    assert.equal(rec.targets[1].healthPort, null);

    assert.throws(() => normalizeLocalRecord({ domain: 'bad domain!', targets: [{ ip: '1.2.3.4' }] }));
    assert.throws(() => normalizeLocalRecord({ domain: 'ok.lan', targets: [{ ip: 'not-an-ip' }] }));
  });

  it('round_robin: xoay thứ tự IP trả về mỗi lượt truy vấn', () => {
    const lb = new LocalDnsLoadBalancer();
    const records = [
      normalizeLocalRecord({
        domain: 'web.lan',
        ttl: 15,
        strategy: 'round_robin',
        targets: [{ ip: '192.168.1.10' }, { ip: '192.168.1.11' }, { ip: '192.168.1.12' }],
      }),
    ];

    const r1 = lb.resolve(makeQuery('web.lan', 'A', 1), records);
    const r2 = lb.resolve(makeQuery('web.lan', 'A', 2), records);
    const r3 = lb.resolve(makeQuery('web.lan', 'A', 3), records);
    const r4 = lb.resolve(makeQuery('web.lan', 'A', 4), records);

    assert.deepEqual(r1.ips, ['192.168.1.10', '192.168.1.11', '192.168.1.12']);
    assert.deepEqual(r2.ips, ['192.168.1.11', '192.168.1.12', '192.168.1.10']);
    assert.deepEqual(r3.ips, ['192.168.1.12', '192.168.1.10', '192.168.1.11']);
    assert.deepEqual(r4.ips, ['192.168.1.10', '192.168.1.11', '192.168.1.12']);

    const decoded = dnsPacket.decode(r1.buffer);
    assert.equal(decoded.id, 1);
    assert.equal(decoded.answers.length, 3);
    assert.equal(decoded.answers[0].ttl, 15);
    assert.equal(decoded.answers[0].data, '192.168.1.10');
  });

  it('weighted: phân phối Smooth Weighted Round-Robin đúng tỷ lệ 2:1', () => {
    const lb = new LocalDnsLoadBalancer();
    const records = [
      normalizeLocalRecord({
        domain: 'api.lan',
        strategy: 'weighted',
        targets: [
          { ip: '10.0.0.1', weight: 2 },
          { ip: '10.0.0.2', weight: 1 },
        ],
      }),
    ];

    const primaries = [];
    for (let i = 0; i < 6; i++) {
      const res = lb.resolve(makeQuery('api.lan', 'A', i + 1), records);
      primaries.push(res.ips[0]);
    }
    assert.deepEqual(primaries, ['10.0.0.1', '10.0.0.2', '10.0.0.1', '10.0.0.1', '10.0.0.2', '10.0.0.1']);
  });

  it('trả NODATA cho loại bản ghi khác (AAAA/HTTPS) trên domain nội bộ để không leak ra upstream', () => {
    const lb = new LocalDnsLoadBalancer();
    const records = [
      normalizeLocalRecord({
        domain: 'nas.lan',
        targets: [{ ip: '192.168.1.50' }],
      }),
    ];

    const aaaa = lb.resolve(makeQuery('nas.lan', 'AAAA', 99), records);
    assert.ok(aaaa);
    assert.deepEqual(aaaa.ips, []);
    const decoded = dnsPacket.decode(aaaa.buffer);
    assert.equal(decoded.answers.length, 0);

    const other = lb.resolve(makeQuery('google.com', 'A', 100), records);
    assert.equal(other, null);
  });

  it('TCP Health Check thật: tự loại IP chết khỏi DNS response và hồi phục khi sống lại', async () => {
    // Mở 1 TCP server thật làm backend sống, và 1 cổng đóng làm backend chết
    const aliveServer = net.createServer((s) => s.end());
    await new Promise((resolve) => aliveServer.listen(0, '127.0.0.1', resolve));
    const alivePort = aliveServer.address().port;

    const deadServer = net.createServer();
    await new Promise((resolve) => deadServer.listen(0, '127.0.0.1', resolve));
    const deadPort = deadServer.address().port;
    await new Promise((resolve) => deadServer.close(resolve));

    try {
      // Kiểm tra probeTcpEndpoint trực tiếp
      const okRes = await probeTcpEndpoint('127.0.0.1', alivePort, 500);
      assert.equal(okRes.ok, true);
      const failRes = await probeTcpEndpoint('127.0.0.1', deadPort, 500);
      assert.equal(failRes.ok, false);

      // Dùng probeFn giả lập 2 IP khác nhau trên cùng máy test
      const statusByIp = { '192.168.1.10': true, '192.168.1.11': false };
      const lb = new LocalDnsLoadBalancer({
        probeFn: async (ip) => ({
          ok: Boolean(statusByIp[ip]),
          latencyMs: statusByIp[ip] ? 1.2 : null,
          error: statusByIp[ip] ? null : 'ECONNREFUSED',
        }),
      });

      const records = [
        normalizeLocalRecord({
          domain: 'cluster.lan',
          targets: [
            { ip: '192.168.1.10', healthPort: 80 },
            { ip: '192.168.1.11', healthPort: 80 },
          ],
        }),
      ];

      await lb.runHealthChecks(records);
      const res1 = lb.resolve(makeQuery('cluster.lan', 'A', 1), records);
      assert.deepEqual(res1.ips, ['192.168.1.10']);
      assert.equal(res1.healthyCount, 1);

      // Khi cả 2 đều chết -> fallback trả đủ 2 IP để tránh mất phân giải hoàn toàn
      statusByIp['192.168.1.10'] = false;
      await lb.runHealthChecks(records);
      const resAllDead = lb.resolve(makeQuery('cluster.lan', 'A', 2), records);
      assert.equal(resAllDead.healthyCount, 0);
      assert.equal(resAllDead.ips.length, 2);

      // Khi 192.168.1.11 sống lại -> chỉ trả 192.168.1.11
      statusByIp['192.168.1.11'] = true;
      await lb.runHealthChecks(records);
      const resRecovered = lb.resolve(makeQuery('cluster.lan', 'A', 3), records);
      assert.deepEqual(resRecovered.ips, ['192.168.1.11']);
      assert.equal(resRecovered.healthyCount, 1);
    } finally {
      await new Promise((resolve) => aliveServer.close(resolve));
    }
  });
});
