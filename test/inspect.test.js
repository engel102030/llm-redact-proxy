// Debug inspector: the proxy keeps the full forwarded request (already redacted)
// and the raw upstream response for the last 30 requests, served only over the
// CSRF-guarded /__redact/inspect endpoint. Neither body holds a user secret.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createStats } from '../src/stats.js';
import { createRuntime } from '../src/runtime.js';
import { createProxyServer } from '../src/proxy.js';
import { createMockUpstream } from './helpers/mock-upstream.js';

const SECRET = 'canary-inspect-value-7777';

test('stats keeps request/response bodies for the last 30 only, out of the open feed', () => {
  const stats = createStats({ log: () => {} });
  for (let i = 1; i <= 35; i += 1) {
    const e = stats.record({ method: 'POST', path: '/v1/messages', events: [] });
    stats.rememberReq(e.id, `req-${i}`);
    stats.rememberResp(e.id, `resp-${i}`);
  }
  // oldest evicted: ids 1..5 gone, 6..35 kept (30)
  assert.equal(stats.getBodies(5), null, 'older than the last 30 is dropped');
  assert.deepEqual(stats.getBodies(35), { req: 'req-35', resp: 'resp-35' });
  assert.deepEqual(stats.getBodies(6), { req: 'req-6', resp: 'resp-6' });
  // never leaks into the open feed
  const open = JSON.stringify(stats.toJSON());
  assert.ok(!open.includes('resp-35') && !open.includes('req-35'), 'bodies stay out of stats.json');
});

test('rememberReq stores the body in FULL (no truncation)', () => {
  const stats = createStats({ log: () => {} });
  const big = 'x'.repeat(2 * 1024 * 1024); // 2 MB
  const e = stats.record({ method: 'POST', path: '/v1/messages', events: [] });
  stats.rememberReq(e.id, big);
  assert.equal(stats.getBodies(e.id).req.length, big.length, 'kept complete, uncapped');
});

function tmpConfig(url) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-inspect-'));
  return {
    upstreamUrl: new URL(url),
    upstreamAuth: 'passthrough',
    upstreamKey: null,
    failClosed: true,
    injectNotice: false,
    redactMode: 'strict',
    redactModeFloor: 'named-only',
    redactDisable: [],
    redactIgnore: [],
    restoreMarkers: false,
    showRedactedValues: false,
    configFile: path.join(dir, 'config.json'),
  };
}

async function boot(url) {
  const config = tmpConfig(url);
  const runtime = createRuntime({ config, secrets: [{ name: 'CANARY_KEY', value: SECRET }] });
  const stats = createStats({ log: () => {} });
  const server = createProxyServer({
    config,
    redactor: { redactBody: (raw, ct, opts) => runtime.holder.current.redactBody(raw, ct, opts) },
    stats,
    getUpstream: () => runtime.upstream,
    controller: runtime,
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

test('e2e: /__redact/inspect returns the redacted request + raw response, guarded', async () => {
  const upstream = await createMockUpstream({ response: { ok: true, note: 'vendor-reply' } });
  const app = await boot(upstream.url);
  try {
    await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ messages: [{ role: 'user', content: `my key is ${SECRET}` }] }),
    });

    // missing guard header -> 403
    const noHdr = await fetch(`${app.url}/__redact/inspect?id=1`);
    assert.equal(noHdr.status, 403);

    const d = await (await fetch(`${app.url}/__redact/inspect?id=1`, { headers: { 'x-redact-panel': '1' } })).json();
    // request captured is the REDACTED one - secret absent, marker present
    assert.ok(!d.req.includes(SECRET), 'stored request must not contain the secret');
    assert.ok(d.req.includes('[REDACTED:CANARY_KEY]'), 'stored request is the redacted body');
    // response captured is the vendor reply
    assert.ok(d.resp.includes('vendor-reply'), 'raw response captured');

    // unknown id -> 404
    const missing = await fetch(`${app.url}/__redact/inspect?id=999`, { headers: { 'x-redact-panel': '1' } });
    assert.equal(missing.status, 404);
  } finally {
    await app.close();
    await upstream.close();
  }
});
