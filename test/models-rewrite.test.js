// The proxy rewrites GET /v1/models to add "[1m]" context variants so a host
// that builds its model list from /v1/models (and can't know the upstream
// context window) can offer/select the 1M-context model. The liveness probe
// on HEAD/GET / is answered locally (no vendor 404).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createProxyServer } from '../src/proxy.js';
import { createStats } from '../src/stats.js';
import { createRedactor } from '../src/redact.js';

function upstreamServing(payload) {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(payload));
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

async function startProxyWith(upstreamUrl) {
  const config = {
    upstreamUrl: new URL(upstreamUrl),
    upstreamAuth: 'passthrough',
    upstreamKey: null,
    failClosed: true,
    injectNotice: true,
    redactMode: 'strict',
    redactModeFloor: 'named-only',
    redactDisable: [],
    redactIgnore: [],
  };
  const server = createProxyServer({ config, redactor: createRedactor({ secrets: [] }), stats: createStats({ log: () => {} }) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

test('GET /v1/models tags every id with [1m] except Haiku; names stay clean; no drops/dupes', async () => {
  const upstream = await upstreamServing({
    data: [
      { id: 'claude-opus-4-8', display_name: 'Claude Opus 4.8', type: 'model' },
      { id: 'claude-opus-4-7', display_name: 'Claude Opus 4.7', type: 'model' },
      { id: 'claude-sonnet-5', display_name: 'Claude Sonnet 5', type: 'model' },
      { id: 'claude-fable-5', display_name: 'Claude Fable 5', type: 'model' },
      { id: 'claude-sonnet-4-6', display_name: 'Claude Sonnet 4.6', type: 'model' },
      { id: 'claude-haiku-4-5-20251001', display_name: 'Claude Haiku 4.5', type: 'model' },
    ],
  });
  const proxy = await startProxyWith(upstream.url);
  try {
    const res = await fetch(`${proxy.url}/v1/models`);
    assert.equal(res.status, 200);
    const body = await res.json();
    const ids = body.data.map((m) => m.id);
    // same count as upstream (nothing dropped, nothing duplicated)
    assert.equal(ids.length, 6);
    // 1M families get the [1m] suffix
    assert.ok(ids.includes('claude-opus-4-8[1m]'));
    assert.ok(ids.includes('claude-opus-4-7[1m]'));
    assert.ok(ids.includes('claude-sonnet-5[1m]'));
    assert.ok(ids.includes('claude-fable-5[1m]'));
    // Haiku and Sonnet below 5 stay base (no 1M)
    assert.ok(ids.includes('claude-haiku-4-5-20251001'));
    assert.ok(!ids.includes('claude-haiku-4-5-20251001[1m]'));
    assert.ok(ids.includes('claude-sonnet-4-6'));
    assert.ok(!ids.includes('claude-sonnet-4-6[1m]'), 'sonnet 4.6 must not get [1m]');
    // display names untouched (clean)
    assert.equal(body.data.find((m) => m.id === 'claude-opus-4-8[1m]').display_name, 'Claude Opus 4.8');
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('HEAD / and GET / are answered locally with 200 (no vendor round-trip)', async () => {
  const upstream = await upstreamServing({ data: [] });
  const proxy = await startProxyWith(upstream.url);
  try {
    const head = await fetch(`${proxy.url}/`, { method: 'HEAD' });
    assert.equal(head.status, 200);
    const get = await fetch(`${proxy.url}/`);
    assert.equal(get.status, 200);
    const body = await get.json();
    assert.equal(body.status, 'ok');
  } finally {
    await proxy.close();
    await upstream.close();
  }
});
