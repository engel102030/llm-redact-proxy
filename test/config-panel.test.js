// End-to-end for the dashboard config API: the server starts with no provider,
// serves the panel, accepts a provider via POST /__redact/config (CSRF-guarded),
// then forwards live to it. No restart, no env, no file editing.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createMockUpstream } from './helpers/mock-upstream.js';
import { createProxyServer } from '../src/proxy.js';
import { createStats } from '../src/stats.js';
import { createRuntime } from '../src/runtime.js';

function makeConfig() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-panel-'));
  return {
    listenHost: '127.0.0.1',
    listenPort: 0,
    upstreamUrl: null,
    upstreamAuth: 'passthrough',
    upstreamKey: null,
    failClosed: true,
    injectNotice: true,
    redactMode: 'strict',
    redactModeFloor: 'named-only',
    redactDisable: [],
    redactIgnore: [],
    configFile: path.join(dir, 'config.json'),
  };
}

async function boot(config) {
  const runtime = createRuntime({ config, secrets: [{ name: 'PANEL_SECRET', value: 'panel-secret-value-123' }] });
  const stats = createStats({ log: () => {} });
  const liveRedactor = { redactBody: (raw, ct) => runtime.holder.current.redactBody(raw, ct) };
  const server = createProxyServer({
    config,
    redactor: liveRedactor,
    stats,
    getUpstream: () => runtime.upstream,
    controller: runtime,
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return { runtime, server, url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

test('no provider configured -> proxy request returns 503, panel still served', async () => {
  const app = await boot(makeConfig());
  try {
    const res = await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hi: 1 }),
    });
    assert.equal(res.status, 503);
    const panel = await fetch(`${app.url}/__redact/`);
    assert.equal(panel.status, 200);
    const cfg = await (await fetch(`${app.url}/__redact/config`)).json();
    assert.equal(cfg.upstreamUrl, null);
  } finally {
    await app.close();
  }
});

test('POST config sets the provider and traffic forwards live', async () => {
  const upstream = await createMockUpstream();
  const app = await boot(makeConfig());
  try {
    const save = await fetch(`${app.url}/__redact/config`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-redact-panel': '1' },
      body: JSON.stringify({ upstreamUrl: upstream.url, upstreamAuth: 'passthrough' }),
    });
    const saved = await save.json();
    assert.equal(saved.ok, true);
    assert.equal(saved.settings.upstreamUrl, `${upstream.url}/`.replace(/\/\/$/, '/'));

    const res = await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: 'here is panel-secret-value-123 ok' }),
    });
    assert.equal(res.status, 200);
    assert.equal(upstream.requests.length, 1);
    assert.ok(!upstream.requests[0].body.includes('panel-secret-value-123'), 'secret leaked upstream');
    assert.ok(upstream.requests[0].body.includes('[REDACTED:PANEL_SECRET]'));
  } finally {
    await app.close();
    await upstream.close();
  }
});

test('POST config without the panel header is rejected (CSRF guard)', async () => {
  const app = await boot(makeConfig());
  try {
    const res = await fetch(`${app.url}/__redact/config`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ upstreamUrl: 'https://evil.example' }),
    });
    assert.equal(res.status, 403);
    const cfg = await (await fetch(`${app.url}/__redact/config`)).json();
    assert.equal(cfg.upstreamUrl, null, 'provider must not have changed');
  } finally {
    await app.close();
  }
});

test('switching provider from the panel routes to the new upstream', async () => {
  const up1 = await createMockUpstream({ response: { who: 'one' } });
  const up2 = await createMockUpstream({ response: { who: 'two' } });
  const app = await boot(makeConfig());
  const post = (body) =>
    fetch(`${app.url}/__redact/config`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-redact-panel': '1' },
      body: JSON.stringify(body),
    });
  try {
    await post({ upstreamUrl: up1.url });
    await fetch(`${app.url}/v1/x`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(up1.requests.length, 1);

    await post({ upstreamUrl: up2.url });
    await fetch(`${app.url}/v1/x`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(up2.requests.length, 1);
    assert.equal(up1.requests.length, 1, 'old provider should get no new traffic');
  } finally {
    await app.close();
    await up1.close();
    await up2.close();
  }
});

test('config POST enforces the redaction-mode floor', async () => {
  const config = makeConfig();
  config.redactMode = 'strict';
  config.redactModeFloor = 'balanced';
  const app = await boot(config);
  try {
    const res = await fetch(`${app.url}/__redact/config`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-redact-panel': '1' },
      body: JSON.stringify({ redactMode: 'named-only' }),
    });
    assert.equal(res.status, 400);
    const d = await res.json();
    assert.match(d.error, /floor/);
  } finally {
    await app.close();
  }
});
