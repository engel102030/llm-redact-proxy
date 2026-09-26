// End-to-end: a runtime with an active provider (aliases + custom headers)
// drives the proxy. The request model is rewritten alias -> real id, custom
// headers reach the upstream, /v1/models exposes the alias names, the dashboard
// CRUD endpoints manage the registry, and /__redact/reset clears counters.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../src/proxy.js';
import { createStats } from '../src/stats.js';
import { createRuntime } from '../src/runtime.js';
import { createMockUpstream } from './helpers/mock-upstream.js';

async function boot(upstreamUrl, providerOverrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reg-'));
  const config = {
    upstreamUrl: null,
    upstreamAuth: 'replace',
    upstreamKey: null,
    configFile: path.join(dir, 'config.json'),
    providersFile: path.join(dir, 'providers.json'),
    redactMode: 'strict',
    redactModeFloor: 'named-only',
    redactDisable: [],
    redactIgnore: [],
    failClosed: true,
    injectNotice: false,
    restoreMarkers: false,
    showRedactedValues: false,
  };
  fs.writeFileSync(
    config.providersFile,
    JSON.stringify({
      active: 'euro',
      providers: {
        euro: {
          url: upstreamUrl,
          auth: 'replace',
          key: 'up-key',
          headers: { 'user-agent': 'TestUA/1.0' },
          aliases: { 'claude-opus-4-8': 'accounts/euromodels/models/claude-opus-4-8' },
          ...providerOverrides,
        },
      },
    }),
  );
  const runtime = createRuntime({ config, secrets: [] });
  const server = createProxyServer({
    config,
    redactor: { redactBody: (raw, ct, opts) => runtime.holder.current.redactBody(raw, ct, opts) },
    stats: createStats({ log: () => {} }),
    getUpstream: () => runtime.upstream,
    controller: runtime,
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    runtime,
    close: async () => {
      await new Promise((r) => server.close(r));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

const panel = { 'content-type': 'application/json', 'x-redact-panel': '1' };

test('active provider rewrites model alias -> real id and adds custom headers', async () => {
  const up = await createMockUpstream();
  const app = await boot(up.url);
  try {
    await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'client' },
      body: JSON.stringify({ model: 'claude-opus-4-8', max_tokens: 8, messages: [{ role: 'user', content: 'hi' }] }),
    });
    const req = up.requests[0];
    assert.equal(JSON.parse(req.body).model, 'accounts/euromodels/models/claude-opus-4-8');
    assert.equal(req.headers['user-agent'], 'TestUA/1.0');
    assert.equal(req.headers['x-api-key'], 'up-key'); // replace auth from the provider
  } finally {
    await app.close();
    await up.close();
  }
});

test('a [1m]-tagged alias is stripped then mapped to the real id', async () => {
  const up = await createMockUpstream();
  const app = await boot(up.url);
  try {
    await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-opus-4-8[1m]', max_tokens: 8, messages: [] }),
    });
    assert.equal(JSON.parse(up.requests[0].body).model, 'accounts/euromodels/models/claude-opus-4-8');
  } finally {
    await app.close();
    await up.close();
  }
});

test('/v1/models returns the active provider aliases as clean names (no [1m])', async () => {
  const up = await createMockUpstream();
  const app = await boot(up.url);
  try {
    const j = await (await fetch(`${app.url}/v1/models`)).json();
    assert.deepEqual(j.data.map((m) => m.id), ['claude-opus-4-8']);
  } finally {
    await app.close();
    await up.close();
  }
});

test('dashboard registry endpoints: list, create, activate, CSRF guard, delete', async () => {
  const app = await boot('https://euromodels.xyz/anthropic');
  try {
    let reg = await (await fetch(`${app.url}/__redact/providers`)).json();
    assert.equal(reg.active, 'euro');
    assert.equal(reg.providers[0].id, 'euro');
    assert.equal('key' in reg.providers[0], false); // never exposes the key

    let d = await (
      await fetch(`${app.url}/__redact/providers`, {
        method: 'POST',
        headers: panel,
        body: JSON.stringify({ id: 'nb', url: 'https://api.neutralbeats.com', auth: 'replace', key: 'sk-nb' }),
      })
    ).json();
    assert.ok(d.ok);
    assert.ok(d.registry.providers.find((p) => p.id === 'nb'));

    d = await (
      await fetch(`${app.url}/__redact/providers/activate`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'nb' }) })
    ).json();
    assert.equal(d.registry.active, 'nb');
    assert.equal(app.runtime.upstream.url.href, 'https://api.neutralbeats.com/'); // live upstream switched

    const noCsrf = await fetch(`${app.url}/__redact/providers`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(noCsrf.status, 403);

    d = await (
      await fetch(`${app.url}/__redact/providers/delete`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'nb' }) })
    ).json();
    assert.equal(d.registry.active, 'euro'); // active removed -> falls back
  } finally {
    await app.close();
  }
});

test('/__redact/reset clears counters and the recent log', async () => {
  const up = await createMockUpstream();
  const app = await boot(up.url);
  try {
    await fetch(`${app.url}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'claude-opus-4-8', messages: [] }) });
    let s = await (await fetch(`${app.url}/__redact/stats.json`)).json();
    assert.ok(s.totals.requests >= 1);

    const r = await fetch(`${app.url}/__redact/reset`, { method: 'POST', headers: { 'x-redact-panel': '1' } });
    assert.equal(r.status, 200);
    s = await (await fetch(`${app.url}/__redact/stats.json`)).json();
    assert.equal(s.totals.requests, 0);
    assert.equal(s.recent.length, 0);

    const noCsrf = await fetch(`${app.url}/__redact/reset`, { method: 'POST' });
    assert.equal(noCsrf.status, 403);
  } finally {
    await app.close();
    await up.close();
  }
});
