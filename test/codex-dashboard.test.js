// Dashboard side of the Codex provider: creating a codex-oauth provider from
// the form, the login route (returns the authorize URL and stores the login
// after the callback), the logout route, the CSRF guard, and the panel HTML
// carrying the login controls. The public registry never carries a token.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../src/proxy.js';
import { createStats } from '../src/stats.js';
import { createRuntime } from '../src/runtime.js';
import { fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

const panel = { 'content-type': 'application/json', 'x-redact-panel': '1' };

async function boot({ exchange, fetchModels } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-dash-'));
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
  const runtime = createRuntime({
    config,
    secrets: [],
    codexDeps: {
      port: 0,
      exchange: exchange ?? (async () => ({ access: fakeAccessToken({ accountId: 'acc-5' }), refresh: 'R5', idToken: fakeIdToken({ email: 'dash@example.com' }) })),
      fetchModels: fetchModels ?? (async () => [{ slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low'] }]),
    },
  });
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
    providersFile: config.providersFile,
    close: async () => {
      await new Promise((r) => server.close(r));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

test('create a codex-oauth provider from the form, log in through the route, log out', async () => {
  const app = await boot();
  try {
    let d = await (await fetch(`${app.url}/__redact/providers`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'codex', auth: 'codex-oauth', url: '', headers: {}, aliases: {} }) })).json();
    assert.ok(d.ok);
    let p = d.registry.providers.find((x) => x.id === 'codex');
    assert.equal(p.url, 'https://chatgpt.com/backend-api/codex');
    assert.equal(p.auth, 'codex-oauth');
    assert.deepEqual(p.codex, { loggedIn: false, email: null, plan: null, expiresAt: null, models: [] });
    assert.equal(app.runtime.upstream.auth, 'codex-oauth'); // first provider becomes active

    const noCsrf = await fetch(`${app.url}/__redact/providers/codex/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'codex' }) });
    assert.equal(noCsrf.status, 403);

    const bad = await fetch(`${app.url}/__redact/providers/codex/login`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'missing' }) });
    assert.equal(bad.status, 400);

    d = await (await fetch(`${app.url}/__redact/providers/codex/login`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'codex' }) })).json();
    assert.ok(d.ok);
    assert.ok(d.url.startsWith('https://auth.openai.com/oauth/authorize?'));
    const state = new URL(d.url).searchParams.get('state');

    const busy = await fetch(`${app.url}/__redact/providers/codex/login`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'codex' }) });
    assert.equal(busy.status, 409);

    const cb = await fetch(`http://127.0.0.1:${d.port}/auth/callback?code=abc&state=${encodeURIComponent(state)}`);
    assert.equal(cb.status, 200);

    const reg = await (await fetch(`${app.url}/__redact/providers`)).json();
    p = reg.providers.find((x) => x.id === 'codex');
    assert.deepEqual(p.codex, { loggedIn: true, email: 'dash@example.com', plan: 'plus', expiresAt: 4102444800000, models: ['gpt-5.5'] });
    const text = JSON.stringify(reg);
    assert.equal(text.includes('R5'), false);
    assert.equal(text.includes(fakeAccessToken({ accountId: 'acc-5' })), false);
    assert.equal(JSON.parse(fs.readFileSync(app.providersFile, 'utf8')).providers.codex.codex.tokens.refresh, 'R5');

    // the live proxy now serves the plan's models locally
    const models = await (await fetch(`${app.url}/v1/models`)).json();
    assert.deepEqual(models.data.map((m) => m.id), ['gpt-5.5']);

    d = await (await fetch(`${app.url}/__redact/providers/codex/logout`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'codex' }) })).json();
    assert.ok(d.ok);
    assert.equal(d.registry.providers.find((x) => x.id === 'codex').codex.loggedIn, false);
    const noCsrfOut = await fetch(`${app.url}/__redact/providers/codex/logout`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'codex' }) });
    assert.equal(noCsrfOut.status, 403);
  } finally {
    await app.close();
  }
});

test('the panel HTML carries the codex-oauth option and the login controls', async () => {
  const app = await boot();
  try {
    const html = await (await fetch(`${app.url}/__redact/`)).text();
    assert.ok(html.includes('id="p_codexlogin"'));
    assert.ok(html.includes('id="p_codexlogout"'));
    assert.ok(html.includes('id="codexstatus"'));
    assert.ok((html.match(/value="codex-oauth"/g) ?? []).length >= 2); // top form + editor
    assert.ok(html.includes("providers/codex/login"));
  } finally {
    await app.close();
  }
});
