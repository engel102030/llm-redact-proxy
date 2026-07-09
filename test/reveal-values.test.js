// Opt-in value reveal: the redactor can capture the ACTUAL matched values, the
// stats store keeps them out of the open feed, and the dashboard serves them
// only over the CSRF-guarded /__redact/values endpoint when enabled.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRedactor } from '../src/redact.js';
import { createStats } from '../src/stats.js';
import { createRuntime } from '../src/runtime.js';
import { createProxyServer } from '../src/proxy.js';
import { createMockUpstream } from './helpers/mock-upstream.js';

const SECRET = 'canary-secret-value-9999';
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrstuv';

test('redactor captures matched values only when captureValues is set', () => {
  const r = createRedactor({ secrets: [{ name: 'CANARY_KEY', value: SECRET }], mode: 'strict' });
  const body = JSON.stringify({ messages: [{ role: 'user', content: `key ${SECRET} tok ${JWT}` }] });

  const off = r.redactBody(body, 'application/json');
  assert.deepEqual(off.captures, [], 'no values retained by default');

  const on = r.redactBody(body, 'application/json', { captureValues: true });
  const byRule = Object.fromEntries(on.captures.map((c) => [c.rule, c.value]));
  assert.equal(byRule.CANARY_KEY, SECRET, 'Layer A value captured');
  assert.equal(byRule.jwt, JWT, 'Layer B value captured');
});

test('stats keeps captures OUT of the open feed but serves them via revealValues', () => {
  const stats = createStats({ log: () => {} });
  const entry = stats.record({
    method: 'POST',
    path: '/v1/messages',
    events: [{ rule: 'CANARY_KEY', count: 1 }],
    captures: [{ rule: 'CANARY_KEY', value: SECRET }],
  });
  stats.finish(entry, { status: 200 });

  const open = JSON.stringify(stats.toJSON());
  assert.ok(!open.includes(SECRET), 'open stats feed must never contain the value');
  assert.equal(stats.toJSON().recent[0].captures, undefined, 'captures stripped from the feed');

  const reveal = stats.revealValues();
  assert.equal(reveal.recent[0].captures[0].value, SECRET, 'reveal exposes the value');
  assert.deepEqual(reveal.perRuleValues.CANARY_KEY, [SECRET]);
});

function tmpConfig(url) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-reveal-'));
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

async function boot(url, { showValues }) {
  const config = tmpConfig(url);
  const runtime = createRuntime({ config, secrets: [{ name: 'CANARY_KEY', value: SECRET }] });
  runtime.apply({ showRedactedValues: showValues }, { persist: false });
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

async function sendSecret(base) {
  await fetch(`${base}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ messages: [{ role: 'user', content: `key ${SECRET}` }] }),
  });
}

test('/__redact/values reveals captured values only when enabled AND with the guard header', async () => {
  const upstream = await createMockUpstream();
  const app = await boot(upstream.url, { showValues: true });
  try {
    await sendSecret(app.url);

    // open feed never carries the value
    const feed = await (await fetch(`${app.url}/__redact/stats.json`)).text();
    assert.ok(!feed.includes(SECRET), 'stats.json must not contain the value');

    // missing guard header -> 403
    const noHdr = await fetch(`${app.url}/__redact/values`);
    assert.equal(noHdr.status, 403);

    // guarded + enabled -> value revealed
    const ok = await (await fetch(`${app.url}/__redact/values`, { headers: { 'x-redact-panel': '1' } })).json();
    assert.equal(ok.enabled, true);
    assert.deepEqual(ok.perRuleValues.CANARY_KEY, [SECRET]);
  } finally {
    await app.close();
    await upstream.close();
  }
});

test('/__redact/values stays empty when the toggle is off (nothing retained)', async () => {
  const upstream = await createMockUpstream();
  const app = await boot(upstream.url, { showValues: false });
  try {
    await sendSecret(app.url);
    const d = await (await fetch(`${app.url}/__redact/values`, { headers: { 'x-redact-panel': '1' } })).json();
    assert.equal(d.enabled, false);
    assert.deepEqual(d.perRuleValues, {});
    assert.deepEqual(d.recent, []);
  } finally {
    await app.close();
    await upstream.close();
  }
});
