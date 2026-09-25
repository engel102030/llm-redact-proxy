// The runtime controller: applies provider/mode changes in place, persists
// them, enforces the redaction-mode floor, and never exposes the key value.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRuntime } from '../src/runtime.js';
import { loadSettings } from '../src/settings.js';

function baseConfig(overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-rt-'));
  return {
    upstreamUrl: null,
    upstreamAuth: 'passthrough',
    upstreamKey: null,
    redactMode: 'strict',
    redactModeFloor: 'named-only',
    redactDisable: [],
    redactIgnore: [],
    configFile: path.join(dir, 'config.json'),
    ...overrides,
  };
}

test('starts with no provider when none configured', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  assert.equal(rt.upstream.url, null);
  assert.equal(rt.mode, 'strict');
});

test('apply sets the provider live and persists it', () => {
  const config = baseConfig();
  const rt = createRuntime({ config, secrets: [] });
  rt.apply({ upstreamUrl: 'https://prov.example/anthropic', upstreamAuth: 'passthrough' });
  assert.equal(rt.upstream.url.href, 'https://prov.example/anthropic');
  const persisted = loadSettings(config.configFile);
  assert.equal(persisted.upstreamUrl, 'https://prov.example/anthropic');
});

test('restoreMarkers is off by default, toggles live, persists, and gates on secrets', () => {
  const config = baseConfig();
  const rt = createRuntime({ config, secrets: [{ name: 'K', value: 'the-value-123456' }] });
  // default off
  assert.equal(rt.restoreMarkers, false);
  assert.equal(rt.getRestore().enabled, false);
  // turn on
  rt.apply({ restoreMarkers: true });
  assert.equal(rt.restoreMarkers, true);
  const r = rt.getRestore();
  assert.equal(r.enabled, true);
  assert.equal(r.map.get('K'), 'the-value-123456');
  assert.equal(loadSettings(config.configFile).restoreMarkers, true);
  assert.equal(rt.publicSettings().restoreMarkers, true);
});

test('restoreMarkers on but no secrets registered stays disabled (nothing to restore)', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  rt.apply({ restoreMarkers: true }, { persist: false });
  assert.equal(rt.restoreMarkers, true);
  assert.equal(rt.getRestore().enabled, false, 'no map -> effectively off');
});

test('persisted settings are loaded on boot over env defaults', () => {
  const config = baseConfig();
  createRuntime({ config, secrets: [] }).apply({ upstreamUrl: 'https://saved.example/v1' });
  const rt2 = createRuntime({ config, secrets: [] });
  assert.equal(rt2.upstream.url.href, 'https://saved.example/v1');
});

test('switching provider takes effect without rebuild', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  rt.apply({ upstreamUrl: 'https://a.example' });
  assert.equal(rt.upstream.url.host, 'a.example');
  rt.apply({ upstreamUrl: 'https://b.example' });
  assert.equal(rt.upstream.url.host, 'b.example');
});

test('replace auth requires a key', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  assert.throws(() => rt.apply({ upstreamUrl: 'https://p.example', upstreamAuth: 'replace' }), /key/);
  rt.apply({ upstreamUrl: 'https://p.example', upstreamAuth: 'replace', upstreamKey: 'k-123456' });
  assert.equal(rt.upstream.auth, 'replace');
});

test('publicSettings never exposes the key value', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  rt.apply({ upstreamUrl: 'https://p.example', upstreamAuth: 'replace', upstreamKey: 'super-secret-key-1' });
  const pub = rt.publicSettings();
  assert.equal(pub.hasKey, true);
  assert.equal(pub.upstreamKey, undefined);
  assert.ok(!JSON.stringify(pub).includes('super-secret-key-1'));
});

test('mode floor blocks lowering below it', () => {
  const rt = createRuntime({ config: baseConfig({ redactMode: 'strict', redactModeFloor: 'balanced' }), secrets: [] });
  assert.throws(() => rt.apply({ redactMode: 'named-only' }), /floor/);
  rt.apply({ redactMode: 'balanced' }); // at the floor is allowed
  assert.equal(rt.mode, 'balanced');
});

test('a floor above the starting mode is clamped up on boot is a config concern, runtime keeps given mode', () => {
  const rt = createRuntime({ config: baseConfig({ redactMode: 'balanced' }), secrets: [] });
  assert.equal(rt.mode, 'balanced');
});

test('disabled mode is blocked by the default floor, allowed when floor permits', () => {
  const blocked = createRuntime({ config: baseConfig({ redactModeFloor: 'named-only' }), secrets: [] });
  assert.throws(() => blocked.apply({ redactMode: 'disabled' }), /floor/);

  const allowed = createRuntime({ config: baseConfig({ redactModeFloor: 'disabled' }), secrets: [] });
  allowed.apply({ redactMode: 'disabled' });
  assert.equal(allowed.mode, 'disabled');
  // In disabled mode the redactor is a passthrough.
  const out = allowed.holder.current.redactBody(JSON.stringify({ c: 'leak-me-value-123' }), 'application/json');
  assert.ok(out.body.includes('leak-me-value-123'));
});

test('invalid upstream url is rejected', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  assert.throws(() => rt.apply({ upstreamUrl: 'ftp://nope.example' }), /http/);
});

test('a corrupt persisted config does not crash boot', () => {
  const config = baseConfig();
  fs.writeFileSync(config.configFile, '{ this is not json');
  const rt = createRuntime({ config, secrets: [] });
  assert.equal(rt.upstream.url, null); // fell back to defaults
});

test('setSecrets rebuilds the redactor with the new list', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  const before = rt.holder.current.redactBody(JSON.stringify({ c: 'my-secret-value-123 here' }), 'application/json');
  assert.ok(before.body.includes('my-secret-value-123'));
  rt.setSecrets([{ name: 'S', value: 'my-secret-value-123' }]);
  const after = rt.holder.current.redactBody(JSON.stringify({ c: 'my-secret-value-123 here' }), 'application/json');
  assert.ok(!after.body.includes('my-secret-value-123'));
  assert.ok(after.body.includes('[REDACTED:S]'));
});

// ---------------------------------------------------------------------------
// Codex (ChatGPT subscription) provider: guard, credential adapter, login
// ---------------------------------------------------------------------------
import { loadProviders } from '../src/providers.js';
import { fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

function codexConfig(providers) {
  const config = baseConfig({ upstreamAuth: 'replace', upstreamKey: null });
  config.providersFile = path.join(path.dirname(config.configFile), 'providers.json');
  config.redactDisable = [];
  config.redactIgnore = [];
  if (providers) fs.writeFileSync(config.providersFile, JSON.stringify(providers));
  return config;
}

const NOW = 1_700_000_000_000;
const login = (expSec) => ({
  tokens: { access: fakeAccessToken({ accountId: 'acc-1', expSec }), refresh: 'R1', idToken: fakeIdToken(), accountId: 'acc-1', expiresAt: expSec * 1000 },
  account: { email: 'me@example.com', plan: 'plus' },
  models: [{ slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium'] }],
  fetchedAt: 1,
});

test('codex-oauth is only accepted against chatgpt.com or loopback', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  assert.throws(() => rt.apply({ upstreamUrl: 'https://api.openai.com/v1', upstreamAuth: 'codex-oauth' }), /chatgpt\.com/);
  rt.apply({ upstreamUrl: 'https://chatgpt.com/backend-api/codex', upstreamAuth: 'codex-oauth' });
  assert.equal(rt.upstream.auth, 'codex-oauth');
  rt.apply({ upstreamUrl: 'http://127.0.0.1:1', upstreamAuth: 'codex-oauth' });
  assert.equal(rt.codexAdapter(), null); // no active codex provider in the registry
});

test('codexAdapter: fresh stored token is returned as-is; an expired one is refreshed and persisted', async () => {
  const config = codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth', codex: login(NOW / 1000 + 3600) } } });
  const calls = [];
  const request = async (url, opts) => {
    calls.push({ url, opts });
    return { status: 200, body: JSON.stringify({ access_token: fakeAccessToken({ accountId: 'acc-1', expSec: NOW / 1000 + 7200 }), refresh_token: 'R2' }) };
  };
  const rt = createRuntime({ config, secrets: [], codexDeps: { request, now: () => NOW } });
  assert.equal(rt.upstream.auth, 'codex-oauth');
  assert.equal(rt.upstream.url.href, 'https://chatgpt.com/backend-api/codex');
  const a = rt.codexAdapter();
  assert.deepEqual(a.profile().models.map((m) => m.slug), ['gpt-5.5']);
  assert.equal(a.profile().effortMap.high, 'xhigh');
  const c = await a.credentials();
  assert.equal(c.accountId, 'acc-1');
  assert.equal(calls.length, 0); // fresh: no refresh

  // expire it: credentials() refreshes and the file carries the rotated tokens
  fs.writeFileSync(config.providersFile, JSON.stringify({ active: 'codex', providers: { codex: { auth: 'codex-oauth', codex: login(NOW / 1000 - 10) } } }));
  const rt2 = createRuntime({ config, secrets: [], codexDeps: { request, now: () => NOW } });
  const c2 = await rt2.codexAdapter().credentials();
  assert.equal(calls.length, 1);
  assert.equal(JSON.parse(calls[0].opts.body).refresh_token, 'R1');
  assert.equal(c2.accountId, 'acc-1');
  const saved = loadProviders(config.providersFile);
  assert.equal(saved.providers.codex.codex.tokens.refresh, 'R2');
  assert.equal(saved.providers.codex.codex.tokens.expiresAt, (NOW / 1000 + 7200) * 1000);
  assert.equal(saved.providers.codex.codex.account.email, 'me@example.com'); // untouched by a refresh
  // forced refresh (after a backend 401) goes through the same path
  const c3 = await rt2.codexAdapter().refresh();
  assert.equal(calls.length, 2);
  assert.equal(c3.accountId, 'acc-1');
  // refresh failure -> null
  const rt3 = createRuntime({ config: codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth', codex: login(NOW / 1000 - 10) } } }), secrets: [], codexDeps: { request: async () => ({ status: 401, body: '' }), now: () => NOW } });
  assert.equal(await rt3.codexAdapter().credentials(), null);
  // not logged in -> null credentials, adapter still answers profile()
  const rt4 = createRuntime({ config: codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth' } } }), secrets: [] });
  assert.equal(await rt4.codexAdapter().credentials(), null);
  assert.equal(rt4.codexAdapter().profile().models, null);
});

test('codexLogin starts the listener and stores the result; codexLogout wipes it', async () => {
  const config = codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth' } } });
  const rt = createRuntime({
    config,
    secrets: [],
    codexDeps: {
      port: 0,
      now: () => NOW,
      exchange: async () => ({ access: fakeAccessToken({ accountId: 'acc-2' }), refresh: 'R9', idToken: fakeIdToken({ email: 'x@y.z' }) }),
      fetchModels: async () => [{ slug: 'gpt-5.6-sol', displayName: 'GPT-5.6-Sol', visibility: 'list', defaultLevel: 'low', levels: ['low'] }],
    },
  });
  await assert.rejects(rt.codexLogin('nope'), /unknown provider/);
  const { url, port } = await rt.codexLogin('codex');
  const state = new URL(url).searchParams.get('state');
  const res = await fetch(`http://127.0.0.1:${port}/auth/callback?code=c&state=${encodeURIComponent(state)}`);
  assert.equal(res.status, 200);
  let pub = rt.providers().providers[0];
  assert.deepEqual(pub.codex, { loggedIn: true, email: 'x@y.z', plan: 'plus', expiresAt: 4102444800000, models: ['gpt-5.6-sol'], limits: null });
  assert.equal(loadProviders(config.providersFile).providers.codex.codex.tokens.refresh, 'R9');
  pub = rt.codexLogout('codex').providers[0];
  assert.equal(pub.codex.loggedIn, false);
  assert.equal(loadProviders(config.providersFile).providers.codex.codex, null);
  rt.upsertProvider('plain', { auth: 'replace', key: 'k', url: 'https://x.y' });
  await assert.rejects(rt.codexLogin('plain'), /codex-oauth/);
});

test('concurrent credentials() calls near expiry share one in-flight refresh', async () => {
  const config = codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth', codex: login(NOW / 1000 - 10) } } });
  let calls = 0;
  const request = async () => {
    calls += 1;
    await new Promise((r) => setTimeout(r, 20));
    return { status: 200, body: JSON.stringify({ access_token: fakeAccessToken({ accountId: 'acc-1', expSec: NOW / 1000 + 7200 }), refresh_token: 'R-once' }) };
  };
  const rt = createRuntime({ config, secrets: [], codexDeps: { request, now: () => NOW } });
  const a = rt.codexAdapter();
  const [c1, c2, c3] = await Promise.all([a.credentials(), a.credentials(), rt.codexAdapter().refresh()]);
  assert.equal(calls, 1, 'one refresh for all concurrent callers');
  assert.equal(c1.accountId, 'acc-1');
  assert.deepEqual(c1, c2);
  assert.deepEqual(c1, c3);
  // the shared refresh is over: a later forced refresh is a new call
  await rt.codexAdapter().refresh();
  assert.equal(calls, 2);
});

test('the codex adapter profile carries the provider prune config', () => {
  const config = codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth', prune: { keepToolUses: 3 } } } });
  const rt = createRuntime({ config, secrets: [] });
  assert.equal(rt.codexAdapter().profile().prune.keepToolUses, 3);
  assert.equal(rt.codexAdapter().profile().prune.triggerTokens, 120000);
});

test('reported plan usage shows up in the public registry view for the codex provider (not persisted)', () => {
  const config = codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth', codex: login(NOW / 1000 + 3600) } } });
  const rt = createRuntime({ config, secrets: [], codexDeps: { now: () => NOW } });
  assert.equal(rt.providers().providers[0].codex.limits, null);
  rt.codexAdapter().reportLimits({ planType: 'prolite', activeLimit: 'premium', primary: { usedPercent: 58, windowMinutes: 10080, resetAt: NOW + 1000 }, secondary: null, credits: null, observedAt: NOW });
  const view = rt.providers().providers[0].codex.limits;
  assert.equal(view.primary.usedPercent, 58);
  assert.equal(view.planType, 'prolite');
  assert.equal('limits' in (loadProviders(config.providersFile).providers.codex.codex ?? {}), false);
});
