// Unit tests for the provider registry: normalize/validate, CRUD with active
// tracking, alias resolution + body rewrite, public view (no keys), persistence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  emptyRegistry,
  normalizeProvider,
  upsertProvider,
  removeProvider,
  setActive,
  activeProvider,
  resolveModel,
  applyAliasToBody,
  publicRegistry,
  loadProviders,
  saveProviders,
  setCodexAuth,
  clearCodexAuth,
} from '../src/providers.js';
import { fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

test('normalizeProvider validates url and auth, lowercases header keys', () => {
  const p = normalizeProvider({
    label: '  Euro  ',
    url: 'https://euromodels.xyz/anthropic',
    auth: 'replace',
    key: 'sk-1',
    headers: { 'User-Agent': 'Mozilla/5.0', Empty: '' },
    aliases: { 'claude-opus-4-8': 'accounts/euromodels/models/claude-opus-4-8', bad: 123 },
  });
  assert.equal(p.label, 'Euro');
  assert.equal(p.url, 'https://euromodels.xyz/anthropic');
  assert.equal(p.auth, 'replace');
  assert.equal(p.key, 'sk-1');
  assert.deepEqual(p.headers, { 'user-agent': 'Mozilla/5.0' }); // empty dropped
  assert.deepEqual(p.aliases, { 'claude-opus-4-8': 'accounts/euromodels/models/claude-opus-4-8' });
});

test('normalizeProvider rejects a non-http url and a bad auth', () => {
  assert.throws(() => normalizeProvider({ url: 'ftp://x.y' }), /http/);
  assert.throws(() => normalizeProvider({ url: 'https://x.y', auth: 'nope' }), /auth must be/);
});

test('upsertProvider adds, first becomes active, replace requires a key', () => {
  const reg = emptyRegistry();
  upsertProvider(reg, 'euro', { url: 'https://euromodels.xyz/anthropic', auth: 'replace', key: 'sk-1' });
  assert.equal(reg.active, 'euro');
  assert.equal(reg.providers.euro.key, 'sk-1');
  assert.throws(() => upsertProvider(reg, 'bad', { url: 'https://x.y', auth: 'replace' }), /requires a key/);
});

test('upsertProvider keeps the existing key when the update omits it', () => {
  const reg = emptyRegistry();
  upsertProvider(reg, 'euro', { url: 'https://a.b', auth: 'replace', key: 'sk-secret' });
  upsertProvider(reg, 'euro', { url: 'https://a.b/v2', auth: 'replace' }); // no key
  assert.equal(reg.providers.euro.key, 'sk-secret');
  assert.equal(reg.providers.euro.url, 'https://a.b/v2');
});

test('setActive / removeProvider maintain a valid active pointer', () => {
  const reg = emptyRegistry();
  upsertProvider(reg, 'a', { url: 'https://a', auth: 'passthrough' });
  upsertProvider(reg, 'b', { url: 'https://b', auth: 'passthrough' });
  assert.equal(reg.active, 'a');
  setActive(reg, 'b');
  assert.equal(reg.active, 'b');
  assert.throws(() => setActive(reg, 'ghost'), /unknown provider/);
  removeProvider(reg, 'b'); // active removed -> falls back
  assert.equal(reg.active, 'a');
  removeProvider(reg, 'a');
  assert.equal(reg.active, null);
});

test('resolveModel maps an alias and passes unknown models through', () => {
  const p = normalizeProvider({ aliases: { 'claude-opus-4-8': 'accounts/x/opus' } });
  assert.equal(resolveModel(p, 'claude-opus-4-8'), 'accounts/x/opus');
  assert.equal(resolveModel(p, 'claude-sonnet-5'), 'claude-sonnet-5');
  assert.equal(resolveModel(null, 'x'), 'x');
});

test('applyAliasToBody rewrites the model in a JSON body, else leaves it byte-identical', () => {
  const aliases = { 'claude-opus-4-8': 'accounts/x/opus' };
  const src = JSON.stringify({ model: 'claude-opus-4-8', max_tokens: 8, messages: [] });
  const { body, aliased } = applyAliasToBody(src, aliases);
  assert.equal(aliased, true);
  assert.equal(JSON.parse(body).model, 'accounts/x/opus');
  assert.equal(JSON.parse(body).max_tokens, 8);

  const noHit = JSON.stringify({ model: 'other' });
  assert.deepEqual(applyAliasToBody(noHit, aliases), { body: noHit, aliased: false });
  assert.deepEqual(applyAliasToBody('not json', aliases), { body: 'not json', aliased: false });
  assert.deepEqual(applyAliasToBody('{"model":"x"}', {}), { body: '{"model":"x"}', aliased: false });
});

test('publicRegistry hides key values but exposes hasKey', () => {
  const reg = emptyRegistry();
  upsertProvider(reg, 'euro', { url: 'https://a', auth: 'replace', key: 'sk-secret', aliases: { o: 'real' } });
  const pub = publicRegistry(reg);
  assert.equal(pub.active, 'euro');
  const p = pub.providers[0];
  assert.equal(p.id, 'euro');
  assert.equal(p.hasKey, true);
  assert.equal('key' in p, false);
  assert.deepEqual(p.aliases, { o: 'real' });
});

test('save/load round-trip preserves providers, active and aliases; chmod 600', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-'));
  const file = path.join(dir, 'providers.json');
  const reg = emptyRegistry();
  upsertProvider(reg, 'euro', {
    url: 'https://euromodels.xyz/anthropic', auth: 'replace', key: 'sk-1',
    headers: { 'user-agent': 'UA' }, aliases: { 'claude-opus-4-8': 'accounts/x/opus' },
  });
  upsertProvider(reg, 'nb', { url: 'https://api.neutralbeats.com', auth: 'replace', key: 'sk-2' });
  setActive(reg, 'nb');
  saveProviders(file, reg);

  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  const back = loadProviders(file);
  assert.equal(back.active, 'nb');
  assert.equal(back.providers.euro.aliases['claude-opus-4-8'], 'accounts/x/opus');
  assert.equal(back.providers.euro.headers['user-agent'], 'UA');
  assert.equal(back.providers.nb.key, 'sk-2');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('loadProviders returns null for a missing file and repairs a bad active pointer', () => {
  assert.equal(loadProviders('/nonexistent/xyz/providers.json'), null);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-'));
  const file = path.join(dir, 'providers.json');
  fs.writeFileSync(file, JSON.stringify({ active: 'ghost', providers: { real: { url: 'https://a', auth: 'passthrough' } } }));
  const reg = loadProviders(file);
  assert.equal(reg.active, 'real'); // ghost -> first real provider
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// codex-oauth records (ChatGPT subscription login)
// ---------------------------------------------------------------------------
const LOGIN = {
  tokens: { access: fakeAccessToken({ accountId: 'acc-1' }), refresh: 'R', idToken: fakeIdToken(), accountId: 'acc-1', expiresAt: 4102444800000 },
  account: { email: 'me@example.com', plan: 'plus' },
  models: [{ slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium'] }, { slug: 'gpt-reserve', visibility: 'hide', levels: [] }],
  fetchedAt: 1234,
};

test('codex-oauth provider: default url, effort map, sanitized login record', () => {
  const p = normalizeProvider({ auth: 'codex-oauth' });
  assert.equal(p.url, 'https://chatgpt.com/backend-api/codex');
  assert.deepEqual(p.effortMap, { low: 'low', medium: 'medium', high: 'xhigh', max: 'max' });
  assert.equal(p.codex, null);
  assert.equal(p.key, null);

  const q = normalizeProvider({ auth: 'codex-oauth', url: 'http://127.0.0.1:9', effortMap: { high: 'max', bogus: 'x', low: 7 }, codex: { ...LOGIN, extra: true, tokens: { ...LOGIN.tokens, junk: 1 } } });
  assert.equal(q.url, 'http://127.0.0.1:9');
  assert.deepEqual(q.effortMap, { low: 'low', medium: 'medium', high: 'max', max: 'max' });
  assert.deepEqual(Object.keys(q.codex).sort(), ['account', 'fetchedAt', 'models', 'tokens']);
  assert.deepEqual(Object.keys(q.codex.tokens).sort(), ['access', 'accountId', 'expiresAt', 'idToken', 'refresh']);
  assert.equal(q.codex.models.length, 2);
  assert.equal(q.codex.models[1].displayName, 'gpt-reserve');

  // other auth modes carry neither field
  const r = normalizeProvider({ auth: 'replace', key: 'k', url: 'https://x.y', codex: LOGIN, effortMap: { high: 'max' } });
  assert.equal(r.codex, null);
  assert.equal(r.effortMap, null);
});

test('upsert keeps the stored login when the form omits it; setCodexAuth merges; clearCodexAuth wipes', () => {
  const reg = emptyRegistry();
  upsertProvider(reg, 'codex', { auth: 'codex-oauth' });
  setCodexAuth(reg, 'codex', LOGIN);
  assert.equal(reg.providers.codex.codex.tokens.accountId, 'acc-1');
  // the dashboard form re-saves without a codex field (and a blank url)
  upsertProvider(reg, 'codex', { label: 'Codex', auth: 'codex-oauth', url: '' });
  assert.equal(reg.providers.codex.codex.tokens.accountId, 'acc-1');
  assert.equal(reg.providers.codex.url, 'https://chatgpt.com/backend-api/codex');
  assert.equal(reg.providers.codex.effortMap.high, 'xhigh');
  // a token refresh only touches tokens
  setCodexAuth(reg, 'codex', { tokens: { ...LOGIN.tokens, access: 'A2' } });
  assert.equal(reg.providers.codex.codex.tokens.access, 'A2');
  assert.equal(reg.providers.codex.codex.account.email, 'me@example.com');
  assert.equal(reg.providers.codex.codex.models.length, 2);
  assert.throws(() => setCodexAuth(reg, 'nope', LOGIN), /unknown provider/);
  upsertProvider(reg, 'plain', { auth: 'replace', key: 'k', url: 'https://x.y' });
  assert.throws(() => setCodexAuth(reg, 'plain', LOGIN), /not codex-oauth/);
  clearCodexAuth(reg, 'codex');
  assert.equal(reg.providers.codex.codex, null);
});

test('public view exposes login state and model slugs, never a token; round-trips through the file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-codex-'));
  const file = path.join(dir, 'providers.json');
  const reg = emptyRegistry();
  upsertProvider(reg, 'codex', { auth: 'codex-oauth' });
  setCodexAuth(reg, 'codex', LOGIN);
  const pub = publicRegistry(reg);
  const view = pub.providers[0];
  assert.deepEqual(view.codex, { loggedIn: true, email: 'me@example.com', plan: 'plus', expiresAt: 4102444800000, models: ['gpt-5.5'] });
  assert.deepEqual(view.effortMap, { low: 'low', medium: 'medium', high: 'xhigh', max: 'max' });
  const text = JSON.stringify(pub);
  assert.equal(text.includes(LOGIN.tokens.access), false);
  assert.equal(text.includes('"refresh"'), false);
  assert.equal(text.includes('"R"'), false);
  saveProviders(file, reg);
  const back = loadProviders(file);
  assert.equal(back.providers.codex.codex.tokens.refresh, 'R');
  assert.equal(back.providers.codex.codex.models[0].slug, 'gpt-5.5');
  assert.equal(publicRegistry(emptyRegistry()).providers.length, 0);
  const off = emptyRegistry();
  upsertProvider(off, 'codex', { auth: 'codex-oauth' });
  assert.deepEqual(publicRegistry(off).providers[0].codex, { loggedIn: false, email: null, plan: null, expiresAt: null, models: [] });
  fs.rmSync(dir, { recursive: true, force: true });
});
