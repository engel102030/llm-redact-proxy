// OAuth helpers for the ChatGPT Codex backend: PKCE, authorize URL, code
// exchange, refresh, claim parsing, host guard, request headers, model list.
// Every network call is injected; no test touches the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  createPkce,
  buildAuthorizeUrl,
  exchangeCode,
  refreshTokens,
  decodeJwtClaims,
  accountFromTokens,
  tokensFresh,
  isCodexHost,
  isLoopbackHost,
  codexRequestHeaders,
  fetchCodexModels,
  normalizeCodexModels,
  CODEX_CLIENT_ID,
  CODEX_REDIRECT_URI,
  CODEX_DEFAULT_BASE_URL,
  REFRESH_SKEW_MS,
} from '../src/codex-auth.js';
import { fakeJwt, fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

test('PKCE: S256 challenge of the verifier, fresh state each time', () => {
  const a = createPkce();
  const b = createPkce();
  assert.equal(a.challenge, b64url(createHash('sha256').update(a.verifier).digest()));
  assert.ok(a.verifier.length >= 43 && /^[A-Za-z0-9_-]+$/.test(a.verifier));
  assert.notEqual(a.state, b.state);
  assert.notEqual(a.verifier, b.verifier);
});

test('authorize URL carries the Codex client id, fixed redirect, scope, PKCE and state', () => {
  const u = new URL(buildAuthorizeUrl({ state: 'st', challenge: 'ch' }));
  assert.equal(`${u.origin}${u.pathname}`, 'https://auth.openai.com/oauth/authorize');
  const p = u.searchParams;
  assert.equal(p.get('response_type'), 'code');
  assert.equal(p.get('client_id'), CODEX_CLIENT_ID);
  assert.equal(p.get('redirect_uri'), CODEX_REDIRECT_URI);
  assert.equal(CODEX_REDIRECT_URI, 'http://localhost:1455/auth/callback');
  assert.equal(p.get('scope'), 'openid profile email offline_access');
  assert.equal(p.get('code_challenge'), 'ch');
  assert.equal(p.get('code_challenge_method'), 'S256');
  assert.equal(p.get('state'), 'st');
  assert.equal(p.get('id_token_add_organizations'), 'true');
  assert.equal(p.get('codex_cli_simplified_flow'), 'true');
  assert.equal(p.get('originator'), 'codex_cli_rs');
});

test('exchangeCode posts the form grant and parses tokens; failures throw without the code in the message', async () => {
  const calls = [];
  const request = async (url, opts) => {
    calls.push({ url, opts });
    return { status: 200, body: JSON.stringify({ access_token: 'A', refresh_token: 'R', id_token: 'I' }) };
  };
  const t = await exchangeCode({ code: 'c0de', verifier: 'v', request });
  assert.deepEqual(t, { access: 'A', refresh: 'R', idToken: 'I' });
  assert.equal(calls[0].url, 'https://auth.openai.com/oauth/token');
  assert.equal(calls[0].opts.method, 'POST');
  assert.equal(calls[0].opts.headers['content-type'], 'application/x-www-form-urlencoded');
  const form = new URLSearchParams(calls[0].opts.body);
  assert.equal(form.get('grant_type'), 'authorization_code');
  assert.equal(form.get('code'), 'c0de');
  assert.equal(form.get('code_verifier'), 'v');
  assert.equal(form.get('client_id'), CODEX_CLIENT_ID);
  assert.equal(form.get('redirect_uri'), CODEX_REDIRECT_URI);
  await assert.rejects(exchangeCode({ code: 'c0de', verifier: 'v', request: async () => ({ status: 400, body: '{}' }) }), (e) => /HTTP 400/.test(e.message) && !e.message.includes('c0de'));
  await assert.rejects(exchangeCode({ code: 'c0de', verifier: 'v', request: async () => ({ status: 200, body: '{"nope":1}' }) }), /no access token/);
});

test('refreshTokens: JSON grant, keeps the old refresh token when none is rotated, form fallback on 400, null on failure', async () => {
  const calls = [];
  const ok = async (url, opts) => {
    calls.push(opts);
    return { status: 200, body: JSON.stringify({ access_token: 'A2', id_token: 'I2' }) };
  };
  assert.deepEqual(await refreshTokens({ refreshToken: 'R1', request: ok }), { access: 'A2', refresh: 'R1', idToken: 'I2' });
  assert.equal(calls[0].headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(calls[0].body), { client_id: CODEX_CLIENT_ID, grant_type: 'refresh_token', refresh_token: 'R1', scope: 'openid profile email' });

  const fallback = [];
  const rejectsJson = async (url, opts) => {
    fallback.push(opts.headers['content-type']);
    if (opts.headers['content-type'] === 'application/json') return { status: 400, body: 'unsupported' };
    return { status: 200, body: JSON.stringify({ access_token: 'A3', refresh_token: 'R3' }) };
  };
  assert.deepEqual(await refreshTokens({ refreshToken: 'R1', request: rejectsJson }), { access: 'A3', refresh: 'R3', idToken: '' });
  assert.deepEqual(fallback, ['application/json', 'application/x-www-form-urlencoded']);

  assert.equal(await refreshTokens({ refreshToken: 'R1', request: async () => ({ status: 401, body: '{}' }) }), null);
  assert.equal(await refreshTokens({ refreshToken: 'R1', request: async () => { throw new Error('net'); } }), null);
  assert.equal(await refreshTokens({ refreshToken: '', request: ok }), null);
});

test('accountFromTokens reads account id, plan, email and expiry from the claims', () => {
  const access = fakeAccessToken({ accountId: 'acc-9', plan: 'pro', expSec: 1800000000 });
  const idToken = fakeIdToken({ email: 'me@example.com' });
  assert.deepEqual(accountFromTokens({ access, idToken }), { accountId: 'acc-9', email: 'me@example.com', plan: 'pro', expiresAt: 1800000000000 });
  assert.deepEqual(accountFromTokens({ access: 'garbage', idToken: '' }), { accountId: null, email: null, plan: null, expiresAt: null });
  assert.equal(decodeJwtClaims('garbage'), null);
  assert.deepEqual(decodeJwtClaims(fakeJwt({ a: 1 })), { a: 1 });
});

test('tokensFresh applies the 5 minute skew and trusts an unknown expiry', () => {
  const now = 1_000_000_000_000;
  assert.equal(tokensFresh({ access: 'A', expiresAt: now + REFRESH_SKEW_MS + 1 }, now), true);
  assert.equal(tokensFresh({ access: 'A', expiresAt: now + REFRESH_SKEW_MS - 1 }, now), false);
  assert.equal(tokensFresh({ access: 'A', expiresAt: null }, now), true);
  assert.equal(tokensFresh({ access: '', expiresAt: null }, now), false);
  assert.equal(tokensFresh(null, now), false);
});

test('host guard: chatgpt.com and its subdomains, loopback for tests, nothing else', () => {
  assert.equal(isCodexHost(new URL('https://chatgpt.com/backend-api/codex')), true);
  assert.equal(isCodexHost(new URL('https://api.chatgpt.com/x')), true);
  assert.equal(isCodexHost(new URL('https://chatgpt.com.evil.example/')), false);
  assert.equal(isCodexHost(new URL('https://api.openai.com/')), false);
  assert.equal(isLoopbackHost(new URL('http://127.0.0.1:1234')), true);
  assert.equal(isLoopbackHost(new URL('http://localhost:1234')), true);
  assert.equal(isLoopbackHost(new URL('https://chatgpt.com')), false);
  assert.equal(CODEX_DEFAULT_BASE_URL, 'https://chatgpt.com/backend-api/codex');
});

test('request headers carry the exact backend contract', () => {
  const h = codexRequestHeaders({ access: 'TOK', accountId: 'acc-1', sessionId: 'sess' });
  assert.equal(h.authorization, 'Bearer TOK');
  assert.equal(h['chatgpt-account-id'], 'acc-1');
  assert.equal(h['openai-beta'], 'responses=experimental');
  assert.equal(h.originator, 'codex_cli_rs');
  assert.match(h['user-agent'], /^codex_cli_rs\/0\.156\.1 \(.+; .+\) unknown$/);
  assert.equal(h.accept, 'text/event-stream');
  assert.equal(h['content-type'], 'application/json');
  assert.equal(h.session_id, 'sess');
});

test('fetchCodexModels normalizes the backend list; any failure yields null', async () => {
  const body = {
    models: [
      { slug: 'gpt-5.5', display_name: 'GPT-5.5', visibility: 'list', default_reasoning_level: 'medium', supported_reasoning_levels: [{ effort: 'low' }, { effort: 'medium' }] },
      { slug: 'gpt-reserve', visibility: 'hide', supported_reasoning_levels: ['low'] },
      { nope: true },
    ],
  };
  const calls = [];
  const request = async (url, opts) => {
    calls.push({ url, opts });
    return { status: 200, body: JSON.stringify(body) };
  };
  const models = await fetchCodexModels({ access: 'TOK', accountId: 'acc-1', request });
  assert.deepEqual(models, [
    { slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium'] },
    { slug: 'gpt-reserve', displayName: 'gpt-reserve', visibility: 'hide', defaultLevel: null, levels: ['low'] },
  ]);
  // the backend gates new models by client version: the announced version must track the current Codex CLI
  assert.equal(calls[0].url, 'https://chatgpt.com/backend-api/codex/models?client_version=0.156.1');
  assert.equal(calls[0].opts.method, 'GET');
  assert.equal(calls[0].opts.headers.authorization, 'Bearer TOK');
  assert.equal(calls[0].opts.headers['chatgpt-account-id'], 'acc-1');
  assert.equal(calls[0].opts.headers.accept, 'application/json');
  assert.equal(await fetchCodexModels({ access: 'TOK', accountId: 'acc-1', request: async () => ({ status: 500, body: '' }) }), null);
  assert.equal(await fetchCodexModels({ access: 'TOK', accountId: 'acc-1', request: async () => { throw new Error('net'); } }), null);
  assert.equal(normalizeCodexModels('not json'), null);
  assert.equal(normalizeCodexModels({ data: [] }), null);
});
