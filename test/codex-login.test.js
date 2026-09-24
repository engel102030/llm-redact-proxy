// The one-shot OAuth callback listener: builds the authorize URL, validates
// the state, exchanges the code, stores tokens + account + models through
// onResult, then closes. Only one login at a time. No network: exchange and
// model fetch are injected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startCodexLogin, loginInProgress } from '../src/codex-login.js';
import { fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

const MODELS = [{ slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium'] }];

function deps(results, { fail = false } = {}) {
  return {
    port: 0,
    exchange: async ({ code, verifier }) => {
      assert.equal(typeof verifier, 'string');
      if (fail) throw new Error('exchange exploded');
      results.exchanged.push(code);
      return { access: fakeAccessToken({ accountId: 'acc-7', plan: 'plus', expSec: 1900000000 }), refresh: 'R7', idToken: fakeIdToken({ email: 'a@b.c' }) };
    },
    fetchModels: async ({ access, accountId }) => {
      assert.equal(accountId, 'acc-7');
      assert.ok(access);
      return MODELS;
    },
    onResult: (r) => results.stored.push(r),
    nowMs: () => 1234,
  };
}

test('authorize URL, wrong state rejected without storing, then a good callback stores the login and closes', async () => {
  const results = { exchanged: [], stored: [] };
  const login = await startCodexLogin(deps(results));
  assert.equal(loginInProgress(), true);
  const u = new URL(login.url);
  assert.equal(u.hostname, 'auth.openai.com');
  assert.equal(u.searchParams.get('redirect_uri'), 'http://localhost:1455/auth/callback');
  const state = u.searchParams.get('state');
  assert.ok(state);

  const bad = await fetch(`http://127.0.0.1:${login.port}/auth/callback?code=x&state=wrong`);
  assert.equal(bad.status, 400);
  assert.equal(results.stored.length, 0);
  assert.equal(results.exchanged.length, 0);
  assert.equal(loginInProgress(), false); // closed after the first callback

  const again = await startCodexLogin(deps(results));
  const state2 = new URL(again.url).searchParams.get('state');
  assert.notEqual(state2, state);
  const ok = await fetch(`http://127.0.0.1:${again.port}/auth/callback?code=abc&state=${encodeURIComponent(state2)}`);
  assert.equal(ok.status, 200);
  assert.match(await ok.text(), /Logged in/);
  assert.deepEqual(results.exchanged, ['abc']);
  assert.equal(results.stored.length, 1);
  const r = results.stored[0];
  assert.equal(r.tokens.accountId, 'acc-7');
  assert.equal(r.tokens.refresh, 'R7');
  assert.equal(r.tokens.expiresAt, 1900000000000);
  assert.deepEqual(r.account, { email: 'a@b.c', plan: 'plus' });
  assert.deepEqual(r.models, MODELS);
  assert.equal(r.fetchedAt, 1234);
  assert.equal(loginInProgress(), false);
});

test('an exchange failure answers an error page and stores nothing', async () => {
  const results = { exchanged: [], stored: [] };
  const login = await startCodexLogin(deps(results, { fail: true }));
  const state = new URL(login.url).searchParams.get('state');
  const res = await fetch(`http://127.0.0.1:${login.port}/auth/callback?code=abc&state=${encodeURIComponent(state)}`);
  assert.equal(res.status, 500);
  assert.match(await res.text(), /exchange exploded/);
  assert.equal(results.stored.length, 0);
  assert.equal(loginInProgress(), false);
});

test('only one login at a time; close() frees it; other paths are 404', async () => {
  const results = { exchanged: [], stored: [] };
  const login = await startCodexLogin(deps(results));
  await assert.rejects(startCodexLogin(deps(results)), (e) => e.code === 'LOGIN_IN_PROGRESS');
  const other = await fetch(`http://127.0.0.1:${login.port}/nope`);
  assert.equal(other.status, 404);
  login.close();
  assert.equal(loginInProgress(), false);
  const next = await startCodexLogin(deps(results));
  next.close();
});
