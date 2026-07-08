// The "oauth" auth mode: the proxy strips the caller's token and injects the
// user's Claude subscription OAuth token, but ONLY when the destination is the
// official Anthropic API. Sending that token to a third party would be a
// serious leak, so the guard is enforced in both the runtime and the proxy.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  readClaudeOAuth,
  clearClaudeOAuthCache,
  isAnthropicHost,
  applyOAuthHeaders,
} from '../src/claude-auth.js';
import { createRuntime } from '../src/runtime.js';
import { createProxyServer } from '../src/proxy.js';
import { createStats } from '../src/stats.js';
import { createMockUpstream } from './helpers/mock-upstream.js';

function tmpConfig(overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-oauth-'));
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
    ...overrides,
  };
}

test('isAnthropicHost accepts official hosts, rejects others', () => {
  assert.equal(isAnthropicHost(new URL('https://api.anthropic.com')), true);
  assert.equal(isAnthropicHost(new URL('https://foo.anthropic.com')), true);
  assert.equal(isAnthropicHost(new URL('https://api.anthropic.com.evil.com')), false);
  assert.equal(isAnthropicHost(new URL('https://token-plan-sgp.xiaomimimo.com/anthropic')), false);
});

test('readClaudeOAuth reads a credentials file via env override', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-cred-'));
  const file = path.join(dir, 'creds.json');
  fs.writeFileSync(file, JSON.stringify({ claudeAiOauth: { accessToken: 'oauth-access-abc123', expiresAt: 9999999999999 } }));
  const prev = process.env.CLAUDE_CREDENTIALS_FILE;
  process.env.CLAUDE_CREDENTIALS_FILE = file;
  clearClaudeOAuthCache();
  try {
    const cred = readClaudeOAuth();
    assert.equal(cred.accessToken, 'oauth-access-abc123');
  } finally {
    if (prev === undefined) delete process.env.CLAUDE_CREDENTIALS_FILE;
    else process.env.CLAUDE_CREDENTIALS_FILE = prev;
    clearClaudeOAuthCache();
  }
});

test('runtime refuses oauth against a non-anthropic provider', () => {
  const rt = createRuntime({ config: tmpConfig(), secrets: [] });
  assert.throws(
    () => rt.apply({ upstreamUrl: 'https://token-plan-sgp.xiaomimimo.com/anthropic', upstreamAuth: 'oauth' }),
    /anthropic\.com/,
  );
});

test('runtime accepts oauth against the official Anthropic API', () => {
  const rt = createRuntime({ config: tmpConfig(), secrets: [] });
  rt.apply({ upstreamUrl: 'https://api.anthropic.com', upstreamAuth: 'oauth' });
  assert.equal(rt.upstream.auth, 'oauth');
});

async function boot(config, getOAuth) {
  const runtime = createRuntime({ config, secrets: [] });
  const stats = createStats({ log: () => {} });
  const liveRedactor = { redactBody: (raw, ct) => runtime.holder.current.redactBody(raw, ct) };
  const server = createProxyServer({
    config,
    redactor: liveRedactor,
    stats,
    getUpstream: () => runtime.upstream,
    controller: runtime,
    getOAuth,
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return { runtime, url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

test('applyOAuthHeaders drops x-api-key, sets Bearer, ensures the beta flag', () => {
  const h1 = applyOAuthHeaders({ 'x-api-key': 'caller-mimo-token' }, 'sub-token-xyz-987');
  assert.equal(h1['x-api-key'], undefined);
  assert.equal(h1.authorization, 'Bearer sub-token-xyz-987');
  assert.equal(h1['anthropic-beta'], 'oauth-2025-04-20');

  // merges with an existing beta list, no duplication
  const h2 = applyOAuthHeaders({ 'anthropic-beta': 'other-flag-1' }, 'tok');
  assert.equal(h2['anthropic-beta'], 'other-flag-1,oauth-2025-04-20');
  const h3 = applyOAuthHeaders({ 'anthropic-beta': 'oauth-2025-04-20' }, 'tok');
  assert.equal(h3['anthropic-beta'], 'oauth-2025-04-20');
});

test('proxy oauth guard blocks a non-anthropic host even if forced at runtime', async () => {
  const upstream = await createMockUpstream();
  const config = tmpConfig();
  config.upstreamUrl = new URL(upstream.url);
  const app = await boot(config, () => ({ accessToken: 'sub-token-must-not-leak', expiresAt: null }));
  try {
    // Force oauth against the (non-anthropic) mock, bypassing the runtime guard.
    app.runtime.upstream.auth = 'oauth';
    const res = await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'caller-token' },
      body: JSON.stringify({ hi: 1 }),
    });
    assert.equal(res.status, 400);
    assert.equal(upstream.requests.length, 0, 'subscription token must not reach a non-anthropic host');
  } finally {
    await app.close();
    await upstream.close();
  }
});

test('oauth mode returns 502 when no subscription credential is available', async () => {
  const config = tmpConfig();
  config.upstreamUrl = new URL('https://api.anthropic.com');
  config.upstreamAuth = 'oauth';
  const app = await boot(config, () => null);
  try {
    const res = await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hi: 1 }),
    });
    assert.equal(res.status, 502);
    const d = await res.json();
    assert.match(d.error.message, /credential/i);
  } finally {
    await app.close();
  }
});
