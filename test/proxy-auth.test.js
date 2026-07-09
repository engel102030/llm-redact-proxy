// Replace-mode auth: the proxy strips whatever credential the client sent and
// injects the configured upstream key. It must ALWAYS set x-api-key (the native
// Anthropic header most gateways validate), even when the client authenticated
// only with Authorization: Bearer - some hosts (e.g. Overclock custom providers)
// send only Bearer, and a gateway that reads x-api-key would otherwise see no
// key and reject the request with 401.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createProxyServer } from '../src/proxy.js';
import { createStats } from '../src/stats.js';
import { createRedactor } from '../src/redact.js';
import { createMockUpstream } from './helpers/mock-upstream.js';

async function boot(upstreamUrl) {
  const config = {
    upstreamUrl: new URL(upstreamUrl),
    upstreamAuth: 'replace',
    upstreamKey: 'up-secret-key-123456',
    failClosed: true,
    injectNotice: false,
    redactMode: 'strict',
    redactModeFloor: 'named-only',
    redactDisable: [],
    redactIgnore: [],
  };
  const server = createProxyServer({
    config,
    redactor: createRedactor({ secrets: [] }),
    stats: createStats({ log: () => {} }),
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

test('replace: client sends only Authorization Bearer -> x-api-key is still set to our key', async () => {
  const upstream = await createMockUpstream();
  const app = await boot(upstream.url);
  try {
    await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer client-token-xyz' },
      body: JSON.stringify({ hi: 1 }),
    });
    const got = upstream.requests[0].headers;
    assert.equal(got['x-api-key'], 'up-secret-key-123456', 'x-api-key must be set to our key');
    assert.equal(got.authorization, 'Bearer up-secret-key-123456', 'Bearer also carries our key');
    assert.ok(!JSON.stringify(got).includes('client-token-xyz'), 'client credential must not leak');
  } finally {
    await app.close();
    await upstream.close();
  }
});

test('replace: client sends only x-api-key -> our key in x-api-key, no Authorization added', async () => {
  const upstream = await createMockUpstream();
  const app = await boot(upstream.url);
  try {
    await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'client-api-key-abc' },
      body: JSON.stringify({ hi: 1 }),
    });
    const got = upstream.requests[0].headers;
    assert.equal(got['x-api-key'], 'up-secret-key-123456');
    assert.equal(got.authorization, undefined, 'no Bearer when the client did not use one');
    assert.ok(!JSON.stringify(got).includes('client-api-key-abc'), 'client credential must not leak');
  } finally {
    await app.close();
    await upstream.close();
  }
});

test('replace: client sends no credential -> x-api-key is still injected', async () => {
  const upstream = await createMockUpstream();
  const app = await boot(upstream.url);
  try {
    await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hi: 1 }),
    });
    const got = upstream.requests[0].headers;
    assert.equal(got['x-api-key'], 'up-secret-key-123456');
    assert.equal(got.authorization, undefined);
  } finally {
    await app.close();
    await upstream.close();
  }
});
