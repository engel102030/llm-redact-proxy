// The proxy tags model ids with "[1m]" in /v1/models (a UI signal to open a 1M
// local window). That tag is NOT a real model - it must be stripped from the
// outgoing request body before the message call reaches the upstream, which
// rejects the literal "...[1m]" id ("model is not enabled"). When a tag is
// stripped on a replace-mode (gateway) path, the 1M-context beta flag is added
// so a large window is still accepted upstream.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createProxyServer } from '../src/proxy.js';
import { createStats } from '../src/stats.js';
import { createRedactor } from '../src/redact.js';
import { createMockUpstream } from './helpers/mock-upstream.js';
import { ONE_M_BETA } from '../src/models.js';

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

test('replace: a [1m] model id is stripped and the 1M beta is added upstream', async () => {
  const upstream = await createMockUpstream();
  const app = await boot(upstream.url);
  try {
    await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'client' },
      body: JSON.stringify({
        model: 'claude-opus-4-8[1m]',
        max_tokens: 16,
        messages: [{ role: 'user', content: 'hi' }],
      }),
    });
    const req = upstream.requests[0];
    const sent = JSON.parse(req.body);
    assert.equal(sent.model, 'claude-opus-4-8', 'the [1m] tag must be stripped from the model id');
    assert.equal(sent.max_tokens, 16, 'the rest of the body is preserved');
    assert.deepEqual(sent.messages, [{ role: 'user', content: 'hi' }]);
    const beta = String(req.headers['anthropic-beta'] ?? '').split(',').map((s) => s.trim());
    assert.ok(beta.includes(ONE_M_BETA), 'the 1M-context beta flag must be present');
    assert.ok(!req.body.includes('[1m]'), 'no [1m] marker crosses the wire');
  } finally {
    await app.close();
    await upstream.close();
  }
});

test('replace: a clean model id is forwarded unchanged with no 1M beta', async () => {
  const upstream = await createMockUpstream();
  const app = await boot(upstream.url);
  try {
    await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'client' },
      body: JSON.stringify({
        model: 'claude-opus-4-8',
        max_tokens: 16,
        messages: [{ role: 'user', content: 'hi' }],
      }),
    });
    const req = upstream.requests[0];
    assert.equal(JSON.parse(req.body).model, 'claude-opus-4-8');
    const beta = String(req.headers['anthropic-beta'] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    assert.ok(!beta.includes(ONE_M_BETA), 'no 1M beta is added when no [1m] tag was present');
  } finally {
    await app.close();
    await upstream.close();
  }
});
