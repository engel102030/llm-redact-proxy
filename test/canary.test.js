// THE REAL PROOF: full round-trip through the proxy against a recording
// upstream. A unique canary value is planted in the request body in every
// encoding. The body the upstream actually RECEIVED must not contain the
// canary in any form. This is the end-to-end zero-leak guarantee.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMockUpstream } from './helpers/mock-upstream.js';
import { startProxy } from './helpers/start-proxy.js';
import { createRedactor } from '../src/redact.js';
import { NOTICE_SENTINEL } from '../src/inject.js';

const CANARY = 'CANARY-7f3a1b2c-uniq-value-98765';

test('canary round-trip: no variant of the canary reaches the upstream', async () => {
  const upstream = await createMockUpstream();
  const redactor = createRedactor({ secrets: [{ name: 'CANARY_TOKEN', value: CANARY }] });
  const proxy = await startProxy({ upstreamUrl: upstream.url, redactor });

  try {
    const requestBody = JSON.stringify({
      model: 'claude-fable-5',
      system: 'You are a coding agent.',
      messages: [
        { role: 'user', content: `plain: ${CANARY}` },
        { role: 'user', content: `base64: ${Buffer.from(CANARY).toString('base64')}` },
        { role: 'user', content: `base64url: ${Buffer.from(CANARY).toString('base64url')}` },
        { role: 'user', content: `urlencoded: ${encodeURIComponent(CANARY)}` },
        { role: 'user', content: `hex: ${Buffer.from(CANARY).toString('hex')}` },
        {
          role: 'user',
          content: `basic-auth blob: ${Buffer.from(`admin:${CANARY}`).toString('base64')}`,
        },
        { role: 'user', content: `conn string: mysql://root:${CANARY}@db:3306/app` },
      ],
    });

    const res = await fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: requestBody,
    });
    assert.equal(res.status, 200);
    assert.equal(upstream.requests.length, 1);

    const received = upstream.requests[0].body;

    const leakForms = {
      literal: CANARY,
      base64: Buffer.from(CANARY).toString('base64'),
      base64url: Buffer.from(CANARY).toString('base64url'),
      urlencoded: encodeURIComponent(CANARY),
      hexLower: Buffer.from(CANARY).toString('hex'),
      hexUpper: Buffer.from(CANARY).toString('hex').toUpperCase(),
      basicAuthBlob: Buffer.from(`admin:${CANARY}`).toString('base64'),
    };
    for (const [form, value] of Object.entries(leakForms)) {
      assert.ok(!received.includes(value), `CANARY LEAKED upstream as ${form}`);
    }

    assert.doesNotThrow(() => JSON.parse(received), 'forwarded body must be valid JSON');
    assert.ok(received.includes('[REDACTED:CANARY_TOKEN]'), 'marker missing upstream');
    assert.ok(received.includes(NOTICE_SENTINEL), 'redaction notice was not injected');
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('clean request round-trip: body arrives upstream byte-identical, no notice', async () => {
  const upstream = await createMockUpstream();
  const redactor = createRedactor({ secrets: [{ name: 'CANARY_TOKEN', value: CANARY }] });
  const proxy = await startProxy({ upstreamUrl: upstream.url, redactor });

  try {
    const requestBody = JSON.stringify({
      model: 'claude-fable-5',
      messages: [{ role: 'user', content: 'no secrets here, refactor foo() please' }],
    });
    const res = await fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: requestBody,
    });
    assert.equal(res.status, 200);
    assert.equal(upstream.requests[0].body, requestBody);
    assert.ok(!upstream.requests[0].body.includes(NOTICE_SENTINEL));
  } finally {
    await proxy.close();
    await upstream.close();
  }
});
