// FAIL CLOSED: if redaction cannot be performed, the raw body must NEVER
// reach the upstream. Blocking is correct; forwarding on error is a leak.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { createMockUpstream } from './helpers/mock-upstream.js';
import { startProxy } from './helpers/start-proxy.js';
import { createRedactor } from '../src/redact.js';

const throwingRedactor = {
  redactBody() {
    throw new Error('boom: simulated redaction failure');
  },
};

test('redaction error blocks the request; upstream receives nothing', async () => {
  const upstream = await createMockUpstream();
  const proxy = await startProxy({ upstreamUrl: upstream.url, redactor: throwingRedactor });
  try {
    const res = await fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: 'super-secret-raw-body' }),
    });
    assert.ok(res.status >= 500, `expected 5xx, got ${res.status}`);
    assert.equal(upstream.requests.length, 0, 'raw body reached the upstream');
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('undecodable content-encoding blocks the request', async () => {
  const upstream = await createMockUpstream();
  const proxy = await startProxy({
    upstreamUrl: upstream.url,
    redactor: createRedactor({ secrets: [] }),
  });
  try {
    const res = await fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
      body: 'this is not valid gzip data at all',
    });
    assert.ok(res.status >= 400, `expected error status, got ${res.status}`);
    assert.equal(upstream.requests.length, 0);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('gzipped request body is decompressed and redacted', async () => {
  const upstream = await createMockUpstream();
  const secret = 'gzip-hidden-secret-9876';
  const proxy = await startProxy({
    upstreamUrl: upstream.url,
    redactor: createRedactor({ secrets: [{ name: 'GZ', value: secret }] }),
  });
  try {
    const raw = JSON.stringify({ content: `value ${secret} end` });
    const res = await fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
      body: zlib.gzipSync(Buffer.from(raw)),
    });
    assert.equal(res.status, 200);
    assert.equal(upstream.requests.length, 1);
    const received = upstream.requests[0];
    assert.ok(!received.body.includes(secret), 'secret leaked through gzip path');
    assert.ok(received.body.includes('[REDACTED:GZ]'));
    assert.equal(received.headers['content-encoding'], undefined);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('FAIL_CLOSED=false forwards on redaction error (documented opt-out)', async () => {
  const upstream = await createMockUpstream();
  const proxy = await startProxy({
    upstreamUrl: upstream.url,
    redactor: throwingRedactor,
    configOverrides: { failClosed: false },
  });
  try {
    const res = await fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: 'raw' }),
    });
    assert.equal(res.status, 200);
    assert.equal(upstream.requests.length, 1);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});
