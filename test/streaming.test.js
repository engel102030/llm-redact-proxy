// SSE passthrough: the upstream response must stream back unbuffered and
// byte-intact. The proxy only touches the REQUEST, never the response body.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMockUpstream } from './helpers/mock-upstream.js';
import { startProxy } from './helpers/start-proxy.js';
import { createRedactor } from '../src/redact.js';

test('SSE response streams through intact and incrementally', async () => {
  const events = [
    'event: message_start\ndata: {"type":"message_start"}\n\n',
    'event: content_block_delta\ndata: {"delta":{"text":"hello"}}\n\n',
    'event: message_stop\ndata: {"type":"message_stop"}\n\n',
  ];
  const upstream = await createMockUpstream({ sse: true, sseEvents: events, sseDelayMs: 25 });
  const proxy = await startProxy({
    upstreamUrl: upstream.url,
    redactor: createRedactor({ secrets: [] }),
  });
  try {
    const res = await fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ stream: true }),
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/event-stream/);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let received = '';
    let chunkCount = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunkCount += 1;
      received += decoder.decode(value, { stream: true });
    }
    assert.equal(received, events.join(''), 'stream content altered');
    assert.ok(chunkCount >= 2, `expected incremental chunks, got ${chunkCount}`);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('plain JSON response passes through with status and headers', async () => {
  const upstream = await createMockUpstream({ response: { id: 'msg_1', ok: true }, status: 201 });
  const proxy = await startProxy({
    upstreamUrl: upstream.url,
    redactor: createRedactor({ secrets: [] }),
  });
  try {
    const res = await fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hello: 'world' }),
    });
    assert.equal(res.status, 201);
    const parsed = await res.json();
    assert.deepEqual(parsed, { id: 'msg_1', ok: true });
  } finally {
    await proxy.close();
    await upstream.close();
  }
});
