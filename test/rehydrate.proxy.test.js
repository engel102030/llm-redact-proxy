// End-to-end proof of the redact->rehydrate loop through the real proxy:
//  - REQUEST: the real secret value in the outgoing body is redacted (vendor
//    never sees it).
//  - RESPONSE: a {{NAME}} the model emits is substituted back to the real value
//    before the CLI receives it (only when restore is enabled).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRuntime } from '../src/runtime.js';
import { createProxyServer } from '../src/proxy.js';
import { createStats } from '../src/stats.js';
import { createMockUpstream } from './helpers/mock-upstream.js';

const CANARY = 'canary-value-abc-123456';

function tmpConfig(upstreamUrl) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-rehy-'));
  return {
    listenHost: '127.0.0.1',
    listenPort: 0,
    upstreamUrl: new URL(upstreamUrl),
    upstreamAuth: 'passthrough',
    upstreamKey: null,
    failClosed: true,
    injectNotice: false,
    redactMode: 'strict',
    redactModeFloor: 'named-only',
    redactDisable: [],
    redactIgnore: [],
    restoreMarkers: false,
    configFile: path.join(dir, 'config.json'),
  };
}

async function boot(upstreamUrl, { restore }) {
  const config = tmpConfig(upstreamUrl);
  const runtime = createRuntime({ config, secrets: [{ name: 'CANARY_KEY', value: CANARY }] });
  runtime.apply({ restoreMarkers: restore }, { persist: false });
  const liveRedactor = { redactBody: (raw, ct) => runtime.holder.current.redactBody(raw, ct) };
  const server = createProxyServer({
    config,
    redactor: liveRedactor,
    stats: createStats({ log: () => {} }),
    getUpstream: () => runtime.upstream,
    controller: runtime,
    getRestore: () => runtime.getRestore(),
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return { runtime, url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

const sseEvents = [
  `event: content_block_start\ndata: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'text' } })}\n\n`,
  `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'run: curl -H "x-api-key: {{CANARY_KEY}}"' } })}\n\n`,
  `event: content_block_stop\ndata: ${JSON.stringify({ type: 'content_block_stop', index: 0 })}\n\n`,
  `event: message_stop\ndata: ${JSON.stringify({ type: 'message_stop' })}\n\n`,
];

test('restore ON: request is redacted outbound, response {{NAME}} is rehydrated inbound', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents });
  const app = await boot(upstream.url, { restore: true });
  try {
    const res = await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ messages: [{ role: 'user', content: `my key is ${CANARY}` }] }),
    });
    const body = await res.text();

    // OUTBOUND: the vendor must NOT have seen the real value.
    assert.ok(!upstream.requests[0].body.includes(CANARY), 'secret must not leak in the request');
    assert.ok(upstream.requests[0].body.includes('[REDACTED:CANARY_KEY]'), 'request was redacted');

    // INBOUND: the CLI receives the real value in place of the marker.
    assert.ok(body.includes(CANARY), 'response marker was rehydrated to the real value');
    assert.ok(!body.includes('{{CANARY_KEY}}'), 'no marker remains');
    // Every SSE data line stays valid JSON.
    for (const line of body.split('\n')) {
      if (line.startsWith('data:')) JSON.parse(line.slice(5).trim());
    }
  } finally {
    await app.close();
    await upstream.close();
  }
});

test('restore OFF: the {{NAME}} marker passes through untouched (no value injected)', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents });
  const app = await boot(upstream.url, { restore: false });
  try {
    const res = await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }),
    });
    const body = await res.text();
    assert.ok(body.includes('{{CANARY_KEY}}'), 'marker left as-is when restore is off');
    assert.ok(!body.includes(CANARY), 'no value injected when restore is off');
  } finally {
    await app.close();
    await upstream.close();
  }
});

test('restore ON but marker split across two SSE deltas still rehydrates', async () => {
  const split = [
    `data: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'text' } })}\n\n`,
    `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'key {{CANARY' } })}\n\n`,
    `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '_KEY}} end' } })}\n\n`,
    `data: ${JSON.stringify({ type: 'content_block_stop', index: 0 })}\n\n`,
  ];
  const upstream = await createMockUpstream({ sse: true, sseEvents: split });
  const app = await boot(upstream.url, { restore: true });
  try {
    const res = await fetch(`${app.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }),
    });
    const body = await res.text();
    assert.ok(body.includes(CANARY), 'split marker rehydrated');
    assert.ok(!body.includes('{{CANARY'), 'no partial marker leaks');
  } finally {
    await app.close();
    await upstream.close();
  }
});
