// End-to-end for the codex-oauth upstream path: redaction happens BEFORE
// translation (the canary proof), translation failures fail closed, the
// Responses SSE is translated back to Anthropic SSE, a 401 triggers one
// refresh + replay, 429 passes through, /v1/models and count_tokens are
// answered locally without ever contacting the upstream.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createMockUpstream } from './helpers/mock-upstream.js';
import { startProxy } from './helpers/start-proxy.js';
import { createRedactor } from '../src/redact.js';
import { TEXT_TURN, TOOL_TURN, sseFrames } from './helpers/codex-fixtures.js';

const CANARY = 'CODEX-CANARY-9f2b7e-uniq-value-31337';
const MODELS = [
  { slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium', 'high', 'xhigh'] },
  { slug: 'gpt-reserve', displayName: 'Reserve', visibility: 'hide', defaultLevel: 'medium', levels: ['low'] },
];

function fakeAdapter({ access = 'tok-1', accountId = 'acc-1', models = MODELS, effortMap = null, refreshed = 'tok-2', creds = true } = {}) {
  const calls = { credentials: 0, refresh: 0 };
  return {
    calls,
    profile: () => ({ models, effortMap }),
    credentials: async () => {
      calls.credentials += 1;
      return creds ? { access, accountId } : null;
    },
    refresh: async () => {
      calls.refresh += 1;
      return refreshed ? { access: refreshed, accountId } : null;
    },
  };
}

// An upstream whose answers are scripted per request (the last one repeats).
function scriptedUpstream(responders, { path = '' } = {}) {
  const requests = [];
  let i = 0;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, headers: { ...req.headers }, body: Buffer.concat(chunks).toString('utf8') });
      const r = responders[Math.min(i, responders.length - 1)];
      i += 1;
      r(req, res);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ url: `http://127.0.0.1:${server.address().port}${path}`, requests, close: () => new Promise((r) => server.close(r)) });
    });
  });
}
const sseResponder = (frames, headers = {}) => (req, res) => {
  res.writeHead(200, headers); // NOTE: no content-type by default, like the real backend
  for (const f of frames) res.write(f);
  res.end();
};
const jsonResponder = (status, obj) => (req, res) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj));
};

async function boot(upstreamUrl, adapter, extra = {}) {
  return startProxy({
    upstreamUrl,
    redactor: createRedactor({ secrets: [{ name: 'CODEX_CANARY', value: CANARY }] }),
    configOverrides: { upstreamAuth: 'codex-oauth', injectNotice: false, ...extra },
    serverOptions: { codexAdapter: () => adapter },
  });
}

const post = (url, body, headers = {}) =>
  fetch(`${url}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'client-key-must-not-forward', ...headers }, body: JSON.stringify(body) });

test('canary round-trip: redaction runs before translation, nothing leaks, backend contract honoured', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN), sseDelayMs: 1 });
  const adapter = fakeAdapter();
  const proxy = await boot(upstream.url, adapter);
  try {
    const res = await post(proxy.url, {
      model: 'gpt-5.5[1m]',
      max_tokens: 64000,
      stream: true,
      system: 'You are a test agent.',
      output_config: { effort: 'max' },
      metadata: { user_id: 'session-xyz' },
      messages: [
        { role: 'user', content: `my secret is ${CANARY}` },
        { role: 'user', content: `base64: ${Buffer.from(CANARY).toString('base64')}` },
      ],
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/event-stream/);
    const body = await res.text();
    assert.ok(body.includes('event: message_start'));
    assert.ok(body.includes('"type":"thinking"'));
    assert.ok(body.includes('"signature":"ENC1"'));
    assert.ok(body.includes('"text":"Hi"'));
    assert.ok(body.includes('event: message_stop'));

    assert.equal(upstream.requests.length, 1);
    const sent = upstream.requests[0];
    assert.equal(sent.url, '/responses');
    assert.equal(sent.body.includes(CANARY), false, 'literal canary leaked');
    assert.equal(sent.body.includes(Buffer.from(CANARY).toString('base64')), false, 'base64 canary leaked');
    assert.ok(sent.body.includes('[REDACTED:CODEX_CANARY]'));
    const wire = JSON.parse(sent.body);
    assert.equal(wire.model, 'gpt-5.5');
    assert.equal(wire.store, false);
    assert.equal(wire.stream, true);
    assert.deepEqual(wire.reasoning, { effort: 'xhigh', summary: 'auto' }); // max clamped to gpt-5.5's ceiling
    assert.equal('max_output_tokens' in wire, false);
    assert.equal(wire.instructions, 'You are a test agent.');
    assert.equal(sent.headers.authorization, 'Bearer tok-1');
    assert.equal(sent.headers['chatgpt-account-id'], 'acc-1');
    assert.equal(sent.headers['openai-beta'], 'responses=experimental');
    assert.equal('x-api-key' in sent.headers, false, 'client credential forwarded');
    assert.equal(adapter.calls.refresh, 0);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('the inspector keeps the TRANSLATED body (what actually left)', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN), sseDelayMs: 1 });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    // Consume the stream: stats are finished only once the upstream ends.
    await (await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi' }] })).text();
    const s = await (await fetch(`${proxy.url}/__redact/stats.json`)).json();
    const id = s.recent[0].id;
    const d = await (await fetch(`${proxy.url}/__redact/inspect?id=${id}`, { headers: { 'x-redact-panel': '1' } })).json();
    assert.ok(JSON.parse(d.req).input, 'stored request is the Responses body');
    assert.ok(d.resp.includes('response.completed'), 'raw upstream SSE captured');
    assert.equal(s.recent[0].status, 200);
    assert.equal(s.recent[0].inputTokens, 24);
    assert.equal(s.recent[0].outputTokens, 18);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('fail closed: an untranslatable body is answered 400 and the upstream receives nothing', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN) });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: [{ type: 'document', source: {} }] }] });
    assert.equal(res.status, 400);
    const j = await res.json();
    assert.match(j.error.message, /unsupported content block type: document/);
    assert.equal(upstream.requests.length, 0);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('tool call turn streams back as a tool_use block; stream:false folds into one JSON message', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TOOL_TURN), sseDelayMs: 1 });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const streamed = await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'weather' }], tools: [{ name: 'get_weather', input_schema: { type: 'object' } }] });
    const text = await streamed.text();
    assert.ok(text.includes('"type":"tool_use","id":"call_1","name":"get_weather"'));
    assert.ok(text.includes('"partial_json":"{\\"city\\":"'));
    assert.ok(text.includes('"stop_reason":"tool_use"'));

    const single = await post(proxy.url, { model: 'gpt-5.5', stream: false, messages: [{ role: 'user', content: 'weather' }] });
    assert.equal(single.status, 200);
    assert.match(single.headers.get('content-type'), /application\/json/);
    const m = await single.json();
    assert.equal(m.type, 'message');
    assert.equal(m.model, 'gpt-5.5');
    assert.deepEqual(m.content, [{ type: 'tool_use', id: 'call_1', name: 'get_weather', input: { city: 'Paris' } }]);
    assert.equal(m.stop_reason, 'tool_use');
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('401 -> one refresh + replay with the new token; a second 401 is a 502 no_codex_oauth', async () => {
  const upstream = await scriptedUpstream([jsonResponder(401, { detail: 'expired' }), sseResponder(sseFrames(TEXT_TURN))]);
  const adapter = fakeAdapter();
  const proxy = await boot(upstream.url, adapter);
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 200);
    assert.ok((await res.text()).includes('event: message_stop'));
    assert.equal(upstream.requests.length, 2);
    assert.equal(upstream.requests[0].headers.authorization, 'Bearer tok-1');
    assert.equal(upstream.requests[1].headers.authorization, 'Bearer tok-2');
    assert.equal(adapter.calls.refresh, 1);
  } finally {
    await proxy.close();
    await upstream.close();
  }
  const always401 = await scriptedUpstream([jsonResponder(401, { detail: 'expired' })]);
  const dead = fakeAdapter({ refreshed: null });
  const proxy2 = await boot(always401.url, dead);
  try {
    const res = await post(proxy2.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 502);
    assert.equal((await res.json()).error.type, 'no_codex_oauth');
    assert.equal(always401.requests.length, 1);
  } finally {
    await proxy2.close();
    await always401.close();
  }
});

test('no login -> 502 no_codex_oauth before anything is sent; misconfigured host -> 400', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN) });
  const proxy = await boot(upstream.url, fakeAdapter({ creds: false }));
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 502);
    assert.equal((await res.json()).error.type, 'no_codex_oauth');
    assert.equal(upstream.requests.length, 0);
  } finally {
    await proxy.close();
    await upstream.close();
  }
  const proxy2 = await boot('https://api.openai.com/v1', fakeAdapter());
  try {
    const res = await post(proxy2.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error.type, 'codex_misconfig');
  } finally {
    await proxy2.close();
  }
});

test('429 passes through with the backend detail; other errors become 502 with the detail', async () => {
  const limited = await scriptedUpstream([jsonResponder(429, { detail: 'usage limit reached, resets in 3h' })]);
  const proxy = await boot(limited.url, fakeAdapter());
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 429);
    const j = await res.json();
    assert.equal(j.error.type, 'rate_limit_error');
    assert.match(j.error.message, /usage limit reached/);
  } finally {
    await proxy.close();
    await limited.close();
  }
  const broken = await scriptedUpstream([jsonResponder(400, { detail: 'Unsupported parameter: foo' })]);
  const proxy2 = await boot(broken.url, fakeAdapter());
  try {
    const res = await post(proxy2.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 502);
    const j = await res.json();
    assert.equal(j.error.type, 'upstream_error');
    assert.match(j.error.message, /HTTP 400.*Unsupported parameter: foo/);
  } finally {
    await proxy2.close();
    await broken.close();
  }
});

test('a 200 that is not a Responses stream never becomes a finished message', async () => {
  const bogus = await scriptedUpstream([jsonResponder(200, { ok: true })]);
  const proxy = await boot(bogus.url, fakeAdapter());
  try {
    const streamed = await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi' }] });
    const text = await streamed.text();
    assert.ok(text.includes('event: error'));
    assert.equal(text.includes('message_stop'), false);
    const single = await post(proxy.url, { model: 'gpt-5.5', stream: false, messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(single.status, 502);
  } finally {
    await proxy.close();
    await bogus.close();
  }
});

test('a provider url already ending in /responses is not doubled', async () => {
  const upstream = await scriptedUpstream([sseResponder(sseFrames(TEXT_TURN))], { path: '/backend-api/codex/responses' });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 200);
    await res.text();
    assert.equal(upstream.requests[0].url, '/backend-api/codex/responses');
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('/v1/models and count_tokens are answered locally, never touching the upstream', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN) });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const models = await (await fetch(`${proxy.url}/v1/models`)).json();
    assert.deepEqual(models.data.map((m) => m.id), ['gpt-5.5']); // hidden model excluded, no [1m]
    assert.equal(models.data[0].display_name, 'GPT-5.5');
    const count = await (await fetch(`${proxy.url}/v1/messages/count_tokens`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'gpt-5.5', messages: [{ role: 'user', content: 'hello world' }] }) })).json();
    assert.ok(Number.isInteger(count.input_tokens) && count.input_tokens > 0);
    const other = await fetch(`${proxy.url}/v1/complete`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(other.status, 404);
    assert.equal(upstream.requests.length, 0);
  } finally {
    await proxy.close();
    await upstream.close();
  }
  // no fetched list -> the static four
  const proxy2 = await boot('http://127.0.0.1:9', fakeAdapter({ models: null }));
  try {
    const models = await (await fetch(`${proxy2.url}/v1/models`)).json();
    assert.deepEqual(models.data.map((m) => m.id), ['gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5.5']);
  } finally {
    await proxy2.close();
  }
});
