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
    assert.equal(s.recent[0].inputTokens, 24); // dashboard shows the TOTAL input (uncached + cached)
    assert.equal(s.recent[0].outputTokens, 18);
    // the client sees Anthropic semantics and a non-zero estimate up front
    const sse = await (await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi again' }] })).text();
    const start = JSON.parse(sse.split('\n').find((l) => l.startsWith('data: ') && l.includes('message_start')).slice(6));
    assert.ok(start.message.usage.input_tokens > 0, 'message_start carries an input estimate');
    const delta = JSON.parse(sse.split('\n').find((l) => l.startsWith('data: ') && l.includes('message_delta')).slice(6));
    assert.deepEqual(delta.usage, { input_tokens: 19, output_tokens: 18, cache_read_input_tokens: 5, cache_creation_input_tokens: 0 });
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('fail closed: an untranslatable body is answered 400 and the upstream receives nothing', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN) });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: [{ type: 'container_upload', file_id: 'f' }] }] });
    assert.equal(res.status, 400);
    const j = await res.json();
    assert.match(j.error.message, /unsupported content block type: container_upload/);
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
    assert.deepEqual(models.data.map((m) => m.id), ['gpt-6-astra', 'gpt-6-sol', 'gpt-6-luna', 'gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5.5']);
  } finally {
    await proxy2.close();
  }
});

test('session_id is stable per Claude Code session (derived from metadata.user_id) so the backend cache routes consistently', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN), sseDelayMs: 1 });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const body = (userId) => ({ model: 'gpt-5.5', stream: true, metadata: userId ? { user_id: userId } : undefined, messages: [{ role: 'user', content: 'hi' }] });
    await (await post(proxy.url, body('session-A'))).text();
    await (await post(proxy.url, body('session-A'))).text();
    await (await post(proxy.url, body('session-B'))).text();
    await (await post(proxy.url, body(null))).text();
    await (await post(proxy.url, body(null))).text();
    const sids = upstream.requests.map((r) => r.headers.session_id);
    assert.match(sids[0], /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.equal(sids[0], sids[1], 'same Claude Code session -> same session_id');
    assert.notEqual(sids[0], sids[2], 'different session -> different session_id');
    assert.notEqual(sids[3], sids[4], 'no metadata.user_id -> a fresh id per request');
    assert.equal(sids[0].includes('session-A'), false);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('the message_start input estimate is calibrated per session from the previous turn (no meter swing)', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN), sseDelayMs: 1 });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const { estimateTokens } = await import('../src/codex-translate.js');
    const startUsage = (sse) => JSON.parse(sse.split('\n').find((l) => l.startsWith('data: ') && l.includes('message_start')).slice(6)).message.usage.input_tokens;
    const turn = async (userId, text) => startUsage(await (await post(proxy.url, { model: 'gpt-5.5', stream: true, metadata: { user_id: userId }, messages: [{ role: 'user', content: text }] })).text());

    const first = await turn('cal-A', 'x'.repeat(4000));
    const sent1 = estimateTokens(JSON.parse(upstream.requests[0].body));
    assert.ok(first > 0 && first < sent1, 'uncalibrated: a conservative fraction of bytes/4');
    // TEXT_TURN reports a real total of 24 tokens: the next turn of the same session scales bytes/4 by 24/sent1
    const second = await turn('cal-A', 'x'.repeat(8000));
    const sent2 = estimateTokens(JSON.parse(upstream.requests[1].body));
    assert.equal(second, Math.round((sent2 * 24) / sent1));
    // another session starts uncalibrated
    const other = await turn('cal-B', 'x'.repeat(8000));
    assert.notEqual(other, second);
    assert.ok(other > second);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('the active provider prune config is applied: old tool results leave as placeholders, the last ones intact', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN), sseDelayMs: 1 });
  const adapter = fakeAdapter();
  adapter.profile = () => ({ models: MODELS, effortMap: null, prune: { enabled: true, triggerTokens: 2000, keepToolUses: 1, clearAtLeastTokens: 500, reasoning: 'turn' } });
  const proxy = await boot(upstream.url, adapter);
  try {
    const messages = [{ role: 'user', content: 'go' }];
    for (let n = 1; n <= 3; n += 1) {
      messages.push({ role: 'assistant', content: [{ type: 'thinking', thinking: '', signature: `ENC${n}` }, { type: 'tool_use', id: `call_${n}`, name: 'Read', input: { n } }] });
      messages.push({ role: 'user', content: [{ type: 'tool_result', tool_use_id: `call_${n}`, content: 'y'.repeat(6000) }] });
    }
    await (await post(proxy.url, { model: 'gpt-5.5', stream: true, messages })).text();
    const wire = JSON.parse(upstream.requests[0].body);
    const outputs = wire.input.filter((i) => i.type === 'function_call_output').map((o) => o.output === '[tool result cleared to save context]');
    assert.deepEqual(outputs, [true, true, false]);
    assert.equal(wire.input.filter((i) => i.type === 'reasoning').length, 3, 'all three are in the current tool loop');
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// Plan usage (rate-limit headers the backend returns on every response)
// ---------------------------------------------------------------------------
import { parseCodexLimits } from '../src/codex-upstream.js';

test('parseCodexLimits reads the x-codex-* headers into a plan-usage record', () => {
  const limits = parseCodexLimits({
    'x-codex-plan-type': 'prolite',
    'x-codex-active-limit': 'premium',
    'x-codex-primary-used-percent': '58',
    'x-codex-primary-window-minutes': '10080',
    'x-codex-primary-reset-after-seconds': '599769',
    'x-codex-primary-reset-at': '1790951642',
    'x-codex-secondary-used-percent': '0',
    'x-codex-secondary-window-minutes': '0',
    'x-codex-secondary-reset-at': '',
    'x-codex-credits-has-credits': 'False',
    'x-codex-credits-balance': '0',
    'x-codex-credits-unlimited': 'False',
  }, 1_700_000_000_000);
  assert.deepEqual(limits, {
    planType: 'prolite',
    activeLimit: 'premium',
    primary: { usedPercent: 58, windowMinutes: 10080, resetAt: 1790951642000 },
    secondary: null,
    credits: { hasCredits: false, unlimited: false, balance: '0' },
    observedAt: 1_700_000_000_000,
  });
  assert.equal(parseCodexLimits({ 'content-type': 'application/json' }, 1), null);
  const both = parseCodexLimits({ 'x-codex-primary-used-percent': '12', 'x-codex-primary-window-minutes': '10080', 'x-codex-secondary-used-percent': '80', 'x-codex-secondary-window-minutes': '300', 'x-codex-secondary-reset-at': '1790000000' }, 5);
  assert.deepEqual(both.secondary, { usedPercent: 80, windowMinutes: 300, resetAt: 1790000000000 });
  assert.equal(both.planType, null);
});

test('plan usage headers are reported to the adapter on every answered request and noted in the log line', async () => {
  const limitHeaders = { 'x-codex-plan-type': 'prolite', 'x-codex-primary-used-percent': '58', 'x-codex-primary-window-minutes': '10080', 'x-codex-primary-reset-at': '1790951642' };
  const upstream = await scriptedUpstream([sseResponder(sseFrames(TEXT_TURN), limitHeaders), jsonResponder(429, { detail: 'usage limit reached' })]);
  const adapter = fakeAdapter();
  const reported = [];
  adapter.reportLimits = (l) => reported.push(l);
  const proxy = await boot(upstream.url, adapter);
  try {
    await (await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi' }] })).text();
    assert.equal(reported.length, 1);
    assert.equal(reported[0].primary.usedPercent, 58);
    assert.equal(reported[0].planType, 'prolite');
    const s = await (await fetch(`${proxy.url}/__redact/stats.json`)).json();
    assert.match(s.recent[0].note, /quota 58%/);
    // a 429 without the headers reports nothing new
    await post(proxy.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(reported.length, 1);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});
