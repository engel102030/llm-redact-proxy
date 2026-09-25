// End-to-end over the WebSocket transport: the proxy opens one socket per
// conversation, sends response.create, streams the events back as Anthropic
// SSE, continues the next turn with previous_response_id + delta, retries as
// a full send when the server lost the continuation, reports the plan usage
// carried by codex.rate_limits, and falls back to plain HTTP when the
// upgrade is refused or the provider is configured transport: "http".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startWsServer } from './helpers/ws-server.js';
import { startProxy } from './helpers/start-proxy.js';
import { createRedactor } from '../src/redact.js';
import { TEXT_TURN, TOOL_TURN, sseFrames } from './helpers/codex-fixtures.js';

const CANARY = 'WS-CANARY-7e1c2a-uniq-value-424242';
const MODELS = [{ slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium'] }];
const RATE_LIMITS = { type: 'codex.rate_limits', plan_type: 'prolite', rate_limits: { allowed: true, limit_reached: false, primary: { used_percent: 61, window_minutes: 10080, reset_after_seconds: 1000, reset_at: 1790951642 }, secondary: null }, credits: { has_credits: false, unlimited: false, balance: '0' } };

function fakeAdapter({ transport = 'ws' } = {}) {
  const reported = [];
  return {
    reported,
    profile: () => ({ models: MODELS, effortMap: null, prune: { enabled: false }, transport }),
    credentials: async () => ({ access: 'tok-1', accountId: 'acc-1' }),
    refresh: async () => ({ access: 'tok-2', accountId: 'acc-1' }),
    reportLimits: (l) => reported.push(l),
  };
}

// A fake Codex WS backend: answers every response.create with `script(body, n)` events.
async function fakeBackend({ script, onHttp, reject } = {}) {
  const created = [];
  const server = await startWsServer({
    reject,
    onHttp,
    onMessage: (conn, text) => {
      const body = JSON.parse(text);
      created.push(body);
      const events = script(body, created.length);
      for (const e of events) conn.send(JSON.stringify(e));
    },
  });
  return { ...server, created };
}

async function boot(backend, adapter) {
  return startProxy({
    upstreamUrl: `${backend.httpUrl}/backend-api/codex`,
    redactor: createRedactor({ secrets: [{ name: 'WS_CANARY', value: CANARY }] }),
    configOverrides: { upstreamAuth: 'codex-oauth', injectNotice: false },
    serverOptions: { codexAdapter: () => adapter },
  });
}

const post = (url, body) => fetch(`${url}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'client-key-must-not-forward' }, body: JSON.stringify(body) });

test('two turns of one session: full send, then previous_response_id + delta; canary never leaves; quota reported from the socket', async () => {
  const backend = await fakeBackend({ script: (body, n) => [RATE_LIMITS, ...TEXT_TURN.map((e) => (e.type === 'response.completed' ? { ...e, response: { ...e.response, id: `resp_${n}` } } : e))], onHttp: (req, res) => { res.writeHead(500); res.end('http must not be used'); } });
  const adapter = fakeAdapter();
  const proxy = await boot(backend, adapter);
  try {
    const history = [{ role: 'user', content: `secret ${CANARY}` }];
    const r1 = await post(proxy.url, { model: 'gpt-5.5', stream: true, metadata: { user_id: 'sess-1' }, messages: history });
    assert.equal(r1.status, 200);
    const sse1 = await r1.text();
    assert.ok(sse1.includes('event: message_start') && sse1.includes('"text":"Hi"') && sse1.includes('event: message_stop'));
    assert.equal(backend.requests.length, 1, 'one socket');
    const h = backend.requests[0].headers;
    assert.equal(h['openai-beta'], 'responses_websockets=2026-02-06');
    assert.equal(h.authorization, 'Bearer tok-1');
    assert.equal(h['chatgpt-account-id'], 'acc-1');
    assert.equal('x-api-key' in h, false);
    assert.equal(backend.created[0].type, 'response.create');
    assert.equal('previous_response_id' in backend.created[0], false);
    assert.equal(JSON.stringify(backend.created[0]).includes(CANARY), false, 'canary leaked');
    assert.ok(JSON.stringify(backend.created[0]).includes('[REDACTED:WS_CANARY]'));
    assert.equal(adapter.reported[0]?.primary?.usedPercent, 61);
    assert.equal(adapter.reported[0]?.planType, 'prolite');

    // turn 2: the client replays the assistant answer and asks again
    history.push({ role: 'assistant', content: [{ type: 'thinking', thinking: '', signature: 'ENC1' }, { type: 'text', text: 'Hi.' }] });
    history.push({ role: 'user', content: 'and again' });
    const r2 = await post(proxy.url, { model: 'gpt-5.5', stream: true, metadata: { user_id: 'sess-1' }, messages: history });
    assert.equal(r2.status, 200);
    assert.ok((await r2.text()).includes('event: message_stop'));
    assert.equal(backend.requests.length, 1, 'same socket reused');
    assert.equal(backend.created[1].previous_response_id, 'resp_1');
    assert.deepEqual(backend.created[1].input, [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: 'and again' }] }]);
    assert.equal(backend.httpRequests.length, 0);
    const s = await (await fetch(`${proxy.url}/__redact/stats.json`)).json();
    assert.match(s.recent[0].note, /ws delta/);
    assert.match(s.recent[1].note, /ws full/);
  } finally {
    await proxy.close();
    await backend.close();
  }
});

test('a tool loop continues with the tool result as the delta and stream:false is folded the same way', async () => {
  const backend = await fakeBackend({ script: (body, n) => (n === 1 ? TOOL_TURN.map((e) => (e.type === 'response.completed' ? { ...e, response: { ...e.response, id: 'resp_a' } } : e)) : TEXT_TURN) });
  const proxy = await boot(backend, fakeAdapter());
  try {
    const messages = [{ role: 'user', content: 'weather' }];
    const first = await (await post(proxy.url, { model: 'gpt-5.5', stream: false, metadata: { user_id: 'sess-2' }, messages, tools: [{ name: 'get_weather', input_schema: { type: 'object' } }] })).json();
    assert.deepEqual(first.content, [{ type: 'tool_use', id: 'call_1', name: 'get_weather', input: { city: 'Paris' } }]);
    messages.push({ role: 'assistant', content: first.content });
    messages.push({ role: 'user', content: [{ type: 'tool_result', tool_use_id: 'call_1', content: '18C' }] });
    const second = await (await post(proxy.url, { model: 'gpt-5.5', stream: false, metadata: { user_id: 'sess-2' }, messages, tools: [{ name: 'get_weather', input_schema: { type: 'object' } }] })).json();
    assert.equal(second.content.at(-1).text, 'Hi.');
    assert.equal(backend.created[1].previous_response_id, 'resp_a');
    assert.deepEqual(backend.created[1].input, [{ type: 'function_call_output', call_id: 'call_1', output: '18C' }]);
  } finally {
    await proxy.close();
    await backend.close();
  }
});

test('when the server rejects the continuation the turn is retried once as a full send on the same socket', async () => {
  const backend = await fakeBackend({ script: (body, n) => (body.previous_response_id ? [{ type: 'error', message: 'previous response not found', code: 'previous_response_not_found' }] : TEXT_TURN.map((e) => (e.type === 'response.completed' ? { ...e, response: { ...e.response, id: `resp_${n}` } } : e))) });
  const proxy = await boot(backend, fakeAdapter());
  try {
    const messages = [{ role: 'user', content: 'one' }];
    await (await post(proxy.url, { model: 'gpt-5.5', stream: true, metadata: { user_id: 'sess-3' }, messages })).text();
    messages.push({ role: 'assistant', content: [{ type: 'text', text: 'Hi.' }] }, { role: 'user', content: 'two' });
    const r = await post(proxy.url, { model: 'gpt-5.5', stream: true, metadata: { user_id: 'sess-3' }, messages });
    assert.equal(r.status, 200);
    assert.ok((await r.text()).includes('event: message_stop'));
    assert.equal(backend.created.length, 3);
    assert.equal(backend.created[1].previous_response_id, 'resp_1');
    assert.equal('previous_response_id' in backend.created[2], false);
    assert.equal(backend.created[2].input.length, 3);
  } finally {
    await proxy.close();
    await backend.close();
  }
});

test('a refused upgrade falls back to plain HTTP for a while; transport "http" never opens a socket', async () => {
  const sse = sseFrames(TEXT_TURN);
  const refused = await fakeBackend({ reject: { status: 403, text: 'Forbidden', body: 'no ws' }, onHttp: (req, res) => { res.writeHead(200); for (const f of sse) res.write(f); res.end(); } });
  const proxy = await boot(refused, fakeAdapter());
  try {
    for (let i = 0; i < 2; i += 1) {
      const r = await post(proxy.url, { model: 'gpt-5.5', stream: true, metadata: { user_id: 'sess-4' }, messages: [{ role: 'user', content: 'hi' }] });
      assert.equal(r.status, 200);
      assert.ok((await r.text()).includes('event: message_stop'));
    }
    assert.equal(refused.requests.length, 1, 'the upgrade is attempted once, then http is used until the backoff expires');
    assert.equal(refused.httpRequests.length, 2);
    assert.equal(refused.httpRequests[0].url, '/backend-api/codex/responses');
  } finally {
    await proxy.close();
    await refused.close();
  }
  const plain = await fakeBackend({ onHttp: (req, res) => { res.writeHead(200); for (const f of sse) res.write(f); res.end(); } });
  const proxy2 = await boot(plain, fakeAdapter({ transport: 'http' }));
  try {
    const r = await post(proxy2.url, { model: 'gpt-5.5', stream: true, metadata: { user_id: 'sess-5' }, messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(r.status, 200);
    await r.text();
    assert.equal(plain.requests.length, 0);
    assert.equal(plain.httpRequests.length, 1);
  } finally {
    await proxy2.close();
    await plain.close();
  }
});
