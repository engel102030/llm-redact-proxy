// Continuation over the Codex WebSocket transport: after a response the
// server keeps the conversation, so the next turn only needs the NEW items
// plus previous_response_id. The registry decides, per conversation, whether
// the client's translated input still matches what the server has (then a
// delta is sent) or not (full resend). Reasoning items never travel in a
// delta: every one the client replays was produced by the server.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createContinuationRegistry, CONTINUATION_TTL_MS } from '../src/codex-continuation.js';

const user = (t) => ({ type: 'message', role: 'user', content: [{ type: 'input_text', text: t }] });
const call = (id, args) => ({ type: 'function_call', call_id: id, name: 'Read', arguments: args });
const out = (id, text) => ({ type: 'function_call_output', call_id: id, output: text });
const reasoning = (enc) => ({ type: 'reasoning', summary: [], encrypted_content: enc });
const assistant = (text) => ({ type: 'message', role: 'assistant', content: [{ type: 'output_text', text }] });
const base = { model: 'gpt-5.6-sol', instructions: 'be terse', tools: [{ type: 'function', name: 'Read', parameters: {}, strict: false }], tool_choice: 'auto', parallel_tool_calls: true, reasoning: { effort: 'low', summary: 'auto' } };
const req = (input) => ({ ...base, input });

test('first turn is full; after commit the next turn is a delta with previous_response_id, reasoning items excluded', () => {
  let now = 1_000_000;
  const reg = createContinuationRegistry({ now: () => now });
  const t1 = req([user('q1')]);
  const p1 = reg.plan('conv', t1);
  assert.equal(p1.mode, 'full');
  assert.deepEqual(p1.input, t1.input);
  reg.commit('conv', { translated: t1, sentInput: t1.input, responseId: 'resp_1', outputItems: [reasoning('ENC1'), call('c1', '{"path":"a"}')] });
  // the client replays the server's output (reasoning + call) and adds the tool result
  const t2 = req([user('q1'), reasoning('ENC1'), call('c1', '{"path":"a"}'), out('c1', 'file a')]);
  const p2 = reg.plan('conv', t2);
  assert.equal(p2.mode, 'delta');
  assert.equal(p2.previousResponseId, 'resp_1');
  assert.deepEqual(p2.input, [out('c1', 'file a')]);
  reg.commit('conv', { translated: t2, sentInput: p2.input, responseId: 'resp_2', outputItems: [reasoning('ENC2'), assistant('done')] });
  // next user turn: the client dropped old-turn reasoning (prune scope "turn") - still a delta
  const t3 = req([user('q1'), call('c1', '{"path":"a"}'), out('c1', 'file a'), assistant('done'), user('q2')]);
  const p3 = reg.plan('conv', t3);
  assert.equal(p3.mode, 'delta');
  assert.equal(p3.previousResponseId, 'resp_2');
  assert.deepEqual(p3.input, [user('q2')]);
});

test('a changed prompt signature (tools, model, instructions, reasoning) forces a full resend', () => {
  const reg = createContinuationRegistry();
  const t1 = req([user('q1')]);
  reg.plan('conv', t1);
  reg.commit('conv', { translated: t1, sentInput: t1.input, responseId: 'resp_1', outputItems: [assistant('a')] });
  const history = [user('q1'), assistant('a'), user('q2')];
  assert.equal(reg.plan('conv', req(history)).mode, 'delta');
  assert.equal(reg.plan('conv', { ...req(history), tools: [] }).mode, 'full');
  assert.equal(reg.plan('conv', { ...req(history), model: 'gpt-5.5' }).mode, 'full');
  assert.equal(reg.plan('conv', { ...req(history), reasoning: { effort: 'high', summary: 'auto' } }).mode, 'full');
});

test('a modified history (e.g. a tool result cleared by pruning) forces a full resend, and the full send re-anchors the transcript', () => {
  const reg = createContinuationRegistry();
  const t1 = req([user('q1'), call('c1', '{}'), out('c1', 'big output'), assistant('ok'), user('q2')]);
  reg.plan('conv', t1);
  reg.commit('conv', { translated: t1, sentInput: t1.input, responseId: 'resp_1', outputItems: [assistant('sure')] });
  const pruned = req([user('q1'), call('c1', '{}'), out('c1', '[tool result cleared to save context]'), assistant('ok'), user('q2'), assistant('sure'), user('q3')]);
  const p = reg.plan('conv', pruned);
  assert.equal(p.mode, 'full');
  assert.deepEqual(p.input, pruned.input);
  reg.commit('conv', { translated: pruned, sentInput: pruned.input, responseId: 'resp_2', outputItems: [assistant('fine')] });
  const next = req([...pruned.input, assistant('fine'), user('q4')]);
  const p2 = reg.plan('conv', next);
  assert.equal(p2.mode, 'delta');
  assert.deepEqual(p2.input, [user('q4')]);
});

test('function_call arguments are compared as JSON values (key order and spacing may differ on replay)', () => {
  const reg = createContinuationRegistry();
  const t1 = req([user('q1')]);
  reg.plan('conv', t1);
  reg.commit('conv', { translated: t1, sentInput: t1.input, responseId: 'resp_1', outputItems: [call('c1', '{"b": 1, "a": "x"}')] });
  const replay = req([user('q1'), call('c1', '{"a":"x","b":1}'), out('c1', 'r')]);
  const p = reg.plan('conv', replay);
  assert.equal(p.mode, 'delta');
  assert.deepEqual(p.input, [out('c1', 'r')]);
});

test('consecutive assistant text items are merged for comparison (the client replays them as one message)', () => {
  const reg = createContinuationRegistry();
  const t1 = req([user('q1')]);
  reg.plan('conv', t1);
  reg.commit('conv', { translated: t1, sentInput: t1.input, responseId: 'resp_1', outputItems: [assistant('part one. '), assistant('part two.')] });
  const replay = req([user('q1'), { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'part one. ' }, { type: 'output_text', text: 'part two.' }] }, user('q2')]);
  const p = reg.plan('conv', replay);
  assert.equal(p.mode, 'delta');
  assert.deepEqual(p.input, [user('q2')]);
});

test('a shorter or unrelated history, an expired state and an unknown conversation are full sends; invalidate drops the state', () => {
  let now = 1_000_000;
  const reg = createContinuationRegistry({ now: () => now });
  const t1 = req([user('q1'), assistant('a'), user('q2')]);
  reg.plan('conv', t1);
  reg.commit('conv', { translated: t1, sentInput: t1.input, responseId: 'resp_1', outputItems: [assistant('b')] });
  assert.equal(reg.plan('conv', req([user('q1')])).mode, 'full', 'shorter history');
  assert.equal(reg.plan('other', req([user('q1'), assistant('a'), user('q2'), assistant('b'), user('q3')])).mode, 'full', 'unknown conversation');
  reg.commit('conv', { translated: t1, sentInput: t1.input, responseId: 'resp_1', outputItems: [assistant('b')] });
  now += CONTINUATION_TTL_MS + 1;
  assert.equal(reg.plan('conv', req([user('q1'), assistant('a'), user('q2'), assistant('b'), user('q3')])).mode, 'full', 'expired');
  reg.commit('conv', { translated: t1, sentInput: t1.input, responseId: 'resp_1', outputItems: [assistant('b')] });
  reg.invalidate('conv');
  assert.equal(reg.plan('conv', req([user('q1'), assistant('a'), user('q2'), assistant('b'), user('q3')])).mode, 'full', 'invalidated');
});

test('the registry is bounded: the oldest conversations are evicted', () => {
  const reg = createContinuationRegistry({ maxConversations: 2 });
  for (const k of ['a', 'b', 'c']) {
    const t = req([user(k)]);
    reg.plan(k, t);
    reg.commit(k, { translated: t, sentInput: t.input, responseId: `r_${k}`, outputItems: [assistant('x')] });
  }
  assert.equal(reg.plan('a', req([user('a'), assistant('x'), user('more')])).mode, 'full');
  assert.equal(reg.plan('c', req([user('c'), assistant('x'), user('more')])).mode, 'delta');
});
