// Native Codex compaction for Claude Code's /compact. On the compaction turn
// the proxy asks the backend for its encrypted compaction item and keeps a
// native history (retained user messages + that item); once Claude Code has
// stored the text summary the model wrote, later turns that start with that
// summary get the native history instead. Pure logic here; no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  COMPACT_MESSAGE_PREFIX,
  COMPACT_MESSAGE_TASK,
  isCompactionTurn,
  splitEnvelope,
  stripCompactionInstruction,
  buildNativeHistory,
  summaryFromOutputItems,
  createCompactionRegistry,
  COMPACTION_TTL_MS,
  RETAINED_MESSAGE_TOKEN_BUDGET,
} from '../src/codex-compaction.js';

const user = (t) => ({ type: 'message', role: 'user', content: [{ type: 'input_text', text: t }] });
const dev = (t) => ({ type: 'message', role: 'developer', content: [{ type: 'input_text', text: t }] });
const assistant = (t) => ({ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: t }] });
const call = (id) => ({ type: 'function_call', call_id: id, name: 'Read', arguments: '{}' });
const out = (id, t) => ({ type: 'function_call_output', call_id: id, output: t });
const COMPACT_PROMPT = `${COMPACT_MESSAGE_PREFIX}\n\n${COMPACT_MESSAGE_TASK}, paying close attention to the user's explicit requests.`;
const req = (input, extra = {}) => ({ model: 'gpt-5.6-sol', instructions: 'be terse', tools: [], input, ...extra });

test('a compaction turn is recognized by the two Claude Code markers in the last user message', () => {
  assert.equal(isCompactionTurn(req([user('hi'), assistant('yo'), user(COMPACT_PROMPT)])), true);
  assert.equal(isCompactionTurn(req([user('hi'), assistant('yo'), { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'Please compact.' }, { type: 'input_text', text: COMPACT_PROMPT }] }])), true);
  assert.equal(isCompactionTurn(req([user(COMPACT_PROMPT), assistant('x'), user('later')])), false, 'only the LAST user message counts');
  assert.equal(isCompactionTurn(req([user(COMPACT_MESSAGE_TASK)])), false, 'both markers are required');
  assert.equal(isCompactionTurn(req([user('hi'), out('c1', COMPACT_PROMPT)])), false, 'tool outputs never trigger');
});

test('the envelope (leading developer messages) is split off and the compaction instruction is stripped', () => {
  const input = [dev('system prompt'), dev('hooks'), user('q1'), assistant('a1'), { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'a reminder' }, { type: 'input_text', text: COMPACT_PROMPT }] }];
  const { envelope, conversation } = splitEnvelope(input);
  assert.deepEqual(envelope, [dev('system prompt'), dev('hooks')]);
  assert.equal(conversation.length, 3);
  const stripped = stripCompactionInstruction(conversation);
  assert.deepEqual(stripped.at(-1), user('a reminder'));
  assert.deepEqual(stripCompactionInstruction([user('q1'), user(COMPACT_PROMPT)]), [user('q1')], 'a message left empty is dropped');
});

test('native history = the most recent user/developer messages within the token budget, then the compaction item', () => {
  const big = 'x'.repeat(RETAINED_MESSAGE_TOKEN_BUDGET * 4); // one message that alone exceeds the budget
  const conversation = [user('first'), assistant('a'), call('c1'), out('c1', 'tool'), user(big), assistant('b'), user('last question')];
  const comp = { type: 'compaction', encrypted_content: 'ENC' };
  const history = buildNativeHistory(conversation, comp);
  assert.equal(history.at(-1), comp);
  const kept = history.slice(0, -1);
  assert.ok(kept.every((m) => m.type === 'message' && m.role === 'user'), 'only user/developer messages are retained');
  assert.deepEqual(kept.at(-1), user('last question'));
  const bigKept = kept.find((m) => m.content[0].text.startsWith('xxxx'));
  assert.ok(bigKept && bigKept.content[0].text.length < big.length, 'an oversized message is truncated to fit');
  assert.equal(kept.some((m) => m.content[0].text === 'first'), false, 'nothing beyond the budget');
});

test('the anchor text is the <summary> block of the assistant output when present, else the whole text, never under 32 bytes', () => {
  assert.equal(summaryFromOutputItems([assistant('preface <summary>  The team decided to ship on Friday.  </summary> trailer')]), 'The team decided to ship on Friday.');
  assert.equal(summaryFromOutputItems([assistant('Line one of a long enough summary. '), assistant('Line two.')]), 'Line one of a long enough summary. Line two.');
  assert.equal(summaryFromOutputItems([assistant('too short')]), null);
  assert.equal(summaryFromOutputItems([{ type: 'reasoning', summary: [], encrypted_content: 'E' }]), null);
});

test('registry: begin -> anchor -> replay swaps the summary message for the native history; mismatches clear the state', () => {
  let now = 1_000_000;
  const reg = createCompactionRegistry({ now: () => now });
  const native = [user('last question'), { type: 'compaction', encrypted_content: 'ENC' }];
  const summary = 'A detailed summary of everything that happened in the session so far.';
  reg.begin('conv', { model: 'gpt-5.6-sol', nativeHistory: native });
  assert.equal(reg.replay('conv', req([user(`This session is being continued. ${summary}`), user('next')])), null, 'not anchored yet');
  reg.anchor('conv', { model: 'gpt-5.6-sol', summaryText: summary });
  const replayed = reg.replay('conv', req([dev('sys'), user(`This session is being continued from a previous conversation.\n\n${summary}`), user('next')]));
  assert.deepEqual(replayed.input, [dev('sys'), ...native, user('next')]);
  assert.equal(reg.replay('conv', req([dev('sys'), user(`intro ${summary}`)])), null, 'nothing after the summary yet');
  assert.equal(reg.replay('conv', req([user(`${summary} ${summary}`), user('x')])), null, 'the summary must appear exactly once');
  assert.equal(reg.replay('conv', req([user('unrelated first message'), user('x')])), null, 'and the state is cleared on a mismatch');
  assert.equal(reg.replay('conv', req([user(`${summary}`), user('x')])), null, 'cleared');
  reg.begin('conv', { model: 'gpt-5.6-sol', nativeHistory: native });
  reg.anchor('conv', { model: 'gpt-5.6-sol', summaryText: summary });
  assert.equal(reg.replay('conv', req([user(summary), user('x')], { model: 'gpt-5.5' })), null, 'a different model clears the state');
  reg.begin('conv', { model: 'gpt-5.6-sol', nativeHistory: native });
  reg.anchor('conv', { model: 'gpt-5.6-sol', summaryText: summary });
  now += COMPACTION_TTL_MS + 1;
  assert.equal(reg.replay('conv', req([user(summary), user('x')])), null, 'expired');
  assert.equal(reg.replay('nope', req([user(summary), user('x')])), null, 'unknown conversation');
});

test('anchor without a matching begin, or with a summary that is too short, leaves no state', () => {
  const reg = createCompactionRegistry();
  reg.anchor('conv', { model: 'm', summaryText: 'A detailed summary of everything that happened in the session so far.' });
  assert.equal(reg.size(), 0);
  reg.begin('conv', { model: 'm', nativeHistory: [{ type: 'compaction', encrypted_content: 'E' }] });
  reg.anchor('conv', { model: 'm', summaryText: null });
  assert.equal(reg.size(), 0);
});
