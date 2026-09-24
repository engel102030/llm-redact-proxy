// Request translation: Anthropic Messages -> the Responses dialect the Codex
// backend speaks. Translation runs AFTER redaction, so strictness here is
// about correctness (fail closed on anything unknown), not about leaks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  anthropicToCodex,
  mapEffort,
  findModel,
  DEFAULT_EFFORT_MAP,
  DEFAULT_INSTRUCTIONS,
  CODEX_DEFAULT_MODELS,
} from '../src/codex-translate.js';

const base = { model: 'gpt-5.6-sol', messages: [{ role: 'user', content: 'hi' }] };

test('minimal request: fixed Codex fields, default instructions, dropped Anthropic-only fields', () => {
  const out = anthropicToCodex({
    ...base,
    max_tokens: 64000,
    temperature: 0.2,
    top_p: 1,
    stop_sequences: ['x'],
    metadata: { user_id: 'user-1' },
    thinking: { type: 'adaptive', display: 'omitted' },
    context_management: { edits: [] },
    service_tier: 'auto',
  });
  assert.equal(out.model, 'gpt-5.6-sol');
  assert.equal(out.instructions, DEFAULT_INSTRUCTIONS);
  assert.deepEqual(out.input, [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: 'hi' }] }]);
  assert.equal(out.store, false);
  assert.equal(out.stream, true);
  assert.deepEqual(out.include, ['reasoning.encrypted_content']);
  assert.equal(out.parallel_tool_calls, true);
  assert.equal(out.tool_choice, 'auto');
  assert.deepEqual(out.tools, []);
  assert.equal(out.prompt_cache_key.length, 64); // sha256 hex of metadata.user_id
  assert.equal(out.prompt_cache_key.includes('user-1'), false);
  for (const k of ['max_output_tokens', 'max_tokens', 'temperature', 'top_p', 'stop_sequences', 'metadata', 'thinking', 'context_management', 'service_tier']) {
    assert.equal(k in out, false, `${k} must not be forwarded`);
  }
  assert.equal('prompt_cache_key' in anthropicToCodex(base), false);
});

test('[1m] suffix is stripped from the model id', () => {
  assert.equal(anthropicToCodex({ ...base, model: 'gpt-5.5[1m]' }).model, 'gpt-5.5');
});

test('system string and text blocks become instructions joined by a blank line', () => {
  assert.equal(anthropicToCodex({ ...base, system: '  Be terse.  ' }).instructions, 'Be terse.');
  const out = anthropicToCodex({ ...base, system: [{ type: 'text', text: 'A', cache_control: { type: 'ephemeral' } }, { type: 'text', text: '' }, { type: 'text', text: 'B' }] });
  assert.equal(out.instructions, 'A\n\nB');
  assert.equal(anthropicToCodex({ ...base, system: [] }).instructions, DEFAULT_INSTRUCTIONS);
});

test('effort: default map, provider map, clamp to the model levels', () => {
  assert.equal(mapEffort('high'), 'xhigh');
  assert.equal(mapEffort('low'), 'low');
  assert.equal(mapEffort('max', { levels: ['low', 'medium', 'high', 'xhigh'] }), 'xhigh');
  assert.equal(mapEffort('low', { levels: ['medium', 'high'] }), 'medium');
  assert.equal(mapEffort('medium', { effortMap: { ...DEFAULT_EFFORT_MAP, medium: 'high' } }), 'high');
  assert.equal(mapEffort('weird', { levels: ['low', 'medium'] }), 'weird'); // unknown: let the backend reject it
  assert.equal(mapEffort(undefined), null);
  const out = anthropicToCodex({ ...base, model: 'gpt-5.5', output_config: { effort: 'max' } }, { models: CODEX_DEFAULT_MODELS });
  assert.deepEqual(out.reasoning, { effort: 'xhigh', summary: 'auto' });
  assert.deepEqual(anthropicToCodex({ ...base, output_config: { effort: 'high' } }).reasoning, { effort: 'xhigh', summary: 'auto' });
});

test('no effort from the client: the model default level, else medium', () => {
  assert.equal(anthropicToCodex(base, { models: CODEX_DEFAULT_MODELS }).reasoning.effort, 'low'); // gpt-5.6-sol default
  assert.equal(anthropicToCodex({ ...base, model: 'unknown-model' }).reasoning.effort, 'medium');
  assert.equal(findModel(CODEX_DEFAULT_MODELS, 'gpt-5.5').defaultLevel, 'medium');
  assert.equal(findModel(null, 'gpt-5.5'), null);
});

test('tool loop: tool_use -> function_call, tool_result -> function_call_output, order kept', () => {
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: 'weather?' },
      { role: 'assistant', content: [{ type: 'text', text: 'checking' }, { type: 'tool_use', id: 'call_1', name: 'get_weather', input: { city: 'Paris' } }] },
      {
        role: 'user',
        content: [
          { type: 'tool_result', tool_use_id: 'call_1', is_error: true, content: [{ type: 'text', text: '18C' }, { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AA==' } }] },
          { type: 'text', text: 'and now?' },
        ],
      },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'weather?' }] },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'checking' }] },
    { type: 'function_call', call_id: 'call_1', name: 'get_weather', arguments: '{"city":"Paris"}' },
    { type: 'function_call_output', call_id: 'call_1', output: 'ERROR: 18C\n[image omitted]' },
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'and now?' }] },
  ]);
});

test('tool_result with a string or no content', () => {
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'c1', content: 'plain' }, { type: 'tool_result', tool_use_id: 'c2' }] },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'function_call_output', call_id: 'c1', output: 'plain' },
    { type: 'function_call_output', call_id: 'c2', output: '' },
  ]);
});

test('thinking with a signature replays as a reasoning item; without one it is dropped', () => {
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: 'q' },
      {
        role: 'assistant',
        content: [
          { type: 'thinking', thinking: 'plan', signature: 'ENC' },
          { type: 'thinking', thinking: 'no sig', signature: '' },
          { type: 'redacted_thinking', data: 'zzz' },
          { type: 'text', text: 'answer' },
        ],
      },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'q' }] },
    { type: 'reasoning', summary: [{ type: 'summary_text', text: 'plan' }], encrypted_content: 'ENC' },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'answer' }] },
  ]);
  const empty = anthropicToCodex({ ...base, messages: [{ role: 'assistant', content: [{ type: 'thinking', thinking: '', signature: 'ENC2' }] }] });
  assert.deepEqual(empty.input, [{ type: 'reasoning', summary: [], encrypted_content: 'ENC2' }]);
});

test('user image becomes an input_image data URL; url sources pass through', () => {
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: [{ type: 'text', text: 'look' }, { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: 'QUJD' } }, { type: 'image', source: { type: 'url', url: 'https://x/y.png' } }] },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'look' }, { type: 'input_image', image_url: 'data:image/jpeg;base64,QUJD' }, { type: 'input_image', image_url: 'https://x/y.png' }] },
  ]);
});

test('tools: function tools mapped, defer_loading ignored, server tools dropped, tool_choice mapped', () => {
  const out = anthropicToCodex({
    ...base,
    tools: [
      { name: 'Read', description: 'read a file', input_schema: { type: 'object' }, defer_loading: true },
      { type: 'web_search_20250305', name: 'web_search' },
      { type: 'custom', name: 'Grep', input_schema: { type: 'object', properties: {} } },
    ],
    tool_choice: { type: 'any', disable_parallel_tool_use: true },
  });
  assert.deepEqual(out.tools, [
    { type: 'function', name: 'Read', description: 'read a file', parameters: { type: 'object' }, strict: false },
    { type: 'function', name: 'Grep', parameters: { type: 'object', properties: {} }, strict: false },
  ]);
  assert.equal(out.tool_choice, 'required');
  assert.equal(out.parallel_tool_calls, false);
  assert.deepEqual(anthropicToCodex({ ...base, tools: [{ name: 'x', input_schema: {} }], tool_choice: { type: 'tool', name: 'x' } }).tool_choice, { type: 'function', name: 'x' });
  assert.equal(anthropicToCodex({ ...base, tool_choice: { type: 'none' } }).tool_choice, 'none');
  assert.equal(anthropicToCodex({ ...base, tool_choice: { type: 'any' } }).tool_choice, 'auto'); // no tools: required would be rejected
});

test('a system-role message (Claude Code sends its prompt this way for non-Claude models) becomes a developer item, order kept', () => {
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: 'hi' },
      { role: 'system', content: [{ type: 'text', text: 'You are Claude Code.', cache_control: { type: 'ephemeral' } }, { type: 'text', text: 'Be brief.' }] },
      { role: 'system', content: 'plain string' },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'hi' }] },
    { type: 'message', role: 'developer', content: [{ type: 'input_text', text: 'You are Claude Code.' }, { type: 'input_text', text: 'Be brief.' }] },
    { type: 'message', role: 'developer', content: [{ type: 'input_text', text: 'plain string' }] },
  ]);
  assert.throws(() => anthropicToCodex({ ...base, messages: [{ role: 'system', content: [{ type: 'image', source: { type: 'url', url: 'x' } }] }] }), /only supported in user messages/);
  assert.throws(() => anthropicToCodex({ ...base, messages: [{ role: 'tool', content: 'x' }] }), /unsupported message role: tool/);
});

test('tool-search artefacts: tool_reference parts become text, tool_addition blocks are dropped', () => {
  // Claude Code's ToolSearch answers with tool_reference parts and then adds a
  // system message with tool_addition blocks; every tool is already sent in
  // tools[], so the reference is informational.
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'c1', content: [{ type: 'text', text: 'found:' }, { type: 'tool_reference', tool_name: 'ArtifactData' }, { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: 'AA==' } }] }] },
      { role: 'system', content: [{ type: 'text', text: 'tools added' }, { type: 'tool_addition', tool: { type: 'tool_reference', name: 'ArtifactData' } }] },
      { role: 'system', content: [{ type: 'tool_addition', tool: { type: 'tool_reference', name: 'Bash' } }] },
      { role: 'user', content: 'go' },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'function_call_output', call_id: 'c1', output: 'found:\n[tool available: ArtifactData]\n[document omitted]' },
    { type: 'message', role: 'developer', content: [{ type: 'input_text', text: 'tools added' }] },
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'go' }] },
  ]);
  assert.throws(() => anthropicToCodex({ ...base, messages: [{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 'c1', content: [{ type: 'tool_reference' }] }] }] }), /tool_reference has no tool_name/);
});

test('unknown content block or malformed request throws (fail closed)', () => {
  assert.throws(() => anthropicToCodex({ ...base, messages: [{ role: 'user', content: [{ type: 'document', source: {} }] }] }), /unsupported content block type: document/);
  assert.throws(() => anthropicToCodex({ ...base, messages: [{ role: 'function', content: 'x' }] }), /unsupported message role/);
  assert.throws(() => anthropicToCodex({ ...base, messages: 'nope' }), /messages must be an array/);
  assert.throws(() => anthropicToCodex({ messages: [] }), /model is required/);
  assert.throws(() => anthropicToCodex({ ...base, system: [{ type: 'image' }] }), /text blocks/);
  assert.throws(() => anthropicToCodex({ ...base, tools: [{ name: '', input_schema: {} }] }), /tool has no name/);
  assert.throws(() => anthropicToCodex({ ...base, tool_choice: { type: 'tool' } }), /needs a name/);
  assert.throws(() => anthropicToCodex('not an object'), /JSON object/);
});

// ---------------------------------------------------------------------------
// Response side: Responses SSE -> Anthropic SSE events
// ---------------------------------------------------------------------------
import { SseDecoder, CodexReducer, serializeSse, errorSse, accumulateMessage, estimateTokens } from '../src/codex-translate.js';
import { TEXT_TURN, TOOL_TURN } from './helpers/codex-fixtures.js';

function run(events) {
  const r = new CodexReducer({ messageId: 'msg_1', model: 'gpt-5.6-sol' });
  const out = [];
  for (const e of events) out.push(...r.push(e));
  return { out, r };
}

test('text turn: reasoning (empty summary) -> thinking block with signature, text block, end_turn + usage', () => {
  const { out, r } = run(TEXT_TURN);
  assert.deepEqual(
    out.map((e) => e.event),
    ['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'content_block_start', 'content_block_delta', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop'],
  );
  assert.deepEqual(out[0].data.message, { id: 'msg_1', type: 'message', role: 'assistant', model: 'gpt-5.6-sol', content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } });
  assert.deepEqual(out[1].data, { type: 'content_block_start', index: 0, content_block: { type: 'thinking', thinking: '', signature: '' } });
  assert.deepEqual(out[2].data.delta, { type: 'signature_delta', signature: 'ENC1' });
  assert.deepEqual(out[4].data, { type: 'content_block_start', index: 1, content_block: { type: 'text', text: '' } });
  assert.deepEqual(out[5].data.delta, { type: 'text_delta', text: 'Hi' });
  assert.deepEqual(out[8].data, { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { input_tokens: 24, output_tokens: 18, cache_read_input_tokens: 5 } });
  assert.equal(r.done, true);
  assert.deepEqual(r.push({ type: 'response.output_text.delta', output_index: 9, delta: 'late' }), []); // after done: ignored
});

test('tool turn: function_call -> tool_use block with input_json deltas, stop_reason tool_use', () => {
  const { out } = run(TOOL_TURN);
  assert.deepEqual(out[1].data, { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'call_1', name: 'get_weather', input: {} } });
  assert.deepEqual(out[2].data.delta, { type: 'input_json_delta', partial_json: '{"city":' });
  assert.deepEqual(out[3].data.delta, { type: 'input_json_delta', partial_json: '"Paris"}' });
  assert.equal(out[4].event, 'content_block_stop');
  assert.equal(out[5].data.delta.stop_reason, 'tool_use');
  assert.deepEqual(out[5].data.usage, { input_tokens: 10, output_tokens: 6, cache_read_input_tokens: 0 });
});

test('function_call whose arguments never streamed: the final arguments become one delta', () => {
  const { out } = run([
    { type: 'response.created', response: {} },
    { type: 'response.output_item.added', output_index: 0, item: { id: 'fc', type: 'function_call', call_id: 'c9', name: 'ls', arguments: '' } },
    { type: 'response.output_item.done', output_index: 0, item: { id: 'fc', type: 'function_call', call_id: 'c9', name: 'ls', arguments: '{"path":"."}' } },
    { type: 'response.completed', response: { usage: {} } },
  ]);
  assert.deepEqual(out[2].data.delta, { type: 'input_json_delta', partial_json: '{"path":"."}' });
});

test('reasoning summary deltas stream as thinking_delta; a second part gets a blank-line separator', () => {
  const { out } = run([
    { type: 'response.created', response: {} },
    { type: 'response.output_item.added', output_index: 0, item: { id: 'rs', type: 'reasoning', summary: [] } },
    { type: 'response.reasoning_summary_part.added', output_index: 0, summary_index: 0, part: { type: 'summary_text', text: '' } },
    { type: 'response.reasoning_summary_text.delta', output_index: 0, summary_index: 0, delta: 'Think A' },
    { type: 'response.reasoning_summary_part.done', output_index: 0, summary_index: 0 },
    { type: 'response.reasoning_summary_part.added', output_index: 0, summary_index: 1, part: { type: 'summary_text', text: '' } },
    { type: 'response.reasoning_summary_text.delta', output_index: 0, summary_index: 1, delta: 'Think B' },
    { type: 'response.output_item.done', output_index: 0, item: { id: 'rs', type: 'reasoning', summary: [{ type: 'summary_text', text: 'Think A' }, { type: 'summary_text', text: 'Think B' }], encrypted_content: 'ENC' } },
    { type: 'response.completed', response: { usage: {} } },
  ]);
  const thinking = out.filter((e) => e.data.delta?.type === 'thinking_delta').map((e) => e.data.delta.thinking).join('');
  assert.equal(thinking, 'Think A\n\nThink B');
  assert.equal(out.filter((e) => e.data.delta?.type === 'signature_delta').length, 1);
});

test('summary present only in the done item is emitted once', () => {
  const { out } = run([
    { type: 'response.created', response: {} },
    { type: 'response.output_item.added', output_index: 0, item: { id: 'rs', type: 'reasoning', summary: [] } },
    { type: 'response.output_item.done', output_index: 0, item: { id: 'rs', type: 'reasoning', summary: [{ type: 'summary_text', text: 'Only here' }], encrypted_content: 'E' } },
    { type: 'response.completed', response: { usage: {} } },
  ]);
  const thinking = out.filter((e) => e.data.delta?.type === 'thinking_delta').map((e) => e.data.delta.thinking);
  assert.deepEqual(thinking, ['Only here']);
});

test('out-of-order delta, duplicate created, wrong block kind, failed and error events throw', () => {
  assert.throws(() => run([{ type: 'response.created' }, { type: 'response.output_text.delta', output_index: 3, delta: 'x' }]), /not open/);
  assert.throws(() => run([{ type: 'response.created' }, { type: 'response.created' }]), /duplicate/);
  assert.throws(() => run([{ type: 'response.output_text.delta', output_index: 0, delta: 'x' }]), /before response.created/);
  assert.throws(
    () => run([{ type: 'response.created' }, { type: 'response.output_item.added', output_index: 0, item: { type: 'message' } }, { type: 'response.reasoning_summary_text.delta', output_index: 0, delta: 'x' }]),
    /for a text block/,
  );
  assert.throws(() => run([{ type: 'response.created' }, { type: 'response.failed', response: { error: { message: 'quota exhausted' } } }]), /quota exhausted/);
  assert.throws(() => run([{ type: 'response.created' }, { type: 'error', message: 'boom' }]), /boom/);
  assert.throws(() => run([{ nope: true }]), /no type/);
});

test('unknown item types and unknown events are ignored; incomplete -> max_tokens and open blocks are closed', () => {
  const { out, r } = run([
    { type: 'response.created', response: {} },
    { type: 'response.output_item.added', output_index: 0, item: { id: 'ws', type: 'web_search_call' } },
    { type: 'response.web_search_call.searching', output_index: 0 },
    { type: 'response.output_item.done', output_index: 0, item: { id: 'ws', type: 'web_search_call' } },
    { type: 'response.output_item.added', output_index: 1, item: { id: 'm', type: 'message', content: [] } },
    { type: 'response.output_text.delta', output_index: 1, delta: 'partial' },
    { type: 'response.incomplete', response: { usage: { input_tokens: 1, output_tokens: 2 } } },
  ]);
  assert.deepEqual(out.map((e) => e.event), ['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop']);
  assert.equal(out[1].data.index, 0); // the ignored item consumed no index
  assert.equal(out[4].data.delta.stop_reason, 'max_tokens');
  assert.equal(r.done, true);
});

test('SseDecoder: frames split across chunks, CRLF, [DONE], comments, a final frame without blank line, size cap', () => {
  const d = new SseDecoder();
  const text = ': keepalive\nevent: x\ndata: {"a":1}\n\ndata: {"b":\ndata: 2}\r\n\r\ndata: [DONE]\n\ndata: {"c":3}';
  const all = [...d.push(Buffer.from(text.slice(0, 20))), ...d.push(Buffer.from(text.slice(20, 50))), ...d.push(text.slice(50)), ...d.flush()];
  assert.deepEqual(all, [{ a: 1 }, { b: 2 }, { c: 3 }]);
  assert.deepEqual(new SseDecoder().flush(), []);
  assert.throws(() => new SseDecoder().push('data: not-json\n\n'), /not valid JSON/);
  // a tool-call done frame repeats the full arguments: multi-megabyte frames must pass
  // (arrives in chunks, like a real stream - the partial frame sits in the buffer)
  const bigFrame = `data: {"x":"${'y'.repeat(2 * 1024 * 1024)}"}\n\n`;
  const chunked = new SseDecoder();
  const first = chunked.push(bigFrame.slice(0, 1536 * 1024));
  assert.deepEqual(first, []);
  const big = chunked.push(bigFrame.slice(1536 * 1024));
  assert.equal(big[0].x.length, 2 * 1024 * 1024);
  assert.throws(() => new SseDecoder().push(`data: {"x":"${'y'.repeat(8 * 1024 * 1024 + 16)}`), /size limit/);
});

test('serializeSse and errorSse produce Anthropic SSE frames', () => {
  const s = serializeSse([{ event: 'message_stop', data: { type: 'message_stop' } }]);
  assert.equal(s, 'event: message_stop\ndata: {"type":"message_stop"}\n\n');
  assert.equal(errorSse('bad'), 'event: error\ndata: {"type":"error","error":{"type":"api_error","message":"bad"}}\n\n');
});

test('accumulateMessage folds a stream into one Messages-API body', () => {
  const tool = accumulateMessage(run(TOOL_TURN).out);
  assert.equal(tool.type, 'message');
  assert.equal(tool.id, 'msg_1');
  assert.equal(tool.stop_reason, 'tool_use');
  assert.deepEqual(tool.content, [{ type: 'tool_use', id: 'call_1', name: 'get_weather', input: { city: 'Paris' } }]);
  assert.deepEqual(tool.usage, { input_tokens: 10, output_tokens: 6, cache_read_input_tokens: 0 });
  const text = accumulateMessage(run(TEXT_TURN).out);
  assert.deepEqual(text.content, [{ type: 'thinking', thinking: '', signature: 'ENC1' }, { type: 'text', text: 'Hi.' }]);
  assert.throws(() => accumulateMessage([]), /before message_start/);
});

test('estimateTokens is a deterministic bytes/4 estimate over what is sent', () => {
  assert.equal(estimateTokens({ instructions: 'abcd', input: [], tools: [] }), Math.ceil((4 + 2 + 2) / 4));
});
