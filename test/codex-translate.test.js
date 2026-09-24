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

test('unknown content block or malformed request throws (fail closed)', () => {
  assert.throws(() => anthropicToCodex({ ...base, messages: [{ role: 'user', content: [{ type: 'document', source: {} }] }] }), /unsupported content block type: document/);
  assert.throws(() => anthropicToCodex({ ...base, messages: [{ role: 'system', content: 'x' }] }), /unsupported message role/);
  assert.throws(() => anthropicToCodex({ ...base, messages: 'nope' }), /messages must be an array/);
  assert.throws(() => anthropicToCodex({ messages: [] }), /model is required/);
  assert.throws(() => anthropicToCodex({ ...base, system: [{ type: 'image' }] }), /text blocks/);
  assert.throws(() => anthropicToCodex({ ...base, tools: [{ name: '', input_schema: {} }] }), /tool has no name/);
  assert.throws(() => anthropicToCodex({ ...base, tool_choice: { type: 'tool' } }), /needs a name/);
  assert.throws(() => anthropicToCodex('not an object'), /JSON object/);
});
