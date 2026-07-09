// Rehydration engine: {{NAME}} in a response is substituted back to the real
// secret value, streaming-safe (markers may be split across SSE deltas).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMarkerMap,
  createFieldReplacer,
  rehydrateJsonBody,
  createSseRehydrator,
  jsonEscapeInner,
} from '../src/rehydrate.js';

const SECRETS = [
  { name: 'VIBECODE_API_KEY', value: 'cap_exampleFAKEkey000000000000000000' },
  { name: 'DB_PASSWORD', value: 'p@ss"w\\rd-123' }, // contains chars that need JSON escaping
];
const map = () => buildMarkerMap(SECRETS);

// Feed a string one character at a time through a field replacer - the worst
// case for marker splitting. The concatenated output must equal a single-shot
// replacement.
function drip(text, opts) {
  const r = createFieldReplacer(map(), opts);
  let out = '';
  for (const ch of text) out += r.push(ch);
  out += r.flush();
  return out;
}

test('field replacer substitutes a complete marker in one push', () => {
  const r = createFieldReplacer(map());
  assert.equal(r.push('key is {{VIBECODE_API_KEY}} ok') + r.flush(), 'key is cap_exampleFAKEkey000000000000000000 ok');
});

test('field replacer matches a marker split across EVERY boundary (char drip)', () => {
  const text = 'a {{VIBECODE_API_KEY}} b {{DB_PASSWORD}} c';
  const expected = 'a cap_exampleFAKEkey000000000000000000 b p@ss"w\\rd-123 c';
  assert.equal(drip(text), expected);
});

test('field replacer leaves unknown names and stray braces untouched', () => {
  assert.equal(drip('{{UNKNOWN}} and {{ not a marker }} and { lone'), '{{UNKNOWN}} and {{ not a marker }} and { lone');
});

test('field replacer escape mode JSON-escapes the value (for tool_use fragments)', () => {
  // Raw mode keeps the literal value; escape mode escapes quotes/backslashes.
  assert.equal(drip('{{DB_PASSWORD}}', { escape: false }), 'p@ss"w\\rd-123');
  assert.equal(drip('{{DB_PASSWORD}}', { escape: true }), 'p@ss\\"w\\\\rd-123');
});

test('empty map is a passthrough', () => {
  const r = createFieldReplacer(buildMarkerMap([]));
  assert.equal(r.push('{{VIBECODE_API_KEY}}') + r.flush(), '{{VIBECODE_API_KEY}}');
});

test('rehydrateJsonBody restores markers inside a JSON body and keeps it valid', () => {
  const body = JSON.stringify({ content: [{ type: 'text', text: 'run curl -H "k: {{DB_PASSWORD}}"' }] });
  const out = rehydrateJsonBody(body, map());
  const parsed = JSON.parse(out); // must stay valid despite quotes/backslashes in the value
  assert.equal(parsed.content[0].text, `run curl -H "k: ${SECRETS[1].value}"`);
  assert.ok(!out.includes('{{DB_PASSWORD}}'));
});

// --- SSE ---

function collectSse(events) {
  const sse = createSseRehydrator(map());
  let out = '';
  for (const e of events) out += sse.push(e);
  out += sse.flush();
  return out;
}

test('SSE: {{NAME}} inside a single text_delta becomes the value', () => {
  const input =
    'event: content_block_delta\n' +
    `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'key {{VIBECODE_API_KEY}} done' } })}\n\n`;
  const out = collectSse([input]);
  assert.ok(out.includes('cap_exampleFAKEkey000000000000000000'));
  assert.ok(!out.includes('{{VIBECODE_API_KEY}}'));
});

test('SSE: marker split across two text_delta events is still substituted', () => {
  const ev = (text) => `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } })}\n\n`;
  // "{{VIBE" in the first event, "CODE_API_KEY}}" in the second.
  const out = collectSse([
    `data: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'text' } })}\n\n`,
    ev('here: {{VIBE'),
    ev('CODE_API_KEY}} !'),
    `data: ${JSON.stringify({ type: 'content_block_stop', index: 0 })}\n\n`,
  ]);
  assert.ok(out.includes('cap_exampleFAKEkey000000000000000000'), 'value restored across the split');
  assert.ok(!out.includes('{{VIBE'), 'no partial marker leaks');
  // Every data line must remain parseable JSON.
  for (const line of out.split('\n')) {
    if (line.startsWith('data:')) JSON.parse(line.slice(5).trim());
  }
});

test('SSE: tool_use input_json_delta gets the value JSON-escaped so the assembled JSON is valid', () => {
  const start = `data: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'Bash' } })}\n\n`;
  const d1 = `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"command":"curl -H \\"k: {{DB_PASS' } })}\n\n`;
  const d2 = `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: 'WORD}}\\""}' } })}\n\n`;
  const stop = `data: ${JSON.stringify({ type: 'content_block_stop', index: 0 })}\n\n`;
  // reassemble partial_json from the transformed events
  let assembled = '';
  const full = collectSse([start, d1, d2, stop]);
  for (const line of full.split('\n')) {
    if (!line.startsWith('data:')) continue;
    const obj = JSON.parse(line.slice(5).trim());
    if (obj.type === 'content_block_delta' && obj.delta.type === 'input_json_delta') assembled += obj.delta.partial_json;
  }
  const toolInput = JSON.parse(assembled); // MUST be valid JSON
  assert.equal(toolInput.command, `curl -H "k: ${SECRETS[1].value}"`);
  assert.ok(assembled.includes('p@ss'), 'real value present');
  assert.ok(!assembled.includes('{{DB_PASSWORD}}'));
});

test('SSE: clean stream with no markers is passed through (parse-equivalent)', () => {
  const events = [
    `data: ${JSON.stringify({ type: 'message_start', message: { id: 'x' } })}\n\n`,
    `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'hello world' } })}\n\n`,
    'event: ping\ndata: {"type": "ping"}\n\n',
    `data: ${JSON.stringify({ type: 'message_stop' })}\n\n`,
  ];
  const out = collectSse(events);
  assert.ok(out.includes('hello world'));
  assert.ok(out.includes('ping'));
});

test('jsonEscapeInner produces splice-safe escaping', () => {
  assert.equal(jsonEscapeInner('a"b\\c'), 'a\\"b\\\\c');
});
