// No-false-positive guarantee: a body with no secret passes through
// byte-identical (no reserialization drift) and stays valid JSON.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../src/redact.js';

const redactor = () =>
  createRedactor({ secrets: [{ name: 'K', value: 'some-secret-not-present-here' }] });

test('clean JSON body passes through byte-identical', () => {
  const raw = JSON.stringify({
    model: 'claude-fable-5',
    max_tokens: 1024,
    system: 'You are a helpful assistant. Answer in Portuguese.',
    messages: [
      { role: 'user', content: 'Refactor the parse function in src/util.js to handle nulls.' },
      {
        role: 'assistant',
        content: 'Here is the refactor:\n```js\nfunction parse(x) {\n  return x ?? null;\n}\n```',
      },
    ],
  });
  const { body, events } = redactor().redactBody(raw, 'application/json');
  assert.equal(body, raw, 'clean body must not be modified at all');
  assert.equal(events.length, 0);
});

test('clean non-JSON body passes through byte-identical', () => {
  const raw = 'just some plain text, nothing secret about it at all';
  const { body, events } = redactor().redactBody(raw, 'text/plain');
  assert.equal(body, raw);
  assert.equal(events.length, 0);
});

test('redacted JSON body is still valid JSON the vendor can parse', () => {
  const r = createRedactor({ secrets: [{ name: 'K', value: 'leak-me-1234567' }] });
  const raw = JSON.stringify({
    messages: [{ role: 'user', content: 'key is leak-me-1234567, use it' }],
  });
  const { body } = r.redactBody(raw, 'application/json');
  const parsed = JSON.parse(body);
  assert.equal(parsed.messages[0].role, 'user');
  assert.ok(parsed.messages[0].content.includes('[REDACTED:K]'));
});
