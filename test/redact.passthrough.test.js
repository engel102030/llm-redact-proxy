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

test('metadata.user_id (Claude Code protocol id) survives strict redaction', () => {
  // The device/account hash Claude Code sends is high-entropy hex - the entropy
  // rule would redact it, but some gateways validate metadata.user_id and reject
  // a mangled request. It is a protocol identifier, not a credential: carve it out.
  const userId = '{"device_id":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6","account_uuid":"11112222-3333-4444-5555-666677778888"}';
  const raw = JSON.stringify({
    model: 'claude-opus-4-8',
    metadata: { user_id: userId },
    messages: [{ role: 'user', content: 'hi' }],
  });
  const r = createRedactor({ secrets: [], mode: 'strict' });
  const { body, events } = r.redactBody(raw, 'application/json');
  assert.equal(body, raw, 'protocol identifier must pass through untouched');
  assert.equal(events.length, 0);
});

test('a real secret next to metadata.user_id is still redacted', () => {
  // The carve-out is path-scoped: it must not shield a leak elsewhere in the body.
  const raw = JSON.stringify({
    metadata: { user_id: '{"device_id":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"}' },
    messages: [{ role: 'user', content: 'token: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6' }],
  });
  const r = createRedactor({ secrets: [], mode: 'strict' });
  const { body } = r.redactBody(raw, 'application/json');
  const parsed = JSON.parse(body);
  assert.ok(parsed.metadata.user_id.includes('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'), 'user_id kept');
  assert.ok(parsed.messages[0].content.includes('[REDACTED:high-entropy-hex]'), 'message hex redacted');
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
