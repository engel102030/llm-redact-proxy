// Thinking-block signatures are opaque vendor blobs the client must echo back
// verbatim (Anthropic validates them; the Codex path carries the encrypted
// reasoning there). The entropy layer must leave them alone - and only them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor, PROTECTED_PATHS } from '../src/redact.js';

const blob = Array.from({ length: 60 }, (_, i) => Buffer.from(`enc-chunk-${i}-${Math.random().toString(36).slice(2)}`).toString('base64url')).join('');
const SECRET = 'real-secret-value-4c1d9e-31337';

test('strict mode leaves messages[].content[].signature intact while still redacting the rest', () => {
  const r = createRedactor({ secrets: [{ name: 'MY_SECRET', value: SECRET }], mode: 'strict' });
  const body = JSON.stringify({
    model: 'm',
    messages: [
      { role: 'user', content: `key ${SECRET}` },
      { role: 'assistant', content: [{ type: 'thinking', thinking: 'plan', signature: blob }, { type: 'text', text: `see ${blob}` }] },
    ],
  });
  const { body: out, events } = r.redactBody(body, 'application/json', {});
  const parsed = JSON.parse(out);
  assert.equal(parsed.messages[1].content[0].signature, blob, 'signature must survive');
  assert.equal(parsed.messages[0].content, 'key [REDACTED:MY_SECRET]');
  assert.ok(parsed.messages[1].content[1].text.includes('[REDACTED:high-entropy-base64]'), 'the same blob in a text block is still redacted');
  assert.ok(events.some((e) => e.rule === 'MY_SECRET'));
  assert.ok(PROTECTED_PATHS.has('messages.content.signature'));
});

test('a signature at any other path is not protected', () => {
  const r = createRedactor({ secrets: [], mode: 'strict' });
  const body = JSON.stringify({ signature: blob, nested: { signature: blob } });
  const parsed = JSON.parse(r.redactBody(body, 'application/json', {}).body);
  assert.equal(parsed.signature, '[REDACTED:high-entropy-base64]');
  assert.equal(parsed.nested.signature, '[REDACTED:high-entropy-base64]');
});
