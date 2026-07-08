// Redaction modes control how aggressive Layer B is, trading UX friction for
// coverage. Layer A (named secrets) is ALWAYS on - registering a secret is an
// explicit opt-in and must never be weakened by a mode.
//   named-only : only registered secrets (zero false positives)
//   balanced   : named + shape rules (bearer/pem/vendor/cookie), NO entropy
//   strict     : everything, including entropy-gated blobs (default)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../src/redact.js';

const NAMED = { name: 'DB', value: 'named-secret-value-123' };
const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVad';
const ENTROPY_HEX = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

function redact(content, opts) {
  const r = createRedactor({ secrets: [NAMED], ...opts });
  return r.redactBody(JSON.stringify({ content }), 'application/json');
}

test('default mode is strict (most secure) when none is given', () => {
  const { body } = redact(`k ${ENTROPY_HEX}`);
  assert.ok(!body.includes(ENTROPY_HEX), 'default should behave as strict and redact entropy');
});

test('named-only: registered secret redacted, shapes and entropy pass', () => {
  const named = redact(`v ${NAMED.value}`, { mode: 'named-only' });
  assert.ok(named.body.includes('[REDACTED:DB]'));
  assert.ok(!named.body.includes(NAMED.value));

  const jwt = redact(`t ${JWT}`, { mode: 'named-only' });
  assert.ok(jwt.body.includes(JWT), 'named-only must NOT touch a JWT');

  const ent = redact(`h ${ENTROPY_HEX}`, { mode: 'named-only' });
  assert.ok(ent.body.includes(ENTROPY_HEX), 'named-only must NOT touch entropy blobs');
});

test('balanced: shapes redacted, entropy passes', () => {
  const jwt = redact(`t ${JWT}`, { mode: 'balanced' });
  assert.ok(!jwt.body.includes(JWT), 'balanced should redact a JWT');

  const ent = redact(`h ${ENTROPY_HEX}`, { mode: 'balanced' });
  assert.ok(ent.body.includes(ENTROPY_HEX), 'balanced must NOT redact entropy blobs');

  const named = redact(`v ${NAMED.value}`, { mode: 'balanced' });
  assert.ok(!named.body.includes(NAMED.value), 'named secret always redacted');
});

test('disabled: nothing is redacted, not even a registered secret or a JWT', () => {
  const jwtBody = redact(`v ${NAMED.value} and t ${JWT}`, { mode: 'disabled' });
  assert.ok(jwtBody.body.includes(NAMED.value), 'registered secret must pass in disabled mode');
  assert.ok(jwtBody.body.includes(JWT), 'JWT must pass in disabled mode');
  assert.equal(jwtBody.events.length, 0);
});

test('disabled: body is returned untouched (byte-identical)', () => {
  const r = createRedactor({ secrets: [NAMED], mode: 'disabled' });
  const raw = JSON.stringify({ messages: [{ role: 'user', content: `key ${NAMED.value}` }] });
  const { body, events } = r.redactBody(raw, 'application/json');
  assert.equal(body, raw);
  assert.equal(events.length, 0);
});

test('strict: shapes AND entropy redacted', () => {
  const jwt = redact(`t ${JWT}`, { mode: 'strict' });
  assert.ok(!jwt.body.includes(JWT));
  const ent = redact(`h ${ENTROPY_HEX}`, { mode: 'strict' });
  assert.ok(!ent.body.includes(ENTROPY_HEX));
});

test('disabledRules turns off a single rule while keeping the rest', () => {
  const { body } = redact(`t ${JWT} and h ${ENTROPY_HEX}`, {
    mode: 'strict',
    disabledRules: ['jwt'],
  });
  assert.ok(body.includes(JWT), 'jwt rule was disabled, should pass');
  assert.ok(!body.includes(ENTROPY_HEX), 'other rules still active');
});

test('disabledRules can turn off a named secret by its name', () => {
  const { body } = redact(`v ${NAMED.value}`, { mode: 'strict', disabledRules: ['DB'] });
  assert.ok(body.includes(NAMED.value), 'named secret DB was disabled');
});

test('ignore list: a literal value marked safe is never redacted', () => {
  const safeCookie = 'sessionid=internal-test-cookie-abc123';
  const { body } = redact(`${safeCookie} here`, {
    mode: 'strict',
    ignore: ['internal-test-cookie-abc123'],
  });
  assert.ok(body.includes('internal-test-cookie-abc123'), 'ignored value should pass');
});

test('ignore list: a /regex/ pattern marks a whole class safe', () => {
  const { body } = redact(`hash ${ENTROPY_HEX}`, {
    mode: 'strict',
    ignore: ['/^[0-9a-f]{64}$/'],
  });
  assert.ok(body.includes(ENTROPY_HEX), 'entropy hash matched by ignore regex should pass');
});

test('ignore never overrides a named secret (opt-in wins over convenience)', () => {
  const { body } = redact(`v ${NAMED.value}`, {
    mode: 'named-only',
    ignore: [NAMED.value],
  });
  assert.ok(!body.includes(NAMED.value), 'a registered secret must be redacted even if ignored');
});
