// Layer B coverage: shape-based regex rules for dynamic secrets that are not
// in the static list, plus the entropy gate that protects normal text.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor, shannonEntropy } from '../src/redact.js';

function redact(content) {
  const r = createRedactor({ secrets: [] });
  const raw = JSON.stringify({ content });
  return r.redactBody(raw, 'application/json');
}

test('JWT is redacted', () => {
  const jwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c';
  const { body, events } = redact(`token: ${jwt}`);
  assert.ok(!body.includes(jwt));
  assert.ok(events.some((e) => e.rule === 'jwt'));
});

test('PEM private key block is redacted', () => {
  const pem = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH',
    'anotherlineofkeymaterial1234567890abcdefghijklmnopqrstuvwxyz',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');
  const { body, events } = redact(`here is the key:\n${pem}\ndone`);
  assert.ok(!body.includes('MIIEowIBAAKCAQEA'));
  assert.ok(events.some((e) => e.rule === 'pem-private-key'));
});

test('Authorization Bearer token is redacted, header context preserved', () => {
  const { body, events } = redact('Authorization: Bearer sess-abc123def456ghi789jkl012');
  assert.ok(!body.includes('sess-abc123def456ghi789jkl012'));
  assert.ok(body.includes('Bearer '), 'the Bearer prefix should survive for context');
  assert.ok(events.some((e) => e.rule === 'bearer-token'));
});

test('x-api-key header value is redacted', () => {
  const { body, events } = redact('x-api-key: sk-ant-api03-notreal-1234567890abcdef');
  assert.ok(!body.includes('notreal-1234567890abcdef'));
  assert.ok(events.some((e) => e.rule === 'x-api-key' || e.rule === 'openai-key'));
});

test('vendor key shapes are redacted', () => {
  const samples = {
    'openai-key': 'sk-abcdefghijklmnopqrstuv1234',
    'aws-access-key': 'AKIAIOSFODNN7EXAMPLEX',
    'google-api-key': 'AIzaSyA1234567890abcdefghijklmnopqrstuv',
    'slack-token': 'xoxb-123456789012-abcdefghijklmnop',
    'github-token': 'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
  };
  for (const [rule, sample] of Object.entries(samples)) {
    const { body, events } = redact(`value: ${sample}`);
    assert.ok(!body.includes(sample), `${rule} sample leaked`);
    assert.ok(events.some((e) => e.rule === rule), `${rule} event missing`);
  }
});

test('session cookies are redacted', () => {
  const { body } = redact('Set-Cookie: sessionid=9f8e7d6c5b4a392817061524; Path=/');
  assert.ok(!body.includes('9f8e7d6c5b4a392817061524'));
  const r2 = redact('the url had ?csrftoken=abcdef123456789012345 in it');
  assert.ok(!r2.body.includes('abcdef123456789012345'));
});

test('high-entropy hex blob is redacted, low-entropy hex is not', () => {
  const hot = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
  const cold = 'a'.repeat(64);
  const rHot = redact(`digest: ${hot}`);
  assert.ok(!rHot.body.includes(hot), 'high-entropy hex leaked');
  const rCold = redact(`padding: ${cold}`);
  assert.ok(rCold.body.includes(cold), 'low-entropy hex was wrongly redacted');
});

test('high-entropy base64 run is redacted, normal identifier is not', () => {
  const hot = 'n4bQgYhMfWWaL1qgxVrQFaO7TxsrC4Is0V1sFbDwCgg=';
  const cold = 'thisIsAPerfectlyNormalCamelCaseIdentifierName';
  const rHot = redact(`sig: ${hot}`);
  assert.ok(!rHot.body.includes(hot), 'high-entropy base64 leaked');
  const rCold = redact(`function ${cold}() {}`);
  assert.ok(rCold.body.includes(cold), 'normal identifier was wrongly redacted');
});

test('shannonEntropy sanity', () => {
  assert.equal(shannonEntropy('aaaa'), 0);
  assert.ok(shannonEntropy('9f86d081884c7d65') > 3);
  assert.ok(shannonEntropy('aaaaaaaaaaaaaaab') < 1);
});
