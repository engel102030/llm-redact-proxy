// Layer A coverage: a known secret must be redacted in EVERY encoding it can
// appear as inside an outgoing body. Zero leak tolerated.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../src/redact.js';

const SECRET = { name: 'DB_PASSWORD', value: 'S3cr3t-Value_42-xyzzy' };
const MARKER = '[REDACTED:DB_PASSWORD]';

function redactor() {
  return createRedactor({ secrets: [SECRET] });
}

function assertNoLeak(body, value) {
  const forms = [
    value,
    Buffer.from(value, 'utf8').toString('base64'),
    Buffer.from(value, 'utf8').toString('base64url'),
    encodeURIComponent(value),
    Buffer.from(value, 'utf8').toString('hex'),
  ];
  for (const f of forms) {
    assert.ok(!body.includes(f), `leak: body still contains ${f.slice(0, 16)}...`);
  }
}

test('plain literal inside a JSON string is redacted', () => {
  const raw = JSON.stringify({ messages: [{ role: 'user', content: `the password is ${SECRET.value} ok` }] });
  const { body, events } = redactor().redactBody(raw, 'application/json');
  assert.ok(body.includes(MARKER));
  assertNoLeak(body, SECRET.value);
  assert.ok(events.some((e) => e.rule === 'DB_PASSWORD' && e.count >= 1));
  assert.doesNotThrow(() => JSON.parse(body), 'body must stay valid JSON');
});

test('base64 form is redacted', () => {
  const enc = Buffer.from(SECRET.value, 'utf8').toString('base64');
  const raw = JSON.stringify({ content: `blob: ${enc} end` });
  const { body } = redactor().redactBody(raw, 'application/json');
  assertNoLeak(body, SECRET.value);
  assert.doesNotThrow(() => JSON.parse(body));
});

test('base64url form is redacted', () => {
  const enc = Buffer.from(SECRET.value, 'utf8').toString('base64url');
  const raw = JSON.stringify({ content: `token=${enc}` });
  const { body } = redactor().redactBody(raw, 'application/json');
  assertNoLeak(body, SECRET.value);
});

test('url-encoded form is redacted', () => {
  const enc = encodeURIComponent(SECRET.value);
  const raw = JSON.stringify({ content: `GET /login?pw=${enc} HTTP/1.1` });
  const { body } = redactor().redactBody(raw, 'application/json');
  assertNoLeak(body, SECRET.value);
});

test('json-escaped form is redacted (secret with quotes and backslashes)', () => {
  const tricky = { name: 'TRICKY', value: 'pa"ss\\word-123456' };
  const r = createRedactor({ secrets: [tricky] });
  const raw = JSON.stringify({ content: `creds: ${tricky.value}` });
  assert.ok(raw.includes('pa\\"ss\\\\word'), 'sanity: escaped form present in raw body');
  const { body } = r.redactBody(raw, 'application/json');
  assert.ok(!body.includes(tricky.value), 'literal leaked');
  assert.ok(!body.includes(JSON.stringify(tricky.value).slice(1, -1)), 'escaped form leaked');
  assert.ok(body.includes('[REDACTED:TRICKY]'));
});

test('secret embedded mid base64 blob (basic-auth style) is destroyed', () => {
  const blob = Buffer.from(`user:${SECRET.value}`, 'utf8').toString('base64');
  const raw = JSON.stringify({ content: `Authorization header was Basic ${blob}` });
  const { body } = redactor().redactBody(raw, 'application/json');
  assert.ok(!body.includes(blob), 'the aligned base64 blob survived intact');
});

test('secret inside a connection string is redacted', () => {
  const raw = JSON.stringify({ content: `mysql://root:${SECRET.value}@10.0.0.5:3306/app` });
  const { body } = redactor().redactBody(raw, 'application/json');
  assertNoLeak(body, SECRET.value);
});

test('multiple occurrences all redacted and counted', () => {
  const raw = JSON.stringify({ a: SECRET.value, b: `x ${SECRET.value} y`, c: [SECRET.value] });
  const { body, events } = redactor().redactBody(raw, 'application/json');
  assertNoLeak(body, SECRET.value);
  const ev = events.find((e) => e.rule === 'DB_PASSWORD');
  assert.ok(ev.count >= 3, `expected >=3 hits, got ${ev.count}`);
});

test('non-JSON body still gets Layer A redaction', () => {
  const raw = `plain text with ${SECRET.value} inside`;
  const { body } = redactor().redactBody(raw, 'text/plain');
  assert.ok(body.includes(MARKER));
  assertNoLeak(body, SECRET.value);
});
