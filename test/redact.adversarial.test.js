// Adversarial round: attack payloads that try to smuggle a known secret past
// the engine through less obvious encodings and body positions. Every case
// here must either be redacted or is explicitly documented as out of scope.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../src/redact.js';

// Value chosen so its base64 contains '+' and '/' characters, which makes
// the url-encoded-base64 form differ from plain base64.
const SECRET = { name: 'ADV', value: '????????>>>>secret-1234' };
const B64 = Buffer.from(SECRET.value, 'utf8').toString('base64');

function redactor() {
  return createRedactor({ secrets: [SECRET] });
}

test('sanity: chosen secret exercises the special base64 chars', () => {
  assert.ok(/[+/]/.test(B64), `test needs +/ in base64, got ${B64}`);
  assert.notEqual(encodeURIComponent(B64), B64);
});

test('url-encoded base64 form is redacted (webhook/query-string smuggling)', () => {
  const smuggled = encodeURIComponent(B64);
  const raw = JSON.stringify({ content: `callback was https://x.test/cb?auth=${smuggled}` });
  const { body } = redactor().redactBody(raw, 'application/json');
  assert.ok(!body.includes(smuggled), 'url-encoded base64 leaked');
  assert.ok(!body.includes(B64), 'base64 leaked');
});

test('double base64 is redacted', () => {
  const twice = Buffer.from(B64, 'utf8').toString('base64');
  const raw = JSON.stringify({ content: `blob ${twice}` });
  const { body } = redactor().redactBody(raw, 'application/json');
  assert.ok(!body.includes(twice), 'double-base64 leaked');
});

test('secret used as an object KEY is redacted', () => {
  const raw = JSON.stringify({ [SECRET.value]: 'connected', other: 1 });
  const { body } = redactor().redactBody(raw, 'application/json');
  assert.ok(!body.includes(SECRET.value), 'secret leaked as object key');
  assert.doesNotThrow(() => JSON.parse(body));
});

test('dynamic secret (JWT) used as an object KEY is redacted', () => {
  const jwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVad';
  const raw = JSON.stringify({ sessions: { [jwt]: { active: true } } });
  const { body } = redactor().redactBody(raw, 'application/json');
  assert.ok(!body.includes(jwt), 'JWT leaked as object key');
  assert.doesNotThrow(() => JSON.parse(body));
});

test('unicode secret is matched in all variants', () => {
  const uni = { name: 'UNI', value: 'senha-ção-❤️-9876' };
  const r = createRedactor({ secrets: [uni] });
  const forms = [
    uni.value,
    Buffer.from(uni.value, 'utf8').toString('base64'),
    encodeURIComponent(uni.value),
    Buffer.from(uni.value, 'utf8').toString('hex'),
  ];
  for (const form of forms) {
    const raw = JSON.stringify({ content: `v: ${form}` });
    const { body } = r.redactBody(raw, 'application/json');
    assert.ok(!body.includes(form), `unicode secret leaked as ${form.slice(0, 12)}...`);
  }
});

test('adjacent repetitions are all destroyed', () => {
  const raw = JSON.stringify({ content: SECRET.value + SECRET.value + SECRET.value });
  const { body } = redactor().redactBody(raw, 'application/json');
  assert.ok(!body.includes(SECRET.value));
});

test('secret inside a deeply nested structure is redacted', () => {
  const raw = JSON.stringify({
    a: [{ b: { c: [{ d: { e: [`deep ${SECRET.value} end`] } }] } }],
  });
  const { body } = redactor().redactBody(raw, 'application/json');
  assert.ok(!body.includes(SECRET.value));
});

test('MIME-wrapped base64 of a LONG secret: the long runs are entropy-caught', () => {
  // A newline inserted mid-base64 breaks substring matching by design; for
  // blobs whose runs are >=40 chars the entropy layer still fires. Shorter
  // wrapped fragments are a documented residual risk.
  const longSecret = { name: 'LONG', value: 'long-secret-value-0123456789-abcdefghijklmno-!!' };
  const r = createRedactor({ secrets: [longSecret] });
  const b64 = Buffer.from(longSecret.value, 'utf8').toString('base64'); // 64 chars
  const wrapped = `${b64.slice(0, 44)}\n${b64.slice(44)}`;
  const raw = JSON.stringify({ content: `key:\n${wrapped}` });
  const { body } = r.redactBody(raw, 'application/json');
  assert.ok(!body.includes(b64.slice(0, 44)), 'first MIME line (>=40 chars) leaked');
});

test('regex-special characters in a secret cannot break matching', () => {
  const tricky = { name: 'RE', value: 'a+b*c?d(e)f[g]h{2}$^.|secret' };
  const r = createRedactor({ secrets: [tricky] });
  const raw = JSON.stringify({ content: `v=${tricky.value};` });
  const { body } = r.redactBody(raw, 'application/json');
  assert.ok(!body.includes(tricky.value));
  assert.ok(body.includes('[REDACTED:RE]'));
});

test('huge body with many matches stays fast and complete', () => {
  const parts = [];
  for (let i = 0; i < 2000; i += 1) parts.push(`msg ${i} ${SECRET.value}`);
  const raw = JSON.stringify({ content: parts.join(' | ') });
  const start = process.hrtime.bigint();
  const { body, events } = redactor().redactBody(raw, 'application/json');
  const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
  assert.ok(!body.includes(SECRET.value));
  const ev = events.find((e) => e.rule === 'ADV');
  assert.equal(ev.count, 2000);
  assert.ok(elapsedMs < 2000, `redaction too slow: ${elapsedMs}ms`);
});
