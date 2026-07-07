// Notice injection: when a request had redactions, the proxy appends a note
// telling the model the values were censored locally and how to reference
// secrets by name instead (env vars / secrets file at runtime).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildNotice, injectNotice, NOTICE_SENTINEL } from '../src/inject.js';

test('buildNotice names the redacted secrets and carries the sentinel', () => {
  const notice = buildNotice(['MYSQL_PASSWORD', 'jwt']);
  assert.ok(notice.includes(NOTICE_SENTINEL));
  assert.ok(notice.includes('MYSQL_PASSWORD'));
  assert.ok(notice.includes('jwt'));
  assert.ok(notice.toLowerCase().includes('environment variable'));
});

test('injects into a string system prompt (Anthropic shape)', () => {
  const body = { system: 'You are a coding agent.', messages: [] };
  const changed = injectNotice(body, ['DB_PASSWORD']);
  assert.equal(changed, true);
  assert.ok(body.system.startsWith('You are a coding agent.'));
  assert.ok(body.system.includes(NOTICE_SENTINEL));
});

test('injects into an array system prompt (Anthropic content blocks)', () => {
  const body = { system: [{ type: 'text', text: 'You are a coding agent.' }], messages: [] };
  const changed = injectNotice(body, ['DB_PASSWORD']);
  assert.equal(changed, true);
  assert.equal(body.system.length, 2);
  assert.ok(body.system[1].text.includes(NOTICE_SENTINEL));
});

test('prepends a system message when only messages exist (OpenAI shape)', () => {
  const body = { messages: [{ role: 'user', content: 'hi' }] };
  const changed = injectNotice(body, ['DB_PASSWORD']);
  assert.equal(changed, true);
  assert.equal(body.messages[0].role, 'system');
  assert.ok(body.messages[0].content.includes(NOTICE_SENTINEL));
  assert.equal(body.messages[1].role, 'user');
});

test('does not duplicate the notice when the sentinel is already present', () => {
  const body = { system: `existing ${NOTICE_SENTINEL} already here`, messages: [] };
  const changed = injectNotice(body, ['DB_PASSWORD']);
  assert.equal(changed, false);
  const occurrences = body.system.split(NOTICE_SENTINEL).length - 1;
  assert.equal(occurrences, 1);
});

test('returns false on a body shape it does not understand', () => {
  const body = { prompt: 'legacy completion style' };
  const changed = injectNotice(body, ['X']);
  assert.equal(changed, false);
});
