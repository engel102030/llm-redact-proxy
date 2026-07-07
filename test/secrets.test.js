import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSecretsFile, buildNeedles, MIN_SECRET_LENGTH } from '../src/secrets.js';

test('parseSecretsFile ignores comments and blank lines', () => {
  const text = [
    '# a comment',
    '',
    'MYSQL_PASSWORD=hunter2-longer',
    '   ',
    '# another',
    'bare-secret-value-123',
  ].join('\n');
  const secrets = parseSecretsFile(text);
  assert.equal(secrets.length, 2);
  assert.deepEqual(secrets[0], { name: 'MYSQL_PASSWORD', value: 'hunter2-longer' });
});

test('parseSecretsFile splits KEY=VALUE on the first equals sign only', () => {
  const secrets = parseSecretsFile('DB_URL=mysql://user:pa=ss@host/db');
  assert.equal(secrets.length, 1);
  assert.equal(secrets[0].name, 'DB_URL');
  assert.equal(secrets[0].value, 'mysql://user:pa=ss@host/db');
});

test('parseSecretsFile auto-names bare values', () => {
  const secrets = parseSecretsFile('first-bare-secret\nsecond-bare-secret');
  assert.equal(secrets[0].name, 'SECRET_1');
  assert.equal(secrets[1].name, 'SECRET_2');
});

test('parseSecretsFile rejects values shorter than the minimum', () => {
  const secrets = parseSecretsFile(`SHORT=abc\nOK=${'x'.repeat(MIN_SECRET_LENGTH)}`);
  assert.equal(secrets.length, 1);
  assert.equal(secrets[0].name, 'OK');
});

test('buildNeedles covers literal, base64, base64url, url-encoded, json-escaped, hex', () => {
  const value = 'S3cr3t Value/42+"x\\y';
  const needles = buildNeedles({ name: 'T', value });
  const all = needles.map((n) => n.needle);

  assert.ok(all.includes(value), 'literal');
  assert.ok(all.includes(Buffer.from(value, 'utf8').toString('base64')), 'base64 padded');
  assert.ok(
    all.some((n) => Buffer.from(value, 'utf8').toString('base64url').startsWith(n) && n.length >= 8),
    'base64url core',
  );
  assert.ok(all.includes(encodeURIComponent(value)), 'url-encoded');
  assert.ok(all.includes(JSON.stringify(value).slice(1, -1)), 'json-escaped');
  assert.ok(all.includes(Buffer.from(value, 'utf8').toString('hex')), 'hex lower');
});

test('buildNeedles base64 offset variants catch a secret embedded mid-blob', () => {
  const value = 'SuperSecretPass123';
  const needles = buildNeedles({ name: 'T', value }).map((n) => n.needle);
  // "user:" prefix is 5 bytes -> alignment offset 2 inside the base64 stream.
  for (const prefix of ['', 'u', 'us', 'user:', 'a-longer-username:']) {
    const blob = Buffer.from(prefix + value, 'utf8').toString('base64');
    assert.ok(
      needles.some((n) => blob.includes(n)),
      `no needle matches inside base64("${prefix}" + secret)`,
    );
  }
});

test('buildNeedles drops needles that are too short to be safe', () => {
  const needles = buildNeedles({ name: 'T', value: 'abcdef' });
  for (const { needle } of needles) {
    assert.ok(needle.length >= 6, `needle too short: ${JSON.stringify(needle)}`);
  }
});
