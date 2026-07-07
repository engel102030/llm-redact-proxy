import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig, parseDotEnv } from '../src/config.js';

const BASE_ENV = { UPSTREAM_URL: 'https://api.example.com' };
// A guaranteed-empty cwd so a stray .env in the system temp dir cannot
// contaminate default-value assertions.
const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-empty-'));

test('defaults are applied', () => {
  const cfg = loadConfig({ env: { ...BASE_ENV }, cwd: emptyDir });
  assert.equal(cfg.listenHost, '127.0.0.1');
  assert.equal(cfg.listenPort, 8788);
  assert.equal(cfg.upstreamAuth, 'passthrough');
  assert.equal(cfg.failClosed, true);
  assert.equal(cfg.injectNotice, true);
  assert.equal(cfg.upstreamUrl.origin, 'https://api.example.com');
});

test('missing UPSTREAM_URL throws', () => {
  assert.throws(() => loadConfig({ env: {}, cwd: emptyDir }), /UPSTREAM_URL/);
});

test('non-loopback LISTEN_ADDR is refused', () => {
  assert.throws(
    () => loadConfig({ env: { ...BASE_ENV, LISTEN_ADDR: '0.0.0.0:8788' }, cwd: emptyDir }),
    /127\.0\.0\.1|loopback/,
  );
});

test('localhost is normalized to 127.0.0.1', () => {
  const cfg = loadConfig({ env: { ...BASE_ENV, LISTEN_ADDR: 'localhost:9999' }, cwd: emptyDir });
  assert.equal(cfg.listenHost, '127.0.0.1');
  assert.equal(cfg.listenPort, 9999);
});

test('UPSTREAM_AUTH=replace requires UPSTREAM_KEY', () => {
  assert.throws(
    () => loadConfig({ env: { ...BASE_ENV, UPSTREAM_AUTH: 'replace' }, cwd: emptyDir }),
    /UPSTREAM_KEY/,
  );
  const cfg = loadConfig({
    env: { ...BASE_ENV, UPSTREAM_AUTH: 'replace', UPSTREAM_KEY: 'k-123456' },
    cwd: emptyDir,
  });
  assert.equal(cfg.upstreamAuth, 'replace');
  assert.equal(cfg.upstreamKey, 'k-123456');
});

test('FAIL_CLOSED=false is honored', () => {
  const cfg = loadConfig({ env: { ...BASE_ENV, FAIL_CLOSED: 'false' }, cwd: emptyDir });
  assert.equal(cfg.failClosed, false);
});

test('redaction mode defaults to strict (most secure)', () => {
  const cfg = loadConfig({ env: { ...BASE_ENV }, cwd: emptyDir });
  assert.equal(cfg.redactMode, 'strict');
  assert.equal(cfg.redactModeFloor, 'named-only');
  assert.deepEqual(cfg.redactDisable, []);
  assert.deepEqual(cfg.redactIgnore, []);
});

test('redaction mode knobs are parsed', () => {
  const cfg = loadConfig({
    env: {
      ...BASE_ENV,
      REDACT_MODE: 'balanced',
      REDACT_MODE_FLOOR: 'balanced',
      REDACT_DISABLE: 'jwt, high-entropy-hex',
      REDACT_IGNORE: 'safe-value-123, /^[0-9a-f]{64}$/',
    },
    cwd: emptyDir,
  });
  assert.equal(cfg.redactMode, 'balanced');
  assert.equal(cfg.redactModeFloor, 'balanced');
  assert.deepEqual(cfg.redactDisable, ['jwt', 'high-entropy-hex']);
  assert.deepEqual(cfg.redactIgnore, ['safe-value-123', '/^[0-9a-f]{64}$/']);
});

test('invalid REDACT_MODE is rejected', () => {
  assert.throws(
    () => loadConfig({ env: { ...BASE_ENV, REDACT_MODE: 'off' }, cwd: emptyDir }),
    /REDACT_MODE/,
  );
});

test('a floor above the mode raises the effective mode to the floor', () => {
  const cfg = loadConfig({
    env: { ...BASE_ENV, REDACT_MODE: 'named-only', REDACT_MODE_FLOOR: 'balanced' },
    cwd: emptyDir,
  });
  // The floor is a hard minimum; a mode below it is clamped up.
  assert.equal(cfg.redactMode, 'balanced');
  assert.equal(cfg.redactModeFloor, 'balanced');
});

test('parseDotEnv handles comments, blanks and quoted values', () => {
  const vars = parseDotEnv('# c\n\nA=1\nB="two words"\nC=\'single\'\nD=plain # not a comment\n');
  assert.deepEqual(vars, { A: '1', B: 'two words', C: 'single', D: 'plain # not a comment' });
});

test('.env file is read, real env wins over it', () => {
  const dir = fs.mkdtempSync(path.join(emptyDir, 'redact-cfg-'));
  fs.writeFileSync(path.join(dir, '.env'), 'UPSTREAM_URL=https://from-file.example\nFAIL_CLOSED=false\n');
  const fromFile = loadConfig({ env: {}, cwd: dir });
  assert.equal(fromFile.upstreamUrl.origin, 'https://from-file.example');
  assert.equal(fromFile.failClosed, false);
  const overridden = loadConfig({ env: { UPSTREAM_URL: 'https://from-env.example' }, cwd: dir });
  assert.equal(overridden.upstreamUrl.origin, 'https://from-env.example');
});
