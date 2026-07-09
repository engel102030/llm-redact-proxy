// The runtime controller: applies provider/mode changes in place, persists
// them, enforces the redaction-mode floor, and never exposes the key value.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRuntime } from '../src/runtime.js';
import { loadSettings } from '../src/settings.js';

function baseConfig(overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-rt-'));
  return {
    upstreamUrl: null,
    upstreamAuth: 'passthrough',
    upstreamKey: null,
    redactMode: 'strict',
    redactModeFloor: 'named-only',
    redactDisable: [],
    redactIgnore: [],
    configFile: path.join(dir, 'config.json'),
    ...overrides,
  };
}

test('starts with no provider when none configured', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  assert.equal(rt.upstream.url, null);
  assert.equal(rt.mode, 'strict');
});

test('apply sets the provider live and persists it', () => {
  const config = baseConfig();
  const rt = createRuntime({ config, secrets: [] });
  rt.apply({ upstreamUrl: 'https://prov.example/anthropic', upstreamAuth: 'passthrough' });
  assert.equal(rt.upstream.url.href, 'https://prov.example/anthropic');
  const persisted = loadSettings(config.configFile);
  assert.equal(persisted.upstreamUrl, 'https://prov.example/anthropic');
});

test('restoreMarkers is off by default, toggles live, persists, and gates on secrets', () => {
  const config = baseConfig();
  const rt = createRuntime({ config, secrets: [{ name: 'K', value: 'the-value-123456' }] });
  // default off
  assert.equal(rt.restoreMarkers, false);
  assert.equal(rt.getRestore().enabled, false);
  // turn on
  rt.apply({ restoreMarkers: true });
  assert.equal(rt.restoreMarkers, true);
  const r = rt.getRestore();
  assert.equal(r.enabled, true);
  assert.equal(r.map.get('K'), 'the-value-123456');
  assert.equal(loadSettings(config.configFile).restoreMarkers, true);
  assert.equal(rt.publicSettings().restoreMarkers, true);
});

test('restoreMarkers on but no secrets registered stays disabled (nothing to restore)', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  rt.apply({ restoreMarkers: true }, { persist: false });
  assert.equal(rt.restoreMarkers, true);
  assert.equal(rt.getRestore().enabled, false, 'no map -> effectively off');
});

test('persisted settings are loaded on boot over env defaults', () => {
  const config = baseConfig();
  createRuntime({ config, secrets: [] }).apply({ upstreamUrl: 'https://saved.example/v1' });
  const rt2 = createRuntime({ config, secrets: [] });
  assert.equal(rt2.upstream.url.href, 'https://saved.example/v1');
});

test('switching provider takes effect without rebuild', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  rt.apply({ upstreamUrl: 'https://a.example' });
  assert.equal(rt.upstream.url.host, 'a.example');
  rt.apply({ upstreamUrl: 'https://b.example' });
  assert.equal(rt.upstream.url.host, 'b.example');
});

test('replace auth requires a key', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  assert.throws(() => rt.apply({ upstreamUrl: 'https://p.example', upstreamAuth: 'replace' }), /key/);
  rt.apply({ upstreamUrl: 'https://p.example', upstreamAuth: 'replace', upstreamKey: 'k-123456' });
  assert.equal(rt.upstream.auth, 'replace');
});

test('publicSettings never exposes the key value', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  rt.apply({ upstreamUrl: 'https://p.example', upstreamAuth: 'replace', upstreamKey: 'super-secret-key-1' });
  const pub = rt.publicSettings();
  assert.equal(pub.hasKey, true);
  assert.equal(pub.upstreamKey, undefined);
  assert.ok(!JSON.stringify(pub).includes('super-secret-key-1'));
});

test('mode floor blocks lowering below it', () => {
  const rt = createRuntime({ config: baseConfig({ redactMode: 'strict', redactModeFloor: 'balanced' }), secrets: [] });
  assert.throws(() => rt.apply({ redactMode: 'named-only' }), /floor/);
  rt.apply({ redactMode: 'balanced' }); // at the floor is allowed
  assert.equal(rt.mode, 'balanced');
});

test('a floor above the starting mode is clamped up on boot is a config concern, runtime keeps given mode', () => {
  const rt = createRuntime({ config: baseConfig({ redactMode: 'balanced' }), secrets: [] });
  assert.equal(rt.mode, 'balanced');
});

test('disabled mode is blocked by the default floor, allowed when floor permits', () => {
  const blocked = createRuntime({ config: baseConfig({ redactModeFloor: 'named-only' }), secrets: [] });
  assert.throws(() => blocked.apply({ redactMode: 'disabled' }), /floor/);

  const allowed = createRuntime({ config: baseConfig({ redactModeFloor: 'disabled' }), secrets: [] });
  allowed.apply({ redactMode: 'disabled' });
  assert.equal(allowed.mode, 'disabled');
  // In disabled mode the redactor is a passthrough.
  const out = allowed.holder.current.redactBody(JSON.stringify({ c: 'leak-me-value-123' }), 'application/json');
  assert.ok(out.body.includes('leak-me-value-123'));
});

test('invalid upstream url is rejected', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  assert.throws(() => rt.apply({ upstreamUrl: 'ftp://nope.example' }), /http/);
});

test('a corrupt persisted config does not crash boot', () => {
  const config = baseConfig();
  fs.writeFileSync(config.configFile, '{ this is not json');
  const rt = createRuntime({ config, secrets: [] });
  assert.equal(rt.upstream.url, null); // fell back to defaults
});

test('setSecrets rebuilds the redactor with the new list', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  const before = rt.holder.current.redactBody(JSON.stringify({ c: 'my-secret-value-123 here' }), 'application/json');
  assert.ok(before.body.includes('my-secret-value-123'));
  rt.setSecrets([{ name: 'S', value: 'my-secret-value-123' }]);
  const after = rt.holder.current.redactBody(JSON.stringify({ c: 'my-secret-value-123 here' }), 'application/json');
  assert.ok(!after.body.includes('my-secret-value-123'));
  assert.ok(after.body.includes('[REDACTED:S]'));
});
