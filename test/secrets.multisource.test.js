// Multi-source secret loading: a global store plus a per-project store, both
// checked for redaction. Duplicate paths are read once; duplicate name+value
// pairs are collapsed; same NAME with a different VALUE keeps both.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadSecretsFromSources } from '../src/secrets.js';

function tmp(content) {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'redact-ms-')), 'secrets.local');
  fs.writeFileSync(p, content);
  return p;
}

test('loads and tags secrets from two sources', () => {
  const g = tmp('GLOBAL_ONE=global-value-111\nSHARED=shared-value-000\n');
  const p = tmp('PROJECT_ONE=project-value-222\n');
  const secrets = loadSecretsFromSources([
    { scope: 'global', path: g },
    { scope: 'project', path: p },
  ]);
  const byName = Object.fromEntries(secrets.map((s) => [s.name, s.source]));
  assert.equal(byName.GLOBAL_ONE, 'global');
  assert.equal(byName.SHARED, 'global');
  assert.equal(byName.PROJECT_ONE, 'project');
  assert.equal(secrets.length, 3);
});

test('identical path is read only once', () => {
  const g = tmp('ONLY=only-value-123456\n');
  const secrets = loadSecretsFromSources([
    { scope: 'global', path: g },
    { scope: 'project', path: g },
  ]);
  assert.equal(secrets.length, 1);
  assert.equal(secrets[0].source, 'global');
});

test('duplicate name+value across files collapses to one', () => {
  const g = tmp('DUP=same-value-999999\n');
  const p = tmp('DUP=same-value-999999\n');
  const secrets = loadSecretsFromSources([
    { scope: 'global', path: g },
    { scope: 'project', path: p },
  ]);
  assert.equal(secrets.length, 1);
});

test('same name with different value keeps both (both must be redacted)', () => {
  const g = tmp('KEY=global-variant-111\n');
  const p = tmp('KEY=project-variant-222\n');
  const secrets = loadSecretsFromSources([
    { scope: 'global', path: g },
    { scope: 'project', path: p },
  ]);
  assert.equal(secrets.length, 2);
  const values = secrets.map((s) => s.value).sort();
  assert.deepEqual(values, ['global-variant-111', 'project-variant-222']);
});

test('missing file is skipped, others still load', () => {
  const g = tmp('PRESENT=present-value-123\n');
  const secrets = loadSecretsFromSources([
    { scope: 'global', path: g },
    { scope: 'project', path: '/nonexistent/secrets.local' },
  ]);
  assert.equal(secrets.length, 1);
  assert.equal(secrets[0].name, 'PRESENT');
});
