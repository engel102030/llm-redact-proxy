// End-to-end: secret_add routes to the chosen store (global / project / both),
// both stores are redacted, and secret_list groups names by scope. Runs
// against the real MCP process with a global and a project secrets file at
// distinct paths.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startMcpClient } from './helpers/mcp-client.js';

const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-scope-proj-'));
const globalFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'redact-scope-glob-')), 'secrets.local');
fs.writeFileSync(globalFile, 'GLOBAL_SEED=global-seed-123456\n');
fs.writeFileSync(path.join(projectDir, 'secrets.local'), 'PROJECT_SEED=project-seed-123456\n');

const client = startMcpClient({
  cwd: projectDir, // project store resolves to projectDir/secrets.local
  env: { SECRETS_FILE: globalFile, UPSTREAM_URL: '', LISTEN_ADDR: '' },
});

after(() => client.close());

async function call(name, args = {}) {
  const res = await client.request('tools/call', { name, arguments: args });
  return res.result;
}

test('handshake', async () => {
  await client.request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  client.notify('notifications/initialized');
});

test('both seed files are loaded and grouped by scope', async () => {
  const r = await call('secret_list');
  const t = r.content[0].text;
  assert.match(t, /\[global\][\s\S]*GLOBAL_SEED/);
  assert.match(t, /\[project\][\s\S]*PROJECT_SEED/);
});

test('secret_add scope=global writes only the global file', async () => {
  await call('secret_add', { name: 'ONLY_GLOBAL', value: 'only-global-1234', scope: 'global' });
  assert.match(fs.readFileSync(globalFile, 'utf8'), /^ONLY_GLOBAL=only-global-1234$/m);
  assert.doesNotMatch(fs.readFileSync(path.join(projectDir, 'secrets.local'), 'utf8'), /ONLY_GLOBAL/);
});

test('secret_add scope=project writes only the project file', async () => {
  await call('secret_add', { name: 'ONLY_PROJECT', value: 'only-project-1234', scope: 'project' });
  assert.match(fs.readFileSync(path.join(projectDir, 'secrets.local'), 'utf8'), /^ONLY_PROJECT=only-project-1234$/m);
  assert.doesNotMatch(fs.readFileSync(globalFile, 'utf8'), /ONLY_PROJECT/);
});

test('secret_add scope=both writes to both files', async () => {
  const r = await call('secret_add', { name: 'IN_BOTH', value: 'in-both-123456', scope: 'both' });
  assert.ok(!r.isError);
  assert.match(fs.readFileSync(globalFile, 'utf8'), /^IN_BOTH=in-both-123456$/m);
  assert.match(fs.readFileSync(path.join(projectDir, 'secrets.local'), 'utf8'), /^IN_BOTH=in-both-123456$/m);
});

test('secret_add default scope is global', async () => {
  await call('secret_add', { name: 'DEFAULTS_GLOBAL', value: 'defaults-global-12' });
  assert.match(fs.readFileSync(globalFile, 'utf8'), /DEFAULTS_GLOBAL/);
  assert.doesNotMatch(fs.readFileSync(path.join(projectDir, 'secrets.local'), 'utf8'), /DEFAULTS_GLOBAL/);
});

test('a project-scoped secret is actually redacted by run', async () => {
  await call('secret_add', { name: 'PROJ_TOKEN', value: 'proj-token-abcdef', scope: 'project' });
  const r = await call('run', { command: 'echo using {{PROJ_TOKEN}}' });
  const t = r.content[0].text;
  assert.ok(t.includes('[REDACTED:PROJ_TOKEN]'), t);
  assert.ok(!t.includes('proj-token-abcdef'));
});

test('invalid scope is rejected', async () => {
  const r = await call('secret_add', { name: 'BAD', value: 'bad-value-123', scope: 'nowhere' });
  assert.ok(r.isError);
  assert.match(r.content[0].text, /scope/);
});

test('GLOBAL: no secret value ever appears in the MCP stdout transcript', () => {
  for (const v of ['global-seed-123456', 'project-seed-123456', 'only-global-1234', 'only-project-1234', 'in-both-123456', 'proj-token-abcdef']) {
    assert.ok(!client.rawStdout.includes(v), `value leaked in stdout: ${v}`);
  }
});
