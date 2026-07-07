// End-to-end tests against the REAL MCP server process over stdio.
// The strongest assertion mirrors the proxy canary proof: the complete
// stdout transcript of the MCP process (everything the model would see)
// must never contain a secret value.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startMcpClient } from './helpers/mcp-client.js';
import { createMockUpstream } from './helpers/mock-upstream.js';

const CANARY = 'mcp-canary-value-777abc';
const ADDED = 'added-later-value-999xyz';

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-mcp-'));
const secretsFile = path.join(workDir, 'secrets.local');
fs.writeFileSync(secretsFile, `CANARY_TOKEN=${CANARY}\n`);

const client = startMcpClient({
  cwd: workDir,
  env: { SECRETS_FILE: secretsFile, UPSTREAM_URL: '', LISTEN_ADDR: '' },
});

after(() => client.close());

test('initialize handshake and tools/list', async () => {
  const init = await client.request('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'test-client', version: '0.0.1' },
  });
  assert.equal(init.result.serverInfo.name, 'llm-redact-proxy');
  assert.ok(init.result.capabilities.tools);
  client.notify('notifications/initialized');

  const list = await client.request('tools/list');
  const names = list.result.tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['redact_mode', 'redaction_stats', 'run', 'secret_add', 'secret_list']);
  for (const tool of list.result.tools) {
    assert.ok(tool.description.length > 10);
    assert.ok(tool.inputSchema);
  }
});

test('run tool executes locally and returns redacted output', async () => {
  const res = await client.request('tools/call', {
    name: 'run',
    arguments: { command: 'echo "the token is {{CANARY_TOKEN}}"' },
  });
  assert.ok(!res.error, JSON.stringify(res.error));
  const text = res.result.content[0].text;
  assert.ok(text.includes('[REDACTED:CANARY_TOKEN]'), text);
  assert.ok(!text.includes(CANARY), 'canary leaked in run output');
  assert.match(text, /exit code: 0/);
});

test('run tool resolves secrets via environment variables too', async () => {
  const res = await client.request('tools/call', {
    name: 'run',
    arguments: { command: 'printf %s "$CANARY_TOKEN"' },
  });
  const text = res.result.content[0].text;
  assert.ok(text.includes('[REDACTED:CANARY_TOKEN]'));
  assert.ok(!text.includes(CANARY));
});

test('run tool refuses unknown placeholders', async () => {
  const res = await client.request('tools/call', {
    name: 'run',
    arguments: { command: 'echo {{NOT_A_SECRET}}' },
  });
  assert.equal(res.result.isError, true);
  assert.match(res.result.content[0].text, /NOT_A_SECRET/);
});

test('secret_add registers a new secret, list shows names only, run resolves it', async () => {
  const addRes = await client.request('tools/call', {
    name: 'secret_add',
    arguments: { name: 'ADDED_LATER', value: ADDED },
  });
  assert.ok(!addRes.error);
  assert.ok(!addRes.result.content[0].text.includes(ADDED), 'add echoed the value back');

  const listRes = await client.request('tools/call', { name: 'secret_list', arguments: {} });
  const listText = listRes.result.content[0].text;
  assert.ok(listText.includes('ADDED_LATER'));
  assert.ok(listText.includes('CANARY_TOKEN'));
  assert.ok(!listText.includes(ADDED), 'list leaked a value');

  const fileText = fs.readFileSync(secretsFile, 'utf8');
  assert.ok(fileText.includes(`ADDED_LATER=${ADDED}`));

  const runRes = await client.request('tools/call', {
    name: 'run',
    arguments: { command: 'echo {{ADDED_LATER}}' },
  });
  const runText = runRes.result.content[0].text;
  assert.ok(runText.includes('[REDACTED:ADDED_LATER]'), runText);
  assert.ok(!runText.includes(ADDED));
});

test('there is no secret_get tool and unknown tools are rejected', async () => {
  const res = await client.request('tools/call', { name: 'secret_get', arguments: {} });
  assert.ok(res.error, 'expected a JSON-RPC error for unknown tool');
});

test('redaction_stats returns counters, never values', async () => {
  const res = await client.request('tools/call', { name: 'redaction_stats', arguments: {} });
  const text = res.result.content[0].text;
  assert.ok(text.includes('totals'));
  assert.ok(!text.includes(CANARY));
  assert.ok(!text.includes(ADDED));
});

test('redact_mode tool reads and sets the mode, honoring the floor', async () => {
  const get = await client.request('tools/call', { name: 'redact_mode', arguments: {} });
  assert.match(get.result.content[0].text, /mode: strict/);

  const set = await client.request('tools/call', {
    name: 'redact_mode',
    arguments: { mode: 'balanced' },
  });
  assert.ok(!set.result.isError);
  assert.match(set.result.content[0].text, /balanced/);

  // Floor defaults to named-only, so dropping there is allowed here.
  const drop = await client.request('tools/call', {
    name: 'redact_mode',
    arguments: { mode: 'named-only' },
  });
  assert.ok(!drop.result.isError);

  const bad = await client.request('tools/call', {
    name: 'redact_mode',
    arguments: { mode: 'off' },
  });
  assert.ok(bad.result.isError, 'invalid mode should error');

  // restore strict for the transcript assertions below
  await client.request('tools/call', { name: 'redact_mode', arguments: { mode: 'strict' } });
});

test('GLOBAL: the entire MCP stdout transcript never contains a secret value', () => {
  assert.ok(!client.rawStdout.includes(CANARY), 'canary leaked in MCP stdout');
  assert.ok(!client.rawStdout.includes(ADDED), 'added secret leaked in MCP stdout');
});

test('embedded proxy starts with the MCP process and redacts traffic', async () => {
  const upstream = await createMockUpstream();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-mcp-proxy-'));
  const sf = path.join(dir, 'secrets.local');
  fs.writeFileSync(sf, `CANARY_TOKEN=${CANARY}\n`);
  const proxyClient = startMcpClient({
    cwd: dir,
    env: {
      SECRETS_FILE: sf,
      UPSTREAM_URL: upstream.url,
      LISTEN_ADDR: '127.0.0.1:0',
    },
  });
  try {
    const m = await proxyClient.waitForStderr(/proxy listening on http:\/\/127\.0\.0\.1:(\d+)/);
    const port = Number(m[1]);
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ system: 's', messages: [{ role: 'user', content: `pw ${CANARY}` }] }),
    });
    assert.equal(res.status, 200);
    assert.equal(upstream.requests.length, 1);
    assert.ok(!upstream.requests[0].body.includes(CANARY), 'canary leaked through embedded proxy');
    assert.ok(upstream.requests[0].body.includes('[REDACTED:CANARY_TOKEN]'));
  } finally {
    proxyClient.close();
    await upstream.close();
  }
});
