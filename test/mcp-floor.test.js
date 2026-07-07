// A configured floor is a hard minimum: the redact_mode tool cannot drop
// below it. This is the guard against a prompt-injected model loosening its
// own protection to exfiltrate.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startMcpClient } from './helpers/mcp-client.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-floor-'));
fs.writeFileSync(path.join(dir, 'secrets.local'), 'DB=floor-secret-value-123\n');

const client = startMcpClient({
  cwd: dir,
  env: {
    SECRETS_FILE: path.join(dir, 'secrets.local'),
    UPSTREAM_URL: '',
    LISTEN_ADDR: '',
    REDACT_MODE: 'strict',
    REDACT_MODE_FLOOR: 'balanced',
  },
});

after(() => client.close());

test('handshake', async () => {
  await client.request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  client.notify('notifications/initialized');
});

test('redact_mode refuses to go below the configured floor', async () => {
  const res = await client.request('tools/call', {
    name: 'redact_mode',
    arguments: { mode: 'named-only' },
  });
  assert.ok(res.result.isError, 'dropping below floor should error');
  assert.match(res.result.content[0].text, /floor|balanced/i);

  // At or above the floor is allowed.
  const ok = await client.request('tools/call', {
    name: 'redact_mode',
    arguments: { mode: 'balanced' },
  });
  assert.ok(!ok.result.isError);
});
