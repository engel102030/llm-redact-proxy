// MCP server entrypoint. One process serves both:
//   - the MCP stdio tools (run / secret_add / secret_list / redaction_stats)
//   - the embedded redaction proxy (when UPSTREAM_URL is configured)
// so adding this server to the CLI's .mcp.json boots everything automatically.
//
// stdout is reserved for JSON-RPC; ALL logging goes to stderr.
import fs from 'node:fs';
import { loadConfig } from './config.js';
import { loadSecrets, MIN_SECRET_LENGTH } from './secrets.js';
import { createRedactor } from './redact.js';
import { createStats } from './stats.js';
import { createProxyServer } from './proxy.js';
import { createRunner } from './runner.js';
import { createRpcServer, rpcError } from './mcp-protocol.js';

const log = (line) => process.stderr.write(`${line}\n`);

const config = loadConfig({ requireUpstream: false });

let secrets = loadSecrets(config.secretsFile);
const holder = { current: createRedactor({ secrets }) };

function reload() {
  secrets = loadSecrets(config.secretsFile);
  holder.current = createRedactor({ secrets });
  log(`[redact] secrets reloaded: ${secrets.length} name(s)`);
}
// Pick up manual edits to the secrets file without a restart.
fs.watchFile(config.secretsFile, { interval: 2000 }, reload);

const stats = createStats({ log });
const runner = createRunner({
  getSecrets: () => secrets,
  getRedactor: () => holder.current,
});

// ---- embedded proxy -------------------------------------------------------
if (config.upstreamUrl) {
  const liveRedactor = { redactBody: (raw, ct) => holder.current.redactBody(raw, ct) };
  const server = createProxyServer({ config, redactor: liveRedactor, stats });
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      log('[redact] proxy port busy (another instance running?) - continuing with MCP tools only');
    } else {
      log(`[redact] proxy failed to start: ${err.message}`);
    }
  });
  server.listen(config.listenPort, config.listenHost, () => {
    const { port } = server.address();
    log(`[redact] proxy listening on http://${config.listenHost}:${port}`);
    log(`[redact] point your CLI at it: export ANTHROPIC_BASE_URL=http://${config.listenHost}:${port}`);
  });
} else {
  log('[redact] UPSTREAM_URL not set - embedded proxy disabled, MCP tools only');
}

// ---- secrets file upsert --------------------------------------------------
function upsertSecret(name, value) {
  let text = '';
  try {
    text = fs.readFileSync(config.secretsFile, 'utf8');
  } catch {
    // File does not exist yet; it will be created below.
  }
  const line = `${name}=${value}`;
  const re = new RegExp(`^${name}=.*$`, 'm');
  if (re.test(text)) {
    text = text.replace(re, line);
  } else {
    if (text && !text.endsWith('\n')) text += '\n';
    text += `${line}\n`;
  }
  fs.writeFileSync(config.secretsFile, text, { mode: 0o600 });
  reload();
}

// ---- MCP tools ------------------------------------------------------------
const TOOLS = [
  {
    name: 'run',
    description:
      'Execute a shell command LOCALLY on the user\'s machine with secret values filled in. ' +
      'Use {{NAME}} placeholders (or $NAME as an environment variable) wherever a credential ' +
      'goes, e.g. mysql -u root -p{{MYSQL_PASSWORD}} -e "SELECT 1". The real value is ' +
      'substituted locally, the command runs, and the output comes back with all secrets ' +
      'redacted - the literal value never enters the conversation. ALWAYS prefer this tool ' +
      'over asking the user for a credential. Use secret_list to see available names.',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: 'Shell command with {{NAME}} placeholders for secrets',
        },
        timeout_ms: {
          type: 'number',
          description: 'Kill the command after this many milliseconds (default 120000, max 600000)',
        },
      },
      required: ['command'],
    },
  },
  {
    name: 'secret_add',
    description:
      'Register a secret VALUE under a NAME in the local gitignored secrets file. From then ' +
      'on the value is redacted from all outgoing LLM traffic and can be used in the run ' +
      'tool as {{NAME}} or $NAME. Use when the user shares a new credential or a token ' +
      'appears at runtime. The value is never echoed back.',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Identifier, e.g. MYSQL_PASSWORD (letters, digits, underscore)',
        },
        value: { type: 'string', description: 'The secret value (min 6 chars)' },
      },
      required: ['name', 'value'],
    },
  },
  {
    name: 'secret_list',
    description: 'List the NAMES of registered secrets. Values are never returned by any tool.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'redaction_stats',
    description:
      'Counters from the local redaction proxy and runner: totals, per-rule counts, recent ' +
      'requests. Rule names and counts only - never values.',
    inputSchema: { type: 'object', properties: {} },
  },
];

const text = (t) => ({ content: [{ type: 'text', text: t }] });

async function callTool(name, args) {
  switch (name) {
    case 'run': {
      try {
        const result = await runner.run({ command: args.command, timeoutMs: args.timeout_ms });
        const head = `exit code: ${result.exitCode}${result.timedOut ? ' (timed out)' : ''}`;
        return {
          content: [{ type: 'text', text: `${head}\n${result.output}` }],
          isError: result.exitCode !== 0,
        };
      } catch (err) {
        return { content: [{ type: 'text', text: `error: ${err.message}` }], isError: true };
      }
    }
    case 'secret_add': {
      const { name: secretName, value } = args;
      if (typeof secretName !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(secretName)) {
        return { content: [{ type: 'text', text: 'error: invalid name (use letters, digits, underscore)' }], isError: true };
      }
      if (typeof value !== 'string' || value.length < MIN_SECRET_LENGTH) {
        return { content: [{ type: 'text', text: `error: value must be at least ${MIN_SECRET_LENGTH} chars` }], isError: true };
      }
      if (/[\r\n]/.test(value)) {
        return { content: [{ type: 'text', text: 'error: value must not contain newlines' }], isError: true };
      }
      upsertSecret(secretName, value);
      return text(
        `secret ${secretName} registered (${value.length} chars, value never echoed). ` +
          `It is now redacted from outgoing traffic and usable in run as {{${secretName}}} or $${secretName}.`,
      );
    }
    case 'secret_list': {
      const names = secrets.map((s) => s.name).sort();
      return text(names.length ? names.join('\n') : 'no secrets registered yet');
    }
    case 'redaction_stats':
      return text(JSON.stringify(stats.toJSON(), null, 2));
    default:
      throw rpcError(-32602, `unknown tool: ${name}`);
  }
}

// ---- MCP protocol wiring --------------------------------------------------
createRpcServer({
  handlers: {
    initialize: (params) => ({
      protocolVersion: params.protocolVersion ?? '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'llm-redact-proxy', version: '0.2.0' },
    }),
    'notifications/initialized': () => {},
    ping: () => ({}),
    'tools/list': () => ({ tools: TOOLS }),
    'tools/call': async (params) => callTool(params.name, params.arguments ?? {}),
  },
});

log(`[redact] MCP server ready (secrets: ${secrets.length}, proxy: ${config.upstreamUrl ? 'enabled' : 'off'})`);
