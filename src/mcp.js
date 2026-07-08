// MCP server entrypoint. One process serves both:
//   - the MCP stdio tools (run / secret_add / secret_list / redaction_stats)
//   - the embedded redaction proxy (when UPSTREAM_URL is configured)
// so adding this server to the CLI's .mcp.json boots everything automatically.
//
// stdout is reserved for JSON-RPC; ALL logging goes to stderr.
import fs from 'node:fs';
import path from 'node:path';
import { loadConfig } from './config.js';
import { loadSecretsFromSources, MIN_SECRET_LENGTH } from './secrets.js';
import { createRedactor, MODES, MODE_RANK } from './redact.js';
import { createStats } from './stats.js';
import { createProxyServer } from './proxy.js';
import { createRunner } from './runner.js';
import { createRpcServer, rpcError } from './mcp-protocol.js';

const log = (line) => process.stderr.write(`${line}\n`);

const config = loadConfig({ requireUpstream: false });

let secrets = loadSecretsFromSources(config.secretSources);
let currentMode = config.redactMode;

function build() {
  return createRedactor({
    secrets,
    mode: currentMode,
    disabledRules: config.redactDisable,
    ignore: config.redactIgnore,
  });
}
const holder = { current: build() };

function reload() {
  secrets = loadSecretsFromSources(config.secretSources);
  holder.current = build();
  const g = secrets.filter((s) => s.source === 'global').length;
  const p = secrets.filter((s) => s.source === 'project').length;
  log(`[redact] secrets reloaded: ${secrets.length} name(s) (global ${g}, project ${p})`);
}
// Pick up manual edits to either secrets file without a restart. Distinct
// paths only (global and project may resolve to the same file).
for (const filePath of new Set(config.secretSources.map((s) => s.path))) {
  fs.watchFile(filePath, { interval: 2000 }, reload);
}

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
// scope: 'global' | 'project' | 'both'. Returns the scopes actually written.
function upsertSecret(name, value, scope = 'global') {
  const targets = [];
  if (scope === 'global' || scope === 'both') targets.push(config.globalSecretsFile);
  if (scope === 'project' || scope === 'both') targets.push(config.projectSecretsFile);
  // Dedup: global and project may resolve to the same file.
  const paths = [...new Set(targets)];

  for (const filePath of paths) {
    let text = '';
    try {
      text = fs.readFileSync(filePath, 'utf8');
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
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, text, { mode: 0o600 });
  }
  reload();
  return paths.length;
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
      'Register a secret VALUE under a NAME so it is redacted from all outgoing LLM traffic ' +
      'and usable in the run tool as {{NAME}} or $NAME. Use when the user shares a new ' +
      'credential or a token appears at runtime. The value is never echoed back. Choose ' +
      'the scope: "global" (shared across all projects), "project" (only this project\'s ' +
      'secrets file), or "both". If unsure which scope, ask the user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Identifier, e.g. MYSQL_PASSWORD (letters, digits, underscore)',
        },
        value: { type: 'string', description: 'The secret value (min 6 chars)' },
        scope: {
          type: 'string',
          enum: ['global', 'project', 'both'],
          description: 'Where to store it (default global)',
        },
      },
      required: ['name', 'value'],
    },
  },
  {
    name: 'secret_list',
    description:
      'List the NAMES of registered secrets, grouped by scope (global / project). Values ' +
      'are never returned by any tool.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'redaction_stats',
    description:
      'Counters from the local redaction proxy and runner: totals, per-rule counts, recent ' +
      'requests. Rule names and counts only - never values.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'redact_mode',
    description:
      'Read or change how aggressively unregistered secrets are redacted. Call with no ' +
      'arguments to read the current mode. Modes: "named-only" (only secrets in the list; ' +
      'zero false positives, use for internal/test work where leaking a random token is ' +
      'fine), "balanced" (named + recognizable secret shapes like JWT/PEM/API-keys, no ' +
      'entropy guessing), "strict" (everything, most secure - default). Registered secrets ' +
      'are ALWAYS redacted regardless of mode. A configured floor may prevent lowering it.',
    inputSchema: {
      type: 'object',
      properties: {
        mode: { type: 'string', enum: MODES, description: 'New mode; omit to just read the current one' },
      },
    },
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
      const scope = args.scope ?? 'global';
      if (typeof secretName !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(secretName)) {
        return { content: [{ type: 'text', text: 'error: invalid name (use letters, digits, underscore)' }], isError: true };
      }
      if (typeof value !== 'string' || value.length < MIN_SECRET_LENGTH) {
        return { content: [{ type: 'text', text: `error: value must be at least ${MIN_SECRET_LENGTH} chars` }], isError: true };
      }
      if (/[\r\n]/.test(value)) {
        return { content: [{ type: 'text', text: 'error: value must not contain newlines' }], isError: true };
      }
      if (!['global', 'project', 'both'].includes(scope)) {
        return { content: [{ type: 'text', text: 'error: scope must be global, project or both' }], isError: true };
      }
      const written = upsertSecret(secretName, value, scope);
      const where = scope === 'both' && written === 1 ? 'global (project resolves to the same file)' : scope;
      return text(
        `secret ${secretName} registered in ${where} (${value.length} chars, value never echoed). ` +
          `It is now redacted from outgoing traffic and usable in run as {{${secretName}}} or $${secretName}.`,
      );
    }
    case 'secret_list': {
      if (secrets.length === 0) return text('no secrets registered yet');
      const byScope = { global: [], project: [] };
      for (const s of secrets) (byScope[s.source] ?? (byScope[s.source] = [])).push(s.name);
      const lines = [];
      for (const scope of ['global', 'project']) {
        const names = (byScope[scope] ?? []).sort();
        if (names.length) lines.push(`[${scope}]`, ...names.map((n) => `  ${n}`));
      }
      return text(lines.join('\n'));
    }
    case 'redaction_stats':
      return text(JSON.stringify(stats.toJSON(), null, 2));
    case 'redact_mode': {
      if (args.mode === undefined) {
        return text(`mode: ${currentMode} (floor: ${config.redactModeFloor})`);
      }
      if (!MODES.includes(args.mode)) {
        return { content: [{ type: 'text', text: `error: invalid mode. Use one of ${MODES.join('|')}` }], isError: true };
      }
      // The floor is a hard minimum. This is the guard against a prompt-
      // injected model loosening its own protection to exfiltrate.
      if (MODE_RANK[args.mode] < MODE_RANK[config.redactModeFloor]) {
        return {
          content: [{ type: 'text', text: `error: mode "${args.mode}" is below the configured floor "${config.redactModeFloor}"; cannot lower further` }],
          isError: true,
        };
      }
      currentMode = args.mode;
      holder.current = build();
      log(`[redact] mode changed to ${currentMode}`);
      return text(`mode set to ${currentMode}`);
    }
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

log(`[redact] secret stores: global=${config.globalSecretsFile} project=${config.projectSecretsFile}`);
log(`[redact] MCP server ready (secrets: ${secrets.length}, proxy: ${config.upstreamUrl ? 'enabled' : 'off'})`);
