// Config loader: real environment variables win over a local .env file,
// which wins over defaults. Zero dependencies.
import fs from 'node:fs';
import path from 'node:path';
import { MODES, MODE_RANK } from './redact.js';

const DEFAULTS = {
  LISTEN_ADDR: '127.0.0.1:8788',
  SECRETS_FILE: './secrets.local',
  UPSTREAM_AUTH: 'passthrough',
  FAIL_CLOSED: 'true',
  INJECT_NOTICE: 'true',
  REDACT_MODE: 'strict',
  REDACT_MODE_FLOOR: 'named-only',
};

const splitList = (v) =>
  (v ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

export function parseDotEnv(text) {
  const vars = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    vars[key] = value;
  }
  return vars;
}

export function loadConfig({ env = process.env, cwd = process.cwd(), requireUpstream = true } = {}) {
  let fileVars = {};
  const dotEnvPath = path.join(cwd, '.env');
  if (fs.existsSync(dotEnvPath)) {
    fileVars = parseDotEnv(fs.readFileSync(dotEnvPath, 'utf8'));
  }
  // Empty string counts as unset so wrappers can explicitly blank a var.
  const pick = (v) => (v !== undefined && v !== '' ? v : undefined);
  const get = (key) => pick(env[key]) ?? pick(fileVars[key]) ?? DEFAULTS[key];

  const listenAddr = get('LISTEN_ADDR');
  const colon = listenAddr.lastIndexOf(':');
  if (colon < 0) throw new Error(`LISTEN_ADDR must be host:port, got "${listenAddr}"`);
  let listenHost = listenAddr.slice(0, colon);
  const listenPort = Number(listenAddr.slice(colon + 1));
  if (!Number.isInteger(listenPort) || listenPort < 0 || listenPort > 65535) {
    throw new Error(`LISTEN_ADDR has an invalid port: "${listenAddr}"`);
  }
  if (listenHost === 'localhost') listenHost = '127.0.0.1';
  // The proxy MUST be local only. A remote redactor would receive the
  // un-redacted body first, defeating the entire purpose.
  if (listenHost !== '127.0.0.1') {
    throw new Error(
      `LISTEN_ADDR must bind 127.0.0.1 (loopback only), got "${listenHost}". ` +
        'This proxy sees un-redacted bodies and must never be reachable remotely.',
    );
  }

  const upstreamRaw = get('UPSTREAM_URL');
  if (!upstreamRaw && requireUpstream) {
    throw new Error('UPSTREAM_URL is required (the vendor endpoint to forward redacted requests to)');
  }
  let upstreamUrl = null;
  if (upstreamRaw) {
    upstreamUrl = new URL(upstreamRaw);
    if (upstreamUrl.protocol !== 'https:' && upstreamUrl.protocol !== 'http:') {
      throw new Error(`UPSTREAM_URL must be http(s), got "${upstreamUrl.protocol}"`);
    }
  }

  const upstreamAuth = get('UPSTREAM_AUTH');
  if (upstreamAuth !== 'passthrough' && upstreamAuth !== 'replace') {
    throw new Error(`UPSTREAM_AUTH must be "passthrough" or "replace", got "${upstreamAuth}"`);
  }
  const upstreamKey = env.UPSTREAM_KEY ?? fileVars.UPSTREAM_KEY ?? null;
  if (upstreamAuth === 'replace' && !upstreamKey) {
    throw new Error('UPSTREAM_AUTH=replace requires UPSTREAM_KEY');
  }

  const requestedMode = get('REDACT_MODE');
  if (!MODES.includes(requestedMode)) {
    throw new Error(`REDACT_MODE must be one of ${MODES.join('|')}, got "${requestedMode}"`);
  }
  const floor = get('REDACT_MODE_FLOOR');
  if (!MODES.includes(floor)) {
    throw new Error(`REDACT_MODE_FLOOR must be one of ${MODES.join('|')}, got "${floor}"`);
  }
  // The floor is a hard minimum; a starting mode below it is clamped up.
  const redactMode = MODE_RANK[requestedMode] < MODE_RANK[floor] ? floor : requestedMode;

  return {
    listenHost,
    listenPort,
    upstreamUrl,
    upstreamAuth,
    upstreamKey,
    secretsFile: path.resolve(cwd, get('SECRETS_FILE')),
    failClosed: get('FAIL_CLOSED') !== 'false',
    injectNotice: get('INJECT_NOTICE') !== 'false',
    redactMode,
    redactModeFloor: floor,
    redactDisable: splitList(get('REDACT_DISABLE')),
    redactIgnore: splitList(get('REDACT_IGNORE')),
  };
}
