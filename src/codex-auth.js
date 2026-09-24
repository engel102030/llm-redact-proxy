// OAuth + wire contract for the ChatGPT Codex backend. The user logs in from
// the dashboard with the same PKCE flow, client id and fixed redirect the
// Codex CLI uses; the resulting tokens live in providers.json (chmod 600) and
// are ONLY ever sent to chatgpt.com (or a loopback test upstream - enforced
// in runtime + the upstream handler). Tokens are never logged; no error
// message built here ever contains one.
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import { createHash, randomBytes } from 'node:crypto';

export const CODEX_OAUTH_ISSUER = 'https://auth.openai.com';
export const CODEX_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
export const CODEX_REDIRECT_PORT = 1455;
export const CODEX_REDIRECT_URI = `http://localhost:${CODEX_REDIRECT_PORT}/auth/callback`;
export const CODEX_SCOPE = 'openid profile email offline_access';
export const CODEX_DEFAULT_BASE_URL = 'https://chatgpt.com/backend-api/codex';
export const CODEX_HOST = 'chatgpt.com';
export const CODEX_ORIGINATOR = 'codex_cli_rs';
// Version the backend currently accepts; override with CODEX_CLIENT_VERSION.
export const CODEX_CLIENT_VERSION = process.env.CODEX_CLIENT_VERSION || '0.145.0';
export const REFRESH_SKEW_MS = 5 * 60 * 1000;

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function createPkce() {
  const verifier = b64url(randomBytes(64));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const state = b64url(randomBytes(32));
  return { verifier, challenge, state };
}

export function buildAuthorizeUrl({ state, challenge, issuer = CODEX_OAUTH_ISSUER }) {
  const u = new URL('/oauth/authorize', issuer);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', CODEX_CLIENT_ID);
  u.searchParams.set('redirect_uri', CODEX_REDIRECT_URI);
  u.searchParams.set('scope', CODEX_SCOPE);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('id_token_add_organizations', 'true');
  u.searchParams.set('codex_cli_simplified_flow', 'true');
  u.searchParams.set('state', state);
  u.searchParams.set('originator', CODEX_ORIGINATOR);
  return u.toString();
}

// Minimal transport: resolves { status, body }. Every caller takes it as an
// injectable `request` so tests never touch the network.
export function httpRequest(url, { method = 'GET', headers = {}, body = null, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const transport = u.protocol === 'https:' ? https : http;
    const data = body === null || body === undefined ? null : Buffer.from(body);
    const h = { accept: 'application/json', ...headers };
    if (data) h['content-length'] = String(data.length);
    const req = transport.request(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: `${u.pathname}${u.search}`,
        method,
        headers: h,
        timeout: timeoutMs,
      },
      (res) => {
        let acc = '';
        res.setEncoding('utf8');
        res.on('data', (c) => {
          acc += c;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: acc }));
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    req.end(data ?? undefined);
  });
}

function parseTokens(body) {
  let j;
  try {
    j = JSON.parse(body);
  } catch {
    return null;
  }
  if (!j || typeof j.access_token !== 'string' || !j.access_token) return null;
  return {
    access: j.access_token,
    refresh: typeof j.refresh_token === 'string' ? j.refresh_token : '',
    idToken: typeof j.id_token === 'string' ? j.id_token : '',
  };
}

// Authorization code -> tokens (form-encoded, as the Codex CLI does).
export async function exchangeCode({ code, verifier, issuer = CODEX_OAUTH_ISSUER, request = httpRequest }) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: CODEX_REDIRECT_URI,
    client_id: CODEX_CLIENT_ID,
    code_verifier: verifier,
  }).toString();
  const res = await request(`${issuer}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (res.status !== 200) throw new Error(`token exchange failed (HTTP ${res.status})`);
  const tokens = parseTokens(res.body);
  if (!tokens) throw new Error('token exchange returned no access token');
  return tokens;
}

// refresh_token grant. JSON body first (the Codex CLI's form); a 4xx other
// than 401/403 is retried form-encoded in case the endpoint wants that.
// Returns null when no token can be obtained - the fix is logging in again
// from the dashboard. The old refresh token is kept when none is rotated.
export async function refreshTokens({ refreshToken, issuer = CODEX_OAUTH_ISSUER, request = httpRequest }) {
  if (!refreshToken) return null;
  const url = `${issuer}/oauth/token`;
  const params = { client_id: CODEX_CLIENT_ID, grant_type: 'refresh_token', refresh_token: refreshToken, scope: 'openid profile email' };
  let res;
  try {
    res = await request(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(params) });
    if (res.status >= 400 && res.status < 500 && res.status !== 401 && res.status !== 403) {
      res = await request(url, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(params).toString(),
      });
    }
  } catch {
    return null;
  }
  if (!res || res.status !== 200) return null;
  const tokens = parseTokens(res.body);
  if (!tokens) return null;
  return { ...tokens, refresh: tokens.refresh || refreshToken };
}

export function decodeJwtClaims(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const claims = JSON.parse(json);
    return claims && typeof claims === 'object' ? claims : null;
  } catch {
    return null;
  }
}

const AUTH_CLAIM = 'https://api.openai.com/auth';
const PROFILE_CLAIM = 'https://api.openai.com/profile';

// Account identity + expiry from the token claims. accountId is REQUIRED by
// the backend (chatgpt-account-id header); expiresAt drives the refresh.
export function accountFromTokens({ access, idToken }) {
  const a = decodeJwtClaims(access) ?? {};
  const i = decodeJwtClaims(idToken) ?? {};
  const auth = (a[AUTH_CLAIM] && typeof a[AUTH_CLAIM] === 'object' ? a[AUTH_CLAIM] : i[AUTH_CLAIM]) ?? {};
  const profile = (i[PROFILE_CLAIM] && typeof i[PROFILE_CLAIM] === 'object' ? i[PROFILE_CLAIM] : a[PROFILE_CLAIM]) ?? {};
  return {
    accountId: typeof auth.chatgpt_account_id === 'string' ? auth.chatgpt_account_id : null,
    email: typeof profile.email === 'string' ? profile.email : typeof i.email === 'string' ? i.email : null,
    plan: typeof auth.chatgpt_plan_type === 'string' ? auth.chatgpt_plan_type : null,
    expiresAt: Number.isFinite(a.exp) ? a.exp * 1000 : null,
  };
}

export function tokensFresh(tokens, nowMs = Date.now()) {
  if (!tokens || !tokens.access) return false;
  // Unknown expiry: trust the token until the backend answers 401.
  if (!Number.isFinite(tokens.expiresAt)) return true;
  return tokens.expiresAt - REFRESH_SKEW_MS > nowMs;
}

export function isCodexHost(url) {
  const host = url?.hostname ?? '';
  return host === CODEX_HOST || host.endsWith(`.${CODEX_HOST}`);
}

// A process on the user's own machine is inside the trust boundary (it is
// how the test suite proves the canary round-trip).
export function isLoopbackHost(url) {
  const host = url?.hostname ?? '';
  return host === '127.0.0.1' || host === 'localhost' || host === '[::1]' || host === '::1';
}

// The exact header contract of the Codex backend. Built clean-room: the
// caller's own headers are NOT forwarded on this path.
export function codexRequestHeaders({ access, accountId, sessionId, clientVersion = CODEX_CLIENT_VERSION }) {
  const platform = process.platform === 'darwin' ? 'Mac OS' : process.platform;
  return {
    authorization: `Bearer ${access}`,
    'chatgpt-account-id': accountId,
    'openai-beta': 'responses=experimental',
    originator: CODEX_ORIGINATOR,
    'user-agent': `${CODEX_ORIGINATOR}/${clientVersion} (${platform} ${os.release()}; ${process.arch}) unknown`,
    accept: 'text/event-stream',
    'content-type': 'application/json',
    session_id: sessionId,
  };
}

// GET <base>/models?client_version=... -> normalized list, or null on any
// failure (callers fall back to the static list). Never throws.
export async function fetchCodexModels({ baseUrl = CODEX_DEFAULT_BASE_URL, access, accountId, clientVersion = CODEX_CLIENT_VERSION, request = httpRequest }) {
  const url = `${String(baseUrl).replace(/\/$/, '')}/models?client_version=${encodeURIComponent(clientVersion)}`;
  let res;
  try {
    const headers = codexRequestHeaders({ access, accountId, sessionId: 'models', clientVersion });
    headers.accept = 'application/json';
    delete headers['content-type'];
    res = await request(url, { method: 'GET', headers });
  } catch {
    return null;
  }
  if (!res || res.status !== 200) return null;
  return normalizeCodexModels(res.body);
}

export function normalizeCodexModels(body) {
  let j;
  try {
    j = typeof body === 'string' ? JSON.parse(body) : body;
  } catch {
    return null;
  }
  if (!j || !Array.isArray(j.models)) return null;
  const out = [];
  for (const m of j.models) {
    if (!m || typeof m.slug !== 'string' || !m.slug) continue;
    const raw = Array.isArray(m.supported_reasoning_levels) ? m.supported_reasoning_levels : [];
    const levels = raw.map((l) => (typeof l === 'string' ? l : l?.effort)).filter((l) => typeof l === 'string');
    out.push({
      slug: m.slug,
      displayName: typeof m.display_name === 'string' ? m.display_name : m.slug,
      visibility: m.visibility === 'hide' ? 'hide' : 'list',
      defaultLevel: typeof m.default_reasoning_level === 'string' ? m.default_reasoning_level : null,
      levels,
    });
  }
  return out;
}
