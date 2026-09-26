// One-shot local listener for the OAuth callback. The redirect URI is fixed
// by OpenAI's registered client (http://localhost:1455/auth/callback - the
// same port the Codex CLI uses), so the listener binds 127.0.0.1:1455 for
// the duration of ONE login: started from the dashboard, alive for at most
// timeoutMs, closed after the first callback. One login per process at a
// time. Everything that touches the network is injectable for tests.
import http from 'node:http';
import {
  createPkce,
  buildAuthorizeUrl,
  exchangeCode,
  accountFromTokens,
  fetchCodexModels,
  CODEX_REDIRECT_PORT,
  CODEX_DEFAULT_BASE_URL,
} from './codex-auth.js';

let active = null; // { server, close } while a login is in flight

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const page = (title, body) =>
  `<!doctype html><meta charset="utf-8"><title>${escapeHtml(title)}</title>` +
  `<body style="font-family:system-ui;padding:40px;max-width:640px"><h2>${escapeHtml(title)}</h2><p>${body}</p></body>`;

export function loginInProgress() {
  return active !== null;
}

export function startCodexLogin({
  port = CODEX_REDIRECT_PORT,
  host = '127.0.0.1',
  timeoutMs = 5 * 60 * 1000,
  baseUrl = CODEX_DEFAULT_BASE_URL,
  exchange = exchangeCode,
  fetchModels = fetchCodexModels,
  request,
  onResult,
  nowMs = Date.now,
} = {}) {
  if (active) {
    const err = new Error('a ChatGPT login is already in progress');
    err.code = 'LOGIN_IN_PROGRESS';
    return Promise.reject(err);
  }
  const pkce = createPkce();
  const url = buildAuthorizeUrl({ state: pkce.state, challenge: pkce.challenge });

  return new Promise((resolve, reject) => {
    let timer = null;
    let server = null;
    const close = () => {
      if (timer) clearTimeout(timer);
      timer = null;
      if (active && active.server === server) active = null;
      if (server) {
        server.close();
        if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      }
    };

    server = http.createServer(async (req, res) => {
      const u = new URL(req.url ?? '/', 'http://localhost');
      if (u.pathname !== '/auth/callback') {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
        return;
      }
      const send = (code, html) => {
        res.writeHead(code, { 'content-type': 'text/html; charset=utf-8' });
        res.end(html);
      };
      const code = u.searchParams.get('code');
      if (u.searchParams.get('state') !== pkce.state || !code) {
        send(400, page('Login failed', 'State mismatch or missing code. Start the login again from the dashboard.'));
        close();
        return;
      }
      try {
        const tokens = await exchange({ code, verifier: pkce.verifier, request });
        const account = accountFromTokens(tokens);
        if (!account.accountId) throw new Error('the token carries no ChatGPT account id');
        const models = await fetchModels({ baseUrl, access: tokens.access, accountId: account.accountId, request });
        onResult({
          tokens: { access: tokens.access, refresh: tokens.refresh, idToken: tokens.idToken, accountId: account.accountId, expiresAt: account.expiresAt },
          account: { email: account.email, plan: account.plan },
          models,
          fetchedAt: nowMs(),
        });
        send(200, page('Logged in', `Signed in as ${escapeHtml(account.email ?? 'your ChatGPT account')}. You can close this tab.`));
      } catch (err) {
        send(500, page('Login failed', escapeHtml(err.message)));
      }
      close();
    });

    server.on('error', (err) => {
      if (active && active.server === server) active = null;
      reject(err);
    });
    server.listen(port, host, () => {
      active = { server, close };
      timer = setTimeout(close, timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();
      resolve({ url, port: server.address().port, close });
    });
  });
}
