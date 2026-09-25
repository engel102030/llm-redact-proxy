// Codex backend upstream (auth mode "codex-oauth"). The redacted Anthropic
// Messages body is translated to a Responses request and sent to the backend
// either over the WebSocket transport (one socket per conversation, following
// turns send only the new items plus previous_response_id) or over plain
// HTTP (POST <base>/responses); the Responses events are translated back to
// Anthropic SSE (or folded into one JSON message when the client did not ask
// for a stream). Redaction ALWAYS happened before this point; any translation
// failure blocks the request (fail closed). Model discovery and count_tokens
// are answered locally - no token leaves for them.
import http from 'node:http';
import https from 'node:https';
import { randomUUID } from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { isCodexHost, isLoopbackHost, codexRequestHeaders } from './codex-auth.js';
import {
  anthropicToCodex,
  SseDecoder,
  CodexReducer,
  serializeSse,
  errorSse,
  accumulateMessage,
  estimateTokens,
  CODEX_DEFAULT_MODELS,
} from './codex-translate.js';
import { modelsEnvelope } from './models.js';
import { connectWebSocket } from './codex-ws.js';
import { createContinuationRegistry } from './codex-continuation.js';

export const CODEX_MAX_BUFFERED_RESPONSE_BYTES = 8 * 1024 * 1024;
export const CODEX_MAX_ERROR_BODY_BYTES = 16 * 1024;
export const WS_PROTOCOL = 'responses_websockets=2026-02-06';
export const WS_IDLE_MS = 5 * 60 * 1000;
export const WS_REFUSED_BACKOFF_MS = 5 * 60 * 1000;
export const WS_NETWORK_BACKOFF_MS = 30 * 1000;

const MODEL_EPOCH = '1970-01-01T00:00:00Z';
const SSE_HEADERS = { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' };

// ---------------------------------------------------------------------------
// Start-of-stream input estimate. bytes/4 overshoots the tokenizer by a
// stable factor (~1.16 measured on real sessions), so the client's context
// meter would climb during streaming and fall back at the end. Scale by the
// real/estimate ratio observed on the previous turn of the same session
// (keyed by prompt_cache_key); a conservative default until then.
// ---------------------------------------------------------------------------
const DEFAULT_ESTIMATE_RATIO = 0.86;
const CALIBRATION_KEEP = 256;
const calibration = new Map(); // prompt_cache_key -> real tokens / bytes-4 estimate

function estimateInput(translated) {
  const raw = estimateTokens(translated);
  const key = translated.prompt_cache_key;
  const ratio = (key && calibration.get(key)) || DEFAULT_ESTIMATE_RATIO;
  return Math.round(raw * ratio);
}

function calibrate(translated, realTotal) {
  const key = translated.prompt_cache_key;
  if (!key || !Number.isFinite(realTotal) || realTotal <= 0) return;
  const raw = estimateTokens(translated);
  if (!raw) return;
  calibration.delete(key);
  calibration.set(key, realTotal / raw);
  while (calibration.size > CALIBRATION_KEEP) calibration.delete(calibration.keys().next().value);
}

// UUID-v4-shaped id derived from the (sha256 hex) prompt_cache_key: one
// session id per Claude Code session, as the Codex CLI does per conversation.
function sessionIdFor(cacheKey) {
  if (typeof cacheKey !== 'string' || !/^[0-9a-f]{32,}$/.test(cacheKey)) return randomUUID();
  const h = cacheKey;
  const variant = '89ab'[parseInt(h[16], 16) % 4];
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

// ---------------------------------------------------------------------------
// Plan usage the backend reports on every response (x-codex-* headers on
// HTTP, a codex.rate_limits event on the socket). primary = the plan's main
// window (7 days on ChatGPT plans), secondary = a shorter window when the
// plan has one. null when absent.
// ---------------------------------------------------------------------------
export function parseCodexLimits(headers, nowMs = Date.now()) {
  const h = headers ?? {};
  const str = (k) => (typeof h[k] === 'string' && h[k] !== '' ? h[k] : null);
  const num = (k) => (str(k) !== null && Number.isFinite(Number(h[k])) ? Number(h[k]) : null);
  if (num('x-codex-primary-used-percent') === null) return null;
  const window = (prefix) => {
    const used = num(`${prefix}-used-percent`);
    const minutes = num(`${prefix}-window-minutes`);
    if (used === null || !minutes) return null;
    const resetAt = num(`${prefix}-reset-at`);
    return { usedPercent: used, windowMinutes: minutes, resetAt: resetAt ? resetAt * 1000 : null };
  };
  const bool = (k) => (str(k) === null ? null : /^true$/i.test(h[k]));
  const credits =
    str('x-codex-credits-has-credits') === null && str('x-codex-credits-balance') === null
      ? null
      : { hasCredits: bool('x-codex-credits-has-credits') ?? false, unlimited: bool('x-codex-credits-unlimited') ?? false, balance: str('x-codex-credits-balance') ?? '0' };
  return {
    planType: str('x-codex-plan-type'),
    activeLimit: str('x-codex-active-limit'),
    primary: window('x-codex-primary'),
    secondary: window('x-codex-secondary'),
    credits,
    observedAt: nowMs,
  };
}

export function limitsFromEvent(ev, nowMs = Date.now()) {
  if (!ev || ev.type !== 'codex.rate_limits' || !ev.rate_limits || typeof ev.rate_limits !== 'object') return null;
  const window = (w) => {
    if (!w || typeof w !== 'object' || !Number.isFinite(w.used_percent) || !w.window_minutes) return null;
    return { usedPercent: w.used_percent, windowMinutes: w.window_minutes, resetAt: Number.isFinite(w.reset_at) ? w.reset_at * 1000 : null };
  };
  const c = ev.credits && typeof ev.credits === 'object' ? ev.credits : null;
  return {
    planType: typeof ev.plan_type === 'string' ? ev.plan_type : null,
    activeLimit: null,
    primary: window(ev.rate_limits.primary),
    secondary: window(ev.rate_limits.secondary),
    credits: c ? { hasCredits: c.has_credits === true, unlimited: c.unlimited === true, balance: String(c.balance ?? '0') } : null,
    observedAt: nowMs,
  };
}

function readCapped(stream, cap) {
  return new Promise((resolve) => {
    let acc = '';
    stream.setEncoding('utf8');
    stream.on('data', (c) => {
      if (acc.length < cap) acc += c.slice(0, cap - acc.length);
    });
    stream.on('end', () => resolve(acc));
    stream.on('error', () => resolve(acc));
  });
}

function errorDetail(text) {
  try {
    const j = JSON.parse(text);
    if (typeof j.detail === 'string') return j.detail;
    if (typeof j.error?.message === 'string') return j.error.message;
    return JSON.stringify(j.detail ?? j.error ?? j).slice(0, 500);
  } catch {
    return text.slice(0, 500);
  }
}

// ---------------------------------------------------------------------------
// Event sources: both transports feed the same translation loop with parsed
// Responses events. Interface: on('event'|'end'|'error', fn), destroy().
// ---------------------------------------------------------------------------
function makeEmitter() {
  const handlers = { event: [], end: [], error: [] };
  return {
    on: (name, fn) => handlers[name].push(fn),
    emit: (name, arg) => {
      for (const fn of handlers[name]) fn(arg);
    },
  };
}

// HTTP: bytes -> SSE frames -> events. onRaw sees the raw text for the inspector.
function httpSource(upstreamRes, { onRaw, cap = null }) {
  const em = makeEmitter();
  const decoder = new SseDecoder();
  const rawDec = new StringDecoder('utf8');
  let bytes = 0;
  let failed = false;
  let ended = false;
  const fail = (err) => {
    if (failed || ended) return;
    failed = true;
    em.emit('error', err);
  };
  upstreamRes.on('data', (chunk) => {
    bytes += chunk.length;
    onRaw(rawDec.write(chunk), chunk.length);
    if (failed) return;
    if (cap && bytes > cap) {
      fail(new Error('codex upstream response exceeds the size limit'));
      upstreamRes.destroy();
      return;
    }
    try {
      for (const ev of decoder.push(chunk)) em.emit('event', ev);
    } catch (err) {
      fail(err);
      upstreamRes.destroy();
    }
  });
  const end = () => {
    if (ended || failed) return;
    ended = true;
    try {
      for (const ev of decoder.flush()) em.emit('event', ev);
    } catch (err) {
      failed = true;
      em.emit('error', err);
      return;
    }
    em.emit('end');
  };
  upstreamRes.on('end', end);
  upstreamRes.on('close', end);
  upstreamRes.on('error', (err) => fail(err ?? new Error('codex upstream stream failed')));
  return { on: em.on, destroy: () => upstreamRes.destroy() };
}

// WebSocket: one JSON event per message until a terminal event. An `error`
// arriving BEFORE response.created is reported with beforeStart=true so the
// caller can retry the turn (e.g. a lost continuation) without the client
// having seen anything.
function wsSource(ws, { onRaw, timeoutMs }) {
  const em = makeEmitter();
  let started = false;
  let finished = false;
  let timer = null;
  const arm = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => finish('error', new Error('codex websocket timeout')), timeoutMs);
  };
  const detach = () => {
    if (timer) clearTimeout(timer);
    ws.removeListener('message', onMessage);
    ws.removeListener('close', onClose);
  };
  const finish = (kind, arg) => {
    if (finished) return;
    finished = true;
    detach();
    em.emit(kind, arg);
  };
  const onMessage = (text) => {
    if (finished) return;
    onRaw(`${text}\n`, Buffer.byteLength(text, 'utf8'));
    let ev;
    try {
      ev = JSON.parse(text);
    } catch {
      finish('error', new Error('codex websocket sent invalid JSON'));
      ws.close();
      return;
    }
    arm();
    if (ev && ev.type === 'response.created') started = true;
    if (ev && (ev.type === 'error' || ev.type === 'response.failed') && !started) {
      const err = new Error(ev.message ?? ev.error?.message ?? ev.response?.error?.message ?? 'codex websocket error');
      err.beforeStart = true;
      err.code = ev.code ?? ev.error?.code ?? null;
      err.status = ev.status ?? ev.error?.status ?? null;
      finish('error', err);
      return;
    }
    em.emit('event', ev);
    if (ev && (ev.type === 'response.completed' || ev.type === 'response.incomplete' || ev.type === 'response.failed' || ev.type === 'error')) {
      finish('end');
    }
  };
  const onClose = () => finish('error', new Error('codex websocket closed'));
  ws.on('message', onMessage);
  ws.on('close', onClose);
  arm();
  return { on: em.on, destroy: () => { detach(); ws.close(); } };
}

// ---------------------------------------------------------------------------
// Translation loop shared by both transports. Writes the client response,
// except when the source fails before anything was started (beforeStart):
// then it resolves { beforeStart, error } and the caller decides.
// ---------------------------------------------------------------------------
function deliver({ source, res, clientStream, reducer, onEvent }) {
  return new Promise((resolve) => {
    let settled = false;
    let headersSent = false;
    const write = (s) => {
      if (!headersSent) {
        res.writeHead(200, SSE_HEADERS);
        headersSent = true;
      }
      res.write(s);
    };
    const events = [];
    const settle = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const failClient = (message, err) => {
      if (clientStream && headersSent) {
        res.write(errorSse(message));
        res.end();
        settle({ status: 502, sent: true, error: message });
        return;
      }
      if (err && err.beforeStart) {
        settle({ status: 502, sent: false, error: message, beforeStart: true, err });
        return;
      }
      settle({ status: 502, sent: false, error: message, err });
    };
    res.on('close', () => {
      if (settled) return;
      source.destroy();
      settle({ status: null, sent: true, error: 'client disconnected' });
    });
    source.on('event', (ev) => {
      if (settled) return;
      try {
        onEvent?.(ev);
        const out = reducer.push(ev);
        if (!out.length) return;
        if (clientStream) write(serializeSse(out));
        else events.push(...out);
      } catch (err) {
        source.destroy();
        failClient(`codex stream translation failed: ${err.message}`, err);
      }
    });
    source.on('error', (err) => {
      if (settled) return;
      failClient(err.beforeStart ? err.message : `codex upstream failed: ${err.message}`, err);
    });
    source.on('end', () => {
      if (settled) return;
      if (!reducer.done) {
        failClient('codex upstream ended before response.completed');
        return;
      }
      if (clientStream) {
        if (!headersSent) res.writeHead(200, SSE_HEADERS);
        res.end();
        settle({ status: 200, sent: true, error: null });
        return;
      }
      let message;
      try {
        message = accumulateMessage(events);
      } catch (err) {
        failClient(`codex response translation failed: ${err.message}`);
        return;
      }
      const buf = Buffer.from(JSON.stringify(message), 'utf8');
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(buf.length) });
      res.end(buf);
      settle({ status: 200, sent: true, error: null });
    });
  });
}

// ---------------------------------------------------------------------------
// WebSocket transport state: one socket per conversation (+ host), the
// continuation registry, and a backoff after a refused upgrade.
// ---------------------------------------------------------------------------
const continuation = createContinuationRegistry();
const sockets = new Map(); // pool key -> { ws, busy, idleTimer }
let wsBackoffUntil = 0;

function dropSocket(poolKey, { close = true } = {}) {
  const entry = sockets.get(poolKey);
  if (!entry) return;
  sockets.delete(poolKey);
  if (entry.idleTimer) clearTimeout(entry.idleTimer);
  continuation.invalidate(poolKey);
  if (close) entry.ws.close();
}

function armIdle(poolKey) {
  const entry = sockets.get(poolKey);
  if (!entry) return;
  if (entry.idleTimer) clearTimeout(entry.idleTimer);
  entry.idleTimer = setTimeout(() => dropSocket(poolKey), WS_IDLE_MS);
  if (typeof entry.idleTimer.unref === 'function') entry.idleTimer.unref();
}

// Returns the pool entry to use, or null when the caller must use HTTP.
async function acquireSocket({ poolKey, up, upstreamPath, access, accountId, sessionId, timeoutMs, nowMs }) {
  const existing = sockets.get(poolKey);
  if (existing) {
    if (existing.busy || !existing.ws.open) {
      if (!existing.ws.open) dropSocket(poolKey, { close: false });
      return null;
    }
    return existing;
  }
  if (nowMs < wsBackoffUntil) return null;
  const headers = codexRequestHeaders({ access, accountId, sessionId });
  delete headers.accept;
  delete headers['content-type'];
  headers['openai-beta'] = WS_PROTOCOL;
  const url = `${up.url.protocol === 'https:' ? 'wss:' : 'ws:'}//${up.url.host}${upstreamPath}`;
  let ws;
  try {
    ws = await connectWebSocket(url, { headers, timeoutMs });
  } catch (err) {
    wsBackoffUntil = nowMs + (err && err.status ? WS_REFUSED_BACKOFF_MS : WS_NETWORK_BACKOFF_MS);
    return null;
  }
  continuation.invalidate(poolKey); // a new socket starts a fresh continuation
  const entry = { ws, busy: false, idleTimer: null };
  sockets.set(poolKey, entry);
  ws.on('close', () => {
    if (sockets.get(poolKey) === entry) dropSocket(poolKey, { close: false });
  });
  armIdle(poolKey);
  return entry;
}

// For tests: forget every socket and continuation.
export function resetCodexTransportState() {
  for (const key of [...sockets.keys()]) dropSocket(key);
  wsBackoffUntil = 0;
}

// ---------------------------------------------------------------------------
// The request handler. `codex` is the adapter from the runtime:
// { profile(), credentials(), refresh(), reportLimits?() }.
// ---------------------------------------------------------------------------
export async function handleCodexUpstream({ req, res, up, entry, stats, t0, bodyText, codex, aliases = {}, timeoutMs = 10 * 60 * 1000 }) {
  let note = null;
  const usage = { input_tokens: null, output_tokens: null };
  let respAcc = '';
  let respBytes = 0;
  const finish = (status, extra = {}) => stats.finish(entry, { status, durationMs: Date.now() - t0, note, ...extra });
  const finishTurn = (status) => {
    stats.rememberResp(entry?.id, respAcc);
    finish(status, { inputTokens: usage.input_tokens, outputTokens: usage.output_tokens, respBytes });
  };
  const sendJson = (status, obj) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(obj));
    finish(status);
  };

  // Defence in depth: the token must only ever reach the Codex backend or a
  // process on this machine, even if the runtime guard was somehow bypassed.
  if (!isCodexHost(up.url) && !isLoopbackHost(up.url)) {
    sendJson(400, { error: { type: 'codex_misconfig', message: 'codex-oauth auth is only allowed with chatgpt.com' } });
    return;
  }
  if (!codex) {
    sendJson(502, { error: { type: 'no_codex_oauth', message: 'no ChatGPT login for the active provider - log in from the dashboard' } });
    return;
  }

  const pathname = (req.url ?? '/').split('?')[0];
  const profile = codex.profile();
  const models = Array.isArray(profile.models) && profile.models.length > 0 ? profile.models : CODEX_DEFAULT_MODELS;

  // Model discovery: the plan's list (plus alias names), answered locally.
  if (req.method === 'GET' && /^\/v1\/models$/.test(pathname)) {
    const data = models.filter((m) => m.visibility !== 'hide').map((m) => ({ id: m.slug, display_name: m.displayName ?? m.slug, type: 'model', created_at: MODEL_EPOCH }));
    for (const alias of Object.keys(aliases)) {
      if (!data.some((m) => m.id === alias)) data.push({ id: alias, display_name: alias, type: 'model', created_at: MODEL_EPOCH });
    }
    sendJson(200, modelsEnvelope(data));
    return;
  }

  const translateOptions = { models, effortMap: profile.effortMap ?? undefined, prune: profile.prune ?? undefined };
  const translate = () => anthropicToCodex(JSON.parse(bodyText), translateOptions);

  // No count endpoint upstream: a deterministic local estimate.
  if (req.method === 'POST' && pathname.endsWith('/count_tokens')) {
    try {
      sendJson(200, { input_tokens: estimateTokens(translate()) });
    } catch (err) {
      sendJson(400, { error: { type: 'invalid_request_error', message: `codex translation failed: ${err.message}` } });
    }
    return;
  }

  if (req.method !== 'POST' || !pathname.endsWith('/messages')) {
    sendJson(404, { error: { type: 'not_found', message: 'codex-oauth provider serves only /v1/messages, /v1/messages/count_tokens and /v1/models' } });
    return;
  }

  let parsed;
  let translated;
  try {
    parsed = JSON.parse(bodyText);
    translated = anthropicToCodex(parsed, translateOptions);
  } catch (err) {
    // Fail closed: an untranslatable body is never forwarded raw.
    sendJson(400, { error: { type: 'invalid_request_error', message: `codex translation failed: ${err.message}` } });
    return;
  }
  note = `codex model=${translated.model} effort=${translated.reasoning?.effort ?? '-'}`;
  const clientStream = parsed.stream === true;
  // Overwrite the inspector copy: THIS is what actually leaves the machine.
  stats.rememberReq(entry?.id, JSON.stringify(translated));

  let creds;
  try {
    creds = await codex.credentials();
  } catch {
    creds = null;
  }
  if (!creds) {
    sendJson(502, { error: { type: 'no_codex_oauth', message: 'ChatGPT login missing or expired - log in again from the dashboard' } });
    return;
  }

  const basePath = up.url.pathname.replace(/\/$/, '');
  const upstreamPath = basePath.endsWith('/responses') ? basePath : `${basePath}/responses`;
  const sessionId = sessionIdFor(translated.prompt_cache_key);
  const messageId = `msg_${randomUUID().replace(/-/g, '')}`;
  const newReducer = () => new CodexReducer({ messageId, model: parsed.model, inputEstimate: estimateInput(translated) });
  const onRaw = (text, bytes) => {
    respAcc += text;
    respBytes += bytes;
  };
  const reportLimits = (limits) => {
    if (!limits) return;
    if (typeof codex.reportLimits === 'function') codex.reportLimits(limits);
    if (limits.primary) note = `${note} quota ${limits.primary.usedPercent}%`;
  };
  // Per-event bookkeeping shared by both transports: usage for the log,
  // calibration, output items + response id for the continuation registry.
  const turn = { outputItems: [], responseId: null };
  const onEvent = (ev) => {
    if (!ev || typeof ev.type !== 'string') return;
    if (ev.type === 'codex.rate_limits') reportLimits(limitsFromEvent(ev));
    else if (ev.type === 'response.output_item.done' && ev.item) turn.outputItems.push(ev.item);
    else if (ev.type === 'response.completed' || ev.type === 'response.incomplete') {
      const u = ev.response?.usage ?? {};
      const total = Number.isFinite(u.input_tokens) ? u.input_tokens : 0;
      usage.input_tokens = total;
      usage.output_tokens = Number.isFinite(u.output_tokens) ? u.output_tokens : null;
      turn.responseId = typeof ev.response?.id === 'string' ? ev.response.id : null;
      calibrate(translated, total);
    }
  };
  const failJson = (result) => {
    const err = result.err ?? {};
    const rateLimited = err.status === 429 || /rate.?limit|usage limit/i.test(result.error ?? '');
    if (rateLimited) {
      res.writeHead(429, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: result.error } }));
      finishTurn(429);
      return;
    }
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'upstream_error', message: result.error } }));
    finishTurn(502);
  };

  // ---- WebSocket transport (default): one socket per conversation ----
  const poolKey = translated.prompt_cache_key ? `${up.url.host}|${translated.prompt_cache_key}` : null;
  if (profile.transport !== 'http' && poolKey) {
    const socket = await acquireSocket({ poolKey, up, upstreamPath, access: creds.access, accountId: creds.accountId, sessionId, timeoutMs: Math.min(timeoutMs, 20_000), nowMs: Date.now() });
    if (socket) {
      socket.busy = true;
      if (socket.idleTimer) clearTimeout(socket.idleTimer);
      let plan = continuation.plan(poolKey, translated);
      let result = null;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const body = plan.mode === 'delta' ? { type: 'response.create', ...translated, input: plan.input, previous_response_id: plan.previousResponseId } : { type: 'response.create', ...translated };
        note = `${note.replace(/ ws (delta|full)/, '')} ws ${plan.mode}`;
        turn.outputItems = [];
        turn.responseId = null;
        try {
          socket.ws.send(JSON.stringify(body));
        } catch (err) {
          dropSocket(poolKey, { close: false });
          socket.busy = false;
          result = null;
          break;
        }
        result = await deliver({ source: wsSource(socket.ws, { onRaw, timeoutMs }), res, clientStream, reducer: newReducer(), onEvent });
        if (result.beforeStart && plan.mode === 'delta' && attempt === 0) {
          // The server lost the continuation: send everything once.
          continuation.invalidate(poolKey);
          plan = { mode: 'full', input: translated.input, previousResponseId: null };
          continue;
        }
        break;
      }
      socket.busy = false;
      if (result && result.status === 200) {
        if (turn.responseId) continuation.commit(poolKey, { translated, responseId: turn.responseId, outputItems: turn.outputItems });
        else continuation.invalidate(poolKey);
        armIdle(poolKey);
        finishTurn(200);
        return;
      }
      if (result && result.sent) {
        // The client already got an error event (or disconnected): the socket
        // state is unknown, start over next time.
        dropSocket(poolKey);
        finishTurn(result.status);
        return;
      }
      if (result && result.beforeStart) {
        continuation.invalidate(poolKey);
        armIdle(poolKey);
        failJson(result);
        return;
      }
      if (result) {
        dropSocket(poolKey);
        failJson(result);
        return;
      }
      // send failed before anything happened: fall through to HTTP
    } else if (sockets.has(poolKey)) {
      // busy socket: this request goes over HTTP, which desyncs the continuation
      continuation.invalidate(poolKey);
    }
  } else if (poolKey) {
    continuation.invalidate(poolKey);
  }

  // ---- HTTP transport ----
  note = `${note} http`;
  const transport = up.url.protocol === 'https:' ? https : http;
  const upstreamBody = Buffer.from(JSON.stringify(translated), 'utf8');
  const attempt = ({ access, accountId }) =>
    new Promise((resolve, reject) => {
      const headers = codexRequestHeaders({ access, accountId, sessionId });
      headers.host = up.url.host;
      headers['content-length'] = String(upstreamBody.length);
      const r = transport.request(
        {
          protocol: up.url.protocol,
          hostname: up.url.hostname,
          port: up.url.port || (up.url.protocol === 'https:' ? 443 : 80),
          method: 'POST',
          path: upstreamPath,
          headers,
          timeout: timeoutMs,
        },
        resolve,
      );
      r.on('timeout', () => r.destroy(new Error('upstream timeout')));
      r.on('error', reject);
      r.end(upstreamBody);
    });

  let upstreamRes;
  try {
    upstreamRes = await attempt(creds);
    if ((upstreamRes.statusCode ?? 0) === 401) {
      // Expired/revoked access token: refresh once and replay.
      upstreamRes.resume();
      let next = null;
      try {
        next = await codex.refresh();
      } catch {
        next = null;
      }
      if (!next) {
        sendJson(502, { error: { type: 'no_codex_oauth', message: 'ChatGPT token refresh failed - log in again from the dashboard' } });
        return;
      }
      upstreamRes = await attempt(next);
      if ((upstreamRes.statusCode ?? 0) === 401) {
        upstreamRes.resume();
        sendJson(502, { error: { type: 'no_codex_oauth', message: 'the Codex backend rejected the refreshed token - log in again from the dashboard' } });
        return;
      }
    }
  } catch (err) {
    sendJson(502, { error: { type: 'upstream_error', message: `codex upstream request failed: ${err.message}` } });
    return;
  }

  const status = upstreamRes.statusCode ?? 0;
  reportLimits(parseCodexLimits(upstreamRes.headers));
  if (status !== 200) {
    const text = await readCapped(upstreamRes, CODEX_MAX_ERROR_BODY_BYTES);
    stats.rememberResp(entry?.id, text);
    const detail = errorDetail(text);
    if (status === 429) {
      // The plan's usage limit: let the client show its own rate-limit UI.
      res.writeHead(429, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: detail || 'rate limited by the Codex backend' } }));
      finish(429);
      return;
    }
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'upstream_error', message: `codex upstream rejected the request (HTTP ${status})${detail ? `: ${detail}` : ''}` } }));
    finish(502);
    return;
  }

  // 200: a Responses SSE stream (the backend sends no content-type - do not
  // depend on it). Translate as it arrives.
  const result = await deliver({
    source: httpSource(upstreamRes, { onRaw, cap: clientStream ? null : CODEX_MAX_BUFFERED_RESPONSE_BYTES }),
    res,
    clientStream,
    reducer: newReducer(),
    onEvent,
  });
  if (result.sent) finishTurn(result.status);
  else failJson(result);
}
