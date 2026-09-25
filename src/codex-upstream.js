// Codex backend upstream (auth mode "codex-oauth"). The redacted Anthropic
// Messages body is translated to a Responses request, POSTed to
// <base>/responses with the stored ChatGPT token, and the Responses SSE is
// translated back to Anthropic SSE (or folded into one JSON message when the
// client did not ask for a stream). Redaction ALWAYS happened before this
// point; any translation failure blocks the request (fail closed). Model
// discovery and count_tokens are answered locally - no token leaves for them.
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

export const CODEX_MAX_BUFFERED_RESPONSE_BYTES = 8 * 1024 * 1024;
export const CODEX_MAX_ERROR_BODY_BYTES = 16 * 1024;

const MODEL_EPOCH = '1970-01-01T00:00:00Z';

// Start-of-stream input estimate. bytes/4 overshoots the tokenizer by a
// stable factor (~1.16 measured on real sessions), so the client's context
// meter would climb during streaming and fall back at the end. Scale by the
// real/estimate ratio observed on the previous turn of the same session
// (keyed by prompt_cache_key); a conservative default until then.
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

// UUID-v4-shaped id derived from the (sha256 hex) prompt_cache_key.
function sessionIdFor(cacheKey) {
  if (typeof cacheKey !== 'string' || !/^[0-9a-f]{32,}$/.test(cacheKey)) return randomUUID();
  const h = cacheKey;
  const variant = '89ab'[parseInt(h[16], 16) % 4];
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

// Plan usage the backend reports on every response (x-codex-* headers):
// primary = the plan's main window (7 days on ChatGPT plans), secondary = a
// shorter window when the plan has one. null when the headers are absent.
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
  const credits = str('x-codex-credits-has-credits') === null && str('x-codex-credits-balance') === null
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

// `codex` is the adapter from the runtime: { profile(), credentials(), refresh() }.
export async function handleCodexUpstream({ req, res, up, entry, stats, t0, bodyText, codex, aliases = {}, timeoutMs = 10 * 60 * 1000 }) {
  let note = null;
  const finish = (status, extra = {}) => stats.finish(entry, { status, durationMs: Date.now() - t0, note, ...extra });
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
  const upstreamBody = Buffer.from(JSON.stringify(translated), 'utf8');
  // Overwrite the inspector copy: THIS is what actually leaves the machine.
  stats.rememberReq(entry?.id, upstreamBody.toString('utf8'));

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

  const transport = up.url.protocol === 'https:' ? https : http;
  const basePath = up.url.pathname.replace(/\/$/, '');
  const upstreamPath = basePath.endsWith('/responses') ? basePath : `${basePath}/responses`;
  // One session id per Claude Code session (same source as prompt_cache_key),
  // as the Codex CLI does per conversation: the backend routes the prompt
  // cache by it. Random only when the client sent no metadata.user_id.
  const sessionId = sessionIdFor(translated.prompt_cache_key);
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
  const limits = parseCodexLimits(upstreamRes.headers);
  if (limits) {
    if (typeof codex.reportLimits === 'function') codex.reportLimits(limits);
    if (limits.primary) note = `${note} quota ${limits.primary.usedPercent}%`;
  }
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
  const messageId = `msg_${randomUUID().replace(/-/g, '')}`;
  const reducer = new CodexReducer({ messageId, model: parsed.model, inputEstimate: estimateInput(translated) });
  const decoder = new SseDecoder();
  const rawDec = new StringDecoder('utf8');
  let respAcc = '';
  let respBytes = 0;
  const usage = { input_tokens: null, output_tokens: null };
  const noteUsage = (events) => {
    for (const e of events) {
      if (e.event === 'message_delta') {
        // Dashboard counters show the TOTAL input (uncached + cached).
        const u = e.data.usage ?? {};
        usage.input_tokens = (u.input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0);
        usage.output_tokens = u.output_tokens ?? null;
        calibrate(translated, usage.input_tokens);
      }
    }
  };
  const finishStream = (code) => {
    stats.rememberResp(entry?.id, respAcc);
    finish(code, { inputTokens: usage.input_tokens, outputTokens: usage.output_tokens, respBytes });
  };

  if (clientStream) {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
    let ended = false;
    const end = (code) => {
      if (ended) return;
      ended = true;
      res.end();
      finishStream(code);
    };
    const abort = (message) => {
      if (ended) return;
      res.write(errorSse(message));
      upstreamRes.destroy();
      end(502);
    };
    res.on('close', () => {
      if (ended) return;
      ended = true;
      upstreamRes.destroy();
      finishStream(null);
    });
    upstreamRes.on('data', (chunk) => {
      respBytes += chunk.length;
      respAcc += rawDec.write(chunk);
      if (ended) return;
      try {
        for (const ev of decoder.push(chunk)) {
          const out = reducer.push(ev);
          noteUsage(out);
          if (out.length) res.write(serializeSse(out));
        }
      } catch (err) {
        abort(`codex stream translation failed: ${err.message}`);
      }
    });
    upstreamRes.on('end', () => {
      if (ended) return;
      try {
        for (const ev of decoder.flush()) {
          const out = reducer.push(ev);
          noteUsage(out);
          if (out.length) res.write(serializeSse(out));
        }
      } catch (err) {
        abort(`codex stream translation failed: ${err.message}`);
        return;
      }
      if (!reducer.done) {
        res.write(errorSse('codex upstream ended before response.completed'));
        end(502);
        return;
      }
      end(200);
    });
    upstreamRes.on('error', () => abort('codex upstream stream failed'));
    return;
  }

  // Non-streaming client: fold the whole translated stream into one message.
  const events = [];
  let failed = null;
  let concluded = false;
  upstreamRes.on('data', (chunk) => {
    respBytes += chunk.length;
    respAcc += rawDec.write(chunk);
    if (failed) return;
    if (respBytes > CODEX_MAX_BUFFERED_RESPONSE_BYTES) {
      failed = new Error('codex upstream response exceeds the size limit');
      upstreamRes.destroy();
      return;
    }
    try {
      for (const ev of decoder.push(chunk)) events.push(...reducer.push(ev));
    } catch (err) {
      failed = err;
      upstreamRes.destroy();
    }
  });
  const conclude = () => {
    if (concluded) return;
    concluded = true;
    if (!failed) {
      try {
        for (const ev of decoder.flush()) events.push(...reducer.push(ev));
        if (!reducer.done) failed = new Error('codex upstream ended before response.completed');
      } catch (err) {
        failed = err;
      }
    }
    let message = null;
    if (!failed) {
      try {
        message = accumulateMessage(events);
      } catch (err) {
        failed = err;
      }
    }
    if (failed) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'api_error', message: `codex response translation failed: ${failed.message}` } }));
      finishStream(502);
      return;
    }
    noteUsage(events);
    const buf = Buffer.from(JSON.stringify(message), 'utf8');
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(buf.length) });
    res.end(buf);
    finishStream(200);
  };
  upstreamRes.on('end', conclude);
  upstreamRes.on('close', conclude);
  upstreamRes.on('error', (err) => {
    failed = failed ?? err;
    conclude();
  });
}
