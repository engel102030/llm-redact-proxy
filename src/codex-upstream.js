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

  const translate = () => anthropicToCodex(JSON.parse(bodyText), { models, effortMap: profile.effortMap ?? undefined });

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
    translated = anthropicToCodex(parsed, { models, effortMap: profile.effortMap ?? undefined });
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
  const reducer = new CodexReducer({ messageId, model: parsed.model, inputEstimate: estimateTokens(translated) });
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
