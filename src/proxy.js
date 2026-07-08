// The proxy server. Buffers the REQUEST (you cannot redact a stream you have
// not seen), redacts it, then forwards to the upstream. The RESPONSE is piped
// back unbuffered so SSE streams flow chunk by chunk.
//
// FAIL CLOSED: any error between reading the body and finishing redaction
// blocks the request with a local 502. Forwarding on error is a leak.
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import { injectNotice } from './inject.js';
import { handleDashboard } from './dashboard.js';
import { readClaudeOAuth, isAnthropicHost, applyOAuthHeaders } from './claude-auth.js';

const MAX_BODY_BYTES = 64 * 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 10 * 60 * 1000; // generous: SSE streams run long

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function readBody(req, limit = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('request body exceeds size limit'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function decompress(buffer, encoding) {
  if (!encoding) return buffer;
  const enc = String(encoding).trim().toLowerCase();
  if (enc === '' || enc === 'identity') return buffer;
  if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(buffer);
  if (enc === 'deflate') {
    try {
      return zlib.inflateSync(buffer);
    } catch {
      return zlib.inflateRawSync(buffer);
    }
  }
  if (enc === 'br') return zlib.brotliDecompressSync(buffer);
  // Unknown encoding means we cannot see the plaintext to redact it.
  throw new Error(`unsupported content-encoding: ${enc}`);
}

function blockRequest(res, reason) {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.writeHead(502, { 'content-type': 'application/json' });
  res.end(
    JSON.stringify({
      error: {
        type: 'redaction_blocked',
        message: `request blocked by llm-redact-proxy (fail-closed): ${reason}`,
      },
    }),
  );
}

// A proxied host can't learn the upstream context window from /v1/models, so
// the proxy tags every model id with the "[1m]" suffix (which Claude Code reads
// to use a 1M local window) EXCEPT models that don't support 1M: Haiku (any),
// and Sonnet below 5 (sonnet-4.x). The display name is left clean ("Claude Opus
// 4.8", not "... [1m]") and no models are dropped or duplicated.
const NO_ONE_M = /haiku|sonnet-4/i;

function tagOneMIds(list) {
  if (!list || !Array.isArray(list.data)) return list;
  list.data = list.data.map((m) => {
    if (m && typeof m.id === 'string' && !NO_ONE_M.test(m.id) && !m.id.endsWith('[1m]')) {
      return { ...m, id: `${m.id}[1m]` }; // clean display_name kept as-is
    }
    return m;
  });
  return list;
}

export function createProxyServer({ config, redactor, stats, getUpstream, controller, getOAuth }) {
  const oauthOf = getOAuth ?? (() => readClaudeOAuth());
  // Upstream is resolved per request so the dashboard can switch providers
  // live. Falls back to the frozen config when no getter is supplied (the
  // standalone/back-compat path used by tests).
  const upstreamOf =
    getUpstream ??
    (() => ({ url: config.upstreamUrl, auth: config.upstreamAuth, key: config.upstreamKey }));

  return http.createServer(async (req, res) => {
    if ((req.url ?? '').startsWith('/__redact')) {
      const up = upstreamOf();
      handleDashboard(
        req,
        res,
        stats,
        {
          upstream: up.url?.href ?? null,
          mode: controller?.mode ?? config.redactMode ?? null,
          failClosed: config.failClosed,
        },
        controller,
      );
      return;
    }

    // Liveness probe: hosts check the base URL with HEAD/GET /. Answer locally
    // instead of forwarding to a vendor root that 404s.
    if ((req.method === 'GET' || req.method === 'HEAD') && (req.url === '/' || req.url === '')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(req.method === 'HEAD' ? undefined : JSON.stringify({ status: 'ok', service: 'llm-redact-proxy' }));
      return;
    }

    const up = upstreamOf();
    if (!up.url) {
      req.resume(); // drain the body
      res.writeHead(503, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          error: {
            type: 'no_upstream',
            message:
              'No provider configured. Open the dashboard at /__redact/ and set a provider URL.',
          },
        }),
      );
      return;
    }
    const transport = up.url.protocol === 'https:' ? https : http;
    const upstreamBasePath = up.url.pathname.replace(/\/$/, '');

    let rawBuffer;
    try {
      rawBuffer = await readBody(req);
    } catch (err) {
      stats.record({ method: req.method, path: req.url, blocked: true, reason: err.message });
      blockRequest(res, `failed reading request body: ${err.message}`);
      return;
    }

    const t0 = Date.now();
    const reqBytes = rawBuffer.length;
    let entry = null;
    let outBody = null;
    let keepContentEncoding = false;
    if (rawBuffer.length > 0) {
      try {
        const decompressed = decompress(rawBuffer, req.headers['content-encoding']);
        const text = decompressed.toString('utf8');
        const { body, events } = redactor.redactBody(text, req.headers['content-type'] ?? '');

        let finalBody = body;
        if (events.length > 0 && config.injectNotice) {
          try {
            const parsed = JSON.parse(finalBody);
            const names = events.map((e) => e.rule);
            if (injectNotice(parsed, names, { pathHint: req.url ?? '' })) {
              finalBody = JSON.stringify(parsed);
            }
          } catch {
            // Non-JSON body: the markers alone carry the signal.
          }
        }
        entry = stats.record({ method: req.method, path: req.url, events, reqBytes });
        outBody = Buffer.from(finalBody, 'utf8');
      } catch (err) {
        if (config.failClosed) {
          stats.record({ method: req.method, path: req.url, blocked: true, reason: err.message, reqBytes });
          blockRequest(res, err.message);
          return;
        }
        console.warn(
          `[redact] WARNING: redaction failed (${err.message}) and FAIL_CLOSED=false - ` +
            'forwarding the RAW body. This can leak secrets.',
        );
        entry = stats.record({ method: req.method, path: req.url, events: [], reqBytes });
        outBody = rawBuffer;
        keepContentEncoding = true;
      }
    } else {
      entry = stats.record({ method: req.method, path: req.url, events: [], reqBytes });
    }

    const headers = {};
    for (const [key, value] of Object.entries(req.headers)) {
      const k = key.toLowerCase();
      if (HOP_BY_HOP.has(k)) continue;
      if (k === 'host' || k === 'content-length' || k === 'expect') continue;
      if (k === 'content-encoding' && !keepContentEncoding) continue;
      headers[k] = value;
    }
    if (up.auth === 'replace') {
      const hadAuthorization = 'authorization' in headers;
      const hadApiKey = 'x-api-key' in headers;
      delete headers.authorization;
      delete headers['x-api-key'];
      if (hadAuthorization) headers.authorization = `Bearer ${up.key}`;
      if (hadApiKey || !hadAuthorization) headers['x-api-key'] = up.key;
    } else if (up.auth === 'oauth') {
      // Use the user's Claude subscription. Defence in depth: never send the
      // token anywhere but the official Anthropic API.
      if (!isAnthropicHost(up.url)) {
        req.resume();
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { type: 'oauth_misconfig', message: 'oauth auth is only allowed with an *.anthropic.com provider' } }));
        stats.finish(entry, { status: 400, durationMs: Date.now() - t0 });
        return;
      }
      const cred = oauthOf();
      if (!cred || !cred.accessToken) {
        req.resume();
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { type: 'no_oauth', message: 'no Claude subscription credential found - log in with the Claude CLI first' } }));
        stats.finish(entry, { status: 502, durationMs: Date.now() - t0 });
        return;
      }
      // Only the auth token is swapped. The body is passed through UNCHANGED
      // so a genuine Claude Code request stays byte-identical to what the CLI
      // would send natively - premium models are unlocked by the request's own
      // billing-header system block + metadata, which we must never alter.
      applyOAuthHeaders(headers, cred.accessToken);
    }
    headers.host = up.url.host;
    if (outBody) headers['content-length'] = String(outBody.length);

    // Models discovery is rewritten (buffered) to expose [1m] variants; every
    // other path streams through untouched.
    const isModelsList = req.method === 'GET' && /^\/v1\/models\b/.test((req.url ?? '').split('?')[0]);

    const upstreamReq = transport.request(
      {
        protocol: up.url.protocol,
        hostname: up.url.hostname,
        port: up.url.port || (up.url.protocol === 'https:' ? 443 : 80),
        method: req.method,
        path: `${upstreamBasePath}${req.url ?? '/'}`,
        headers,
        timeout: UPSTREAM_TIMEOUT_MS,
      },
      (upstreamRes) => {
        const responseHeaders = {};
        for (const [key, value] of Object.entries(upstreamRes.headers)) {
          if (HOP_BY_HOP.has(key.toLowerCase())) continue;
          responseHeaders[key] = value;
        }

        if (isModelsList) {
          // Buffer, decompress, add the [1m] variants, send uncompressed.
          const respEnc = String(upstreamRes.headers['content-encoding'] ?? '').toLowerCase();
          let src = upstreamRes;
          try {
            if (respEnc === 'gzip' || respEnc === 'x-gzip') src = upstreamRes.pipe(zlib.createGunzip());
            else if (respEnc === 'br') src = upstreamRes.pipe(zlib.createBrotliDecompress());
            else if (respEnc === 'deflate') src = upstreamRes.pipe(zlib.createInflate());
            else if (respEnc === 'zstd' && typeof zlib.createZstdDecompress === 'function') {
              src = upstreamRes.pipe(zlib.createZstdDecompress());
            }
          } catch {
            src = upstreamRes;
          }
          const chunks = [];
          let rawBytes = 0;
          upstreamRes.on('data', (c) => {
            rawBytes += c.length;
          });
          src.on('data', (c) => chunks.push(c));
          const sendModels = (status) => {
            let outBuf;
            try {
              const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              outBuf = Buffer.from(JSON.stringify(tagOneMIds(parsed)), 'utf8');
            } catch {
              outBuf = Buffer.concat(chunks);
            }
            const h = { ...responseHeaders };
            delete h['content-encoding'];
            delete h['content-length'];
            h['content-length'] = String(outBuf.length);
            res.writeHead(status, h);
            res.end(outBuf);
            stats.finish(entry, { status, durationMs: Date.now() - t0, respBytes: rawBytes });
          };
          src.on('end', () => sendModels(upstreamRes.statusCode ?? 200));
          src.on('error', () => {
            if (!res.headersSent) {
              res.writeHead(502, { 'content-type': 'application/json' });
              res.end(JSON.stringify({ error: { type: 'models_rewrite_failed' } }));
            }
            stats.finish(entry, { status: 502, durationMs: Date.now() - t0, respBytes: rawBytes });
          });
          return;
        }

        res.writeHead(upstreamRes.statusCode ?? 502, responseHeaders);

        // Tap the response ONLY to read token-usage numbers and byte count for
        // the dashboard - the body is never stored or logged. A small carry
        // handles a usage number split across chunk boundaries. Adding a data
        // listener alongside pipe() keeps the stream unbuffered.
        let respBytes = 0;
        let inTok = null;
        let outTok = null;
        let carry = '';
        const scan = (s) => {
          const textChunk = carry + s;
          for (const m of textChunk.matchAll(/"input_tokens":\s*(\d+)/g)) {
            const v = Number(m[1]);
            if (inTok === null || v > inTok) inTok = v;
          }
          for (const m of textChunk.matchAll(/"output_tokens":\s*(\d+)/g)) {
            const v = Number(m[1]);
            if (outTok === null || v > outTok) outTok = v;
          }
          carry = textChunk.slice(-64);
        };
        let finished = false;
        const finishStats = () => {
          if (finished) return;
          finished = true;
          stats.finish(entry, {
            status: upstreamRes.statusCode ?? null,
            durationMs: Date.now() - t0,
            inputTokens: inTok,
            outputTokens: outTok,
            respBytes,
          });
        };
        // Token usage lives in the (often compressed) response body. Decompress
        // a COPY of the stream only to read the numbers - the client still
        // receives the original bytes untouched via pipe().
        const respEnc = String(upstreamRes.headers['content-encoding'] ?? '').toLowerCase();
        let sniff = null;
        if (respEnc === 'gzip' || respEnc === 'x-gzip') sniff = zlib.createGunzip();
        else if (respEnc === 'deflate') sniff = zlib.createInflate();
        else if (respEnc === 'br') sniff = zlib.createBrotliDecompress();
        else if (respEnc === 'zstd' && typeof zlib.createZstdDecompress === 'function') {
          sniff = zlib.createZstdDecompress();
        }
        if (sniff) {
          sniff.on('data', (d) => scan(d.toString('utf8')));
          sniff.on('end', finishStats);
          sniff.on('error', finishStats); // bad decode: finish with whatever we have
          upstreamRes.on('data', (chunk) => {
            respBytes += chunk.length;
            sniff.write(chunk);
          });
          upstreamRes.on('end', () => sniff.end());
        } else {
          upstreamRes.on('data', (chunk) => {
            respBytes += chunk.length;
            scan(chunk.toString('utf8'));
          });
          upstreamRes.on('end', finishStats);
        }
        // Unbuffered passthrough: SSE chunks stream straight back.
        upstreamRes.pipe(res);
      },
    );

    upstreamReq.on('timeout', () => upstreamReq.destroy(new Error('upstream timeout')));
    upstreamReq.on('error', (err) => {
      stats.finish(entry, { status: 502, durationMs: Date.now() - t0 });
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          error: { type: 'upstream_error', message: `upstream request failed: ${err.message}` },
        }),
      );
    });

    if (outBody) upstreamReq.end(outBody);
    else upstreamReq.end();
  });
}
