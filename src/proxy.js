// The proxy server. Buffers the REQUEST (you cannot redact a stream you have
// not seen), redacts it, then forwards to the upstream. The RESPONSE is piped
// back unbuffered so SSE streams flow chunk by chunk.
//
// FAIL CLOSED: any error between reading the body and finishing redaction
// blocks the request with a local 502. Forwarding on error is a leak.
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import { StringDecoder } from 'node:string_decoder';
import { injectNotice } from './inject.js';
import { handleDashboard } from './dashboard.js';
import { readClaudeOAuth, isAnthropicHost, applyOAuthHeaders } from './claude-auth.js';
import { buildModelsResponse } from './models.js';
import { createSseRehydrator, rehydrateJsonBody } from './rehydrate.js';

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

export function createProxyServer({ config, redactor, stats, getUpstream, controller, getOAuth, getRestore }) {
  const oauthOf = getOAuth ?? (() => readClaudeOAuth());
  // Response rehydration state, resolved per request so the dashboard toggle
  // takes effect live. Default off (no getter) - back-compat for tests.
  const restoreOf = getRestore ?? (() => ({ enabled: false, map: new Map() }));
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
        // Capture matched values only when the panel opted in to reveal them.
        const captureValues = controller?.showRedactedValues ?? false;
        const { body, events, captures } = redactor.redactBody(
          text,
          req.headers['content-type'] ?? '',
          { captureValues },
        );

        let finalBody = body;
        if (events.length > 0 && config.injectNotice) {
          try {
            const parsed = JSON.parse(finalBody);
            const names = events.map((e) => e.rule);
            if (injectNotice(parsed, names, { pathHint: req.url ?? '', restore: restoreOf().enabled })) {
              finalBody = JSON.stringify(parsed);
            }
          } catch {
            // Non-JSON body: the markers alone carry the signal.
          }
        }
        entry = stats.record({ method: req.method, path: req.url, events, captures, reqBytes });
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
      // Drop whatever credential the client sent and inject OUR key. Anthropic-
      // compatible gateways disagree on which header carries the key: the native
      // Anthropic scheme is x-api-key, but some gateways only read Authorization:
      // Bearer. ALWAYS set x-api-key (the default the majority validate); a host
      // like Overclock sends only Authorization, and mirroring that alone left
      // x-api-key unset - a gateway that checks x-api-key then saw no key (401).
      // Additionally set the Bearer form when the client used it, so Bearer-only
      // gateways still authenticate. A gateway that reads x-api-key ignores the
      // extra Bearer (verified against a live x-api-key-only gateway).
      const hadAuthorization = 'authorization' in headers;
      delete headers.authorization;
      delete headers['x-api-key'];
      headers['x-api-key'] = up.key;
      if (hadAuthorization) headers.authorization = `Bearer ${up.key}`;
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
          const sendModels = (upstreamStatus) => {
            // Tag the gateway's list, or synthesize the canonical one when the
            // gateway does not serve /v1/models (error / non-list) - the host
            // must still get a usable model picker. Always a 200.
            const rawBody = Buffer.concat(chunks).toString('utf8');
            const { status, body } = buildModelsResponse(upstreamStatus, rawBody);
            const outBuf = Buffer.from(JSON.stringify(body), 'utf8');
            const h = { ...responseHeaders };
            delete h['content-encoding'];
            delete h['content-length'];
            h['content-type'] = 'application/json';
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

        // Shared counters: token usage + byte count for the dashboard. A small
        // carry handles a usage number split across chunk boundaries. The body
        // is never stored or logged.
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

        const respEnc = String(upstreamRes.headers['content-encoding'] ?? '').toLowerCase();
        const makeDecompressor = () => {
          if (respEnc === 'gzip' || respEnc === 'x-gzip') return zlib.createGunzip();
          if (respEnc === 'deflate') return zlib.createInflate();
          if (respEnc === 'br') return zlib.createBrotliDecompress();
          if (respEnc === 'zstd' && typeof zlib.createZstdDecompress === 'function') return zlib.createZstdDecompress();
          return null;
        };

        const respCt = String(upstreamRes.headers['content-type'] ?? '').toLowerCase();
        const restore = restoreOf();
        const doRestore =
          restore.enabled &&
          (upstreamRes.statusCode ?? 0) === 200 &&
          (respCt.includes('event-stream') || respCt.includes('json'));

        if (doRestore) {
          // INVERSE of redaction: substitute {{NAME}} back to the real value on
          // the way to the CLI, so a command the model emits runs locally with the
          // true credential (the vendor only ever saw the redacted request). The
          // body must be decoded, transformed, and sent uncompressed (its length
          // changes) - drop the encoding/length headers. SSE stays streamed.
          const h = { ...responseHeaders };
          delete h['content-encoding'];
          delete h['content-length'];
          res.writeHead(upstreamRes.statusCode ?? 502, h);

          const decoder = new StringDecoder('utf8');
          const isSse = respCt.includes('event-stream');
          const sse = isSse ? createSseRehydrator(restore.map) : null;
          let jsonBuf = '';
          let ended = false;
          const endRes = () => {
            if (ended) return;
            ended = true;
            res.end();
            finishStats();
          };
          const onText = (text) => {
            if (!text) return;
            scan(text);
            if (isSse) {
              const out = sse.push(text);
              if (out) res.write(out);
            } else {
              jsonBuf += text; // small non-stream body: buffer, rehydrate whole
            }
          };
          const onEnd = () => {
            if (ended) return;
            if (isSse) {
              const tail = sse.flush();
              if (tail) res.write(tail);
            } else {
              res.write(rehydrateJsonBody(jsonBuf, restore.map));
            }
            endRes();
          };

          const dec = makeDecompressor();
          if (dec) {
            dec.on('data', (d) => onText(decoder.write(d)));
            dec.on('end', () => {
              onText(decoder.end());
              onEnd();
            });
            dec.on('error', endRes); // bad decode: end with whatever we have
            upstreamRes.on('data', (chunk) => {
              respBytes += chunk.length;
              dec.write(chunk);
            });
            upstreamRes.on('end', () => dec.end());
            upstreamRes.on('error', endRes);
          } else {
            upstreamRes.on('data', (chunk) => {
              respBytes += chunk.length;
              onText(decoder.write(chunk));
            });
            upstreamRes.on('end', () => {
              onText(decoder.end());
              onEnd();
            });
            upstreamRes.on('error', endRes);
          }
          return;
        }

        // Passthrough (rehydration off): forward original bytes; tap a
        // decompressed COPY only to read the token numbers.
        res.writeHead(upstreamRes.statusCode ?? 502, responseHeaders);
        const sniff = makeDecompressor();
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
