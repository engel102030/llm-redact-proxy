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

export function createProxyServer({ config, redactor, stats }) {
  const transport = config.upstreamUrl.protocol === 'https:' ? https : http;
  const upstreamBasePath = config.upstreamUrl.pathname.replace(/\/$/, '');

  return http.createServer(async (req, res) => {
    if ((req.url ?? '').startsWith('/__redact')) {
      handleDashboard(req, res, stats);
      return;
    }

    let rawBuffer;
    try {
      rawBuffer = await readBody(req);
    } catch (err) {
      stats.record({ method: req.method, path: req.url, blocked: true, reason: err.message });
      blockRequest(res, `failed reading request body: ${err.message}`);
      return;
    }

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
        stats.record({ method: req.method, path: req.url, events });
        outBody = Buffer.from(finalBody, 'utf8');
      } catch (err) {
        if (config.failClosed) {
          stats.record({ method: req.method, path: req.url, blocked: true, reason: err.message });
          blockRequest(res, err.message);
          return;
        }
        console.warn(
          `[redact] WARNING: redaction failed (${err.message}) and FAIL_CLOSED=false - ` +
            'forwarding the RAW body. This can leak secrets.',
        );
        stats.record({ method: req.method, path: req.url, events: [] });
        outBody = rawBuffer;
        keepContentEncoding = true;
      }
    } else {
      stats.record({ method: req.method, path: req.url, events: [] });
    }

    const headers = {};
    for (const [key, value] of Object.entries(req.headers)) {
      const k = key.toLowerCase();
      if (HOP_BY_HOP.has(k)) continue;
      if (k === 'host' || k === 'content-length' || k === 'expect') continue;
      if (k === 'content-encoding' && !keepContentEncoding) continue;
      headers[k] = value;
    }
    if (config.upstreamAuth === 'replace') {
      const hadAuthorization = 'authorization' in headers;
      const hadApiKey = 'x-api-key' in headers;
      delete headers.authorization;
      delete headers['x-api-key'];
      if (hadAuthorization) headers.authorization = `Bearer ${config.upstreamKey}`;
      if (hadApiKey || !hadAuthorization) headers['x-api-key'] = config.upstreamKey;
    }
    headers.host = config.upstreamUrl.host;
    if (outBody) headers['content-length'] = String(outBody.length);

    const upstreamReq = transport.request(
      {
        protocol: config.upstreamUrl.protocol,
        hostname: config.upstreamUrl.hostname,
        port: config.upstreamUrl.port || (config.upstreamUrl.protocol === 'https:' ? 443 : 80),
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
        res.writeHead(upstreamRes.statusCode ?? 502, responseHeaders);
        // Unbuffered passthrough: SSE chunks stream straight back.
        upstreamRes.pipe(res);
      },
    );

    upstreamReq.on('timeout', () => upstreamReq.destroy(new Error('upstream timeout')));
    upstreamReq.on('error', (err) => {
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
