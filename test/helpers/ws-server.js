// Minimal RFC 6455 WebSocket SERVER for tests (the proxy only needs a client;
// this helper is the counterpart). Accepts the upgrade on a plain http server,
// parses masked client frames (text, ping, close; fragmentation of client
// frames is not needed) and sends unmasked server frames.
import http from 'node:http';
import { createHash } from 'node:crypto';

const GUID = '258EAFA5-E914-47DA-95CA-5AB5DC5AB11';

export function acceptKey(key) {
  return createHash('sha1').update(key + GUID).digest('base64');
}

// Build one server->client frame (unmasked). opcode 1 = text, 8 = close, 10 = pong.
export function serverFrame(payload, { opcode = 1, fin = true } = {}) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  const b0 = (fin ? 0x80 : 0) | opcode;
  let header;
  if (data.length < 126) header = Buffer.from([b0, data.length]);
  else if (data.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = b0; header[1] = 126; header.writeUInt16BE(data.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = b0; header[1] = 127; header.writeBigUInt64BE(BigInt(data.length), 2);
  }
  return Buffer.concat([header, data]);
}

// Parse as many complete client frames as the buffer holds. Returns { frames, rest }.
export function parseClientFrames(buf) {
  const frames = [];
  let off = 0;
  for (;;) {
    if (buf.length - off < 2) break;
    const b0 = buf[off];
    const b1 = buf[off + 1];
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let p = off + 2;
    if (len === 126) { if (buf.length - p < 2) break; len = buf.readUInt16BE(p); p += 2; }
    else if (len === 127) { if (buf.length - p < 8) break; len = Number(buf.readBigUInt64BE(p)); p += 8; }
    let mask = null;
    if (masked) { if (buf.length - p < 4) break; mask = buf.subarray(p, p + 4); p += 4; }
    if (buf.length - p < len) break;
    const payload = Buffer.from(buf.subarray(p, p + len));
    if (mask) for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
    frames.push({ fin, opcode, masked, payload });
    off = p + len;
  }
  return { frames, rest: buf.subarray(off) };
}

// Starts a WS server. `onConnection(conn, upgradeReq)` gets { send(text), sendFrame(buf), close(code), socket }
// and conn emits nothing: instead pass `onMessage(conn, text)`. Client frames are
// delivered as { opcode, payload } to onFrame when given.
export function startWsServer({ onConnection, onMessage, onFrame, path = '/backend-api/codex/responses', reject = null } = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    res.writeHead(426, { 'content-type': 'text/plain' });
    res.end('upgrade required');
  });
  server.on('upgrade', (req, socket, head) => {
    requests.push({ url: req.url, headers: { ...req.headers } });
    if (reject) {
      socket.end(`HTTP/1.1 ${reject.status} ${reject.text ?? 'Nope'}\r\ncontent-type: text/plain\r\ncontent-length: ${Buffer.byteLength(reject.body ?? '')}\r\n\r\n${reject.body ?? ''}`);
      return;
    }
    if (req.url !== path || (req.headers.upgrade ?? '').toLowerCase() !== 'websocket') {
      socket.end('HTTP/1.1 404 Not Found\r\n\r\n');
      return;
    }
    const key = req.headers['sec-websocket-key'];
    const accept = reject === null && typeof key === 'string' ? acceptKey(key) : 'bad';
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    let buf = head.length ? Buffer.from(head) : Buffer.alloc(0);
    let closed = false;
    const conn = {
      socket,
      send: (text) => socket.write(serverFrame(text)),
      sendFrame: (frame) => socket.write(frame),
      close: (code = 1000) => {
        if (closed) return;
        closed = true;
        const p = Buffer.alloc(2);
        p.writeUInt16BE(code, 0);
        socket.write(serverFrame(p, { opcode: 8 }));
        setTimeout(() => socket.end(), 20);
      },
    };
    onConnection?.(conn, req);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const { frames, rest } = parseClientFrames(buf);
      buf = Buffer.from(rest);
      for (const f of frames) {
        onFrame?.(conn, f);
        if (f.opcode === 1) onMessage?.(conn, f.payload.toString('utf8'));
        else if (f.opcode === 9) socket.write(serverFrame(f.payload, { opcode: 10 }));
        else if (f.opcode === 8) {
          if (!closed) { closed = true; socket.write(serverFrame(f.payload, { opcode: 8 })); }
          setTimeout(() => socket.end(), 10);
        }
      }
    });
    socket.on('error', () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ port, url: `ws://127.0.0.1:${port}${path}`, requests, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) });
    });
  });
}
