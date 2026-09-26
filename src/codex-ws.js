// Zero-dependency WebSocket client (RFC 6455) for the Codex backend's
// responses_websockets transport. Text frames only (JSON events), masked
// client frames, ping/pong, close handshake, fragmented server messages.
// Nothing here knows about tokens: the caller passes the auth headers.
import net from 'node:net';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
export const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;

function encodeFrame(opcode, payload) {
  const mask = randomBytes(4);
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x80 | opcode, 0x80 | payload.length]);
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  const masked = Buffer.allocUnsafe(payload.length);
  for (let i = 0; i < payload.length; i += 1) masked[i] = payload[i] ^ mask[i & 3];
  return Buffer.concat([header, mask, masked]);
}

class WsClient extends EventEmitter {
  #buf = Buffer.alloc(0);
  #fragment = null; // { opcode, parts }
  #closing = false;
  #closeCode = null;
  #closeTimer = null;

  constructor(socket, initial, headers) {
    super();
    this.socket = socket;
    this.headers = headers;
    this.open = true;
    socket.on('data', (chunk) => this.#onData(chunk));
    socket.on('close', () => this.#onSocketClose());
    socket.on('error', (err) => {
      this.lastError = err;
      if (this.listenerCount('error') > 0) this.emit('error', err);
    });
    if (initial.length) this.#onData(initial);
  }

  send(text) {
    if (!this.open) throw new Error('websocket is closed');
    this.socket.write(encodeFrame(1, Buffer.from(String(text), 'utf8')));
  }

  close(code = 1000) {
    if (!this.open || this.#closing) return;
    this.#closing = true;
    const payload = Buffer.alloc(2);
    payload.writeUInt16BE(code, 0);
    this.socket.write(encodeFrame(8, payload));
    this.#closeTimer = setTimeout(() => this.socket.destroy(), 1000);
    if (typeof this.#closeTimer.unref === 'function') this.#closeTimer.unref();
  }

  #onSocketClose() {
    if (!this.open) return;
    this.open = false;
    if (this.#closeTimer) clearTimeout(this.#closeTimer);
    this.emit('close', { code: this.#closeCode ?? 1006 });
  }

  #onData(chunk) {
    this.#buf = this.#buf.length ? Buffer.concat([this.#buf, chunk]) : chunk;
    for (;;) {
      const buf = this.#buf;
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let p = 2;
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        p = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        len = Number(buf.readBigUInt64BE(2));
        p = 10;
      }
      if (len > MAX_MESSAGE_BYTES) {
        this.socket.destroy(new Error('websocket frame exceeds the size limit'));
        return;
      }
      let mask = null;
      if (masked) {
        if (buf.length < p + 4) return;
        mask = buf.subarray(p, p + 4);
        p += 4;
      }
      if (buf.length < p + len) return;
      let payload = buf.subarray(p, p + len);
      if (mask) {
        const copy = Buffer.from(payload);
        for (let i = 0; i < copy.length; i += 1) copy[i] ^= mask[i & 3];
        payload = copy;
      }
      this.#buf = buf.subarray(p + len);
      this.#onFrame(fin, opcode, payload);
    }
  }

  #onFrame(fin, opcode, payload) {
    switch (opcode) {
      case 0x0: // continuation
        if (!this.#fragment) return;
        this.#fragment.parts.push(Buffer.from(payload));
        if (fin) this.#deliver();
        return;
      case 0x1:
      case 0x2:
        if (fin) {
          this.emit('message', payload.toString('utf8'));
        } else {
          this.#fragment = { opcode, parts: [Buffer.from(payload)] };
        }
        return;
      case 0x8: {
        this.#closeCode = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
        if (!this.#closing) {
          this.#closing = true;
          try {
            this.socket.write(encodeFrame(8, payload.subarray(0, 2)));
          } catch {
            // socket already gone
          }
        }
        this.socket.end();
        return;
      }
      case 0x9: // ping -> pong with the same payload
        if (this.open) this.socket.write(encodeFrame(0xa, Buffer.from(payload)));
        return;
      default: // pong and unknown opcodes
        return;
    }
  }

  #deliver() {
    const text = Buffer.concat(this.#fragment.parts).toString('utf8');
    this.#fragment = null;
    this.emit('message', text);
  }
}

// Opens a WebSocket. Resolves with the client once the 101 handshake is
// verified (Sec-WebSocket-Accept); rejects with { status, body } on any
// other HTTP answer so the caller can fall back to plain HTTP.
export function connectWebSocket(url, { headers = {}, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(url);
    } catch (err) {
      reject(err);
      return;
    }
    const secure = u.protocol === 'wss:' || u.protocol === 'https:';
    if (!secure && u.protocol !== 'ws:' && u.protocol !== 'http:') {
      reject(new Error(`unsupported websocket url scheme: ${u.protocol}`));
      return;
    }
    const port = Number(u.port) || (secure ? 443 : 80);
    const key = randomBytes(16).toString('base64');
    const expectAccept = createHash('sha1').update(key + GUID).digest('base64');
    const socket = secure ? tls.connect({ host: u.hostname, port, servername: u.hostname }) : net.connect({ host: u.hostname, port });
    let settled = false;
    let buf = Buffer.alloc(0);
    let pending = null; // a refused upgrade waiting for its body
    const timer = setTimeout(() => fail(new Error('websocket handshake timeout')), timeoutMs);
    function fail(err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    }
    function refuse() {
      const err = new Error(`websocket upgrade refused (HTTP ${pending.status})`);
      err.status = pending.status;
      err.body = pending.body.toString('utf8');
      err.headers = pending.headers;
      fail(err);
    }
    socket.once('error', (err) => fail(err));
    socket.once('end', () => {
      if (pending) refuse();
      else fail(new Error('websocket closed during handshake'));
    });
    socket.once(secure ? 'secureConnect' : 'connect', () => {
      const lines = [
        `GET ${u.pathname}${u.search} HTTP/1.1`,
        `Host: ${u.host}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Key: ${key}`,
        'Sec-WebSocket-Version: 13',
      ];
      for (const [k, v] of Object.entries(headers)) {
        if (v !== undefined && v !== null && v !== '') lines.push(`${k}: ${v}`);
      }
      socket.write(`${lines.join('\r\n')}\r\n\r\n`);
    });
    const onData = (chunk) => {
      if (settled) return;
      buf = Buffer.concat([buf, chunk]);
      if (pending) {
        pending.body = Buffer.concat([pending.body, chunk]);
        if (pending.body.length >= pending.length) refuse();
        return;
      }
      const idx = buf.indexOf('\r\n\r\n');
      if (idx < 0) {
        if (buf.length > 64 * 1024) fail(new Error('websocket handshake response too large'));
        return;
      }
      const head = buf.subarray(0, idx).toString('latin1');
      const rest = buf.subarray(idx + 4);
      const [statusLine, ...headerLines] = head.split('\r\n');
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine);
      const status = m ? Number(m[1]) : 0;
      const hdrs = {};
      for (const line of headerLines) {
        const i = line.indexOf(':');
        if (i > 0) hdrs[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      if (status !== 101) {
        const length = Number(hdrs['content-length'] ?? 0);
        pending = { status, headers: hdrs, length, body: Buffer.from(rest) };
        if (rest.length >= length) refuse();
        return;
      }
      if (hdrs['sec-websocket-accept'] !== expectAccept) {
        fail(new Error('websocket upgrade has an invalid Sec-WebSocket-Accept'));
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.removeListener('data', onData);
      resolve(new WsClient(socket, Buffer.from(rest), hdrs));
    };
    socket.on('data', onData);
  });
}
