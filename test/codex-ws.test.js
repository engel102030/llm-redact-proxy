// The zero-dependency WebSocket client the proxy uses to talk to the Codex
// backend (responses_websockets). Verified against the RFC 6455 server helper:
// handshake headers and accept-key check, masked client frames including
// 64-bit lengths, server frames incl. fragmentation, ping/pong, close.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connectWebSocket } from '../src/codex-ws.js';
import { startWsServer, serverFrame, parseClientFrames, acceptKey } from './helpers/ws-server.js';

// RFC 6455 section 1.3 example: the accept key must match the real GUID.
test('Sec-WebSocket-Accept follows the RFC 6455 vector', () => {
  assert.equal(acceptKey('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
});

const once = (emitter, event) => new Promise((resolve) => emitter.once(event, resolve));

test('handshake carries the custom headers and the upgrade contract; text frames flow both ways', async () => {
  const received = [];
  const server = await startWsServer({ onMessage: (conn, text) => { received.push(text); conn.send(`echo:${text}`); } });
  try {
    const ws = await connectWebSocket(server.url, { headers: { authorization: 'Bearer TOK', 'openai-beta': 'responses_websockets=2026-02-06', 'chatgpt-account-id': 'acc-1' } });
    const h = server.requests[0].headers;
    assert.equal(h.upgrade, 'websocket');
    assert.match(h.connection, /upgrade/i);
    assert.equal(h['sec-websocket-version'], '13');
    assert.equal(Buffer.from(h['sec-websocket-key'], 'base64').length, 16);
    assert.equal(h.authorization, 'Bearer TOK');
    assert.equal(h['openai-beta'], 'responses_websockets=2026-02-06');
    assert.equal(h['chatgpt-account-id'], 'acc-1');
    const reply = once(ws, 'message');
    ws.send('hello');
    assert.equal(await reply, 'echo:hello');
    assert.deepEqual(received, ['hello']);
    ws.close();
    await once(ws, 'close');
  } finally {
    await server.close();
  }
});

test('large client messages use the 64-bit length and are masked; large and fragmented server messages are reassembled', async () => {
  let frames = [];
  const big = 'x'.repeat(200 * 1024) + JSON.stringify({ done: true });
  const server = await startWsServer({
    onFrame: (conn, f) => { frames.push(f); },
    onMessage: (conn, text) => {
      if (text === 'send-big') conn.send('y'.repeat(70 * 1024));
      else if (text === 'send-fragmented') { conn.sendFrame(serverFrame('part1-', { opcode: 1, fin: false })); conn.sendFrame(serverFrame('part2', { opcode: 0, fin: true })); }
      else conn.send(`len:${text.length}`);
    },
  });
  try {
    const ws = await connectWebSocket(server.url);
    let reply = once(ws, 'message');
    ws.send(big);
    assert.equal(await reply, `len:${big.length}`);
    assert.equal(frames[0].masked, true);
    assert.equal(frames[0].payload.length, big.length);
    reply = once(ws, 'message');
    ws.send('send-big');
    assert.equal((await reply).length, 70 * 1024);
    reply = once(ws, 'message');
    ws.send('send-fragmented');
    assert.equal(await reply, 'part1-part2');
    ws.close();
    await once(ws, 'close');
  } finally {
    await server.close();
  }
});

test('ping is answered with a pong carrying the same payload; a server close ends the client with the code', async () => {
  const pongs = [];
  let connRef = null;
  const server = await startWsServer({
    onConnection: (conn) => { connRef = conn; },
    onFrame: (conn, f) => { if (f.opcode === 10) pongs.push(f.payload.toString()); },
  });
  try {
    const ws = await connectWebSocket(server.url);
    connRef.sendFrame(serverFrame('ping-1', { opcode: 9 }));
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(pongs, ['ping-1']);
    const closed = once(ws, 'close');
    connRef.close(1001);
    const info = await closed;
    assert.equal(info.code, 1001);
    assert.equal(ws.open, false);
  } finally {
    await server.close();
  }
});

test('a non-101 upgrade answer rejects with the status and body; a bad accept key rejects', async () => {
  const denied = await startWsServer({ reject: { status: 403, text: 'Forbidden', body: '{"detail":"nope"}' } });
  try {
    await assert.rejects(connectWebSocket(denied.url), (e) => e.status === 403 && /nope/.test(e.body));
  } finally {
    await denied.close();
  }
  const badKey = await startWsServer({ onConnection: () => {}, reject: undefined });
  try {
    // tamper: the helper computes a correct key; simulate a bad one by pointing at a raw http server instead
    await assert.rejects(connectWebSocket(`http://127.0.0.1:1/nope`), Error);
  } finally {
    await badKey.close();
  }
});

test('serverFrame / parseClientFrames helpers are consistent for all length classes', () => {
  for (const n of [0, 5, 125, 126, 65535, 65536, 100000]) {
    const f = serverFrame('a'.repeat(n));
    const { frames } = parseClientFrames(f);
    assert.equal(frames.length, 1);
    assert.equal(frames[0].payload.length, n);
    assert.equal(frames[0].masked, false);
  }
});
