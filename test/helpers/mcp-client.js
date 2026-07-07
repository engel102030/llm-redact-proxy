// Minimal MCP stdio client for tests: spawns the real server process and
// speaks newline-delimited JSON-RPC 2.0 with it. Keeps the raw stdout
// transcript so tests can grep it for canary leaks.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export function startMcpClient({ env = {}, cwd } = {}) {
  const child = spawn(process.execPath, [path.join(ROOT, 'src', 'mcp.js')], {
    cwd: cwd ?? ROOT,
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const state = { rawStdout: '', rawStderr: '', buffer: '' };
  const pending = new Map();
  const stderrWaiters = [];
  let nextId = 1;

  child.stdout.on('data', (data) => {
    const text = data.toString('utf8');
    state.rawStdout += text;
    state.buffer += text;
    let idx;
    while ((idx = state.buffer.indexOf('\n')) >= 0) {
      const line = state.buffer.slice(0, idx).trim();
      state.buffer = state.buffer.slice(idx + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg.id !== undefined && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    }
  });

  child.stderr.on('data', (data) => {
    state.rawStderr += data.toString('utf8');
    for (let i = stderrWaiters.length - 1; i >= 0; i -= 1) {
      const { re, resolve } = stderrWaiters[i];
      const m = re.exec(state.rawStderr);
      if (m) {
        stderrWaiters.splice(i, 1);
        resolve(m);
      }
    }
  });

  function request(method, params = {}, timeoutMs = 10000) {
    const id = nextId;
    nextId += 1;
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    return new Promise((resolve, reject) => {
      pending.set(id, resolve);
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error(`timeout waiting for response to ${method}`));
        }
      }, timeoutMs).unref();
    });
  }

  function notify(method, params = {}) {
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  function waitForStderr(re, timeoutMs = 10000) {
    const m = re.exec(state.rawStderr);
    if (m) return Promise.resolve(m);
    return new Promise((resolve, reject) => {
      stderrWaiters.push({ re, resolve });
      setTimeout(() => reject(new Error(`timeout waiting for stderr ${re}`)), timeoutMs).unref();
    });
  }

  function close() {
    child.kill('SIGKILL');
  }

  return {
    child,
    request,
    notify,
    waitForStderr,
    close,
    get rawStdout() {
      return state.rawStdout;
    },
    get rawStderr() {
      return state.rawStderr;
    },
  };
}
