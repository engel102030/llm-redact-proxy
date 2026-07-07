// Minimal MCP stdio transport: JSON-RPC 2.0, one message per line.
// stdout carries ONLY protocol messages; all logging must go to stderr.
export function createRpcServer({ input = process.stdin, output = process.stdout, handlers }) {
  let buffer = '';

  function write(msg) {
    output.write(`${JSON.stringify(msg)}\n`);
  }

  function replyError(id, code, message) {
    write({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
  }

  async function dispatch(msg) {
    const isRequest = msg.id !== undefined && msg.id !== null;
    const handler = handlers[msg.method];
    if (!handler) {
      // Notifications for unknown methods are silently ignored per JSON-RPC.
      if (isRequest) replyError(msg.id, -32601, `method not found: ${msg.method}`);
      return;
    }
    try {
      const result = await handler(msg.params ?? {});
      if (isRequest) write({ jsonrpc: '2.0', id: msg.id, result: result ?? {} });
    } catch (err) {
      if (isRequest) replyError(msg.id, err.rpcCode ?? -32603, err.message);
    }
  }

  input.setEncoding('utf8');
  input.on('data', (chunk) => {
    buffer += chunk;
    let idx;
    while ((idx = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        replyError(null, -32700, 'parse error');
        continue;
      }
      dispatch(msg);
    }
  });

  input.on('end', () => {
    // Client went away; nothing left to serve.
    process.exit(0);
  });

  return { write };
}

export function rpcError(code, message) {
  const err = new Error(message);
  err.rpcCode = code;
  return err;
}
