// Local mock upstream server for tests. Records every request it receives
// (method, url, headers, raw body) so tests can assert on what actually
// crossed the wire - the core proof is grepping these bodies for canaries.
import http from 'node:http';

export function createMockUpstream(options = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      requests.push({
        method: req.method,
        url: req.url,
        headers: { ...req.headers },
        body: Buffer.concat(chunks).toString('utf8'),
      });

      if (options.sse) {
        res.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
        });
        const events = options.sseEvents ?? ['event: ping\ndata: {}\n\n'];
        let i = 0;
        const send = () => {
          if (i < events.length) {
            res.write(events[i]);
            i += 1;
            setTimeout(send, options.sseDelayMs ?? 10);
          } else {
            res.end();
          }
        };
        send();
      } else {
        const payload = JSON.stringify(options.response ?? { ok: true });
        res.writeHead(options.status ?? 200, { 'content-type': 'application/json' });
        res.end(payload);
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        port,
        url: `http://127.0.0.1:${port}`,
        requests,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}
