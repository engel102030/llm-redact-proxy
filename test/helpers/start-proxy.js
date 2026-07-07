// Boots the proxy server on an ephemeral port for end-to-end tests.
import { createProxyServer } from '../../src/proxy.js';
import { createStats } from '../../src/stats.js';

export async function startProxy({ upstreamUrl, redactor, configOverrides = {} }) {
  const config = {
    listenHost: '127.0.0.1',
    listenPort: 0,
    upstreamUrl: new URL(upstreamUrl),
    upstreamAuth: 'passthrough',
    upstreamKey: null,
    failClosed: true,
    injectNotice: true,
    ...configOverrides,
  };
  const stats = createStats({ log: () => {} });
  const server = createProxyServer({ config, redactor, stats });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    server,
    stats,
    close: () => new Promise((r) => server.close(r)),
  };
}
