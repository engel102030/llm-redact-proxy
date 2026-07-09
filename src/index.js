// Standalone entrypoint: load config + secrets, build the runtime (redactor +
// live provider), start the proxy. The provider can be set here via env
// (UPSTREAM_URL) or later from the dashboard - the server always listens so
// the panel is reachable either way.
import { loadConfig } from './config.js';
import { loadSecrets } from './secrets.js';
import { createStats } from './stats.js';
import { createProxyServer } from './proxy.js';
import { createRuntime } from './runtime.js';

const config = loadConfig({ requireUpstream: false });
const secrets = loadSecrets(config.secretsFile);
const runtime = createRuntime({ config, secrets });
const stats = createStats();
const liveRedactor = { redactBody: (raw, ct) => runtime.holder.current.redactBody(raw, ct) };
const server = createProxyServer({
  config,
  redactor: liveRedactor,
  stats,
  getUpstream: () => runtime.upstream,
  controller: runtime,
  getRestore: () => runtime.getRestore(),
});

server.listen(config.listenPort, config.listenHost, () => {
  const base = `http://${config.listenHost}:${config.listenPort}`;
  console.log(`[redact] listening on ${base}`);
  console.log(`[redact] provider: ${runtime.upstream.url?.href ?? 'not set - configure in the dashboard'}`);
  console.log(`[redact] known secrets loaded: ${secrets.length} (values never logged)`);
  console.log(
    `[redact] fail-closed: ${config.failClosed} | notice injection: ${config.injectNotice} | mode: ${runtime.mode}`,
  );
  console.log(`[redact] dashboard: ${base}/__redact/`);
  console.log(`[redact] point your CLI at it, e.g. export ANTHROPIC_BASE_URL=${base}`);
  if (secrets.length === 0) {
    console.warn('[redact] WARNING: no known secrets loaded - only the regex layer is active');
  }
  if (!config.failClosed) {
    console.warn('[redact] WARNING: FAIL_CLOSED=false - redaction errors will forward RAW bodies');
  }
});
