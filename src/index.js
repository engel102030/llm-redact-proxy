// Entrypoint: load config + secrets, build the redactor, start the proxy.
import { loadConfig } from './config.js';
import { loadSecretsFromSources } from './secrets.js';
import { createRedactor } from './redact.js';
import { createStats } from './stats.js';
import { createProxyServer } from './proxy.js';

const config = loadConfig();
const secrets = loadSecretsFromSources(config.secretSources);
const redactor = createRedactor({
  secrets,
  mode: config.redactMode,
  disabledRules: config.redactDisable,
  ignore: config.redactIgnore,
});
const stats = createStats();
const server = createProxyServer({ config, redactor, stats });

server.listen(config.listenPort, config.listenHost, () => {
  const base = `http://${config.listenHost}:${config.listenPort}`;
  console.log(`[redact] listening on ${base}`);
  console.log(`[redact] upstream: ${config.upstreamUrl.href} (auth: ${config.upstreamAuth})`);
  console.log(`[redact] known secrets loaded: ${secrets.length} (values never logged)`);
  console.log(
    `[redact] fail-closed: ${config.failClosed} | notice injection: ${config.injectNotice} | mode: ${config.redactMode}`,
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
