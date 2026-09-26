// Central runtime controller. Holds the live redactor and the current upstream
// provider, and applies settings changes (from the dashboard) in place - no
// restart. Persisted settings (config.json) override env defaults on boot.
import { createRedactor, MODES, MODE_RANK } from './redact.js';
import { loadSettings, saveSettings } from './settings.js';
import { isAnthropicHost } from './claude-auth.js';
import { buildMarkerMap } from './rehydrate.js';
import {
  loadProviders,
  saveProviders,
  emptyRegistry,
  upsertProvider as regUpsert,
  removeProvider as regRemove,
  setActive as regSetActive,
  activeProvider as regActive,
  resolveModel as regResolveModel,
  publicRegistry,
  setCodexAuth,
  clearCodexAuth,
} from './providers.js';
import { isCodexHost, isLoopbackHost, refreshTokens, accountFromTokens, tokensFresh, fetchCodexModels } from './codex-auth.js';
import { startCodexLogin } from './codex-login.js';

export function createRuntime({ config, secrets = [], codexDeps = {} }) {
  let mode = config.redactMode;
  let currentSecrets = secrets;
  // OPT-IN response rehydration: substitute {{NAME}} back to the real value on
  // the way out to the CLI. Off unless explicitly enabled (re-hydrates a secret
  // into the local transcript). See src/rehydrate.js.
  let restoreMarkers = config.restoreMarkers ?? false;
  let markerMap = buildMarkerMap(currentSecrets);
  // OPT-IN: retain the actual matched values so the local panel can reveal them.
  // Off means the redactor is never asked to capture, so nothing is retained.
  let showRedactedValues = config.showRedactedValues ?? false;

  // Mutated in place so the proxy, reading runtime.upstream each request, sees
  // provider changes immediately.
  const upstream = {
    url: config.upstreamUrl ?? null,
    auth: config.upstreamAuth,
    key: config.upstreamKey ?? null,
  };

  const build = () =>
    createRedactor({
      secrets: currentSecrets,
      mode,
      disabledRules: config.redactDisable,
      ignore: config.redactIgnore,
    });
  const holder = { current: build() };

  function apply(patch, { persist = true } = {}) {
    if ('upstreamUrl' in patch) {
      const v = patch.upstreamUrl;
      if (v) {
        const u = new URL(v);
        if (u.protocol !== 'https:' && u.protocol !== 'http:') {
          throw new Error(`upstreamUrl must be http(s), got "${u.protocol}"`);
        }
        upstream.url = u;
      } else {
        upstream.url = null;
      }
    }
    if (patch.upstreamAuth !== undefined) {
      if (!['passthrough', 'replace', 'oauth', 'codex-oauth'].includes(patch.upstreamAuth)) {
        throw new Error('upstreamAuth must be passthrough, replace, oauth or codex-oauth');
      }
      upstream.auth = patch.upstreamAuth;
    }
    if ('upstreamKey' in patch) upstream.key = patch.upstreamKey || null;
    if (patch.redactMode !== undefined) {
      if (!MODES.includes(patch.redactMode)) throw new Error(`invalid redactMode: ${patch.redactMode}`);
      if (MODE_RANK[patch.redactMode] < MODE_RANK[config.redactModeFloor]) {
        throw new Error(`redactMode "${patch.redactMode}" is below the floor "${config.redactModeFloor}"`);
      }
      mode = patch.redactMode;
      holder.current = build();
    }
    if (patch.restoreMarkers !== undefined) {
      restoreMarkers = patch.restoreMarkers === true || patch.restoreMarkers === 'true';
    }
    if (patch.showRedactedValues !== undefined) {
      showRedactedValues = patch.showRedactedValues === true || patch.showRedactedValues === 'true';
    }
    if (upstream.auth === 'replace' && !upstream.key) {
      throw new Error('upstreamAuth=replace requires a key');
    }
    // CRITICAL: the oauth mode injects the user's real Claude subscription
    // token. It must NEVER go to a third party - only the official Anthropic
    // API. Refuse to configure it against any other host.
    if (upstream.auth === 'oauth' && upstream.url && !isAnthropicHost(upstream.url)) {
      throw new Error('upstreamAuth=oauth is only allowed with an *.anthropic.com provider');
    }
    // Same rule for a ChatGPT login: only the Codex backend host (or a
    // loopback process on this machine, which is inside the trust boundary).
    if (
      upstream.auth === 'codex-oauth' &&
      upstream.url &&
      !isCodexHost(upstream.url) &&
      !isLoopbackHost(upstream.url)
    ) {
      throw new Error('upstreamAuth=codex-oauth is only allowed with chatgpt.com');
    }
    if (persist) saveSettings(config.configFile, snapshot());
  }

  function snapshot() {
    return {
      upstreamUrl: upstream.url?.href ?? null,
      upstreamAuth: upstream.auth,
      upstreamKey: upstream.key ?? null,
      redactMode: mode,
      restoreMarkers,
      showRedactedValues,
    };
  }

  // What the dashboard is allowed to read: never the key value, only whether
  // one is set.
  function publicSettings() {
    return {
      upstreamUrl: upstream.url?.href ?? null,
      upstreamAuth: upstream.auth,
      hasKey: !!upstream.key,
      redactMode: mode,
      redactModeFloor: config.redactModeFloor,
      modes: MODES,
      restoreMarkers,
      showRedactedValues,
    };
  }

  function setSecrets(next) {
    currentSecrets = next;
    holder.current = build();
    markerMap = buildMarkerMap(currentSecrets);
  }

  // What the proxy needs to rehydrate responses: whether it is on, and the live
  // name -> value map. Returns an empty map when off so callers can gate cheaply.
  function getRestore() {
    return { enabled: restoreMarkers && markerMap.size > 0, map: markerMap };
  }

  // Apply persisted settings over env defaults (do not re-persist).
  const persisted = loadSettings(config.configFile);
  if (persisted) {
    try {
      apply(persisted, { persist: false });
    } catch (err) {
      // A bad persisted file must not crash boot; keep env defaults.
      console.warn(`[redact] ignoring invalid config.json: ${err.message}`);
    }
  }

  // ---- provider registry (multi-upstream + per-provider model aliases) ----
  // The ACTIVE provider drives `upstream`; its alias map and custom headers
  // apply per request. When the registry is empty (no providers.json), nothing
  // changes and the proxy behaves exactly as the single-upstream config above.
  let registry = loadProviders(config.providersFile) ?? emptyRegistry();
  let activeAliases = {};
  let activeHeaders = {};

  function syncActiveProvider() {
    const p = regActive(registry);
    activeAliases = p?.aliases ?? {};
    activeHeaders = p?.headers ?? {};
    if (p && p.url) {
      // Seed the live upstream from the active provider. persist:false - the
      // registry (providers.json) is the source of truth and is saved on CRUD.
      apply({ upstreamUrl: p.url, upstreamAuth: p.auth, upstreamKey: p.key }, { persist: false });
    }
  }
  function persistRegistry() {
    saveProviders(config.providersFile, registry);
  }
  function upsertProvider(id, input) {
    regUpsert(registry, id, input);
    persistRegistry();
    syncActiveProvider();
    return providersView();
  }
  function removeProvider(id) {
    regRemove(registry, id);
    codexLimits.delete(id);
    persistRegistry();
    syncActiveProvider();
    return providersView();
  }
  function activateProvider(id) {
    regSetActive(registry, id);
    persistRegistry();
    syncActiveProvider();
    return providersView();
  }
  // Internal: the full active-provider record (holds the key + headers) for
  // server-side use only, e.g. the dashboard fetching a provider's model list.
  function providerFor(id) {
    return registry.providers[id] ?? null;
  }
  // alias -> real upstream model id for the active provider (unchanged if none).
  function resolveModel(model) {
    return regResolveModel({ aliases: activeAliases }, model);
  }

  // ---- Codex (ChatGPT subscription) provider ----
  const codexNow = codexDeps.now ?? Date.now;
  // One refresh in flight per provider: parallel requests near expiry (Claude
  // Code fires side calls) would otherwise race with the same refresh token
  // and the losers would report a spurious "log in again".
  let codexRefreshing = null; // { id, promise }
  // Last plan usage the backend reported per codex provider. Memory only: it
  // changes on every request and is not worth a file write.
  const codexLimits = new Map(); // provider id -> parsed x-codex-* limits

  // Public registry view plus the ephemeral plan usage.
  function providersView() {
    const view = publicRegistry(registry);
    for (const p of view.providers) {
      if (p.codex) p.codex.limits = codexLimits.get(p.id) ?? null;
    }
    return view;
  }

  // What the upstream handler needs from the ACTIVE provider, or null when it
  // is not codex-oauth. credentials() refreshes proactively (5 min skew);
  // refresh() is the forced path after a backend 401. Rotated tokens are
  // persisted so the next boot starts from them.
  function codexAdapterFor(id) {
    const p = registry.providers[id] ?? null;
    if (!p || p.auth !== 'codex-oauth') return null;
    const current = () => registry.providers[id]?.codex?.tokens ?? null;
    const doRefresh = async () => {
      const t = current();
      if (!t || !t.refresh) return null;
      const next = await refreshTokens({ refreshToken: t.refresh, request: codexDeps.request });
      if (!next) return null;
      const account = accountFromTokens(next);
      setCodexAuth(registry, id, {
        tokens: { access: next.access, refresh: next.refresh, idToken: next.idToken, accountId: account.accountId ?? t.accountId, expiresAt: account.expiresAt },
      });
      persistRegistry();
      const fresh = current();
      return fresh ? { access: fresh.access, accountId: fresh.accountId } : null;
    };
    const refresh = () => {
      if (codexRefreshing && codexRefreshing.id === id) return codexRefreshing.promise;
      const promise = doRefresh().finally(() => {
        if (codexRefreshing && codexRefreshing.promise === promise) codexRefreshing = null;
      });
      codexRefreshing = { id, promise };
      return promise;
    };
    return {
      profile: () => ({ models: registry.providers[id]?.codex?.models ?? null, effortMap: registry.providers[id]?.effortMap ?? null, prune: registry.providers[id]?.prune ?? null, transport: registry.providers[id]?.transport ?? 'ws' }),
      credentials: async () => {
        const t = current();
        if (!t || !t.access) return null;
        if (tokensFresh(t, codexNow())) return { access: t.access, accountId: t.accountId };
        return refresh();
      },
      refresh,
      reportLimits: (limits) => {
        if (limits && typeof limits === 'object') codexLimits.set(id, limits);
      },
    };
  }
  function codexAdapter() {
    return registry.active ? codexAdapterFor(registry.active) : null;
  }

  // Re-fetch a codex-oauth provider's model list with its stored login (the
  // dashboard "fetch models" button). Persists the list; returns the listed
  // slugs. Throws a plain Error the dashboard turns into a 400/502.
  async function codexFetchModels(id) {
    const p = registry.providers[id];
    if (!p) throw new Error(`unknown provider "${id}"`);
    const adapter = codexAdapterFor(id);
    if (!adapter) throw new Error('provider auth must be codex-oauth');
    const creds = await adapter.credentials();
    if (!creds) {
      const err = new Error('log in with ChatGPT first (edit the provider, then Login with ChatGPT)');
      err.code = 'NOT_LOGGED_IN';
      throw err;
    }
    const models = await (codexDeps.fetchModels ?? fetchCodexModels)({ baseUrl: p.url, access: creds.access, accountId: creds.accountId, request: codexDeps.request });
    if (!models) {
      const err = new Error('the Codex backend did not return a model list');
      err.code = 'UPSTREAM';
      throw err;
    }
    setCodexAuth(registry, id, { models, fetchedAt: codexNow() });
    persistRegistry();
    return models.filter((m) => m.visibility === 'list').map((m) => m.slug);
  }

  // Start a ChatGPT login for a codex-oauth provider: resolves with the URL
  // the panel opens. The callback listener stores the result in the registry.
  async function codexLogin(id) {
    const p = registry.providers[id];
    if (!p) throw new Error(`unknown provider "${id}"`);
    if (p.auth !== 'codex-oauth') throw new Error('provider auth must be codex-oauth to log in');
    const { url, port } = await startCodexLogin({
      port: codexDeps.port,
      timeoutMs: codexDeps.loginTimeoutMs,
      baseUrl: p.url,
      exchange: codexDeps.exchange,
      fetchModels: codexDeps.fetchModels,
      request: codexDeps.request,
      nowMs: codexNow,
      onResult: (r) => {
        setCodexAuth(registry, id, r);
        persistRegistry();
      },
    });
    return { url, port };
  }

  function codexLogout(id) {
    clearCodexAuth(registry, id);
    codexLimits.delete(id);
    persistRegistry();
    return providersView();
  }

  try {
    syncActiveProvider();
  } catch (err) {
    console.warn(`[redact] ignoring invalid providers.json: ${err.message}`);
  }

  return {
    holder,
    upstream,
    get mode() {
      return mode;
    },
    apply,
    snapshot,
    publicSettings,
    setSecrets,
    getRestore,
    get restoreMarkers() {
      return restoreMarkers;
    },
    get showRedactedValues() {
      return showRedactedValues;
    },
    // provider registry
    providers: providersView,
    providerFor,
    upsertProvider,
    removeProvider,
    activateProvider,
    resolveModel,
    codexAdapter,
    codexFetchModels,
    codexLogin,
    codexLogout,
    get activeHeaders() {
      return activeHeaders;
    },
    get activeAliases() {
      return activeAliases;
    },
  };
}
