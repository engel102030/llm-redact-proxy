// Central runtime controller. Holds the live redactor and the current upstream
// provider, and applies settings changes (from the dashboard) in place - no
// restart. Persisted settings (config.json) override env defaults on boot.
import { createRedactor, MODES, MODE_RANK } from './redact.js';
import { loadSettings, saveSettings } from './settings.js';
import { isAnthropicHost } from './claude-auth.js';
import { buildMarkerMap } from './rehydrate.js';

export function createRuntime({ config, secrets = [] }) {
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
      if (!['passthrough', 'replace', 'oauth'].includes(patch.upstreamAuth)) {
        throw new Error('upstreamAuth must be passthrough, replace or oauth');
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
  };
}
