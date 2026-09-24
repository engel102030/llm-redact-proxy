// Provider registry: several named upstreams, exactly one ACTIVE at a time.
// Each provider holds its url/auth/key, optional custom request headers (e.g. a
// browser User-Agent to clear a Cloudflare gate), and a model ALIAS map -
// a custom name the client uses -> the real upstream model id, e.g.
//   "claude-opus-4-8" -> "accounts/euromodels/models/claude-opus-4-8"
// The proxy forwards to the active provider, rewrites the request `model` via
// the alias map, and reflects the aliases in /v1/models. The file may hold keys,
// so it is written chmod 600 and never committed.
import fs from 'node:fs';
import path from 'node:path';

const AUTH = ['passthrough', 'replace', 'oauth'];

export function emptyRegistry() {
  return { active: null, providers: {} };
}

// Normalize + validate one provider record. Throws on invalid url/auth.
export function normalizeProvider(input = {}) {
  const p = {};
  p.label = typeof input.label === 'string' && input.label.trim() ? input.label.trim() : null;

  const url = typeof input.url === 'string' ? input.url.trim() : '';
  if (url) {
    const u = new URL(url); // throws on malformed
    if (u.protocol !== 'https:' && u.protocol !== 'http:') {
      throw new Error(`provider url must be http(s), got "${u.protocol}"`);
    }
    p.url = url;
  } else {
    p.url = null;
  }

  const auth = input.auth ?? 'replace';
  if (!AUTH.includes(auth)) throw new Error(`auth must be one of ${AUTH.join('|')}`);
  p.auth = auth;

  p.key = typeof input.key === 'string' && input.key ? input.key : null;

  // Custom headers sent upstream (lowercased keys). Used e.g. for a browser
  // User-Agent that clears Cloudflare, or a vendor-specific header.
  p.headers = {};
  if (input.headers && typeof input.headers === 'object') {
    for (const [k, v] of Object.entries(input.headers)) {
      if (typeof v === 'string' && v) p.headers[String(k).toLowerCase().trim()] = v;
    }
  }

  // Alias map: custom-name -> real upstream model id.
  p.aliases = {};
  if (input.aliases && typeof input.aliases === 'object') {
    for (const [alias, real] of Object.entries(input.aliases)) {
      const a = String(alias).trim();
      if (a && typeof real === 'string' && real.trim()) p.aliases[a] = real.trim();
    }
  }
  return p;
}

// Create or update a provider. On update, a blank/omitted key keeps the existing
// one (mirrors the dashboard's write-only key field).
export function upsertProvider(reg, id, input) {
  const slug = String(id ?? '').trim();
  if (!slug) throw new Error('provider id is required');
  const existing = reg.providers[slug];
  const merged = { ...input };
  if ((merged.key === undefined || merged.key === '') && existing) merged.key = existing.key;
  const norm = normalizeProvider(merged);
  if (norm.auth === 'replace' && !norm.key) throw new Error('replace auth requires a key');
  reg.providers[slug] = norm;
  if (!reg.active) reg.active = slug; // first provider added becomes active
  return reg;
}

export function removeProvider(reg, id) {
  delete reg.providers[id];
  if (reg.active === id) reg.active = Object.keys(reg.providers)[0] ?? null;
  return reg;
}

export function setActive(reg, id) {
  if (!reg.providers[id]) throw new Error(`unknown provider "${id}"`);
  reg.active = id;
  return reg;
}

export function activeProvider(reg) {
  return reg && reg.active ? reg.providers[reg.active] ?? null : null;
}

// alias -> real model id for a provider. Returns the model unchanged when there
// is no matching alias (so plain ids pass straight through).
export function resolveModel(provider, model) {
  if (!provider || !provider.aliases || typeof model !== 'string') return model;
  return provider.aliases[model] ?? model;
}

// Rewrite the `model` field of a JSON request body through an alias map. Returns
// the (possibly rewritten) body text and whether a rewrite happened. Defensive:
// any JSON problem leaves the body byte-identical (aliased=false).
export function applyAliasToBody(bodyText, aliases) {
  if (!aliases || Object.keys(aliases).length === 0) return { body: bodyText, aliased: false };
  try {
    const parsed = JSON.parse(bodyText);
    if (parsed && typeof parsed.model === 'string' && aliases[parsed.model]) {
      parsed.model = aliases[parsed.model];
      return { body: JSON.stringify(parsed), aliased: true };
    }
  } catch {
    // not JSON / unparseable - leave untouched
  }
  return { body: bodyText, aliased: false };
}

// Public view for the dashboard: never the key value, only whether one is set.
export function publicRegistry(reg) {
  return {
    active: reg.active,
    providers: Object.entries(reg.providers).map(([id, p]) => ({
      id,
      label: p.label,
      url: p.url,
      auth: p.auth,
      hasKey: !!p.key,
      headers: p.headers,
      aliases: p.aliases,
    })),
  };
}

export function loadProviders(file) {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null; // missing or malformed
  }
  const reg = emptyRegistry();
  if (raw && typeof raw === 'object' && raw.providers && typeof raw.providers === 'object') {
    for (const [id, p] of Object.entries(raw.providers)) {
      try {
        reg.providers[id] = normalizeProvider(p);
      } catch {
        // skip a single bad entry rather than losing the whole registry
      }
    }
    if (raw.active && reg.providers[raw.active]) reg.active = raw.active;
    else reg.active = Object.keys(reg.providers)[0] ?? null;
  }
  return reg;
}

export function saveProviders(file, reg) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(reg, null, 2)}\n`, { mode: 0o600 });
}
