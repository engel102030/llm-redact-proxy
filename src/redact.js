// Redaction engine. Two layers, both mandatory:
//   Layer A - known secret VALUES (from the secrets file) matched as plain
//             substrings in every encoding variant. No regex, no backtracking.
//   Layer B - regex rules for secret SHAPES (JWT, PEM, Bearer, vendor keys,
//             cookies) plus entropy-gated blobs, for dynamic secrets the
//             static list cannot contain.
// Replacements use a stable marker [REDACTED:<name>]; the marker contains no
// characters that need JSON escaping, so inserting it inside a JSON string
// keeps the body valid.
import { buildNeedles } from './secrets.js';

export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const marker = (name) => `[REDACTED:${name}]`;

// Runs longer than this are media payloads (base64 images/audio), not
// secrets; redacting them would break vision requests for no security gain.
const MAX_ENTROPY_RUN = 4096;

// keep: number of leading capture groups to preserve (header names etc. stay
// for context; only the credential itself is replaced).
const REGEX_RULES = [
  {
    rule: 'pem-private-key',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  {
    // JSON-escaped PEM (literal backslash-n) for raw bodies that were not parsed.
    rule: 'pem-private-key',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\+[rn]|[A-Za-z0-9+/= ])+-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  { rule: 'jwt', re: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{6,}/g },
  { rule: 'bearer-token', re: /(\bBearer\s+)[A-Za-z0-9._~+/=-]{16,}/gi, keep: 1 },
  { rule: 'x-api-key', re: /(x-api-key["']?\s*[:=]\s*["']?)[A-Za-z0-9._~+/=-]{8,}/gi, keep: 1 },
  { rule: 'openai-key', re: /\bsk-[A-Za-z0-9_-]{20,}/g },
  { rule: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16,}\b/g },
  { rule: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { rule: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
  {
    rule: 'github-token',
    re: /\b(?:gh[opusr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g,
  },
  { rule: 'set-cookie', re: /(set-cookie["']?\s*:\s*)[^\r\n"\\]+/gi, keep: 1 },
  {
    rule: 'session-cookie',
    re: /\b(sessionid|sess_id|session_token|csrftoken|xsrf_token|auth_token|access_token|refresh_token)(=)[^\s;&"'\\]{8,}/gi,
    keep: 2,
  },
];

const ENTROPY_RULES = [
  { rule: 'high-entropy-hex', re: /\b[0-9a-fA-F]{32,}\b/g, threshold: 3.0 },
  { rule: 'high-entropy-base64', re: /[A-Za-z0-9+/]{40,}={0,2}/g, threshold: 4.5 },
  { rule: 'high-entropy-base64', re: /[A-Za-z0-9_-]{40,}/g, threshold: 4.5 },
];

// 'disabled' is a full bypass: no redaction at all (transparent passthrough),
// for a trusted destination like the official Anthropic API. It is the most
// permissive rank, so the floor guards it - reaching it requires an explicit
// REDACT_MODE_FLOOR=disabled.
export const MODES = ['disabled', 'named-only', 'balanced', 'strict'];
export const MODE_RANK = { disabled: 0, 'named-only': 1, balanced: 2, strict: 3 };

// Which Layer B rule groups are active per mode. Layer A (named secrets) is
// ALWAYS on - registering a secret is an explicit opt-in a mode never weakens.
function activeLayerB(mode) {
  if (mode === 'named-only') return { regex: [], entropy: [] };
  if (mode === 'balanced') return { regex: REGEX_RULES, entropy: [] };
  return { regex: REGEX_RULES, entropy: ENTROPY_RULES }; // strict (default)
}

// An ignore entry is either a literal string or a /regex/ (optionally with
// flags). Returns a predicate that says whether a matched span is marked safe.
function buildIgnoreMatcher(ignore = []) {
  const literals = new Set();
  const regexes = [];
  for (const entry of ignore) {
    const m = /^\/(.*)\/([a-z]*)$/is.exec(entry);
    if (m) {
      try {
        regexes.push(new RegExp(m[1], m[2]));
      } catch {
        literals.add(entry); // malformed regex: treat as a literal
      }
    } else {
      literals.add(entry);
    }
  }
  if (literals.size === 0 && regexes.length === 0) return () => false;
  return (span) => literals.has(span) || regexes.some((re) => re.test(span));
}

// captures (optional) is a Map<rule, Set<value>> collecting the ACTUAL matched
// text per rule - populated ONLY when the caller opted in (captureValues). When
// null, no value is ever retained (the default, safest behaviour).
function makeStringRedactor({ needles, regexRules, entropyRules, isIgnored }, events, captures) {
  const bump = (rule, n = 1) => events.set(rule, (events.get(rule) ?? 0) + n);
  const keep = captures
    ? (rule, value) => {
        let set = captures.get(rule);
        if (!set) captures.set(rule, (set = new Set()));
        set.add(value);
      }
    : () => {};

  return function redactString(input) {
    let text = input;

    // Layer A: plain substring replacement, longest needle first.
    for (const { name, needle } of needles) {
      if (text.includes(needle)) {
        const parts = text.split(needle);
        bump(name, parts.length - 1);
        keep(name, needle);
        text = parts.join(marker(name));
      }
    }

    // Layer B: shape rules.
    for (const { rule, re, keep: keepGroups } of regexRules) {
      text = text.replace(re, (...args) => {
        const match = args[0];
        let prefix = '';
        for (let g = 1; g <= (keepGroups ?? 0); g += 1) prefix += args[g];
        if (isIgnored(match) || isIgnored(match.slice(prefix.length))) return match;
        bump(rule);
        keep(rule, match.slice(prefix.length)); // the credential, without the kept prefix
        return prefix + marker(rule);
      });
    }

    // Layer B: entropy-gated blobs.
    for (const { rule, re, threshold } of entropyRules) {
      text = text.replace(re, (match) => {
        if (match.length > MAX_ENTROPY_RUN) return match;
        if (shannonEntropy(match) < threshold) return match;
        if (isIgnored(match)) return match;
        bump(rule);
        keep(rule, match);
        return marker(rule);
      });
    }

    return text;
  };
}

// Dotted JSON paths whose string value is a client PROTOCOL identifier, not
// user data - redacting it corrupts a field the vendor validates (some
// gateways reject the request outright) for zero security gain. metadata.user_id
// is Claude Code's device/account hash: an opaque, per-install constant that
// contains no credential. Arrays do not extend the path, so this matches
// regardless of message nesting.
export const PROTECTED_PATHS = new Set(['metadata.user_id']);

function walkStrings(node, fn, protectedPaths = PROTECTED_PATHS, path = '') {
  if (typeof node === 'string') return protectedPaths.has(path) ? node : fn(node);
  if (Array.isArray(node)) return node.map((n) => walkStrings(n, fn, protectedPaths, path));
  if (node && typeof node === 'object') {
    const out = {};
    for (const [key, value] of Object.entries(node)) {
      // Keys are strings too - a token used as a map key must not survive.
      const childPath = path ? `${path}.${key}` : key;
      out[fn(key)] = walkStrings(value, fn, protectedPaths, childPath);
    }
    return out;
  }
  return node;
}

// A needle is safe to apply to a SERIALIZED JSON body only if none of its
// characters would be escaped by JSON.stringify (quotes, backslashes,
// control chars). Secrets containing those are still covered inside parsed
// strings and by their json-escaped variant, which is serialization-safe.
function isSerializationSafe(needle) {
  for (let i = 0; i < needle.length; i += 1) {
    const code = needle.charCodeAt(i);
    if (code < 0x20 || needle[i] === '"' || needle[i] === '\\') return false;
  }
  return true;
}

export function createRedactor({
  secrets = [],
  mode = 'strict',
  disabledRules = [],
  ignore = [],
} = {}) {
  if (!MODES.includes(mode)) throw new Error(`invalid redaction mode: ${mode}`);

  // Full bypass: forward the body untouched. Even registered secrets pass -
  // this is only for a destination the user explicitly trusts.
  if (mode === 'disabled') {
    return {
      mode,
      redactBody(raw) {
        if (typeof raw !== 'string') throw new TypeError('redactBody expects a string body');
        return { body: raw, events: [], captures: [] };
      },
    };
  }

  const disabled = new Set(disabledRules);

  const needles = secrets
    .flatMap((s) => buildNeedles(s))
    .filter(({ name }) => !disabled.has(name))
    .sort((a, b) => b.needle.length - a.needle.length);

  const serializedSafe = needles.filter(({ needle }) => isSerializationSafe(needle));

  const groups = activeLayerB(mode);
  const regexRules = groups.regex.filter((r) => !disabled.has(r.rule));
  const entropyRules = groups.entropy.filter((r) => !disabled.has(r.rule));
  const isIgnored = buildIgnoreMatcher(ignore);
  const engine = { needles, regexRules, entropyRules, isIgnored };

  function redactBody(raw, contentType = '', { captureValues = false } = {}) {
    if (typeof raw !== 'string') throw new TypeError('redactBody expects a string body');
    const events = new Map();
    // Only allocate the value store when the caller opted in - otherwise no
    // matched value is ever retained.
    const captures = captureValues ? new Map() : null;
    const keep = (rule, value) => {
      if (!captures) return;
      let set = captures.get(rule);
      if (!set) captures.set(rule, (set = new Set()));
      set.add(value);
    };
    const redactString = makeStringRedactor(engine, events, captures);

    let out = null;
    const looksJson = /json/i.test(contentType) || /^\s*[{[]/.test(raw);
    if (looksJson) {
      let parsed;
      let parseOk = true;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parseOk = false;
      }
      if (parseOk) {
        const walked = walkStrings(parsed, redactString);
        let serialized = JSON.stringify(walked);
        // Second pass over the serialized body: encoded blobs living in
        // object keys or crossing string boundaries.
        for (const { name, needle } of serializedSafe) {
          if (serialized.includes(needle)) {
            const parts = serialized.split(needle);
            events.set(name, (events.get(name) ?? 0) + parts.length - 1);
            keep(name, needle);
            serialized = parts.join(marker(name));
          }
        }
        out = serialized;
      }
    }
    if (out === null) out = redactString(raw);

    const eventList = [...events.entries()].map(([rule, count]) => ({ rule, count }));
    const captureList = captures
      ? [...captures.entries()].flatMap(([rule, set]) => [...set].map((value) => ({ rule, value })))
      : [];
    // Nothing matched: return the original bytes untouched (no
    // reserialization drift for clean bodies).
    if (eventList.length === 0) return { body: raw, events: [], captures: [] };
    return { body: out, events: eventList, captures: captureList };
  }

  return { redactBody, mode };
}
