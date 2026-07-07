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

function makeStringRedactor(needles, events) {
  const bump = (rule, n = 1) => events.set(rule, (events.get(rule) ?? 0) + n);

  return function redactString(input) {
    let text = input;

    // Layer A: plain substring replacement, longest needle first.
    for (const { name, needle } of needles) {
      if (text.includes(needle)) {
        const parts = text.split(needle);
        bump(name, parts.length - 1);
        text = parts.join(marker(name));
      }
    }

    // Layer B: shape rules.
    for (const { rule, re, keep } of REGEX_RULES) {
      text = text.replace(re, (...args) => {
        bump(rule);
        let prefix = '';
        for (let g = 1; g <= (keep ?? 0); g += 1) prefix += args[g];
        return prefix + marker(rule);
      });
    }

    // Layer B: entropy-gated blobs.
    for (const { rule, re, threshold } of ENTROPY_RULES) {
      text = text.replace(re, (match) => {
        if (match.length > MAX_ENTROPY_RUN) return match;
        if (shannonEntropy(match) < threshold) return match;
        bump(rule);
        return marker(rule);
      });
    }

    return text;
  };
}

function walkStrings(node, fn) {
  if (typeof node === 'string') return fn(node);
  if (Array.isArray(node)) return node.map((n) => walkStrings(n, fn));
  if (node && typeof node === 'object') {
    const out = {};
    for (const [key, value] of Object.entries(node)) {
      // Keys are strings too - a token used as a map key must not survive.
      out[fn(key)] = walkStrings(value, fn);
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

export function createRedactor({ secrets = [] } = {}) {
  const needles = secrets
    .flatMap((s) => buildNeedles(s))
    .sort((a, b) => b.needle.length - a.needle.length);

  const serializedSafe = needles.filter(({ needle }) => isSerializationSafe(needle));

  function redactBody(raw, contentType = '') {
    if (typeof raw !== 'string') throw new TypeError('redactBody expects a string body');
    const events = new Map();
    const redactString = makeStringRedactor(needles, events);

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
            serialized = parts.join(marker(name));
          }
        }
        out = serialized;
      }
    }
    if (out === null) out = redactString(raw);

    const eventList = [...events.entries()].map(([rule, count]) => ({ rule, count }));
    // Nothing matched: return the original bytes untouched (no
    // reserialization drift for clean bodies).
    if (eventList.length === 0) return { body: raw, events: [] };
    return { body: out, events: eventList };
  }

  return { redactBody };
}
