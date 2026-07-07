// Known-secrets loader (Layer A input). Reads NAME=VALUE lines from the
// gitignored secrets file and expands each value into every encoded form it
// can appear as in a request body. Matching is plain substring search - no
// regex, no backtracking risk.
import fs from 'node:fs';

export const MIN_SECRET_LENGTH = 6;
// A needle shorter than this matches too much unrelated text to be safe.
const MIN_NEEDLE_LENGTH = 6;

export function parseSecretsFile(text) {
  const secrets = [];
  let autoIndex = 0;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    let name;
    let value;
    const keyMatch = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(trimmed);
    if (keyMatch) {
      name = keyMatch[1];
      value = keyMatch[2];
    } else {
      autoIndex += 1;
      name = `SECRET_${autoIndex}`;
      value = trimmed;
    }
    if (value.length < MIN_SECRET_LENGTH) {
      console.warn(`[secrets] skipping "${name}": value shorter than ${MIN_SECRET_LENGTH} chars`);
      continue;
    }
    secrets.push({ name, value });
  }
  return secrets;
}

export function loadSecrets(filePath) {
  if (!fs.existsSync(filePath)) {
    console.warn(
      `[secrets] WARNING: secrets file not found at ${filePath} - ` +
        'Layer A (known secrets) is EMPTY; only the regex layer is active.',
    );
    return [];
  }
  return parseSecretsFile(fs.readFileSync(filePath, 'utf8'));
}

// Base64 of a value embedded mid-stream depends on its byte offset % 3 inside
// the enclosing blob (e.g. "Basic base64(user:pass)"). For each offset we
// compute the stable core: leading chars that mix with preceding bytes are
// dropped, and one trailing char is dropped when the tail group mixes with
// following bytes.
const B64_DROP_LEADING = [0, 2, 3];

function base64Cores(bytes, alphabet) {
  const cores = new Set();
  for (let k = 0; k < 3; k += 1) {
    const padded = Buffer.concat([Buffer.alloc(k), bytes]);
    let enc = padded.toString('base64').replace(/=+$/, '');
    if (alphabet === 'base64url') enc = enc.replace(/\+/g, '-').replace(/\//g, '_');
    let core = enc.slice(B64_DROP_LEADING[k]);
    if ((k + bytes.length) % 3 !== 0) core = core.slice(0, -1);
    if (core.length >= MIN_NEEDLE_LENGTH) cores.add(core);
  }
  return [...cores];
}

function percentEncodeAll(bytes) {
  let out = '';
  for (const b of bytes) out += `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
  return out;
}

export function buildNeedles({ name, value }) {
  const bytes = Buffer.from(value, 'utf8');
  const candidates = new Set();

  candidates.add(value);

  const jsonEscaped = JSON.stringify(value).slice(1, -1);
  if (jsonEscaped !== value) candidates.add(jsonEscaped);

  const urlEncoded = encodeURIComponent(value);
  if (urlEncoded !== value) candidates.add(urlEncoded);
  candidates.add(percentEncodeAll(bytes));

  // Exact padded form first (clean replacement when the whole value was
  // encoded standalone), then the offset-aligned cores. For every base64
  // form also add its url-encoded shape ("+/=" become %2B %2F %3D), which
  // is how encoded credentials travel in query strings and webhooks.
  const addWithUrlForm = (enc) => {
    candidates.add(enc);
    const urlForm = encodeURIComponent(enc);
    if (urlForm !== enc) candidates.add(urlForm);
  };
  addWithUrlForm(bytes.toString('base64'));
  for (const core of base64Cores(bytes, 'base64')) addWithUrlForm(core);
  addWithUrlForm(bytes.toString('base64url'));
  for (const core of base64Cores(bytes, 'base64url')) addWithUrlForm(core);

  candidates.add(bytes.toString('hex'));
  candidates.add(bytes.toString('hex').toUpperCase());

  return [...candidates]
    .filter((needle) => needle.length >= MIN_NEEDLE_LENGTH)
    .sort((a, b) => b.length - a.length)
    .map((needle) => ({ name, needle }));
}
