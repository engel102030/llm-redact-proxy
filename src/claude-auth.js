// Reads the local Claude Code subscription OAuth token so the proxy can
// authenticate to the OFFICIAL Anthropic API as the logged-in user (auth mode
// "oauth"). The token is read from the credentials file or the macOS Keychain
// and cached briefly. It is NEVER logged, and callers MUST only send it to
// *.anthropic.com (enforced in runtime + proxy).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const CACHE_MS = 30_000;
let cache = { at: 0, value: null };

function extract(raw) {
  const j = JSON.parse(raw);
  const o = j.claudeAiOauth || j;
  if (!o || !o.accessToken) return null;
  return { accessToken: o.accessToken, expiresAt: o.expiresAt ?? o.expires_at ?? null };
}

function readFresh() {
  const override = process.env.CLAUDE_CREDENTIALS_FILE;
  const file = override || path.join(os.homedir(), '.claude', '.credentials.json');
  try {
    return extract(fs.readFileSync(file, 'utf8'));
  } catch {
    // fall through to Keychain
  }
  // The Keychain holds the credential on macOS. Skip it when an explicit file
  // override is set (tests / non-mac).
  if (!override && process.platform === 'darwin') {
    try {
      const raw = execFileSync(
        'security',
        ['find-generic-password', '-s', 'Claude Code-credentials', '-w'],
        { encoding: 'utf8' },
      );
      return extract(raw);
    } catch {
      // no keychain item
    }
  }
  return null;
}

// nowMs is injectable so tests are not tied to the wall clock.
export function readClaudeOAuth(nowMs = Date.now()) {
  if (cache.value && nowMs - cache.at < CACHE_MS) return cache.value;
  const value = readFresh();
  cache = { at: nowMs, value };
  return value;
}

export function clearClaudeOAuthCache() {
  cache = { at: 0, value: null };
}

export function isAnthropicHost(url) {
  const host = url?.hostname ?? '';
  return host === 'anthropic.com' || host.endsWith('.anthropic.com');
}

// Beta flag the official Anthropic API requires to accept a subscription OAuth
// token. (The 1M-context beta is NOT added: this subscription is not eligible
// for it - the API returns "long context beta is not yet available for this
// subscription" - so forcing it would break every request.)
export const OAUTH_BETA_FLAGS = ['oauth-2025-04-20'];

// Rewrites request headers to authenticate with the subscription OAuth token:
// drop x-api-key, set the Bearer, and ensure the required beta flags are
// present (merged with any existing anthropic-beta list). Mutates and returns
// the headers object.
export function applyOAuthHeaders(headers, accessToken) {
  delete headers['x-api-key'];
  headers.authorization = `Bearer ${accessToken}`;
  const present = String(headers['anthropic-beta'] ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const flag of OAUTH_BETA_FLAGS) if (!present.includes(flag)) present.push(flag);
  headers['anthropic-beta'] = present.join(',');
  return headers;
}
