// Native Codex compaction for Claude Code's /compact.
//
// Claude Code compacts by asking the model for a text summary and replacing
// its history with that text. The Codex backend has its own compaction: the
// conversation plus a `compaction_trigger` item returns an encrypted
// `compaction` item that later stands in for the history (verified live).
// On a compaction turn the proxy first fetches that item and keeps a native
// history (the most recent user/developer messages within a token budget,
// then the item); the summarize turn then runs as usual and the text the
// model wrote is the anchor. On later turns whose first conversation
// message carries that anchor text (Claude Code's "This session is being
// continued..." message), the native history replaces it. Pure logic; the
// handler does the network calls.
export const COMPACT_MESSAGE_PREFIX = 'CRITICAL: Respond with TEXT ONLY. Do NOT call any tools.';
export const COMPACT_MESSAGE_TASK = 'Your task is to create a detailed summary of the conversation so far';
export const RETAINED_MESSAGE_TOKEN_BUDGET = 20_000;
export const MIN_SUMMARY_BYTES = 32;
export const COMPACTION_TTL_MS = 12 * 60 * 60 * 1000;
export const MAX_COMPACTIONS = 50;

const isMessage = (item, role) => item && item.type === 'message' && (role === undefined || item.role === role);
const textParts = (item) => (Array.isArray(item?.content) ? item.content.filter((p) => p && (p.type === 'input_text' || p.type === 'output_text') && typeof p.text === 'string') : []);
const textOf = (item) => textParts(item).map((p) => p.text).join('');
const isCompactText = (text) => text.includes(COMPACT_MESSAGE_PREFIX) && text.includes(COMPACT_MESSAGE_TASK);

// The LAST user message carries Claude Code's compaction instruction.
export function isCompactionTurn(translated) {
  const input = translated?.input;
  if (!Array.isArray(input)) return false;
  for (let i = input.length - 1; i >= 0; i -= 1) {
    if (isMessage(input[i], 'user')) return textParts(input[i]).some((p) => isCompactText(p.text));
  }
  return false;
}

// Leading developer messages (Claude Code's system prompt, hooks) are the
// envelope; everything after is the conversation.
export function splitEnvelope(input) {
  let n = 0;
  while (n < input.length && isMessage(input[n], 'developer')) n += 1;
  return { envelope: input.slice(0, n), conversation: input.slice(n) };
}

// Remove the compaction instruction from the last user message (drop the
// message when nothing else is left).
export function stripCompactionInstruction(conversation) {
  const out = conversation.slice();
  const last = out[out.length - 1];
  if (isMessage(last, 'user') && Array.isArray(last.content)) {
    const content = last.content.filter((p) => !(p && p.type === 'input_text' && typeof p.text === 'string' && isCompactText(p.text)));
    if (content.length === 0) out.pop();
    else out[out.length - 1] = { ...last, content };
  }
  return out;
}

const partTokens = (p) => (p && p.type === 'input_image' ? 2000 : Math.ceil((typeof p?.text === 'string' ? p.text.length : 0) / 4));
const messageTokens = (item) => (Array.isArray(item.content) ? item.content.reduce((a, p) => a + partTokens(p), 0) : 0);

function truncateMessage(item, maxTokens) {
  let remaining = maxTokens * 4;
  const content = [];
  for (const p of item.content) {
    if (p && p.type === 'input_image') {
      content.push(p);
    } else if (typeof p?.text === 'string') {
      if (remaining <= 0) continue;
      const text = p.text.length > remaining ? `${p.text.slice(0, remaining)}...` : p.text;
      remaining -= p.text.length;
      content.push({ ...p, text });
    }
  }
  return content.length ? { ...item, content } : null;
}

// The most recent user/developer messages that fit the budget (an oversized
// one is truncated), oldest first, then the compaction item.
export function buildNativeHistory(conversation, compactionItem, budgetTokens = RETAINED_MESSAGE_TOKEN_BUDGET) {
  const retained = [];
  let remaining = budgetTokens;
  for (let i = conversation.length - 1; i >= 0 && remaining > 0; i -= 1) {
    const item = conversation[i];
    if (!isMessage(item) || (item.role !== 'user' && item.role !== 'developer')) continue;
    const tokens = Math.max(1, messageTokens(item));
    if (tokens <= remaining) {
      retained.push(item);
      remaining -= tokens;
    } else {
      const cut = truncateMessage(item, remaining);
      if (cut) retained.push(cut);
      remaining = 0;
    }
  }
  retained.reverse();
  retained.push(compactionItem);
  return retained;
}

// What Claude Code will store: the <summary> block of the assistant text if
// there is one, else the whole text. null when too short to anchor safely.
export function summaryFromOutputItems(items) {
  const text = (items ?? [])
    .filter((i) => isMessage(i, 'assistant'))
    .map(textOf)
    .join('')
    .trim();
  let summary = text;
  const open = text.indexOf('<summary>');
  if (open >= 0) {
    const close = text.indexOf('</summary>', open);
    if (close > open) summary = text.slice(open + '<summary>'.length, close).trim();
  }
  return Buffer.byteLength(summary, 'utf8') >= MIN_SUMMARY_BYTES ? summary : null;
}

function countOccurrences(haystack, needle) {
  let count = 0;
  let from = 0;
  for (;;) {
    const i = haystack.indexOf(needle, from);
    if (i < 0) return count;
    count += 1;
    from = i + needle.length;
  }
}

export function createCompactionRegistry({ now = Date.now, ttlMs = COMPACTION_TTL_MS, maxStates = MAX_COMPACTIONS } = {}) {
  const states = new Map(); // key -> { phase, model, nativeHistory, summaryText, updatedAt }

  function begin(key, { model, nativeHistory }) {
    if (!key || !Array.isArray(nativeHistory) || nativeHistory.length === 0) return;
    states.delete(key);
    states.set(key, { phase: 'pending', model, nativeHistory, summaryText: null, updatedAt: now() });
    while (states.size > maxStates) states.delete(states.keys().next().value);
  }

  function anchor(key, { model, summaryText }) {
    const state = states.get(key);
    if (!state) return;
    if (state.model !== model || typeof summaryText !== 'string' || Buffer.byteLength(summaryText, 'utf8') < MIN_SUMMARY_BYTES) {
      states.delete(key);
      return;
    }
    state.phase = 'anchored';
    state.summaryText = summaryText;
    state.updatedAt = now();
  }

  // The translated request with the summary message swapped for the native
  // history, or null when nothing applies (state cleared on a mismatch).
  function replay(key, translated) {
    const state = key ? states.get(key) : null;
    if (!state || state.phase !== 'anchored') return null;
    if (now() - state.updatedAt > ttlMs || state.model !== translated.model) {
      states.delete(key);
      return null;
    }
    const { envelope, conversation } = splitEnvelope(translated.input ?? []);
    const first = conversation[0];
    if (!isMessage(first, 'user') || countOccurrences(textOf(first), state.summaryText) !== 1) {
      states.delete(key);
      return null;
    }
    if (conversation.length === 1) return null;
    state.updatedAt = now();
    return { ...translated, input: [...envelope, ...state.nativeHistory, ...conversation.slice(1)] };
  }

  return { begin, anchor, replay, clear: (key) => states.delete(key), size: () => states.size };
}
