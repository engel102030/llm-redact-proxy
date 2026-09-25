// Continuation over the Codex WebSocket transport. After a response the
// backend keeps the conversation server-side, so the next turn can send
// only the NEW input items plus previous_response_id. This registry keeps,
// per conversation, a normalized transcript of what the server holds and
// decides whether the client's translated input still matches it (send a
// delta) or not (send everything again). Nothing here talks to the network.
//
// Normalization: reasoning items are ignored (every one the client replays
// was produced by the server, which already holds it), consecutive
// assistant messages are merged (the client replays them as one message),
// and function_call arguments are compared as JSON values.
export const CONTINUATION_TTL_MS = 30 * 60 * 1000;
export const MAX_CONVERSATIONS = 200;

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function signatureOf(t) {
  return canonical({
    model: t.model,
    instructions: t.instructions ?? '',
    tools: t.tools ?? [],
    tool_choice: t.tool_choice ?? null,
    parallel_tool_calls: t.parallel_tool_calls ?? null,
    reasoning: t.reasoning ?? null,
  });
}

// -> [{ key, rawEnd }]: comparable key per normalized item and the index of
// the last raw item that contributed to it.
function normalize(items) {
  const out = [];
  for (let i = 0; i < items.length; i += 1) {
    const raw = items[i];
    if (!raw || typeof raw !== 'object' || raw.type === 'reasoning') continue;
    if (raw.type === 'function_call') {
      let args = raw.arguments;
      if (typeof args === 'string') {
        try {
          args = JSON.parse(args);
        } catch {
          // keep the raw string
        }
      }
      out.push({ value: { type: 'function_call', call_id: raw.call_id, name: raw.name, args }, rawEnd: i });
      continue;
    }
    if (raw.type === 'message' && raw.role === 'assistant') {
      const last = out[out.length - 1];
      if (last && last.value.type === 'message' && last.value.role === 'assistant') {
        last.value = { ...last.value, content: last.value.content.concat(raw.content ?? []) };
        last.rawEnd = i;
        continue;
      }
      out.push({ value: { type: 'message', role: 'assistant', content: [...(raw.content ?? [])] }, rawEnd: i });
      continue;
    }
    out.push({ value: raw, rawEnd: i });
  }
  return out.map((e) => ({ key: canonical(e.value), rawEnd: e.rawEnd }));
}

export function createContinuationRegistry({ now = Date.now, maxConversations = MAX_CONVERSATIONS, ttlMs = CONTINUATION_TTL_MS } = {}) {
  const states = new Map(); // conversation key -> { signature, transcript: string[], responseId, updatedAt }

  const full = (translated, reason) => ({ mode: 'full', input: translated.input, previousResponseId: null, reason });

  function plan(key, translated) {
    if (!key) return full(translated, 'no conversation key');
    const state = states.get(key);
    if (!state) return full(translated, 'no state');
    if (now() - state.updatedAt > ttlMs) {
      states.delete(key);
      return full(translated, 'expired');
    }
    if (signatureOf(translated) !== state.signature) return full(translated, 'prompt changed');
    const client = normalize(translated.input);
    const known = state.transcript;
    if (client.length < known.length) return full(translated, 'history shorter than the server transcript');
    for (let i = 0; i < known.length; i += 1) {
      if (client[i].key !== known[i]) return full(translated, 'history changed');
    }
    const boundary = known.length === 0 ? 0 : client[known.length - 1].rawEnd + 1;
    const delta = translated.input.slice(boundary).filter((item) => item && item.type !== 'reasoning');
    if (delta.length === 0) return full(translated, 'nothing new to send');
    return { mode: 'delta', input: delta, previousResponseId: state.responseId, reason: null };
  }

  // Record what the server now holds: the client's full input of this turn
  // plus the response's output items, normalized.
  function commit(key, { translated, responseId, outputItems = [] }) {
    if (!key || !responseId) return;
    const transcript = normalize([...(translated.input ?? []), ...outputItems]).map((e) => e.key);
    states.delete(key);
    states.set(key, { signature: signatureOf(translated), transcript, responseId, updatedAt: now() });
    while (states.size > maxConversations) states.delete(states.keys().next().value);
  }

  function invalidate(key) {
    states.delete(key);
  }

  return { plan, commit, invalidate, size: () => states.size };
}
