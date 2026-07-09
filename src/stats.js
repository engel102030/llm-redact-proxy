// In-memory counters + per-request lifecycle. NEVER logs matched values or
// request/response bodies - only rule names, counts, paths (query stripped),
// status codes, timings, byte sizes and token usage numbers.
export function createStats({ log = console.log } = {}) {
  const startedAtMs = Date.now();
  const startedAt = new Date(startedAtMs).toISOString();
  const totals = {
    requests: 0,
    redactedRequests: 0,
    redactions: 0,
    blocked: 0,
    inputTokens: 0,
    outputTokens: 0,
  };
  const perRule = new Map();
  const recent = [];
  const MAX_RECENT = 200;
  let seq = 0;

  const safePath = (p) => String(p ?? '-').split('?')[0];

  // Opens a request record (called when the request is redacted/forwarded or
  // blocked). Returns the entry so the caller can finish() it once the
  // upstream response completes.
  function record({ method = '-', path = '-', events = [], captures = [], blocked = false, reason = null, reqBytes = 0 }) {
    totals.requests += 1;
    let count = 0;
    for (const e of events) {
      count += e.count;
      perRule.set(e.rule, (perRule.get(e.rule) ?? 0) + e.count);
    }
    totals.redactions += count;
    if (count > 0) totals.redactedRequests += 1;
    if (blocked) totals.blocked += 1;

    seq += 1;
    const entry = {
      id: seq,
      time: new Date().toISOString(),
      method,
      path: safePath(path),
      redactions: count,
      rules: events.map((e) => `${e.rule} x${e.count}`),
      // Actual matched values, retained ONLY when the caller opted in (else []).
      // Held here in memory; served exclusively via the guarded reveal method,
      // never through toJSON() / the open stats feed.
      captures: Array.isArray(captures) ? captures : [],
      blocked,
      reason,
      status: blocked ? 'blocked' : null,
      durationMs: null,
      inputTokens: null,
      outputTokens: null,
      reqBytes,
      respBytes: null,
    };
    recent.unshift(entry);
    if (recent.length > MAX_RECENT) recent.pop();

    const p = entry.path;
    if (blocked) {
      log(`[redact] BLOCKED ${method} ${p} (${reason})`);
    } else if (count > 0) {
      log(`[redact] ${method} ${p} redacted ${count} (${entry.rules.join(', ')})`);
    } else {
      log(`[redact] ${method} ${p} clean`);
    }
    return entry;
  }

  // Completes a record once the upstream response is done.
  function finish(entry, { status = null, durationMs = null, inputTokens = null, outputTokens = null, respBytes = null } = {}) {
    if (!entry) return;
    entry.status = status;
    entry.durationMs = durationMs;
    entry.inputTokens = inputTokens;
    entry.outputTokens = outputTokens;
    entry.respBytes = respBytes;
    if (inputTokens) totals.inputTokens += inputTokens;
    if (outputTokens) totals.outputTokens += outputTokens;
    const tok = inputTokens || outputTokens ? ` tok in ${inputTokens ?? 0}/out ${outputTokens ?? 0}` : '';
    log(`[redact] ${entry.method} ${entry.path} -> ${status ?? '-'} ${durationMs ?? '?'}ms${tok}`);
  }

  // Open feed: NEVER includes matched values. Strips captures from every entry.
  function toJSON() {
    return {
      startedAt,
      uptimeSec: Math.floor((Date.now() - startedAtMs) / 1000),
      totals: { ...totals },
      perRule: Object.fromEntries(perRule),
      recent: recent.map(({ captures, ...rest }) => rest),
    };
  }

  // Guarded reveal: the actual matched values. Only served to the local panel
  // via the CSRF-guarded /__redact/values endpoint. Per-request captures plus a
  // per-rule set of distinct values (from the retained recent window).
  function revealValues() {
    const perRuleValues = {};
    for (const e of recent) {
      for (const { rule, value } of e.captures ?? []) {
        (perRuleValues[rule] ??= new Set()).add(value);
      }
    }
    return {
      recent: recent.map((e) => ({ id: e.id, captures: e.captures ?? [] })),
      perRuleValues: Object.fromEntries(
        Object.entries(perRuleValues).map(([rule, set]) => [rule, [...set]]),
      ),
    };
  }

  return { record, finish, toJSON, revealValues };
}
