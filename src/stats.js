// In-memory counters + per-request log line. NEVER logs matched values or
// request bodies - only rule names, counts and paths (query string stripped).
export function createStats({ log = console.log } = {}) {
  const startedAt = new Date().toISOString();
  const totals = { requests: 0, redactedRequests: 0, redactions: 0, blocked: 0 };
  const perRule = new Map();
  const recent = [];
  const MAX_RECENT = 100;

  const safePath = (p) => String(p ?? '-').split('?')[0];

  function record({ method = '-', path = '-', events = [], blocked = false, reason = null }) {
    totals.requests += 1;
    let count = 0;
    for (const e of events) {
      count += e.count;
      perRule.set(e.rule, (perRule.get(e.rule) ?? 0) + e.count);
    }
    totals.redactions += count;
    if (count > 0) totals.redactedRequests += 1;
    if (blocked) totals.blocked += 1;

    recent.unshift({
      time: new Date().toISOString(),
      method,
      path: safePath(path),
      redactions: count,
      rules: events.map((e) => `${e.rule} x${e.count}`),
      blocked,
      reason,
    });
    if (recent.length > MAX_RECENT) recent.pop();

    const p = safePath(path);
    if (blocked) {
      log(`[redact] BLOCKED ${method} ${p} (${reason})`);
    } else if (count > 0) {
      log(`[redact] ${method} ${p} redacted ${count} (${events.map((e) => `${e.rule} x${e.count}`).join(', ')})`);
    } else {
      log(`[redact] ${method} ${p} clean`);
    }
  }

  function toJSON() {
    return {
      startedAt,
      totals: { ...totals },
      perRule: Object.fromEntries(perRule),
      recent: [...recent],
    };
  }

  return { record, toJSON };
}
