// Tiny local dashboard: GET /__redact/ (HTML) and /__redact/stats.json.
// Shows counters and rule names only - never a secret value, never a body.
export function handleDashboard(req, res, stats) {
  const path = (req.url ?? '').split('?')[0];

  if (path === '/__redact/stats.json') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(stats.toJSON(), null, 2));
    return;
  }

  if (path === '/__redact' || path === '/__redact/') {
    const s = stats.toJSON();
    const ruleRows = Object.entries(s.perRule)
      .sort((a, b) => b[1] - a[1])
      .map(([rule, count]) => `<tr><td>${escapeHtml(rule)}</td><td>${count}</td></tr>`)
      .join('');
    const recentRows = s.recent
      .slice(0, 30)
      .map(
        (r) =>
          `<tr><td>${escapeHtml(r.time)}</td><td>${escapeHtml(r.method)}</td>` +
          `<td>${escapeHtml(r.path)}</td><td>${r.blocked ? 'BLOCKED' : r.redactions}</td>` +
          `<td>${escapeHtml(r.rules.join(', ') || (r.reason ?? ''))}</td></tr>`,
      )
      .join('');
    const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="3">
<title>llm-redact-proxy</title>
<style>
body{font-family:ui-monospace,monospace;margin:2rem;background:#111;color:#ddd}
h1{font-size:1.2rem}h2{font-size:1rem;margin-top:1.5rem}
table{border-collapse:collapse;margin-top:.5rem}
td,th{border:1px solid #444;padding:.25rem .6rem;text-align:left;font-size:.85rem}
.k{color:#8c8}.warn{color:#e88}
</style></head><body>
<h1>llm-redact-proxy</h1>
<p>since ${escapeHtml(s.startedAt)} &middot; requests <span class="k">${s.totals.requests}</span>
&middot; with redactions <span class="k">${s.totals.redactedRequests}</span>
&middot; total redactions <span class="k">${s.totals.redactions}</span>
&middot; blocked <span class="warn">${s.totals.blocked}</span></p>
<h2>redactions by rule</h2>
<table><tr><th>rule</th><th>count</th></tr>${ruleRows || '<tr><td colspan="2">none yet</td></tr>'}</table>
<h2>recent requests</h2>
<table><tr><th>time</th><th>method</th><th>path</th><th>redactions</th><th>rules</th></tr>
${recentRows || '<tr><td colspan="5">none yet</td></tr>'}</table>
<p style="color:#777">values are never shown or stored - rule names and counts only</p>
</body></html>`;
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html);
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[c]);
}
