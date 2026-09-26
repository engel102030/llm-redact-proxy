// Local management dashboard: GET /__redact/ (HTML panel), /__redact/stats.json
// (live JSON, polled by the panel), /__redact/config (GET current provider
// settings, POST to change them live), and /__redact/values (guarded reveal of
// matched values, opt-in). The open feed never carries a secret value; values
// are served only to the local panel via the CSRF-guarded endpoint. The
// provider key is write-only (never returned).
export function handleDashboard(req, res, stats, meta = {}, controller = null) {
  const path = (req.url ?? '').split('?')[0];
  const method = req.method ?? 'GET';
  const json = (code, obj) => {
    res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(obj));
  };
  // Read a small JSON request body, then hand it to the callback. 400 on bad JSON.
  const readJson = (handler) => {
    let body = '';
    req.on('data', (c) => {
      body += c;
      if (body.length > 262144) req.destroy();
    });
    req.on('end', () => {
      let parsed;
      try {
        parsed = JSON.parse(body || '{}');
      } catch {
        return json(400, { ok: false, error: 'invalid json' });
      }
      handler(parsed);
    });
  };

  if (path === '/__redact/config') {
    if (!controller) return json(404, { error: 'config not available' });
    if (method === 'GET') return json(200, controller.publicSettings());
    if (method === 'POST') {
      // CSRF guard: a custom header a cross-site page cannot set without a
      // CORS preflight we never grant. Blocks a malicious site from POSTing
      // to 127.0.0.1 to repoint the provider.
      if (req.headers['x-redact-panel'] !== '1') {
        return json(403, { ok: false, error: 'missing panel header' });
      }
      let body = '';
      req.on('data', (c) => {
        body += c;
        if (body.length > 65536) req.destroy();
      });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body || '{}');
          const patch = {};
          for (const k of ['upstreamUrl', 'upstreamAuth', 'upstreamKey', 'redactMode', 'restoreMarkers', 'showRedactedValues']) {
            if (k in parsed) patch[k] = parsed[k];
          }
          controller.apply(patch);
          json(200, { ok: true, settings: controller.publicSettings() });
        } catch (err) {
          json(400, { ok: false, error: err.message });
        }
      });
      return;
    }
    return json(405, { error: 'method not allowed' });
  }

  if (path === '/__redact/stats.json') {
    return json(200, { ...stats.toJSON(), meta });
  }

  // Guarded reveal of matched VALUES. Separate from the open stats feed and
  // gated by the same CSRF header, so a cross-site page cannot read secrets off
  // 127.0.0.1. Empty unless the panel enabled "show redacted values".
  if (path === '/__redact/values') {
    if (req.headers['x-redact-panel'] !== '1') {
      return json(403, { error: 'missing panel header' });
    }
    const enabled = controller?.showRedactedValues ?? false;
    if (!enabled) return json(200, { enabled: false, recent: [], perRuleValues: {} });
    return json(200, { enabled: true, ...stats.revealValues() });
  }

  // Guarded debug inspector: the full forwarded request + raw response for one
  // of the last 30 requests. Same CSRF guard. Neither body holds a user secret
  // (request already redacted; response is vendor output before restore).
  if (path === '/__redact/inspect') {
    if (req.headers['x-redact-panel'] !== '1') {
      return json(403, { error: 'missing panel header' });
    }
    const id = new URL(req.url ?? '', 'http://x').searchParams.get('id');
    const b = stats.getBodies ? stats.getBodies(id) : null;
    if (!b) return json(404, { error: 'not captured (only the last 30 are kept)' });
    return json(200, { id: Number(id), req: b.req, resp: b.resp });
  }

  // ---- provider registry: list / create-update / activate / delete ----
  const panelGuard = () => req.headers['x-redact-panel'] === '1';
  if (path === '/__redact/providers') {
    if (!controller?.providers) return json(404, { error: 'registry not available' });
    if (method === 'GET') return json(200, controller.providers());
    if (method === 'POST') {
      if (!panelGuard()) return json(403, { ok: false, error: 'missing panel header' });
      return readJson((p) => {
        try {
          const registry = controller.upsertProvider(p.id, {
            label: p.label,
            url: p.url,
            auth: p.auth,
            key: p.key,
            headers: p.headers,
            aliases: p.aliases,
          });
          json(200, { ok: true, registry });
        } catch (err) {
          json(400, { ok: false, error: err.message });
        }
      });
    }
    return json(405, { error: 'method not allowed' });
  }
  if (path === '/__redact/providers/activate' && method === 'POST') {
    if (!panelGuard()) return json(403, { ok: false, error: 'missing panel header' });
    if (!controller?.activateProvider) return json(404, { error: 'registry not available' });
    return readJson((p) => {
      try {
        json(200, { ok: true, registry: controller.activateProvider(p.id) });
      } catch (err) {
        json(400, { ok: false, error: err.message });
      }
    });
  }
  if (path === '/__redact/providers/delete' && method === 'POST') {
    if (!panelGuard()) return json(403, { ok: false, error: 'missing panel header' });
    if (!controller?.removeProvider) return json(404, { error: 'registry not available' });
    return readJson((p) => {
      try {
        json(200, { ok: true, registry: controller.removeProvider(p.id) });
      } catch (err) {
        json(400, { ok: false, error: err.message });
      }
    });
  }
  // ---- Codex (ChatGPT subscription) login / logout ----
  // login: starts the PKCE flow (callback listener on localhost:1455) and
  // returns the authorize URL the panel opens in a new tab. The listener
  // stores the tokens in the registry; the panel polls /__redact/providers.
  if (path === '/__redact/providers/codex/login' && method === 'POST') {
    if (!panelGuard()) return json(403, { ok: false, error: 'missing panel header' });
    if (!controller?.codexLogin) return json(404, { error: 'registry not available' });
    return readJson((p) => {
      controller
        .codexLogin(p.id)
        .then((r) => json(200, { ok: true, url: r.url, port: r.port }))
        .catch((err) => {
          const busy = err.code === 'EADDRINUSE' || err.code === 'LOGIN_IN_PROGRESS';
          json(busy ? 409 : 400, { ok: false, error: busy ? `${err.message} (port 1455 busy or a login already open)` : err.message });
        });
    });
  }
  if (path === '/__redact/providers/codex/logout' && method === 'POST') {
    if (!panelGuard()) return json(403, { ok: false, error: 'missing panel header' });
    if (!controller?.codexLogout) return json(404, { error: 'registry not available' });
    return readJson((p) => {
      try {
        json(200, { ok: true, registry: controller.codexLogout(p.id) });
      } catch (err) {
        json(400, { ok: false, error: err.message });
      }
    });
  }
  // Server-side fetch of a provider's real model list (uses its key + custom
  // headers, so it can clear a Cloudflare gate the browser cannot). Ids only.
  if (path === '/__redact/provider/models') {
    if (!panelGuard()) return json(403, { error: 'missing panel header' });
    if (!controller?.providerFor) return json(404, { error: 'registry not available' });
    const id = new URL(req.url ?? '', 'http://x').searchParams.get('id');
    const p = controller.providerFor(id);
    if (!p) return json(404, { error: 'unknown provider' });
    // A ChatGPT login has no /v1/models: the list comes from the Codex
    // backend with the stored token (and is persisted on the provider).
    if (p.auth === 'codex-oauth' && controller.codexFetchModels) {
      controller
        .codexFetchModels(id)
        .then((models) => json(200, { ok: true, status: 200, models }))
        .catch((e) => json(e.code === 'NOT_LOGGED_IN' ? 400 : 502, { ok: false, status: e.code === 'NOT_LOGGED_IN' ? 400 : 502, error: e.message }));
      return;
    }
    fetchProviderModels(p)
      .then((r) => json(r.ok ? 200 : 502, r))
      .catch((e) => json(502, { ok: false, error: String(e) }));
    return;
  }

  // ---- clear all counters + the recent-request log ----
  if (path === '/__redact/reset' && method === 'POST') {
    if (!panelGuard()) return json(403, { ok: false, error: 'missing panel header' });
    if (stats.reset) stats.reset();
    return json(200, { ok: true });
  }

  if (path === '/__redact' || path === '/__redact/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(PAGE);
    return;
  }

  return json(404, { error: 'not found' });
}

// Fetch a provider's real /v1/models list server-side, with its key + custom
// headers (e.g. a browser User-Agent to clear Cloudflare). Returns ids only.
async function fetchProviderModels(provider) {
  const base = String(provider.url ?? '').replace(/\/$/, '');
  if (!base) return { ok: false, status: 0, error: 'provider has no url' };
  const headers = { 'anthropic-version': '2023-06-01', accept: 'application/json', ...(provider.headers ?? {}) };
  if (provider.auth === 'replace' && provider.key) {
    headers['x-api-key'] = provider.key;
    headers.authorization = `Bearer ${provider.key}`;
  }
  let r;
  try {
    r = await fetch(`${base}/v1/models`, { headers });
  } catch (e) {
    return { ok: false, status: 0, error: String(e?.message ?? e) };
  }
  const text = await r.text();
  if (!r.ok) return { ok: false, status: r.status, error: text.slice(0, 200) };
  let models = [];
  try {
    const data = JSON.parse(text).data;
    if (Array.isArray(data)) models = data.map((m) => m && m.id).filter((x) => typeof x === 'string');
  } catch {
    return { ok: false, status: r.status, error: 'upstream /v1/models was not a JSON list' };
  }
  return { ok: true, status: r.status, models };
}

const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>llm-redact-proxy</title>
<style>
:root{
  --bg:#0a0d13; --grad:radial-gradient(1200px 600px at 80% -10%,#141c2e 0,transparent 60%),radial-gradient(900px 500px at -10% 10%,#151226 0,transparent 55%);
  --card:#111722; --card2:#0d1119; --line:#212a39; --line2:#2c384b;
  --fg:#e8eef7; --dim:#94a2b8; --faint:#5f6d83;
  --accent:#6ea8fe; --accent-ink:#06152f; --accent2:#a78bfa;
  --green:#4ade80; --red:#f87171; --amber:#fbbf24;
  --shadow:0 1px 0 rgba(255,255,255,.03) inset,0 8px 24px -12px rgba(0,0,0,.6);
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme:light){:root{
  --bg:#eef1f7; --grad:radial-gradient(1200px 600px at 80% -10%,#dfe7fb 0,transparent 60%),radial-gradient(900px 500px at -10% 10%,#e7e2fb 0,transparent 55%);
  --card:#ffffff; --card2:#f6f8fc; --line:#e4e9f2; --line2:#d3dbe8;
  --fg:#141b28; --dim:#5b6678; --faint:#8b95a6;
  --accent:#3b6fe0; --accent-ink:#ffffff; --accent2:#7256e8;
  --green:#16a34a; --red:#dc2626; --amber:#d97706;
  --shadow:0 1px 2px rgba(16,24,40,.04),0 8px 24px -14px rgba(16,24,40,.25);
}}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);background-image:var(--grad);background-attachment:fixed;color:var(--fg);
  font-family:var(--sans);font-size:14px;line-height:1.45;-webkit-font-smoothing:antialiased}
.app{max-width:1180px;margin:0 auto;padding:0 20px 64px}
a{color:var(--accent)}

header{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:14px;flex-wrap:wrap;
  padding:16px 20px;margin:0 -20px 20px;background:color-mix(in srgb,var(--bg) 78%,transparent);
  backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:9px;font-weight:650;font-size:15px;letter-spacing:-.01em}
.brand .logo{width:26px;height:26px;border-radius:7px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--accent),var(--accent2));color:var(--accent-ink);font-size:14px}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-left:4px}
.chip{font-size:11.5px;color:var(--dim);background:var(--card2);border:1px solid var(--line);
  border-radius:999px;padding:3px 9px;white-space:nowrap}
.chip b{color:var(--fg);font-weight:600}
.live{margin-left:auto;display:flex;align-items:center;gap:6px;font-size:12px;color:var(--green);font-weight:600}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 0 color-mix(in srgb,var(--green) 60%,transparent);animation:pulse 1.8s infinite}
.live.stale{color:var(--amber)}.live.stale .dot{background:var(--amber)}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--green) 55%,transparent)}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}

.card{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);margin:18px 0}
.card>.hd{display:flex;align-items:center;gap:8px;padding:14px 18px;border-bottom:1px solid var(--line)}
.card>.hd h2{margin:0;font-size:12px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--dim)}
.card>.bd{padding:18px}

.form{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}
.f label.lbl{display:block;color:var(--dim);font-size:12px;font-weight:550;margin-bottom:6px}
.f input[type=text],.f input[type=password],.f input:not([type]),.f select{width:100%;background:var(--card2);color:var(--fg);
  border:1px solid var(--line2);border-radius:9px;padding:10px 11px;font:inherit;transition:border-color .15s,box-shadow .15s}
.f input:focus,.f select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
.f select{appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--dim) 50%),linear-gradient(135deg,var(--dim) 50%,transparent 50%);
  background-position:calc(100% - 16px) 55%,calc(100% - 11px) 55%;background-size:5px 5px,5px 5px;background-repeat:no-repeat;padding-right:30px}
.hint{color:var(--faint);font-size:12px;margin-top:6px;line-height:1.5}
.span2{grid-column:1/-1}
.linkbtn{background:none;border:0;color:var(--accent);font:inherit;font-size:12.5px;cursor:pointer;padding:2px 0;text-decoration:underline;text-underline-offset:2px}
.ip{background:var(--card2);color:var(--fg);border:1px solid var(--line2);border-radius:8px;padding:8px 10px;font:inherit;font-size:13px}
.ip:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 20%,transparent)}
.caprow{align-items:center}

.toggles{display:grid;gap:2px;margin-top:16px;border-top:1px solid var(--line);padding-top:6px}
.toggle{display:flex;gap:12px;align-items:flex-start;padding:12px 2px;border-bottom:1px solid var(--line)}
.toggle:last-child{border-bottom:0}
.tg-body{flex:1}.tg-title{font-weight:600;font-size:13.5px}.tg-hint{color:var(--faint);font-size:12px;margin-top:3px;line-height:1.5}
.switch{position:relative;display:inline-block;width:40px;height:23px;flex:none;margin-top:1px}
.switch input{opacity:0;width:0;height:0}
.switch .sl{position:absolute;inset:0;background:var(--line2);border-radius:999px;cursor:pointer;transition:.18s}
.switch .sl:before{content:"";position:absolute;width:17px;height:17px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.18s;box-shadow:0 1px 3px rgba(0,0,0,.35)}
.switch input:checked+.sl{background:var(--accent)}
.switch input:checked+.sl:before{transform:translateX(17px)}

.actions{display:flex;gap:10px;align-items:center;margin-top:18px;flex-wrap:wrap}
button.btn{background:linear-gradient(180deg,var(--accent),color-mix(in srgb,var(--accent) 85%,#000));color:var(--accent-ink);
  border:0;border-radius:9px;padding:10px 16px;font:inherit;font-weight:650;cursor:pointer;box-shadow:0 6px 16px -10px var(--accent)}
button.btn:active{transform:translateY(1px)}
button.ghost{background:transparent;color:var(--dim);border:1px solid var(--line2);border-radius:9px;padding:10px 14px;font:inherit;cursor:pointer}
button.ghost:hover{color:var(--fg);border-color:var(--dim)}
#cfgmsg{font-size:12.5px;font-weight:550}

.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow)}
.tile .n{font-size:26px;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.tile .l{color:var(--dim);font-size:11.5px;font-weight:550;text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
.tile.alert .n{color:var(--red)}

.wrap{overflow-x:auto;margin:0 -4px}
table{border-collapse:collapse;width:100%;min-width:760px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:12.5px;vertical-align:top}
thead th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em;position:sticky;top:0;background:var(--card);white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:color-mix(in srgb,var(--accent) 6%,transparent)}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.mono{font-family:var(--mono);font-size:12px}
.path{font-family:var(--mono);font-size:12px;color:var(--fg)}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:650;border:1px solid transparent}
.pill.ok{color:var(--green);background:color-mix(in srgb,var(--green) 14%,transparent);border-color:color-mix(in srgb,var(--green) 30%,transparent)}
.pill.err{color:var(--red);background:color-mix(in srgb,var(--red) 14%,transparent);border-color:color-mix(in srgb,var(--red) 30%,transparent)}
.pill.warn{color:var(--amber);background:color-mix(in srgb,var(--amber) 14%,transparent);border-color:color-mix(in srgb,var(--amber) 30%,transparent)}
.pill.mut{color:var(--dim);background:var(--card2);border-color:var(--line2)}
.ok{color:var(--green)}.err{color:var(--red)}.warn{color:var(--amber)}.mut{color:var(--dim)}.faint{color:var(--faint)}
.rulechip{display:inline-block;font-family:var(--mono);font-size:11px;color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent);
  border:1px solid color-mix(in srgb,var(--accent) 26%,transparent);border-radius:6px;padding:1px 6px;margin:1px 3px 1px 0}
.cap{font-family:var(--mono);font-size:11.5px;color:var(--amber);background:color-mix(in srgb,var(--amber) 12%,transparent);
  border:1px solid color-mix(in srgb,var(--amber) 28%,transparent);border-radius:6px;padding:1px 6px;margin:1px 3px 1px 0;cursor:pointer;
  max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom;display:inline-block}
.cap:hover{background:color-mix(in srgb,var(--amber) 22%,transparent)}
.caprow{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.caprow .rn{font-family:var(--mono);font-size:11px;color:var(--dim);min-width:120px}
.empty{color:var(--dim);font-size:12.5px}
.warnbar{display:none;margin:0 0 4px;padding:9px 12px;border-radius:9px;font-size:12px;font-weight:550;
  color:var(--amber);background:color-mix(in srgb,var(--amber) 12%,transparent);border:1px solid color-mix(in srgb,var(--amber) 30%,transparent)}
.warnbar.on{display:block}
.sechd{display:flex;align-items:center;justify-content:space-between;margin:26px 4px 10px}
.sechd h2{margin:0;font-size:12px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--dim)}
.count{font-size:11px;color:var(--faint);font-family:var(--mono)}
.hidec{display:none}
tbody tr.rowclick{cursor:pointer}
.modal{position:fixed;inset:0;z-index:20;display:none;background:rgba(3,6,12,.66);backdrop-filter:blur(3px);padding:32px}
.modal.on{display:flex}
.modal .box{margin:auto;width:min(1000px,100%);max-height:100%;display:flex;flex-direction:column;
  background:var(--card);border:1px solid var(--line2);border-radius:14px;box-shadow:0 24px 64px -24px rgba(0,0,0,.7);overflow:hidden}
.modal .top{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--line)}
.modal .top h3{margin:0;font-size:13px;font-weight:650}
.modal .top .x{margin-left:auto;background:none;border:0;color:var(--dim);font-size:20px;cursor:pointer;line-height:1;padding:0 4px}
.modal .top .x:hover{color:var(--fg)}
.modal .body{overflow:auto;padding:0}
.modal .seg{padding:14px 18px;border-bottom:1px solid var(--line)}
.modal .seg:last-child{border-bottom:0}
.modal .seg .lbl{display:flex;align-items:center;gap:8px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim);font-weight:650;margin-bottom:8px}
.modal .seg .lbl button{margin-left:auto;font-size:11px;background:var(--card2);border:1px solid var(--line2);color:var(--dim);border-radius:6px;padding:3px 8px;cursor:pointer}
.modal .seg .lbl button:hover{color:var(--fg)}
.modal pre{margin:0;white-space:pre-wrap;word-break:break-word;font-family:var(--mono);font-size:11.5px;line-height:1.55;
  color:var(--fg);background:var(--card2);border:1px solid var(--line);border-radius:9px;padding:12px;max-height:44vh;overflow:auto}
</style></head><body>
<div class="app">
<header>
  <span class="brand"><span class="logo">&#128737;</span>llm-redact-proxy</span>
  <span class="chips" id="chips"></span>
  <span class="live" id="live"><span class="dot"></span>live</span>
</header>

<div class="card">
  <div class="hd"><h2>provider configuration</h2></div>
  <div class="bd">
    <div class="form">
      <div class="f span2"><label class="lbl">Provider URL &mdash; upstream the redacted request is forwarded to</label>
        <input id="c_url" placeholder="https://your-provider.example/anthropic">
        <button class="linkbtn" id="c_official" type="button">use Official Anthropic (api.anthropic.com)</button></div>
      <div class="f"><label class="lbl">Auth to provider</label>
        <select id="c_auth">
          <option value="passthrough">passthrough &mdash; forward caller's token</option>
          <option value="replace">replace &mdash; inject the key below</option>
          <option value="oauth">oauth &mdash; my Claude subscription (official only)</option>
          <option value="codex-oauth">codex-oauth &mdash; my ChatGPT login (chatgpt.com)</option>
          </select></div>
      <div class="f"><label class="lbl">Provider key <span class="faint">(only for replace)</span></label>
        <input id="c_key" type="password" placeholder="leave blank to keep current"></div>
      <div class="f span2"><label class="lbl">Redaction mode</label>
        <select id="c_mode"></select>
        <div class="hint" id="modehint"></div></div>
    </div>

    <div class="toggles">
      <div class="toggle">
        <label class="switch"><input id="c_restore" type="checkbox"><span class="sl"></span></label>
        <div class="tg-body"><div class="tg-title">Restore {{NAME}} in responses</div>
          <div class="tg-hint">Off = safest. On: the model can write <span class="mono">{{SECRET_NAME}}</span> (or copy a <span class="mono">[REDACTED:NAME]</span> through) and the proxy substitutes the real value back locally &mdash; re-hydrating it into this machine's transcript. Named secrets only.</div></div>
      </div>
      <div class="toggle">
        <label class="switch"><input id="c_showvals" type="checkbox"><span class="sl"></span></label>
        <div class="tg-body"><div class="tg-title">Show redacted values in this panel</div>
          <div class="tg-hint">Off = safest (names + counts only). On: the panel reveals the actual matched values &mdash; your own credentials plus any dynamic token caught. Kept in memory and served only to this local panel over a guarded endpoint; never to the open stats feed.</div></div>
      </div>
    </div>

    <div class="actions">
      <button class="btn" id="c_save">Save &amp; apply</button>
      <button class="ghost" id="c_reload">Reload</button>
      <span id="cfgmsg" class="mut"></span>
    </div>
  </div>
</div>

<div class="card">
  <div class="hd"><h2>providers</h2></div>
  <div class="bd">
    <div id="provlist" class="wrap"></div>
    <div class="actions"><button class="ghost" id="p_new">+ New provider</button><span id="provmsg" class="mut"></span></div>

    <div id="proveditor" class="hidec" style="margin-top:14px;border-top:1px solid var(--line);padding-top:16px">
      <div class="form">
        <div class="f"><label class="lbl">ID (slug)</label><input id="p_id" placeholder="euromodels"></div>
        <div class="f"><label class="lbl">Label <span class="faint">(optional)</span></label><input id="p_label" placeholder="EuroModels"></div>
        <div class="f span2"><label class="lbl">Provider URL</label><input id="p_url" placeholder="https://euromodels.xyz/anthropic"></div>
        <div class="f"><label class="lbl">Auth</label>
          <select id="p_auth"><option value="replace">replace &mdash; inject key</option><option value="passthrough">passthrough</option><option value="oauth">oauth (official only)</option><option value="codex-oauth">codex-oauth (ChatGPT login)</option></select></div>
        <div class="f"><label class="lbl">Key <span class="faint">(replace)</span></label><input id="p_key" type="password" placeholder="blank keeps current"></div>
        <div class="f span2 hidec" id="codexbox"><label class="lbl">ChatGPT account</label>
          <div class="caprow"><span id="codexstatus" class="faint">not logged in</span>
            <button class="ghost" id="p_codexlogin" type="button" style="padding:6px 12px;font-size:12px">Login with ChatGPT</button>
            <button class="linkbtn" id="p_codexlogout" type="button" style="color:var(--red)">logout</button></div>
          <div class="hint">Save the provider first. Login opens auth.openai.com in a new tab; the proxy listens on localhost:1455 for the callback (the same port the Codex CLI uses). Tokens are stored in providers.json and never shown here. URL can stay blank (defaults to the Codex backend). Effort map (low/medium/high/max &rarr; Codex level) is edited in providers.json.</div></div>
        <div class="f span2"><label class="lbl">User-Agent header <span class="faint">(optional &mdash; clears Cloudflare gates)</span></label>
          <input id="p_ua" placeholder="Mozilla/5.0 (Macintosh&hellip;) Chrome/124.0 Safari/537.36"></div>
      </div>

      <div class="sechd" style="margin:20px 2px 8px">
        <h2>model aliases <span class="faint" style="text-transform:none;letter-spacing:0">custom name &rarr; real upstream id</span></h2>
        <button class="ghost" id="p_fetch">fetch models</button>
      </div>
      <div id="aliaslist"></div>
      <datalist id="modeldl"></datalist>
      <div class="actions" style="margin-top:8px"><button class="ghost" id="p_addalias">+ alias</button><span id="fetchmsg" class="faint" style="font-size:12px"></span></div>

      <div class="actions">
        <button class="btn" id="p_save">Save provider</button>
        <button class="ghost" id="p_cancel">Cancel</button>
      </div>
    </div>
  </div>
</div>

<div class="tiles" id="tiles"></div>

<div class="sechd"><h2>recent requests</h2>
  <span style="display:flex;align-items:center;gap:12px;margin-left:auto">
    <span class="count" id="reqcount"></span>
    <button class="ghost" id="resetbtn" style="padding:6px 12px;font-size:12px">clear logs &amp; counters</button>
  </span></div>
<div class="warnbar" id="valwarn">Values are being revealed below &mdash; anyone with access to this screen can read your credentials.</div>
<div class="wrap"><table id="reqtbl">
<thead><tr><th>time</th><th>method</th><th>path</th><th>status</th>
<th class="num">ms</th><th class="num">req</th><th class="num">resp</th>
<th class="num">in</th><th class="num">out</th><th>redactions</th></tr></thead>
<tbody id="reqbody"></tbody></table></div>

<div class="sechd"><h2>redactions by rule</h2></div>
<div class="wrap"><table id="ruletbl">
<thead><tr><th>rule</th><th class="num">count</th><th class="valcol hidec">matched values (recent)</th></tr></thead>
<tbody id="rulebody"></tbody></table></div>
<p class="empty" id="footnote">Values are never shown, stored or logged &mdash; names and counts only.</p>
<p class="empty faint" style="margin-top:-4px">Click a request to inspect the exact body sent and the raw response (last 30 kept).</p>
</div>

<div class="modal" id="modal">
  <div class="box">
    <div class="top"><h3 id="m_title">request</h3><button class="x" id="m_close" type="button">&times;</button></div>
    <div class="body">
      <div class="seg"><div class="lbl">request sent (redacted)<button id="m_copyreq" type="button">copy</button></div><pre id="m_req"></pre></div>
      <div class="seg"><div class="lbl">raw response (before restore)<button id="m_copyresp" type="button">copy</button></div><pre id="m_resp"></pre></div>
    </div>
  </div>
</div>

<script>
const $=(id)=>document.getElementById(id);
const esc=(s)=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const n=(v)=>v==null?'-':Number(v).toLocaleString('en-US');
const bytes=(b)=>{if(b==null)return '-';if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';return (b/1048576).toFixed(1)+' MB';};
const upt=(s)=>{const h=Math.floor(s/3600),m=Math.floor(s%3600/60),ss=s%60;return (h?h+'h ':'')+(m?m+'m ':'')+ss+'s';};
const trunc=(v,x)=>{v=String(v);return v.length>x?v.slice(0,x)+'\\u2026':v;};

const MODE_HINT={
  disabled:'No redaction \\u2014 forwards everything as-is. ONLY for a fully trusted destination (e.g. the official Anthropic API). A third-party provider would see all your secrets.',
  'named-only':'Only your registered secrets (Layer A), matched in every encoding (literal, base64, URL-encoded, JSON-escaped). No shape detection \\u2014 a dynamic token you never registered would pass through.',
  balanced:'Registered secrets + known SHAPES (Layer B regex): JWT, PEM private keys, Authorization: Bearer, x-api-key, vendor keys (sk-/AKIA/AIza/\\u2026), cookies. No entropy scan.',
  strict:'Everything in balanced PLUS high-entropy blobs (long hex / base64) \\u2014 catches unknown secrets by randomness. Most aggressive; may occasionally over-redact a random-looking string. Default and safest.',
};
function updateModeHint(){$('modehint').textContent=MODE_HINT[$('c_mode').value]||'';}
$('c_mode').addEventListener('change',updateModeHint);

let showVals=false;
async function loadCfg(){
  try{
    const c=await (await fetch('config',{cache:'no-store'})).json();
    $('c_url').value=c.upstreamUrl||'';
    $('c_auth').value=c.upstreamAuth||'passthrough';
    $('c_key').placeholder=c.hasKey?'(key set \\u2014 blank keeps it)':'leave blank to keep current';
    const modes=c.modes||['named-only','balanced','strict'];
    $('c_mode').innerHTML=modes.map(m=>'<option value="'+m+'"'+(m===c.redactMode?' selected':'')+'>'+m
      +(m===c.redactModeFloor?' (floor)':'')+'</option>').join('');
    $('c_restore').checked=!!c.restoreMarkers;
    $('c_showvals').checked=!!c.showRedactedValues;
    showVals=!!c.showRedactedValues;
    applyShowVals();
    updateModeHint();
  }catch(e){$('cfgmsg').textContent='could not load config';$('cfgmsg').className='err';}
}
function applyShowVals(){
  $('valwarn').classList.toggle('on',showVals);
  document.querySelectorAll('.valcol').forEach(el=>el.classList.toggle('hidec',!showVals));
  $('footnote').textContent=showVals
    ?'Values are revealed in this panel and kept in memory while the toggle is on. This screen now exposes real credentials.'
    :'Values are never shown, stored or logged \\u2014 names and counts only.';
}
async function saveCfg(){
  const patch={upstreamUrl:$('c_url').value.trim(),upstreamAuth:$('c_auth').value,redactMode:$('c_mode').value,
    restoreMarkers:$('c_restore').checked,showRedactedValues:$('c_showvals').checked};
  if($('c_key').value)patch.upstreamKey=$('c_key').value;
  $('cfgmsg').textContent='saving\\u2026';$('cfgmsg').className='mut';
  try{
    const r=await fetch('config',{method:'POST',headers:{'content-type':'application/json','x-redact-panel':'1'},body:JSON.stringify(patch)});
    const d=await r.json();
    if(d.ok){$('cfgmsg').textContent='saved \\u2014 applied live';$('cfgmsg').className='ok';$('c_key').value='';loadCfg();tick();}
    else{$('cfgmsg').textContent='error: '+(d.error||r.status);$('cfgmsg').className='err';}
  }catch(e){$('cfgmsg').textContent='save failed: '+e;$('cfgmsg').className='err';}
}
$('c_save').onclick=saveCfg;$('c_reload').onclick=loadCfg;
$('c_official').onclick=()=>{$('c_url').value='https://api.anthropic.com';$('cfgmsg').textContent='official Anthropic \\u2014 remember to save';$('cfgmsg').className='mut';};

// click a revealed value to copy it
document.addEventListener('click',(e)=>{const el=e.target.closest('.cap');if(!el)return;
  e.stopPropagation();
  const v=el.getAttribute('data-full');if(!v)return;
  navigator.clipboard&&navigator.clipboard.writeText(v);
  const old=el.textContent;el.textContent='copied';setTimeout(()=>{el.textContent=old;},700);});

// pretty-print a request body (JSON) for the inspector; leave anything else raw
function pretty(s){try{return JSON.stringify(JSON.parse(s),null,2);}catch(e){return s;}}
function closeModal(){$('modal').classList.remove('on');}
function copyBtn(id,txt){navigator.clipboard&&navigator.clipboard.writeText(txt);const b=$(id);const o=b.textContent;b.textContent='copied';setTimeout(()=>{b.textContent=o;},700);}
async function openInspect(id){
  $('m_title').textContent='request #'+id;
  $('m_req').textContent='loading\\u2026';$('m_resp').textContent='';
  $('modal').classList.add('on');
  try{
    const r=await fetch('inspect?id='+encodeURIComponent(id),{cache:'no-store',headers:{'x-redact-panel':'1'}});
    if(!r.ok){$('m_req').textContent='(not captured \\u2014 only the last 30 requests are kept)';return;}
    const d=await r.json();
    const reqTxt=pretty(d.req||''), respTxt=d.resp||'';
    $('m_req').textContent=reqTxt||'(empty)';
    $('m_resp').textContent=respTxt||'(empty)';
    $('m_copyreq').onclick=()=>copyBtn('m_copyreq',reqTxt);
    $('m_copyresp').onclick=()=>copyBtn('m_copyresp',respTxt);
  }catch(e){$('m_req').textContent='inspect failed: '+e;}
}
// click a request row to inspect it
document.addEventListener('click',(e)=>{const tr=e.target.closest('tr.rowclick');if(!tr)return;
  const id=tr.getAttribute('data-id');if(id)openInspect(id);});
$('m_close').onclick=closeModal;
$('modal').addEventListener('click',(e)=>{if(e.target===$('modal'))closeModal();});
document.addEventListener('keydown',(e)=>{if(e.key==='Escape')closeModal();});

function statusCell(e){
  if(e.blocked)return '<span class="pill warn">blocked</span>';
  if(e.status==null)return '<span class="pill mut">\\u2026</span>';
  const c=e.status>=500?'err':e.status>=400?'warn':e.status>=200?'ok':'mut';
  return '<span class="pill '+c+'">'+esc(e.status)+'</span>';
}
function tile(nv,l,alert){return '<div class="tile'+(alert?' alert':'')+'"><div class="n">'+nv+'</div><div class="l">'+l+'</div></div>';}
function capChip(v){return '<span class="cap" data-full="'+esc(v)+'" title="click to copy">'+esc(trunc(v,44))+'</span>';}
function redactCell(e,caps){
  if(showVals&&caps&&caps.length){
    return caps.map(c=>'<span class="rulechip">'+esc(c.rule)+'</span>'+capChip(c.value)).join(' ');
  }
  if(e.rules&&e.rules.length)return e.rules.map(r=>'<span class="rulechip">'+esc(r)+'</span>').join(' ');
  return '<span class="faint">clean</span>';
}

let lastOk=Date.now(),tickN=0;
async function tick(){
  // refresh the registry view every ~10s so plan usage stays current
  if(tickN++%7===0&&$('proveditor').classList.contains('hidec'))loadProviders();
  let d;try{d=await (await fetch('stats.json',{cache:'no-store'})).json();lastOk=Date.now();}
  catch(e){$('live').className='live stale';$('live').lastChild.textContent=' offline';return;}
  $('live').className='live';
  const t=d.totals,m=d.meta||{};
  $('chips').innerHTML=
    '<span class="chip">upstream <b>'+esc(m.upstream||'not set')+'</b></span>'
    +'<span class="chip">mode <b>'+esc(m.mode||'?')+'</b></span>'
    +'<span class="chip">fail-closed <b>'+esc(m.failClosed)+'</b></span>'
    +'<span class="chip">uptime <b>'+upt(d.uptimeSec)+'</b></span>'+quotaChip();
  $('tiles').innerHTML=tile(n(t.requests),'requests')+tile(n(t.redactedRequests),'with redactions')
    +tile(n(t.redactions),'total redactions')+tile(n(t.blocked),'blocked',t.blocked>0)
    +tile(n(t.inputTokens),'input tokens')+tile(n(t.outputTokens),'output tokens');

  // optional value reveal (guarded endpoint)
  let capById={},perRuleValues={};
  if(showVals){
    try{const v=await (await fetch('values',{cache:'no-store',headers:{'x-redact-panel':'1'}})).json();
      if(v.enabled){for(const r of v.recent)capById[r.id]=r.captures;perRuleValues=v.perRuleValues||{};}
    }catch(e){}
  }

  $('reqcount').textContent=d.recent.length?d.recent.length+' shown':'';
  $('reqbody').innerHTML = d.recent.length ? d.recent.map(e=>
    '<tr class="rowclick" data-id="'+e.id+'"><td class="mut mono">'+esc(e.time.slice(11,19))+'</td><td>'+esc(e.method)+'</td>'
    +'<td class="path">'+esc(e.path)+'</td><td>'+statusCell(e)+'</td>'
    +'<td class="num">'+(e.durationMs==null?'-':n(e.durationMs))+'</td>'
    +'<td class="num faint">'+bytes(e.reqBytes)+'</td><td class="num faint">'+bytes(e.respBytes)+'</td>'
    +'<td class="num">'+n(e.inputTokens)+'</td><td class="num">'+n(e.outputTokens)+'</td>'
    +'<td>'+redactCell(e,capById[e.id])+'</td></tr>'
  ).join('') : '<tr><td colspan="10" class="empty">no requests yet \\u2014 point your CLI at this proxy</td></tr>';

  const rules=Object.entries(d.perRule).sort((a,b)=>b[1]-a[1]);
  $('rulebody').innerHTML = rules.length ? rules.map(([r,c])=>{
    let valcell='';
    if(showVals){const vs=perRuleValues[r]||[];
      valcell='<td class="valcol">'+(vs.length?vs.map(capChip).join(' '):'<span class="faint">\\u2014</span>')+'</td>';
    }
    return '<tr><td><span class="rulechip">'+esc(r)+'</span></td><td class="num">'+n(c)+'</td>'+valcell+'</tr>';
  }).join('') : '<tr><td colspan="3" class="empty">none yet</td></tr>';
}
// ---------- providers registry ----------
let curProviders=[],editingId=null,activeProviderId=null;
const findProv=(id)=>curProviders.find(p=>p.id===id);
async function loadProviders(){
  try{const reg=await (await fetch('providers',{cache:'no-store'})).json();renderProviders(reg);}
  catch(e){$('provlist').innerHTML='<div class="empty">registry unavailable</div>';}
}
function renderProviders(reg){
  curProviders=reg.providers||[];activeProviderId=reg.active||null;
  if(!curProviders.length){$('provlist').innerHTML='<div class="empty">no providers yet \\u2014 add one below</div>';return;}
  let h='<table><thead><tr><th>id</th><th>url</th><th>auth</th><th class="num">aliases</th><th></th></tr></thead><tbody>';
  for(const p of curProviders){
    const active=p.id===reg.active;
    h+='<tr><td><b>'+esc(p.id)+'</b>'+(active?' <span class="pill ok">active</span>':'')+(p.label?'<div class="faint mono">'+esc(p.label)+'</div>':'')+'</td>'
      +'<td class="mono faint">'+esc(trunc(p.url||'\\u2014',46))+'</td>'
      +'<td>'+esc(p.auth)+(p.hasKey?' <span class="faint">\\u00b7 key</span>':'')
        +(p.codex&&p.codex.loggedIn?' <span class="faint">\\u00b7 '+esc(p.codex.email||'logged in')+'</span>':(p.codex?' <span class="warn">\\u00b7 not logged in</span>':''))
        +(p.codex&&p.codex.limits?'<div class="faint" style="margin-top:3px">'+quotaText(p.codex.limits)+'</div>':'')+'</td>'
      +'<td class="num">'+Object.keys(p.aliases||{}).length+'</td>'
      +'<td style="white-space:nowrap;text-align:right">'
        +(active?'':'<button class="linkbtn" data-act="activate" data-id="'+esc(p.id)+'">activate</button> &nbsp;')
        +'<button class="linkbtn" data-act="edit" data-id="'+esc(p.id)+'">edit</button> &nbsp;'
        +'<button class="linkbtn" data-act="del" data-id="'+esc(p.id)+'" style="color:var(--red)">delete</button>'
      +'</td></tr>';
  }
  $('provlist').innerHTML=h+'</tbody></table>';
}
$('provlist').addEventListener('click',async(e)=>{
  const b=e.target.closest('button[data-act]');if(!b)return;
  const id=b.getAttribute('data-id'),act=b.getAttribute('data-act');
  if(act==='activate')await provPost('providers/activate',{id});
  else if(act==='del'){if(confirm('Delete provider "'+id+'"?'))await provPost('providers/delete',{id});}
  else if(act==='edit')openEditor(id);
});
async function provPost(pathx,body){
  try{
    const r=await fetch(pathx,{method:'POST',headers:{'content-type':'application/json','x-redact-panel':'1'},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.ok){$('provmsg').textContent='saved \\u2014 applied live';$('provmsg').className='ok';renderProviders(d.registry);loadCfg();tick();return true;}
    $('provmsg').textContent='error: '+(d.error||r.status);$('provmsg').className='err';return false;
  }catch(e){$('provmsg').textContent='failed: '+e;$('provmsg').className='err';return false;}
}
async function provJson(pathx,body){
  const r=await fetch(pathx,{method:'POST',headers:{'content-type':'application/json','x-redact-panel':'1'},body:JSON.stringify(body)});
  let d;try{d=await r.json();}catch(e){d={ok:false,error:'bad response '+r.status};}
  if(!('ok' in d))d.ok=r.ok;return d;
}
function aliasRow(a,real){
  const div=document.createElement('div');div.className='caprow';div.style.margin='7px 0';
  div.innerHTML='<input class="a-name ip" placeholder="claude-opus-4-8" style="max-width:230px" value="'+esc(a||'')+'">'
    +'<span class="faint">\\u2192</span>'
    +'<input class="a-real ip" list="modeldl" placeholder="accounts/\\u2026/claude-opus-4-8" style="flex:1;min-width:240px" value="'+esc(real||'')+'">'
    +'<button class="linkbtn a-del" style="color:var(--red)">remove</button>';
  return div;
}
function renderAliases(aliases){
  const box=$('aliaslist');box.innerHTML='';
  const ent=Object.entries(aliases||{});
  if(!ent.length)box.appendChild(aliasRow('',''));
  else for(const [a,r] of ent)box.appendChild(aliasRow(a,r));
}
$('aliaslist').addEventListener('click',(e)=>{const b=e.target.closest('.a-del');if(b)b.closest('.caprow').remove();});
$('p_addalias').onclick=()=>$('aliaslist').appendChild(aliasRow('',''));
function openEditor(id){
  editingId=id||null;
  const p=id?findProv(id):null;
  $('p_id').value=p?p.id:'';$('p_id').disabled=!!p;
  $('p_label').value=(p&&p.label)?p.label:'';
  $('p_url').value=p?(p.url||''):'';
  $('p_auth').value=p?p.auth:'replace';
  $('p_key').value='';$('p_key').placeholder=(p&&p.hasKey)?'(key set \\u2014 blank keeps it)':'blank keeps current';
  $('p_ua').value=(p&&p.headers)?(p.headers['user-agent']||''):'';
  renderAliases(p?p.aliases:{});
  // a ChatGPT login already carries the plan's model list: prefill the alias dropdowns
  const known=(p&&p.codex&&p.codex.models)||[];
  $('modeldl').innerHTML=known.map(m=>'<option value="'+esc(m)+'">').join('');
  $('fetchmsg').textContent=known.length?known.length+' models from the ChatGPT login':'';$('provmsg').textContent='';
  syncCodexBox();
  $('proveditor').classList.remove('hidec');
  $('proveditor').scrollIntoView({behavior:'smooth',block:'nearest'});
}
$('p_new').onclick=()=>openEditor(null);
$('p_cancel').onclick=()=>{$('proveditor').classList.add('hidec');editingId=null;};
$('p_fetch').onclick=async()=>{
  const id=$('p_id').value.trim();
  if(!id){$('fetchmsg').textContent='enter an ID and Save the provider first';return;}
  $('fetchmsg').textContent='fetching\\u2026';
  try{
    const r=await fetch('provider/models?id='+encodeURIComponent(id),{cache:'no-store',headers:{'x-redact-panel':'1'}});
    const d=await r.json();
    if(d.ok){$('modeldl').innerHTML=d.models.map(m=>'<option value="'+esc(m)+'">').join('');
      $('fetchmsg').textContent=d.models.length+' models fetched \\u2014 pick from the \\u2192 dropdowns';}
    else if(r.status===404)$('fetchmsg').textContent='save this provider first, then fetch';
    else $('fetchmsg').textContent='fetch failed ('+(d.status||r.status)+'): '+esc(trunc(d.error||'',90));
  }catch(e){$('fetchmsg').textContent='fetch failed: '+e;}
};
// ---------- Codex (ChatGPT subscription) login ----------
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
function codexStatusText(p){
  const c=p&&p.codex;
  if(!c||!c.loggedIn)return 'not logged in';
  const until=c.expiresAt?new Date(c.expiresAt).toLocaleString():'?';
  return (c.email||'logged in')+' \\u00b7 '+(c.plan||'?')+' \\u00b7 '+c.models.length+' models \\u00b7 token valid until '+until+(c.limits?' \\u00b7 '+quotaText(c.limits):'');
}
// plan usage from the backend's x-codex-* headers (updated on every request)
function resetIn(ms){const s=Math.max(0,Math.round((ms-Date.now())/1000));const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?d+'d '+h+'h':h?h+'h '+m+'m':m+'m';}
function windowText(label,w){if(!w)return '';const days=w.windowMinutes>=1440?Math.round(w.windowMinutes/1440)+'d':Math.round(w.windowMinutes/60)+'h';return label+' '+w.usedPercent+'% used of the '+days+' window ('+(100-w.usedPercent)+'% left'+(w.resetAt?', resets in '+resetIn(w.resetAt):'')+')';}
function quotaText(l){
  const parts=[];
  if(l.primary)parts.push(windowText('quota',l.primary));
  if(l.secondary)parts.push(windowText('short window',l.secondary));
  if(l.credits&&(l.credits.hasCredits||l.credits.unlimited))parts.push('credits '+(l.credits.unlimited?'unlimited':l.credits.balance));
  if(l.planType)parts.push('plan '+esc(l.planType));
  return esc(parts.join(' \\u00b7 ')).replace(/&amp;/g,'&');
}
function quotaChip(){
  const active=curProviders.find(p=>p.id===activeProviderId);
  const l=active&&active.codex&&active.codex.limits;
  if(!l||!l.primary)return '';
  const cls=l.primary.usedPercent>=90?'err':l.primary.usedPercent>=70?'warn':'';
  return '<span class="chip" id="quotachip">quota <b class="'+cls+'">'+l.primary.usedPercent+'%</b>'+(l.primary.resetAt?' <span class="faint">resets in '+resetIn(l.primary.resetAt)+'</span>':'')+'</span>';
}
function syncCodexBox(){
  const on=$('p_auth').value==='codex-oauth';
  $('codexbox').classList.toggle('hidec',!on);
  $('p_key').disabled=on;
  const p=editingId?findProv(editingId):null;
  $('codexstatus').textContent=codexStatusText(p);
  $('codexstatus').className=(p&&p.codex&&p.codex.loggedIn)?'ok':'faint';
}
$('p_auth').addEventListener('change',syncCodexBox);
$('p_codexlogin').onclick=async()=>{
  const id=$('p_id').value.trim();
  if(!id||!findProv(id)){$('provmsg').textContent='save this provider first, then log in';$('provmsg').className='err';return;}
  $('provmsg').textContent='opening ChatGPT login\\u2026';$('provmsg').className='mut';
  const d=await provJson('providers/codex/login',{id});
  if(!d.ok){$('provmsg').textContent='login failed: '+(d.error||'?');$('provmsg').className='err';return;}
  window.open(d.url,'_blank');
  $('provmsg').textContent='waiting for the browser login\\u2026';
  for(let i=0;i<150;i++){
    await sleep(2000);
    await loadProviders();
    const p=findProv(id);
    if(p&&p.codex&&p.codex.loggedIn){syncCodexBox();$('provmsg').textContent='logged in';$('provmsg').className='ok';loadCfg();return;}
  }
  $('provmsg').textContent='login timed out \\u2014 try again';$('provmsg').className='err';
};
$('p_codexlogout').onclick=async()=>{
  const id=$('p_id').value.trim();if(!id)return;
  if(await provPost('providers/codex/logout',{id}))syncCodexBox();
};
$('p_save').onclick=async()=>{
  const id=$('p_id').value.trim();
  if(!id){$('provmsg').textContent='id required';$('provmsg').className='err';return;}
  const aliases={};
  document.querySelectorAll('#aliaslist .caprow').forEach(row=>{
    const a=row.querySelector('.a-name').value.trim(),r=row.querySelector('.a-real').value.trim();
    if(a&&r)aliases[a]=r;
  });
  const headers={};const ua=$('p_ua').value.trim();if(ua)headers['user-agent']=ua;
  const body={id,label:$('p_label').value.trim()||null,url:$('p_url').value.trim(),auth:$('p_auth').value,headers,aliases};
  if($('p_key').value)body.key=$('p_key').value;
  if(await provPost('providers',body)){$('proveditor').classList.add('hidec');editingId=null;}
};
// clear counters + logs
$('resetbtn').onclick=async()=>{
  if(!confirm('Clear all counters and the recent-request log?'))return;
  try{await fetch('reset',{method:'POST',headers:{'x-redact-panel':'1'}});tick();}catch(e){}
};

loadCfg();loadProviders();tick();setInterval(tick,1500);
</script>
</body></html>`;
