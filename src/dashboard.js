// Local management dashboard: GET /__redact/ (HTML panel), /__redact/stats.json
// (live JSON, polled by the panel), and /__redact/config (GET current provider
// settings, POST to change them live). Shows counters, per-rule tallies, token
// usage and a live request table - rule names, numbers and paths only, never a
// secret value or a body. The provider key is write-only (never returned).
export function handleDashboard(req, res, stats, meta = {}, controller = null) {
  const path = (req.url ?? '').split('?')[0];
  const method = req.method ?? 'GET';
  const json = (code, obj) => {
    res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(obj));
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
          for (const k of ['upstreamUrl', 'upstreamAuth', 'upstreamKey', 'redactMode']) {
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

  if (path === '/__redact' || path === '/__redact/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(PAGE);
    return;
  }

  return json(404, { error: 'not found' });
}

const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>llm-redact-proxy</title>
<style>
:root{--bg:#0d1017;--panel:#151a23;--line:#242b38;--fg:#dfe6f0;--dim:#8492a6;
--green:#57d38c;--red:#ff6b6b;--amber:#f5c451;--accent:#6ea8fe}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
header{display:flex;align-items:baseline;gap:.75rem;flex-wrap:wrap;
padding:1rem 1.25rem;border-bottom:1px solid var(--line)}
header h1{font-size:1.05rem;margin:0}
header .meta{color:var(--dim);font-size:.8rem}
.live{margin-left:auto;color:var(--green);font-size:.75rem}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);
margin-right:.35rem;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
section{margin:1rem 1.25rem;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:1rem}
section h2{margin:0 0 .8rem;font-size:.78rem;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
.form{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.7rem;align-items:end}
.f label{display:block;color:var(--dim);font-size:.72rem;margin-bottom:.25rem}
.f input,.f select{width:100%;background:var(--bg);color:var(--fg);border:1px solid var(--line);
border-radius:6px;padding:.45rem .55rem;font:inherit}
.f input:focus,.f select:focus{outline:none;border-color:var(--accent)}
.actions{display:flex;gap:.6rem;align-items:center;margin-top:.8rem}
button{background:var(--accent);color:#04122e;border:0;border-radius:6px;padding:.5rem .9rem;
font:inherit;font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:var(--dim);border:1px solid var(--line)}
#cfgmsg{font-size:.8rem}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.6rem;margin:1rem 1.25rem}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.7rem .8rem}
.tile .n{font-size:1.5rem;font-weight:600}
.tile .l{color:var(--dim);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;margin-top:.2rem}
h2.sub{font-size:.8rem;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;margin:.5rem 1.25rem}
.wrap{overflow-x:auto;padding:0 1.25rem 1.5rem}
table{border-collapse:collapse;width:100%;min-width:720px}
th,td{text-align:left;padding:.35rem .55rem;border-bottom:1px solid var(--line);white-space:nowrap;font-size:.8rem}
th{color:var(--dim);font-weight:500;position:sticky;top:0;background:var(--bg)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{padding:.05rem .4rem;border-radius:4px;font-size:.72rem}
.ok{color:var(--green)}.err{color:var(--red)}.warn{color:var(--amber)}.mut{color:var(--dim)}
.rules{color:var(--accent)}
.empty{color:var(--dim);padding:0 1.25rem 1rem}
</style></head><body>
<header>
  <h1>llm-redact-proxy</h1>
  <span class="meta" id="meta">connecting...</span>
  <span class="live"><span class="dot"></span>live</span>
</header>

<section>
  <h2>provider configuration</h2>
  <div class="form">
    <div class="f" style="grid-column:1/-1"><label>provider URL (upstream the redacted request is forwarded to)</label>
      <input id="c_url" placeholder="https://your-provider.example/anthropic">
      <div style="margin-top:.4rem"><button class="ghost" id="c_official" type="button">use Official Anthropic</button></div></div>
    <div class="f"><label>auth to provider</label>
      <select id="c_auth"><option value="passthrough">passthrough (forward the caller's token)</option>
      <option value="replace">replace (inject the key below)</option></select></div>
    <div class="f"><label>provider key (only for replace)</label>
      <input id="c_key" type="password" placeholder="leave blank to keep current"></div>
    <div class="f"><label>redaction mode</label>
      <select id="c_mode"></select></div>
  </div>
  <div class="actions">
    <button id="c_save">save &amp; apply</button>
    <button class="ghost" id="c_reload">reload</button>
    <span id="cfgmsg" class="mut"></span>
  </div>
</section>

<div class="tiles" id="tiles"></div>
<h2 class="sub">recent requests</h2>
<div class="wrap"><table id="reqtbl">
<thead><tr><th>time</th><th>method</th><th>path</th><th>status</th>
<th class="num">ms</th><th class="num">req</th><th class="num">resp</th>
<th class="num">in tok</th><th class="num">out tok</th><th>redactions</th></tr></thead>
<tbody id="reqbody"></tbody></table></div>
<h2 class="sub">redactions by rule</h2>
<div class="wrap"><table id="ruletbl">
<thead><tr><th>rule</th><th class="num">count</th></tr></thead>
<tbody id="rulebody"></tbody></table></div>
<p class="empty">Values are never shown, stored or logged - names and counts only.</p>
<script>
const $=(id)=>document.getElementById(id);
const esc=(s)=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const n=(v)=>v==null?'-':Number(v).toLocaleString('en-US');
const bytes=(b)=>{if(b==null)return '-';if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';return (b/1048576).toFixed(1)+' MB';};
const upt=(s)=>{const h=Math.floor(s/3600),m=Math.floor(s%3600/60),ss=s%60;return (h?h+'h ':'')+(m?m+'m ':'')+ss+'s';};

let cfgLoaded=false;
async function loadCfg(){
  try{
    const c=await (await fetch('config',{cache:'no-store'})).json();
    $('c_url').value=c.upstreamUrl||'';
    $('c_auth').value=c.upstreamAuth||'passthrough';
    $('c_key').placeholder=c.hasKey?'(key set - blank keeps it)':'leave blank to keep current';
    const modes=c.modes||['named-only','balanced','strict'];
    $('c_mode').innerHTML=modes.map(m=>'<option value="'+m+'"'+(m===c.redactMode?' selected':'')+'>'+m
      +(m===c.redactModeFloor?' (floor)':'')+'</option>').join('');
    cfgLoaded=true;
  }catch(e){$('cfgmsg').textContent='could not load config';}
}
async function saveCfg(){
  const patch={upstreamUrl:$('c_url').value.trim(),upstreamAuth:$('c_auth').value,redactMode:$('c_mode').value};
  if($('c_key').value)patch.upstreamKey=$('c_key').value;
  $('cfgmsg').textContent='saving...';$('cfgmsg').className='mut';
  try{
    const r=await fetch('config',{method:'POST',headers:{'content-type':'application/json','x-redact-panel':'1'},body:JSON.stringify(patch)});
    const d=await r.json();
    if(d.ok){$('cfgmsg').textContent='saved - applied live';$('cfgmsg').className='ok';$('c_key').value='';loadCfg();}
    else{$('cfgmsg').textContent='error: '+(d.error||r.status);$('cfgmsg').className='err';}
  }catch(e){$('cfgmsg').textContent='save failed: '+e;$('cfgmsg').className='err';}
}
$('c_save').onclick=saveCfg;$('c_reload').onclick=loadCfg;
$('c_official').onclick=()=>{$('c_url').value='https://api.anthropic.com';$('cfgmsg').textContent='official Anthropic - remember to save';$('cfgmsg').className='mut';};

function statusCell(e){
  if(e.blocked)return '<span class="pill warn">BLOCKED</span>';
  if(e.status==null)return '<span class="pill mut">...</span>';
  const c=e.status>=500?'err':e.status>=400?'warn':e.status>=200?'ok':'mut';
  return '<span class="pill '+c+'">'+esc(e.status)+'</span>';
}
function tile(nv,l){return '<div class="tile"><div class="n">'+nv+'</div><div class="l">'+l+'</div></div>';}
async function tick(){
  let d;try{d=await (await fetch('stats.json',{cache:'no-store'})).json();}catch(e){$('meta').textContent='proxy unreachable';return;}
  const t=d.totals,m=d.meta||{};
  $('meta').innerHTML='upstream '+esc(m.upstream||'(not configured)')+' &middot; mode '+esc(m.mode||'?')
    +' &middot; fail-closed '+esc(m.failClosed)+' &middot; up '+upt(d.uptimeSec);
  $('tiles').innerHTML=tile(n(t.requests),'requests')+tile(n(t.redactedRequests),'with redactions')
    +tile(n(t.redactions),'total redactions')+tile('<span class="'+(t.blocked?'err':'')+'">'+n(t.blocked)+'</span>','blocked')
    +tile(n(t.inputTokens),'input tokens')+tile(n(t.outputTokens),'output tokens');
  $('reqbody').innerHTML = d.recent.length ? d.recent.map(e=>
    '<tr><td class="mut">'+esc(e.time.slice(11,19))+'</td><td>'+esc(e.method)+'</td>'
    +'<td>'+esc(e.path)+'</td><td>'+statusCell(e)+'</td>'
    +'<td class="num">'+(e.durationMs==null?'-':n(e.durationMs))+'</td>'
    +'<td class="num mut">'+bytes(e.reqBytes)+'</td><td class="num mut">'+bytes(e.respBytes)+'</td>'
    +'<td class="num">'+n(e.inputTokens)+'</td><td class="num">'+n(e.outputTokens)+'</td>'
    +'<td class="rules">'+(e.rules&&e.rules.length?esc(e.rules.join(', ')):(e.redactions?e.redactions:'<span class="mut">clean</span>'))+'</td></tr>'
  ).join('') : '<tr><td colspan="10" class="mut">no requests yet - point your CLI at this proxy</td></tr>';
  const rules=Object.entries(d.perRule).sort((a,b)=>b[1]-a[1]);
  $('rulebody').innerHTML = rules.length ? rules.map(([r,c])=>'<tr><td class="rules">'+esc(r)+'</td><td class="num">'+n(c)+'</td></tr>').join('')
    : '<tr><td colspan="2" class="mut">none yet</td></tr>';
}
loadCfg();tick();setInterval(tick,1500);
</script>
</body></html>`;
