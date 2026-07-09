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
.linkbtn{background:none;border:0;color:var(--accent);font:inherit;font-size:12.5px;cursor:pointer;padding:6px 0 0;text-decoration:underline;text-underline-offset:2px}

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
          <option value="oauth">oauth &mdash; my Claude subscription (official only)</option></select></div>
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

<div class="tiles" id="tiles"></div>

<div class="sechd"><h2>recent requests</h2><span class="count" id="reqcount"></span></div>
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
  const v=el.getAttribute('data-full');if(!v)return;
  navigator.clipboard&&navigator.clipboard.writeText(v);
  const old=el.textContent;el.textContent='copied';setTimeout(()=>{el.textContent=old;},700);});

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

let lastOk=Date.now();
async function tick(){
  let d;try{d=await (await fetch('stats.json',{cache:'no-store'})).json();lastOk=Date.now();}
  catch(e){$('live').className='live stale';$('live').lastChild.textContent=' offline';return;}
  $('live').className='live';
  const t=d.totals,m=d.meta||{};
  $('chips').innerHTML=
    '<span class="chip">upstream <b>'+esc(m.upstream||'not set')+'</b></span>'
    +'<span class="chip">mode <b>'+esc(m.mode||'?')+'</b></span>'
    +'<span class="chip">fail-closed <b>'+esc(m.failClosed)+'</b></span>'
    +'<span class="chip">uptime <b>'+upt(d.uptimeSec)+'</b></span>';
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
    '<tr><td class="mut mono">'+esc(e.time.slice(11,19))+'</td><td>'+esc(e.method)+'</td>'
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
loadCfg();tick();setInterval(tick,1500);
</script>
</body></html>`;
