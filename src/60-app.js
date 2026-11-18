const $ = s => document.querySelector(s);
const main = $('#main');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const CAT = {doorway: 'Spam pages', implant: 'Planted malicious code', htaccess: 'Search-engine redirects', integrity: 'Changed or unknown files', uploads: 'PHP in uploads', exposure: 'Exposed files', leftover: 'Traces of earlier attacks', access: 'Risky access', database: 'Database', outdated: 'Out of date', secrets: 'Leaked secrets', code: 'Code weaknesses', config: 'Server settings'};
const SEV = {critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Note'};
const FIX = {quarantine: 'Move to quarantine', htaccess: 'Remove the rule', harden: 'Add protective rule', chmod: 'Tighten permissions', manual: 'Needs you'};
let D = null, RUNS = [], view = 'overview', sel = new Set(), selFor = 0, lastResult = null;
let filt = {site: '', sev: '', cat: '', q: '', show: 'open'};

async function api(name, data = {}) {
  const fd = new FormData();
  fd.append('api', name); fd.append('csrf', BOOT.csrf);
  for (const k in data) fd.append(k, data[k]);
  try {
    const r = await fetch(location.pathname, {method: 'POST', body: fd, credentials: 'same-origin'});
    const t = await r.text();
    if (r.status === 404 || r.status === 410) return {error: 'This tool\'s file is no longer on the server, so nothing can be done from this page. The most common cause is the host\'s malware scanner removing it. Look for seo-spam-fix.php in the scanner\'s list or in the .quarantine folder of the account. Everything this tool moved is still safe in the ssf-data/quarantine folder in the account home: upload the tool again and its Quarantine page will show and restore those runs.'};
    try { return JSON.parse(t); } catch (e) { return {error: 'The server sent an unexpected reply (HTTP ' + r.status + ').'}; }
  } catch (e) { return {error: 'Could not reach the server. Check your connection.'}; }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
const when = ts => ts ? new Date(ts * 1000).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'}) : '';
const size = b => { const u = ['B', 'KB', 'MB', 'GB']; let i = 0; while (b >= 1024 && i < 3) { b /= 1024; i++; } return (i ? b.toFixed(1) : b) + ' ' + u[i]; };
function ask(title, body, yes) {
  return new Promise(res => {
    const d = $('#dlg');
    $('#dlg-t').textContent = title; $('#dlg-b').innerHTML = body; $('#dlg-yes').textContent = yes;
    const done = v => { d.close(); $('#dlg-yes').onclick = $('#dlg-no').onclick = d.oncancel = null; res(v); };
    $('#dlg-yes').onclick = () => done(true); $('#dlg-no').onclick = () => done(false); d.oncancel = () => done(false);
    d.showModal();
  });
}
function gauge(pct, color) {
  const L = 251.33;
  return `<svg viewBox="0 0 200 112" role="img" aria-label="${pct} out of 100"><path d="M20 100A80 80 0 0 1 180 100" fill="none" stroke="var(--panel2)" stroke-width="14" stroke-linecap="round"/><path class="v" d="M20 100A80 80 0 0 1 180 100" fill="none" stroke="${color}" stroke-width="14" stroke-linecap="round" stroke-dasharray="${L}" stroke-dashoffset="${L * (1 - pct / 100)}"/></svg>`;
}
const riskColor = r => r >= 60 ? 'var(--red)' : r >= 25 ? 'var(--orange)' : r > 0 ? 'var(--amber)' : 'var(--teal)';
const openF = () => D.scan.findings.filter(f => f.state === 'open');
const canFix = f => f.state === 'open' && f.fix !== 'manual';

function chrome() {
  document.querySelectorAll('.nav').forEach(b => b.setAttribute('aria-current', b.dataset.view === view ? 'page' : 'false'));
  const nf = $('#n-findings'), nq = $('#n-quarantine');
  const n = D ? openF().filter(f => f.sev !== 'info').length : 0;
  nf.hidden = !n; nf.textContent = n;
  const q = RUNS.filter(r => !r.restored).reduce((a, r) => a + r.items.length, 0);
  nq.hidden = !q; nq.textContent = q;
  const days = Math.max(0, Math.ceil((BOOT.expires * 1000 - Date.now()) / 864e5));
  $('#foot').innerHTML = `Version ${esc(BOOT.version)}<br>Locks itself in ${days} day${days === 1 ? '' : 's'}`;
}
function head(title, right = '') {
  return `<div class="top"><div><h1>${esc(title)}</h1>${D ? `<div class="mut small">${esc(D.scan.meta.host)} &nbsp; scanned ${esc(when(D.scan.meta.finished))} &nbsp; ${D.scan.meta.files.toLocaleString()} files</div>` : ''}</div><div>${right}</div></div>`;
}
function go(v) {
  view = v; chrome();
  if (!D && ['overview', 'findings', 'report'].includes(v)) return renderStart();
  ({overview: renderOverview, findings: renderFindings, quarantine: renderQuarantine, report: renderReport, tool: renderTool, start: renderStart})[v]();
  main.focus({preventScroll: true}); window.scrollTo(0, 0);
}
async function load(to) {
  const r = await api('results');
  if (r.error) { main.innerHTML = `<div class="card"><h2>Something went wrong</h2><p class="bad">${esc(r.error)}</p><button onclick="location.reload()">Reload</button></div>`; return; }
  RUNS = r.runs || [];
  if (r.none) { D = null; if (r.scanning) return scanLoop(); return go(to === 'quarantine' || to === 'tool' ? to : 'start'); }
  D = r;
  if (selFor !== D.scan.meta.finished) { selFor = D.scan.meta.finished; sel = new Set(D.scan.findings.filter(f => canFix(f) && f.tick).map(f => f.id)); }
  else sel = new Set([...sel].filter(id => { const f = D.scan.findings.find(x => x.id === id); return f && canFix(f); }));
  go(to || view);
}

/* ---------- start and scanning ---------- */
function renderStart() {
  view = D ? 'tool' : 'overview'; chrome();
  main.innerHTML = head(D ? 'Scan again' : 'Scan this hosting account') + `<div class="card start" style="max-width:720px">
    <h2>Where should it look?</h2>
    ${BOOT.bases.map((b, i) => `<label><input type="radio" name="where" value="${esc(b.key)}" ${i === BOOT.bases.length - 1 ? 'checked' : ''}><span><b>${esc(b.label)}</b><br><span class="mono mut">${esc(b.path)}</span></span></label>`).join('')}
    <label><input type="radio" name="where" value="custom"><span style="flex:1"><b>Another folder in this account</b><br><input type="text" id="custom" placeholder="/home/user/public_html/example.com" style="width:100%;margin-top:6px" aria-label="Folder path"></span></label>
    <p class="mut" style="margin-top:14px">The scan only reads files. It looks for two things. Infection: spam pages, backdoors and hidden redirects, with WordPress and plugin files compared against the official copies. Weak spots: leaked keys, files that should not be downloadable, unsafe server settings, and common coding mistakes in the site's own PHP and JavaScript. It then proposes what it can fix. Nothing is changed until you choose to.</p>
    <p id="starterr" class="bad" hidden></p>
    <button class="primary" id="startbtn">Start scan</button></div>`;
  $('#custom').onfocus = () => { document.querySelector('input[value=custom]').checked = true; };
  $('#startbtn').onclick = async () => {
    let w = document.querySelector('input[name=where]:checked').value;
    if (w === 'custom') w = $('#custom').value.trim();
    $('#startbtn').disabled = true;
    const r = await api('start', {where: w});
    if (r.error) { $('#starterr').hidden = false; $('#starterr').textContent = r.error; $('#startbtn').disabled = false; return; }
    D = null; scanLoop();
  };
}
function renderScanning(p) {
  main.innerHTML = head('Scanning') + `<div class="card" style="max-width:520px"><div class="gauge">${gauge(p.pct || 0, 'var(--red)')}<div class="num">${p.pct || 0}<span style="font-size:18px">%</span></div><div class="lab">${(p.files || 0).toLocaleString()} files read, ${p.found || 0} findings so far</div></div>
    <p class="mono mut" style="margin-top:14px;min-height:36px;word-break:break-all">${esc(p.current || 'Starting')}</p>
    <p class="mut small">Large accounts take a few minutes. Keep this tab open; if it is closed, sign in again and the scan picks up where it stopped.</p></div>`;
}
async function scanLoop() {
  view = 'overview'; chrome(); renderScanning({});
  let errs = 0;
  for (;;) {
    const r = await api('step');
    if (r.error) {
      if (r.auth === false || ++errs > 5) { main.innerHTML = head('Scan paused') + `<div class="card"><p class="bad">${esc(r.error)}</p><button class="primary" id="resume">Resume scan</button></div>`; const b = $('#resume'); if (b) b.onclick = scanLoop; return; }
      await sleep(2000); continue;
    }
    errs = 0;
    if (r.done) { selFor = 0; lastResult = null; return load('overview'); }
    renderScanning(r);
  }
}

/* ---------- overview ---------- */
function renderOverview() {
  const s = D.summary, sc = D.scan;
  const cats = Object.entries(s.cat).sort((a, b) => b[1] - a[1]); const max = cats.length ? cats[0][1] : 1;
  const bySite = {};
  openF().forEach(f => { if (f.sev === 'info') return; const k = f.site || ''; (bySite[k] = bySite[k] || {n: 0, worst: 9}); bySite[k].n++; bySite[k].worst = Math.min(bySite[k].worst, Object.keys(SEV).indexOf(f.sev)); });
  const fixable = [...sel].length;
  main.innerHTML = head('Overview', `<button id="again">Scan again</button>`) + `
  <div class="grid g3">
    <div class="card gauge"><div style="width:100%">${gauge(s.risk, riskColor(s.risk))}<div class="num">${s.risk}</div><div class="lab" style="color:${riskColor(s.risk)}">${esc(s.label)}</div><div class="mut small">Risk score out of 100</div></div></div>
    <div class="card"><h2>Open findings</h2><div class="sevrow">${['critical', 'high', 'medium', 'low'].map(k => `<button class="sev" data-sev="${k}"><b class="c-${k}">${s.sev[k]}</b>${SEV[k]}<i class="b-${k}"></i></button>`).join('')}</div>
      <p class="mut small" style="margin:14px 0 0">${sc.meta.verified.toLocaleString()} files matched the official WordPress and plugin copies. ${sc.meta.php.toLocaleString()} other PHP files were checked by pattern${sc.meta.audited ? `, and ${sc.meta.audited.toLocaleString()} of the site's own were audited for coding mistakes` : ''}.${s.quarantined ? ` ${s.quarantined} item${s.quarantined === 1 ? ' is' : 's are'} in quarantine.` : ''}</p></div>
    <div class="card"><h2>${s.proposed ? `${s.proposed} fix${s.proposed === 1 ? '' : 'es'} ready to apply` : 'Nothing to quarantine automatically'}</h2>
      <p class="mut">${s.proposed ? 'These were matched with enough confidence that fixing them should not change how the site works. Files are moved, not deleted, rules keep a copy of the original, and all of it can be put back from the Quarantine page.' : (s.risk ? 'What is left needs a decision or a manual fix. Open the findings to see each one.' : 'Nothing known was found. That is not proof the site is clean; see what this tool cannot do under "What to do next".')}</p>
      ${s.proposed ? `<button class="primary" id="review">Review and apply</button>` : `<button id="review">Open findings</button>`}</div>
  </div>
  <div class="grid g2" style="margin-top:14px">
    <div class="card"><h2>What was found</h2>${cats.length ? cats.map(([k, n]) => `<div class="bar" data-cat="${k}"><span>${esc(CAT[k] || k)}</span><span class="t"><i style="width:${Math.max(4, 100 * n / max)}%"></i></span><b>${n}</b></div>`).join('') : '<p class="mut">No open findings.</p>'}</div>
    <div class="card"><h2>Sites in this scan</h2>${sc.installs.length ? `<table><tr><th>Folder</th><th>WordPress</th><th>Core files</th><th>Database</th><th>Open</th></tr>${sc.installs.map(I => { const b = bySite[I.rel] || {n: 0, worst: 9}; const w = Object.keys(SEV)[b.worst]; return `<tr><td class="mono">${esc(I.rel === '.' ? I.label : I.rel)}</td><td>${esc(I.ver || 'missing')}</td><td>${I.core === 'ok' ? '<span class="ok">Compared</span>' : '<span class="mut">Not compared</span>'}</td><td>${I.db === 'checked' ? '<span class="ok">Checked</span>' : '<span class="mut">Not checked</span>'}</td><td>${b.n ? `<span class="pill c-${w}">${b.n}</span>` : '<span class="mut">0</span>'}</td></tr>`; }).join('')}</table>` : '<p class="mut">No WordPress install was found in this folder. Files were still checked for spam pages and backdoors.</p>'}</div>
  </div>
  <div class="card" style="margin-top:14px"><h2>Recently changed PHP and .htaccess files</h2><p class="mut small">The date a break-in happened usually shows up here as a cluster of files changed within minutes of each other. Use it to find the right day in the access logs.</p>
    <table>${sc.recent.slice(0, 12).map(x => `<tr><td style="white-space:nowrap;width:190px">${esc(when(x[0]))}</td><td class="mono" style="word-break:break-all">${esc(x[3])}</td></tr>`).join('') || '<tr><td class="mut">None</td></tr>'}</table></div>`;
  $('#again').onclick = renderStart;
  $('#review').onclick = () => go('findings');
  main.querySelectorAll('.sev').forEach(b => b.onclick = () => { filt.sev = b.dataset.sev; filt.cat = ''; filt.show = 'open'; go('findings'); });
  main.querySelectorAll('.bar[data-cat]').forEach(b => b.onclick = () => { filt.cat = b.dataset.cat; filt.sev = ''; filt.show = 'open'; go('findings'); });
}

/* ---------- findings ---------- */
function renderFindings() {
  const sites = [...new Set(D.scan.findings.map(f => f.site).filter(Boolean))];
  const q = filt.q.toLowerCase();
  const rows = D.scan.findings.filter(f => (filt.show === 'all' || (filt.show === 'open' ? f.state === 'open' : f.state !== 'open')) && (!filt.sev || f.sev === filt.sev) && (!filt.cat || f.cat === filt.cat) && (!filt.site || f.site === filt.site) && (!q || (f.title + ' ' + f.path + ' ' + f.detail).toLowerCase().includes(q)));
  const proposed = D.scan.findings.filter(f => canFix(f) && f.tick).length;
  main.innerHTML = head('Findings') + `
  <div class="tools">
    <button class="chip" data-show="open" aria-pressed="${filt.show === 'open'}">Open</button><button class="chip" data-show="done" aria-pressed="${filt.show === 'done'}">Quarantined</button><button class="chip" data-show="all" aria-pressed="${filt.show === 'all'}">All</button>
    <select id="fsev" aria-label="Severity"><option value="">Any severity</option>${Object.keys(SEV).map(k => `<option value="${k}" ${filt.sev === k ? 'selected' : ''}>${SEV[k]}</option>`).join('')}</select>
    <select id="fcat" aria-label="Type"><option value="">Any type</option>${[...new Set(D.scan.findings.map(f => f.cat))].map(k => `<option value="${k}" ${filt.cat === k ? 'selected' : ''}>${esc(CAT[k] || k)}</option>`).join('')}</select>
    ${sites.length > 1 ? `<select id="fsite" aria-label="Site"><option value="">All sites</option>${sites.map(s => `<option ${filt.site === s ? 'selected' : ''}>${esc(s)}</option>`).join('')}</select>` : ''}
    <input type="text" id="fq" placeholder="Filter by name or path" value="${esc(filt.q)}" aria-label="Filter" style="flex:1;min-width:200px;max-width:300px">
    <span class="sp"></span><button id="selprop">Select the ${proposed} proposed</button><button id="selnone" class="ghost">Clear selection</button>
  </div>
  <div class="card list">${rows.length ? rows.map(f => `
    <div class="f ${f.state !== 'open' ? 'done' : ''}" data-id="${f.id}">
      <span>${canFix(f) ? `<input type="checkbox" ${sel.has(f.id) ? 'checked' : ''} aria-label="Select: ${esc(f.title)}">` : ''}</span>
      <span class="sv"><span class="pill c-${f.sev}">${SEV[f.sev]}</span></span>
      <span><b>${esc(f.title)}</b>${f.path ? `<div class="p mono">${esc(f.path)}</div>` : (f.site ? `<div class="p mono">${esc(f.site)}</div>` : '')}</span>
      <span class="fix">${f.state === 'quarantined' ? '<span class="ok">In quarantine</span>' : f.state === 'gone' ? 'No longer there' : (f.sev === 'info' ? '' : FIX[f.fix])}</span>
      <button class="x" aria-label="Show details" aria-expanded="false">&#9656;</button>
      <div class="more"><p>${esc(f.detail)}</p>${f.ctime ? `<p class="mut small">Last changed ${esc(when(f.ctime))}${f.kind === 'file' && f.size != null ? `, ${size(f.size)}` : ''}. ${esc(CAT[f.cat] || '')}.</p>` : ''}${f.evidence ? `<pre class="ev">${esc(f.evidence)}</pre>` : ''}${f.prompt ? `<div class="prompt"><div class="ph"><b>Paste this into your AI coding tool</b><button class="copy">Copy</button></div><p>${esc(f.prompt)}</p></div>` : ''}</div>
    </div>`).join('') : '<p class="mut" style="padding:18px;margin:0">Nothing matches these filters.</p>'}</div>
  <div class="actionbar" id="bar" hidden><b id="barn"></b><span class="mut small">Nothing is deleted. Every change can be undone from the Quarantine page.</span><span style="flex:1"></span><button class="primary" id="doq">Apply selected</button></div>`;
  const bar = () => { $('#bar').hidden = !sel.size; $('#barn').textContent = sel.size + ' selected'; };
  bar();
  main.querySelectorAll('[data-show]').forEach(b => b.onclick = () => { filt.show = b.dataset.show; renderFindings(); });
  $('#fsev').onchange = e => { filt.sev = e.target.value; renderFindings(); };
  $('#fcat').onchange = e => { filt.cat = e.target.value; renderFindings(); };
  if ($('#fsite')) $('#fsite').onchange = e => { filt.site = e.target.value; renderFindings(); };
  $('#fq').oninput = e => { filt.q = e.target.value; clearTimeout(window._t); window._t = setTimeout(() => { renderFindings(); const i = $('#fq'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }, 250); };
  $('#selprop').onclick = () => { sel = new Set(D.scan.findings.filter(f => canFix(f) && f.tick).map(f => f.id)); renderFindings(); };
  $('#selnone').onclick = () => { sel.clear(); renderFindings(); };
  main.querySelectorAll('.f').forEach(el => {
    const id = +el.dataset.id, cb = el.querySelector('input'), x = el.querySelector('.x');
    if (cb) cb.onchange = () => { cb.checked ? sel.add(id) : sel.delete(id); bar(); };
    x.onclick = () => { const o = el.classList.toggle('open'); x.setAttribute('aria-expanded', o); };
    const cp = el.querySelector('.copy');
    if (cp) cp.onclick = async () => { const t = el.querySelector('.prompt p').textContent; try { await navigator.clipboard.writeText(t); } catch (e) { const ta = document.createElement('textarea'); ta.value = t; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); } cp.textContent = 'Copied'; setTimeout(() => cp.textContent = 'Copy', 1500); };
  });
  $('#doq').onclick = async () => {
    const items = D.scan.findings.filter(f => sel.has(f.id));
    const unsure = items.filter(f => !f.tick).length;
    const ok = await ask(`Apply ${items.length} fix${items.length === 1 ? '' : 'es'}?`, `Nothing is deleted. Files and folders are moved out of the website, .htaccess changes keep a copy of the original, and permission changes are recorded so they can be put back.${unsure ? `<br><br><b style="color:var(--amber)">${unsure} of these ${unsure === 1 ? 'was' : 'were'} not proposed by the scan.</b> Check the site afterwards and restore if anything stops working.` : ''}`, 'Apply');
    if (!ok) return;
    $('#doq').disabled = true;
    const r = await api('quarantine', {ids: JSON.stringify([...sel])});
    lastResult = r; sel.clear();
    await load('quarantine');
  };
}

/* ---------- quarantine ---------- */
function renderQuarantine() {
  let note = '';
  if (lastResult) {
    if (lastResult.error) note = `<div class="note"><b class="bad">${esc(lastResult.error)}</b></div>`;
    else { const ok = lastResult.results.filter(x => x.ok).length, bad = lastResult.results.filter(x => !x.ok);
      note = `<div class="note"><b>${ok} item${ok === 1 ? '' : 's'} handled.</b> Open the site in a private window now and click through the main pages. If anything looks wrong, restore the run below.${bad.length ? `<br><span class="bad">${bad.length} could not be handled:</span><ul class="plain">${bad.map(b => `<li><span class="mono">${esc(b.path)}</span>: ${esc(b.msg)}</li>`).join('')}</ul>` : ''}</div>`; }
  }
  main.innerHTML = head('Quarantine') + note + `<p class="mut" style="max-width:80ch">Quarantined items are kept in <span class="mono">${esc(BOOT.dataDir)}/quarantine</span>${BOOT.dataOutside ? ', outside the website, so nothing in there can be opened from the web.' : '. <b style="color:var(--amber)">This folder is inside the website because the account home was not writable. It is blocked by an .htaccess rule; move it out when you can.</b>'} Delete that folder yourself once you are sure you no longer need it.</p>` +
    (RUNS.length ? RUNS.map(r => `<div class="card" style="margin-bottom:12px"><div class="top" style="margin-bottom:8px"><div><h3>${esc(when(r.created))}</h3><span class="mut small">${r.items.length} item${r.items.length === 1 ? '' : 's'} from <span class="mono">${esc(r.base)}</span></span></div>${r.restored ? `<span class="mut">Restored ${esc(when(r.restored))}</span>` : `<button data-run="${esc(r.run)}">Restore everything in this run</button>`}</div>
      <table>${r.items.map(i => `<tr><td style="width:150px" class="mut">${({htaccess: 'Rule removed', harden: 'Rule added', chmod: 'Permissions'})[i.type] || 'Moved'}</td><td class="mono" style="word-break:break-all">${esc(i.path)}</td></tr>`).join('')}</table></div>`).join('') : '<div class="card"><p class="mut" style="margin:0">Nothing has been quarantined yet. Select findings on the Findings page to move them here.</p></div>');
  main.querySelectorAll('[data-run]').forEach(b => b.onclick = async () => {
    if (!await ask('Restore this run?', 'Every item goes back to where it was and the original .htaccess is put back. If these were spam pages or backdoors, they become live again.', 'Restore')) return;
    b.disabled = true;
    const r = await api('restore', {run: b.dataset.run});
    lastResult = null;
    if (r.error) { await ask('Could not restore', esc(r.error), 'OK'); }
    else { const bad = r.results.filter(x => !x.ok); if (bad.length) await ask('Restored with problems', bad.map(x => `<span class="mono">${esc(x.path)}</span>: ${esc(x.msg)}`).join('<br>'), 'OK'); }
    load('quarantine');
  });
}

/* ---------- report ---------- */
function renderReport() {
  const sc = D.scan;
  main.innerHTML = head('What to do next', `<button id="dltxt">Download report</button> <button id="dljson" class="ghost">Download data</button> <button class="ghost" onclick="window.print()">Print</button>`) + `
  <div class="card"><h2>In this order</h2>${D.recommend.map((r, i) => `<div class="rec"><span class="k p${r.p}">${i + 1}</span><div><h3>${esc(r.title)}</h3><p>${esc(r.body)}</p></div></div>`).join('')}</div>
  <div class="grid g2" style="margin-top:14px">
    <div class="card"><h2>What this tool cannot do</h2><ul class="plain">${D.limits.map(l => `<li>${esc(l)}</li>`).join('')}</ul>${sc.notes.length ? `<h2 style="margin-top:18px">Not checked in this scan</h2><ul class="plain">${sc.notes.map(l => `<li>${esc(l)}</li>`).join('')}</ul>` : ''}</div>
    <div class="card"><h2>Could not be compared with an official copy</h2><p class="mut small">These were only pattern-scanned. Replace them from the vendor you bought them from.</p>${sc.unverified.length ? `<table><tr><th>Site</th><th>Type</th><th>Name</th><th>Why</th></tr>${sc.unverified.map(u => `<tr><td class="mono">${esc(u.site)}</td><td>${esc(u.type)}</td><td>${esc(u.name)} <span class="mut">${esc(u.ver)}</span></td><td class="mut">${esc(u.why)}</td></tr>`).join('')}</table>` : '<p class="mut">Everything found was compared.</p>'}</div>
  </div>`;
  const save = (name, text, type) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], {type})); a.download = name; a.click(); };
  const stamp = new Date(sc.meta.finished * 1000).toISOString().slice(0, 10);
  $('#dltxt').onclick = async () => { const r = await api('report'); if (r.text) save(`seo-spam-fix-${sc.meta.host}-${stamp}.txt`, r.text, 'text/plain'); };
  $('#dljson').onclick = () => save(`seo-spam-fix-${sc.meta.host}-${stamp}.json`, JSON.stringify(D.scan, null, 1), 'application/json');
}

/* ---------- tool ---------- */
function renderTool() {
  main.innerHTML = head('This tool') + `<div class="card" style="max-width:760px">
    <table><tr><td class="mut" style="width:190px">File</td><td class="mono">${esc(BOOT.file)}</td></tr>
    <tr><td class="mut">Scan data and quarantine</td><td class="mono" style="word-break:break-all">${esc(BOOT.dataDir)}</td></tr>
    <tr><td class="mut">Locks itself on</td><td>${esc(when(BOOT.expires))}</td></tr></table>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:16px"><button id="t-scan">Scan again</button><button id="t-discard" ${D ? '' : 'disabled'}>Discard scan results</button><button id="t-del" style="border-color:var(--red);color:var(--red)">Delete this tool from the server</button></div>
    <p class="mut small" style="margin-top:14px">Deleting the tool removes only this file. The quarantine folder stays, so you can upload the tool again later and restore from it.</p></div>`;
  $('#t-scan').onclick = renderStart;
  $('#t-discard').onclick = async () => { if (await ask('Discard scan results?', 'Quarantined items are not affected.', 'Discard')) { await api('discard'); selFor = 0; load('start'); } };
  $('#t-del').onclick = async () => {
    if (!await ask('Delete this tool?', 'The file is removed from the server now. Quarantined items stay where they are.', 'Delete')) return;
    const r = await api('selfdelete');
    document.body.innerHTML = `<div class="login"><div class="card"><h2>${r.ok ? 'Tool deleted' : 'Could not delete'}</h2><p class="mut">${r.ok ? 'The file has been removed from the server. You can close this tab.' : esc(r.error)}</p></div></div>`;
  };
}

document.querySelectorAll('.nav').forEach(b => b.onclick = () => go(b.dataset.view));
load();
