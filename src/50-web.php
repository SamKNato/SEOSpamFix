
/* ------------------------------------------------------------------ web: access control */
if ((ssf_query('ssf_alive') !== null)) { header('Content-Type: text/plain'); echo 'ok'; exit; } // used to test a new .htaccess rule did not break the server
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Cache-Control: no-store');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
$SSF_PW_SET  = SSF_PASSWORD !== 'change-me' && strlen(SSF_PASSWORD) >= 8;
$SSF_EXPIRES = (int) @filemtime(__FILE__) + SSF_EXPIRE_DAYS * 86400;
$SSF_EXPIRED = time() > $SSF_EXPIRES;
$SSF_DATA    = ssf_data_dir();
$ssfJson = function ($a) { header('Content-Type: application/json; charset=utf-8'); echo json_encode($a, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR); exit; };

session_name('ssf_' . substr(sha1(__FILE__), 0, 8));
session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => !empty(ssf_srv('HTTPS')) && ssf_srv('HTTPS') !== 'off']);
session_start();
$ssfLock = ($SSF_DATA ?: sys_get_temp_dir()) . '/ssf-login-' . substr(sha1(__FILE__), 0, 10) . '.json';
$ssfFails = is_file($ssfLock) ? (array) json_decode((string) @file_get_contents($ssfLock), true) : [];
$ssfLocked = (($ssfFails['n'] ?? 0) >= 6) && (time() - ($ssfFails['t'] ?? 0) < 900);
$ssfMsg = '';
$ssfBlocked = !$SSF_PW_SET || $SSF_EXPIRED;
if (!$ssfBlocked && (ssf_srv('REQUEST_METHOD') ?? '') === 'POST' && (ssf_post('pw') !== null)) {
    if ($ssfLocked) $ssfMsg = 'Too many wrong attempts. Try again in 15 minutes.';
    elseif (hash_equals(SSF_PASSWORD, (string) ssf_post('pw'))) {
        session_regenerate_id(true);
        $_SESSION['ok'] = 1; $_SESSION['csrf'] = bin2hex(random_bytes(16));
        @unlink($ssfLock);
        header('Location: ' . strtok(ssf_srv('REQUEST_URI') ?? '', '?'));
        exit;
    } else { @file_put_contents($ssfLock, json_encode(['n' => ($ssfFails['n'] ?? 0) + 1, 't' => time()])); sleep(2); $ssfMsg = 'Wrong password.'; }
}
$ssfAuthed = !$ssfBlocked && !empty($_SESSION['ok']);
$ssfCsrf = (string) ($_SESSION['csrf'] ?? '');

/* ------------------------------------------------------------------ web: API */
if ((ssf_post('api') !== null)) {
    if (!$ssfAuthed) $ssfJson(['error' => 'Signed out. Reload the page and sign in again.', 'auth' => false]);
    if ($ssfCsrf === '' || !hash_equals($ssfCsrf, (string) (ssf_post('csrf') ?? ''))) $ssfJson(['error' => 'Session check failed. Reload the page.']);
    session_write_close();
    @set_time_limit(120);
    $home = ssf_home();
    switch ((string) ssf_post('api')) {
        case 'start':
            $where = (string) (ssf_post('where') ?? 'here');
            $path = $where === 'here' ? __DIR__ : ($where === 'account' ? $home . '/public_html' : $where);
            $real = rtrim((string) realpath($path), '/');
            $allowed = $real !== '' && ($home ? (strpos($real . '/', $home . '/') === 0) : (strpos($real . '/', __DIR__ . '/') === 0 || strpos(__DIR__ . '/', $real . '/') === 0));
            if (!$allowed || $real === $home) $ssfJson(['error' => 'Choose a folder inside this hosting account' . ($home ? ' (not the home folder itself).' : '.')]);
            $ssfJson(ssf_start($real));
        case 'step': $ssfJson(ssf_step());
        case 'results':
            $scan = ssf_load('scan.json');
            if (!$scan) $ssfJson(['none' => true, 'scanning' => (bool) ssf_load('state.json'), 'runs' => ssf_runs()]);
            $ssfJson(['scan' => $scan, 'summary' => ssf_summary($scan), 'recommend' => ssf_recommend($scan), 'limits' => ssf_limits(), 'runs' => ssf_runs()]);
        case 'quarantine': $ssfJson(ssf_quarantine(json_decode((string) (ssf_post('ids') ?? '[]'), true) ?: []));
        case 'restore': $ssfJson(ssf_restore((string) (ssf_post('run') ?? '')));
        case 'report': $scan = ssf_load('scan.json'); $ssfJson($scan ? ['text' => ssf_report_text($scan)] : ['error' => 'No scan results.']);
        case 'discard': @unlink($SSF_DATA . '/scan.json'); @unlink($SSF_DATA . '/state.json'); $ssfJson(['ok' => true]);
        case 'selfdelete': $ok = @unlink(__FILE__); $ssfJson($ok ? ['ok' => true] : ['error' => 'Could not delete the file. Remove it in cPanel File Manager.']);
    }
    $ssfJson(['error' => 'Unknown request.']);
}

/* ------------------------------------------------------------------ web: page */
header('Content-Type: text/html; charset=utf-8');
$ssfBoot = null;
if ($ssfAuthed) {
    $home = ssf_home();
    $bases = [['key' => 'here', 'label' => 'This folder', 'path' => __DIR__]];
    if ($home && is_dir($home . '/public_html') && $home . '/public_html' !== __DIR__) $bases[] = ['key' => 'account', 'label' => 'The whole account (every site in public_html)', 'path' => $home . '/public_html'];
    $ssfBoot = ['csrf' => $ssfCsrf, 'version' => SSF_VERSION, 'bases' => $bases, 'host' => ssf_srv('HTTP_HOST') ?? '', 'expires' => $SSF_EXPIRES, 'dataDir' => $SSF_DATA, 'dataOutside' => $SSF_DATA && !ssf_in_webroot($SSF_DATA), 'file' => basename(__FILE__)];
}
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>SEO Spam Fix</title>
<style>
:root{--bg:#0c0e11;--panel:#14171c;--panel2:#1b1f26;--line:#262b34;--text:#e9ebee;--mut:#8c94a2;--red:#e5383b;--orange:#f07f3b;--amber:#e8b339;--slate:#7c8aa5;--teal:#35b79b;--r:10px}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI Variable Text","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
code,.mono,pre{font-family:ui-monospace,"Cascadia Mono",Consolas,Menlo,monospace;font-size:12px}
button,input,select{font:inherit;color:inherit}
button{cursor:pointer;border:1px solid var(--line);background:var(--panel2);border-radius:8px;padding:8px 14px}
button:hover{border-color:#3a4150}button:focus-visible,input:focus-visible,select:focus-visible,a:focus-visible{outline:2px solid var(--red);outline-offset:2px}
button.primary{background:var(--red);border-color:var(--red);color:#fff;font-weight:600}button.primary:hover{background:#f04a4d}
button.ghost{background:transparent}button:disabled{opacity:.45;cursor:not-allowed}
input[type=text],input[type=password],select{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;min-width:0}
a{color:inherit}
h1{font-size:20px;font-weight:600;margin:0}h2{font-size:15px;font-weight:600;margin:0 0 12px}h3{font-size:14px;font-weight:600;margin:0}
p{margin:0 0 10px}.mut{color:var(--mut)}.small{font-size:12.5px}
.app{display:grid;grid-template-columns:232px 1fr;min-height:100%}
.side{background:var(--panel);border-right:1px solid var(--line);padding:18px 12px;display:flex;flex-direction:column;gap:4px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:10px;padding:4px 8px 18px}.brand b{font-size:15px;letter-spacing:.01em}.brand svg{flex:none}
.nav{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;text-align:left;border:0;background:transparent;border-radius:8px;padding:9px 10px;color:var(--mut)}
.nav:hover{background:var(--panel2);color:var(--text)}.nav[aria-current=page]{background:var(--panel2);color:var(--text);box-shadow:inset 3px 0 0 var(--red)}
.nav .n{font-size:12px;background:var(--bg);border:1px solid var(--line);border-radius:20px;padding:0 7px;color:var(--text)}
.side .foot{margin-top:auto;padding:8px;font-size:12px;color:var(--mut)}
.main{padding:22px 26px 90px;min-width:0}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px;flex-wrap:wrap}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:18px}
.grid{display:grid;gap:14px}.g3{grid-template-columns:minmax(230px,1fr) minmax(280px,1.3fr) minmax(250px,1.1fr)}.g2{grid-template-columns:1fr 1.25fr}
.gauge{display:grid;place-items:center;text-align:center}.gauge svg{width:100%;max-width:240px}.gauge .num{font-size:44px;font-weight:650;line-height:1;margin-top:-58px}.gauge .lab{margin-top:6px;font-weight:600}
.sevrow{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.sev{border:1px solid var(--line);border-radius:8px;padding:12px;background:var(--panel2);text-align:left;width:100%}
.sev b{display:block;font-size:26px;font-weight:650;line-height:1.1}.sev i{display:block;height:3px;border-radius:3px;margin-top:8px}
.c-critical{color:var(--red)}.c-high{color:var(--orange)}.c-medium{color:var(--amber)}.c-low{color:var(--slate)}.c-info{color:var(--mut)}
.b-critical{background:var(--red)}.b-high{background:var(--orange)}.b-medium{background:var(--amber)}.b-low{background:var(--slate)}.b-info{background:#4a5160}
.bar{display:grid;grid-template-columns:150px 1fr 34px;align-items:center;gap:10px;margin:9px 0}.bar .t{height:8px;background:var(--panel2);border-radius:6px;overflow:hidden}.bar .t i{display:block;height:100%;background:var(--red);border-radius:6px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:500;font-size:12.5px}tr:last-child td{border-bottom:0}
.pill{display:inline-block;font-size:11.5px;font-weight:600;border-radius:20px;padding:1px 9px;border:1px solid currentColor;white-space:nowrap}
.tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}.tools .sp{flex:1}
.chip{border-radius:20px;padding:4px 12px;font-size:12.5px}.chip[aria-pressed=true]{border-color:var(--text);background:var(--text);color:var(--bg)}
.f{display:grid;grid-template-columns:26px 86px 1fr auto 28px;gap:10px;align-items:start;padding:11px 12px;border-bottom:1px solid var(--line)}
.f:last-child{border-bottom:0}.f .p{color:var(--mut);word-break:break-all}.f .more{grid-column:3/5;display:none;margin-top:6px}.f.open .more{display:block}
.f .x{border:0;background:transparent;padding:2px 6px;color:var(--mut)}.f.open .x{transform:rotate(90deg)}.f.done{opacity:.55}
.fix{font-size:12px;color:var(--mut);white-space:nowrap}
pre.ev{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-all;margin:8px 0 0;max-height:260px;overflow:auto}
.list{padding:0;overflow:hidden}
.actionbar{position:fixed;left:232px;right:0;bottom:0;background:var(--panel2);border-top:1px solid var(--line);padding:12px 26px;display:flex;gap:12px;align-items:center;z-index:5}
.rec{display:grid;grid-template-columns:30px 1fr;gap:12px;padding:13px 0;border-bottom:1px solid var(--line)}.rec:last-child{border-bottom:0}.rec .k{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;font-weight:650;font-size:12.5px;background:var(--panel2);border:1px solid var(--line)}.rec .k.p1{border-color:var(--red);color:var(--red)}
.rec p{white-space:pre-wrap;margin:4px 0 0;color:#c4c9d2;max-width:78ch}
.prompt{border:1px solid var(--line);border-left:3px solid var(--teal);border-radius:0 8px 8px 0;background:var(--panel2);padding:10px 12px;margin-top:10px}.prompt .ph{display:flex;justify-content:space-between;align-items:center;gap:10px}.prompt p{margin:6px 0 0;color:#c4c9d2;max-width:84ch}.prompt .copy{padding:3px 10px;font-size:12px}.bar[data-cat]{cursor:pointer}.bar[data-cat]:hover span:first-child{text-decoration:underline}
.note{border-left:3px solid var(--amber);background:var(--panel2);padding:10px 14px;border-radius:0 8px 8px 0;margin:0 0 14px}
.ok{color:var(--teal)}.bad{color:var(--red)}
dialog{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:12px;padding:22px;max-width:520px;width:calc(100% - 32px)}dialog::backdrop{background:rgba(5,6,8,.72)}
dialog .row{display:flex;gap:10px;justify-content:flex-end;margin-top:18px}
.login{min-height:100%;display:grid;place-items:center;padding:24px}.login .card{width:100%;max-width:400px}
.start label{display:flex;gap:10px;align-items:flex-start;padding:12px;border:1px solid var(--line);border-radius:8px;margin-bottom:8px;cursor:pointer}.start label:has(input:checked){border-color:var(--red);background:var(--panel2)}
ul.plain{margin:0;padding-left:18px}ul.plain li{margin:5px 0;max-width:80ch}
@media (max-width:1100px){.g3,.g2{grid-template-columns:1fr}}
@media (max-width:820px){.app{grid-template-columns:1fr}.side{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;padding:10px}.brand{padding:4px 8px}.side .foot{display:none}.nav{width:auto}.nav[aria-current=page]{box-shadow:inset 0 -3px 0 var(--red)}.main{padding:16px 14px 100px}.actionbar{left:0;padding:10px 14px}.f{grid-template-columns:24px 1fr 24px}.f .sv{grid-column:2}.f .fix{grid-column:2}.f .more{grid-column:2}.sevrow{grid-template-columns:repeat(2,1fr)}}
@media (prefers-reduced-motion:no-preference){.gauge path.v{transition:stroke-dashoffset .5s ease}.f .x{transition:transform .15s}}
@media print{.side,.actionbar,.tools,button{display:none!important}.app{display:block}body{background:#fff;color:#000}.card{border-color:#bbb;background:#fff;break-inside:avoid}.mut,.rec p,.f .p{color:#333}pre{background:#f4f4f4;border-color:#ccc}}
</style></head><body>
<?php if (!$ssfAuthed): ?>
<div class="login"><div class="card">
  <div class="brand" style="padding:0 0 14px"><svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true"><rect width="28" height="28" rx="7" fill="#e5383b"/><path d="M8 9.5h12M8 14h7M8 18.5h10" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/><circle cx="20" cy="14" r="2.2" fill="#0c0e11"/></svg><b>SEO Spam Fix</b></div>
  <?php if (!$SSF_PW_SET): ?>
    <h2>Set a password first</h2><p class="mut">Open this file in an editor, find the line <code>const SSF_PASSWORD = 'change-me';</code> near the top and replace <code>change-me</code> with a password of at least 8 characters. Upload it again and reload this page.</p>
  <?php elseif ($SSF_EXPIRED): ?>
    <h2>This copy has locked itself</h2><p class="mut">For safety the tool stops working <?php echo (int) SSF_EXPIRE_DAYS; ?> days after it is uploaded, so a forgotten copy cannot be used by someone else. Upload the file again to continue. Anything in quarantine is still there and can be restored after you sign in.</p>
  <?php else: ?>
    <h2>Sign in</h2><?php if ($ssfMsg) echo '<p class="bad">' . htmlspecialchars($ssfMsg) . '</p>'; ?>
    <form method="post" style="display:flex;gap:8px"><input type="password" name="pw" aria-label="Password" placeholder="Password" autofocus style="flex:1"><button class="primary">Sign in</button></form>
  <?php endif; ?>
</div></div>
<?php else: ?>
<div class="app">
  <nav class="side" aria-label="Sections">
    <div class="brand"><svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true"><rect width="28" height="28" rx="7" fill="#e5383b"/><path d="M8 9.5h12M8 14h7M8 18.5h10" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/><circle cx="20" cy="14" r="2.2" fill="#0c0e11"/></svg><b>SEO Spam Fix</b></div>
    <button class="nav" data-view="overview">Overview</button>
    <button class="nav" data-view="findings">Findings <span class="n" id="n-findings" hidden></span></button>
    <button class="nav" data-view="quarantine">Quarantine <span class="n" id="n-quarantine" hidden></span></button>
    <button class="nav" data-view="report">What to do next</button>
    <button class="nav" data-view="tool">This tool</button>
    <div class="foot" id="foot"></div>
  </nav>
  <main class="main" id="main" tabindex="-1"></main>
</div>
<dialog id="dlg"><h2 id="dlg-t"></h2><div id="dlg-b" class="mut"></div><div class="row"><button class="ghost" id="dlg-no">Cancel</button><button class="primary" id="dlg-yes"></button></div></dialog>
<script>
const BOOT = <?php echo json_encode($ssfBoot, JSON_HEX_TAG | JSON_HEX_AMP | JSON_INVALID_UTF8_SUBSTITUTE); ?>;
</script>
<script>
