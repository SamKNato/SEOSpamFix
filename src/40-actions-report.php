
/* ------------------------------------------------------------------ quarantine and restore */
function ssf_protected($abs, $scan) {
    if ($abs === $scan['meta']['base'] || $abs === __FILE__) return true;
    $real = realpath($abs);
    if ($real !== false) {
        foreach ([ssf_self(), (string) realpath(ssf_data_dir())] as $keep) {
            if ($keep !== '' && ($real === $keep || strpos($keep, $real . '/') === 0)) return true; // the tool, its data, or a folder holding them
        }
    }
    foreach ($scan['installs'] as $I) {
        $ip = $I['path'];
        if ($abs === $ip) return true;
        foreach (['wp-admin', 'wp-includes', 'wp-content', 'wp-content/plugins', 'wp-content/themes', 'wp-content/uploads', 'wp-content/mu-plugins', 'wp-config.php', 'index.php', '.htaccess'] as $k) if ($abs === "$ip/$k") return true;
    }
    return false;
}
function ssf_quarantine($ids) {
    $scan = ssf_load('scan.json');
    if (!$scan) return ['error' => 'No scan results. Run a scan first.'];
    $base = $scan['meta']['base'];
    $want = array_flip(array_map('intval', (array) $ids));
    $run = gmdate('Ymd-His');
    $dir = ssf_data_dir() . '/quarantine/' . $run;
    if (!@mkdir($dir . '/files', 0700, true) && !is_dir($dir . '/files')) return ['error' => 'Could not create the quarantine folder. Nothing was changed.'];
    $man = ['run' => $run, 'created' => time(), 'base' => $base, 'items' => [], 'restored' => 0];
    $res = [];
    $inside = function ($abs) use ($base) { $real = realpath(dirname($abs)); return $real !== false && ($real === $base || strpos($real . '/', $base . '/') === 0); };
    foreach ($scan['findings'] as &$f) {
        if (!isset($want[$f['id']]) || $f['state'] !== 'open' || !in_array($f['fix'], ['quarantine', 'htaccess', 'harden', 'chmod'], true)) continue;
        $abs = $base . '/' . $f['path'];
        $r = ['id' => $f['id'], 'path' => $f['path'] ?: $f['title'], 'ok' => false, 'msg' => ''];
        if ($f['fix'] === 'chmod') {
            $modes = [];
            foreach ((array) ($f['paths'] ?? []) as $rel) {
                $a = $base . '/' . $rel;
                if (!$inside($a) || is_link($a) || !file_exists($a)) continue;
                $old = @fileperms($a) & 07777;
                if (@chmod($a, is_dir($a) ? 0755 : 0644)) $modes[$rel] = $old;
            }
            if (!$modes) { $r['msg'] = 'no permissions could be changed'; $res[] = $r; continue; }
            $man['items'][] = ['id' => $f['id'], 'type' => 'chmod', 'path' => count($modes) . ' files and folders', 'modes' => $modes];
            $r['ok'] = true; $r['msg'] = count($modes) . ' permissions tightened';
        } elseif (!$inside($abs)) { $r['msg'] = 'path is outside the scanned folder'; $res[] = $r; continue; }
        elseif ($f['fix'] === 'htaccess' || $f['fix'] === 'harden') {
            $exists = is_file($abs);
            $orig = $exists ? @file_get_contents($abs) : '';
            if ($orig === false) { $r['msg'] = 'file is not readable'; $res[] = $r; continue; }
            $new = $f['fix'] === 'htaccess' ? ssf_ht_strip($orig) : ssf_harden_merge($orig, (string) ($f['rule'] ?? ''));
            if ($new === null || $new === $orig) { $r['msg'] = $f['fix'] === 'htaccess' ? 'redirect block no longer found; file left unchanged' : 'rule already present'; $res[] = $r; continue; }
            $bk = 'htaccess-' . $f['id'] . '.orig';
            if ($exists && @file_put_contents("$dir/$bk", $orig) === false) { $r['msg'] = 'could not save a backup; file left unchanged'; $res[] = $r; continue; }
            if (@file_put_contents($abs, $new, LOCK_EX) === false) { $r['msg'] = 'file is not writable'; $res[] = $r; continue; }
            if ($f['fix'] === 'harden' && strpos(__FILE__, dirname($abs) . '/') === 0 && ($u = ssf_url_for(__FILE__))) {
                list($code) = ssf_http_head($u . '?ssf_alive=1');
                if ($code >= 500) {
                    if ($exists) @file_put_contents($abs, $orig, LOCK_EX); else @unlink($abs);
                    $r['msg'] = 'this server rejected the rule (error ' . $code . '), so it was rolled back; nothing changed';
                    $res[] = $r; continue;
                }
            }
            $man['items'][] = ['id' => $f['id'], 'type' => $f['fix'], 'path' => $f['path'], 'backup' => $exists ? $bk : null];
            $r['ok'] = true; $r['msg'] = $f['fix'] === 'htaccess' ? 'redirect block removed, original saved' : 'protective rule added, original saved';
        } else {
            if (!file_exists($abs) && !is_link($abs)) { $r['msg'] = 'no longer there'; $f['state'] = 'gone'; $res[] = $r; continue; }
            if (ssf_protected($abs, $scan)) { $r['msg'] = 'protected path; refused'; $res[] = $r; continue; }
            $dst = $dir . '/files/' . $f['path'];
            @mkdir(dirname($dst), 0700, true);
            $ok = @rename($abs, $dst);
            if (!$ok && is_file($abs)) { $ok = @copy($abs, $dst) && @unlink($abs); }
            if (!$ok) { $r['msg'] = 'could not move (permissions?)'; $res[] = $r; continue; }
            $man['items'][] = ['id' => $f['id'], 'type' => 'move', 'path' => $f['path']];
            $r['ok'] = true; $r['msg'] = 'moved to quarantine';
        }
        $f['state'] = 'quarantined'; $f['run'] = $run;
        $res[] = $r;
    }
    unset($f);
    if (!$man['items']) { @rmdir($dir . '/files'); @rmdir($dir); return ['ok' => true, 'run' => null, 'results' => $res]; }
    @file_put_contents($dir . '/manifest.json', json_encode($man, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE));
    ssf_save('scan.json', $scan);
    return ['ok' => true, 'run' => $run, 'results' => $res, 'where' => $dir];
}
function ssf_runs() {
    $out = [];
    foreach (array_reverse(@glob(ssf_data_dir() . '/quarantine/*/manifest.json') ?: []) as $mf) {
        $m = json_decode((string) @file_get_contents($mf), true);
        if (is_array($m)) $out[] = ['run' => $m['run'], 'created' => $m['created'], 'restored' => $m['restored'], 'base' => $m['base'], 'items' => array_map(function ($i) { return ['type' => $i['type'], 'path' => $i['path']]; }, $m['items'])];
    }
    return $out;
}
function ssf_restore($run) {
    if (!preg_match('/^\d{8}-\d{6}$/', (string) $run)) return ['error' => 'Unknown quarantine run.'];
    $dir = ssf_data_dir() . '/quarantine/' . $run;
    $m = json_decode((string) @file_get_contents($dir . '/manifest.json'), true);
    if (!is_array($m)) return ['error' => 'Unknown quarantine run.'];
    if ($m['restored']) return ['error' => 'This run was already restored.'];
    $res = []; $back = [];
    foreach (array_reverse($m['items']) as $it) {
        $abs = $m['base'] . '/' . $it['path'];
        $r = ['path' => $it['path'], 'ok' => false, 'msg' => ''];
        if ($it['type'] === 'chmod') {
            $n = 0;
            foreach ((array) $it['modes'] as $rel => $perm) if (@chmod($m['base'] . '/' . $rel, (int) $perm)) $n++;
            $r['ok'] = $n > 0; $r['msg'] = $n . ' permissions put back';
        } elseif ($it['type'] === 'htaccess' || $it['type'] === 'harden') {
            if (empty($it['backup'])) { $r['ok'] = !is_file($abs) || @unlink($abs); $r['msg'] = $r['ok'] ? 'file removed (it did not exist before)' : 'could not remove the file'; }
            else { @copy($abs, $dir . '/' . $it['backup'] . '.changed'); $r['ok'] = @copy($dir . '/' . $it['backup'], $abs); $r['msg'] = $r['ok'] ? 'original restored' : 'could not write the file'; }
        } else {
            $src = $dir . '/files/' . $it['path'];
            if (file_exists($abs)) $r['msg'] = 'something already exists at that path; left in quarantine';
            elseif (!file_exists($src)) $r['msg'] = 'not found in quarantine';
            else { @mkdir(dirname($abs), 0755, true); $r['ok'] = @rename($src, $abs); $r['msg'] = $r['ok'] ? 'restored' : 'could not move back'; }
        }
        if ($r['ok']) $back[$it['id']] = 1;
        $res[] = $r;
    }
    $m['restored'] = time();
    @file_put_contents($dir . '/manifest.json', json_encode($m, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE));
    $scan = ssf_load('scan.json');
    if ($scan) { foreach ($scan['findings'] as &$f) if (($f['run'] ?? '') === $run && isset($back[$f['id']])) { $f['state'] = 'open'; unset($f['run']); } unset($f); ssf_save('scan.json', $scan); }
    return ['ok' => true, 'results' => $res];
}

/* ------------------------------------------------------------------ summary, recommendations, report */
function ssf_summary($scan) {
    $sev = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0]; $cat = []; $prop = 0; $q = 0;
    foreach ($scan['findings'] as $f) {
        if ($f['state'] === 'quarantined') { $q++; continue; }
        if ($f['state'] !== 'open') continue;
        $sev[$f['sev']]++;
        if ($f['sev'] !== 'info') $cat[$f['cat']] = ($cat[$f['cat']] ?? 0) + 1;
        if ($f['tick']) $prop++;
    }
    $risk = min(100, $sev['critical'] * 25 + $sev['high'] * 10 + $sev['medium'] * 3 + $sev['low']);
    $infected = false;
    foreach ($scan['findings'] as $f) if ($f['state'] === 'open' && in_array($f['sev'], ['critical', 'high'], true) && in_array($f['cat'], ['doorway', 'implant', 'htaccess', 'database'], true)) { $infected = true; break; }
    $label = $infected ? 'Infected' : ($risk >= 60 ? 'High risk' : ($risk >= 25 ? 'At risk' : ($risk > 0 ? 'Needs attention' : 'No problems found')));
    return ['sev' => $sev, 'cat' => $cat, 'risk' => $risk, 'label' => $label, 'proposed' => $prop, 'quarantined' => $q];
}
function ssf_recommend($scan) {
    $has = []; $hadIncident = false;
    foreach ($scan['findings'] as $f) { $has[$f['cat']] = ($has[$f['cat']] ?? 0) + 1; if (in_array($f['sev'], ['critical', 'high'], true) && in_array($f['cat'], ['doorway', 'implant', 'htaccess', 'leftover', 'integrity', 'database'], true)) $hadIncident = true; if ($f['cat'] === 'leftover') $hadIncident = true; }
    $t = function ($needle) use ($scan) { foreach ($scan['findings'] as $f) if (stripos($f['title'], $needle) !== false) return true; return false; };
    $r = [];
    if ($hadIncident) {
        $r[] = [1, 'Change every password, today', 'Hosting control panel (cPanel), FTP accounts, each database password (then update wp-config.php), and every WordPress administrator. Then replace the eight keys and salts in wp-config.php with new ones from api.wordpress.org/secret-key/1.1/salt/ so all existing logins are ended. Removing files does not help if the attacker still has a password.'];
        $r[] = [1, 'Find out how they got in', 'This tool removes what was planted; it cannot tell you which door was used. Look at the raw access logs in cPanel for the day the first bad file was created (see "Recently changed files"). Look for POST requests to odd PHP files, logins from unfamiliar countries, and file-manager activity.'];
    }
    if (!empty($has['secrets'])) $r[] = [1, 'Revoke every leaked key and password', 'Hiding or deleting the file does not help once a key has been public: bots collect them within hours. Sign in to each provider named in the findings, revoke or roll the key, and check that account for activity you do not recognise. Then keep keys in server-side code or in a file above public_html, never in JavaScript or HTML.'];
    if (!empty($has['code'])) $r[] = [$t('SQL injection') || $t('system command') || $t('which file the page loads') || $t('no check on the file type') || $t('Password written') || $t('checked in the browser') ? 1 : 2, 'Fix the code weaknesses, worst first', 'Open each "Code weaknesses" finding. It names the file and lines and gives an instruction you can paste into your AI coding tool. Fix critical and high ones first, read the change before uploading it, test the page, then scan again. These are pattern matches: a few will be false alarms, and some real problems will not be matched.'];
    if (!empty($has['config'])) $r[] = [2, 'Apply the server settings', 'Quarantine applies the protective .htaccess rules for you. The rest is done in cPanel: PHP version under "Select PHP Version" or "MultiPHP Manager", error display under "MultiPHP INI Editor", and HTTPS under Domains > "Force HTTPS Redirect".'];
    if (!empty($has['code']) || !empty($has['secrets'])) $r[] = [3, 'Have a person review anything that handles money or personal data', 'This audit matches known patterns. It does not understand what the site is meant to do, so it cannot tell whether one customer can open another customer\'s records, whether prices can be changed in the browser, or whether an admin page checks who is logged in. For payments, logins and personal data, pay for a review before launch.'];
    if (!empty($has['doorway'])) $r[] = [1, 'Clean up in Google Search Console', 'After quarantining the spam pages: open Search Console, remove any owner you do not recognise (Settings > Users and permissions), delete sitemaps you did not submit, and use Removals to drop the spam addresses. Then request indexing of your home page. Spam results can take a few weeks to disappear.'];
    if (!empty($has['htaccess'])) $r[] = [1, 'Re-check .htaccess in a few days', 'If the redirect block comes back, something on the account is rewriting it: a backdoor that was missed, a cron job, or a stolen password.'];
    if ($t('system file')) $r[] = [1, 'Reinstall WordPress core', 'Dashboard > Updates > "Re-install version". This replaces every system file with a clean copy and does not touch your content, themes or plugins.'];
    if ($t('differs from the official') || $t('differ from the official') || $t('Plugin file changed')) $r[] = [1, 'Reinstall the plugins that were changed', 'Delete each flagged plugin and install it again from WordPress.org. Settings live in the database and are kept.'];
    if ($scan['unverified']) { $n = count(ssf_keep($scan['unverified'], function ($u) { return $u['type'] === 'plugin'; })); $r[] = [2, 'Replace premium and custom code from a trusted copy', "$n plugin(s) and all themes could not be compared with an official copy (see the list below). Download fresh copies from the vendor account that holds the licence and replace the folders. If there is no licence, the copy is probably nulled: nulled plugins and themes are one of the commonest ways sites like this get infected. Buy it or remove it."]; }
    if ($t('File-manager') || $t('file-manager tool')) $r[] = [1, 'Remove file-manager plugins', 'They give anyone with an admin login, or an exploit for the plugin, direct access to every file on the account. Use cPanel File Manager or SFTP instead.'];
    if ($t('Remote-control') || $t('connector')) $r[] = [3, 'Confirm who holds the remote-management accounts', 'ManageWP, MainWP, BlogVault, MalCare and similar services can run code on the site by design. Keep the ones you use, with a strong password and 2FA on that service; remove the rest.'];
    if (!empty($has['exposure'])) $r[] = [1, 'Get backups and archives out of the web folders', 'Anything under public_html can be downloaded by address. Keep backups outside public_html or off the server. If a copy of wp-config was exposed, change that database password.'];
    if (!empty($has['uploads'])) $r[] = [2, 'Block PHP from running in uploads', "Add a file named .htaccess inside wp-content/uploads containing:\n<FilesMatch \"\\.(php|phtml|phar)$\">\n  Require all denied\n</FilesMatch>\nThen test that image uploads and any plugin that stores files there still work."];
    if (!empty($has['outdated'])) $r[] = [2, 'Update WordPress, then turn on automatic updates', 'Also update every plugin and theme, and delete the ones that are not active. Remove WordPress installs that are no longer used; an abandoned site is an open door to the rest of the account.'];
    if (count($scan['installs']) >= 2) $r[] = [2, 'Separate the sites', 'Ask the host for a plan where each site has its own account (its own cPanel user). Until then, treat the sites as one: clean all of them together.'];
    if (!empty($has['database'])) $r[] = [1, 'Clean the database by hand', 'Spam stored in posts, pages or settings is not touched by this tool. Remove it in WordPress admin, or restore the database from a backup taken before the infection.'];
    if (!empty($has['leftover'])) $r[] = [2, 'Treat this as a repeat infection', 'Emptied backdoor files mean a scanner cleaned this site before and the attacker came back. A cleaner alone will not hold: the entry point has to be closed (passwords, vulnerable plugins, nulled code).'];
    $r[] = [3, 'Harden what is left', 'Turn on two-factor login for administrators. Add "define(\'DISALLOW_FILE_EDIT\', true);" to wp-config.php. Put a firewall in front of the site (Wordfence or Cloudflare). Keep a scheduled off-site backup.'];
    $r[] = [3, 'Scan again in a week, then delete this tool', 'Run a second scan after the password changes. If new findings appear, the entry point is still open. When you are finished, use "Delete this tool" so it cannot be found by anyone else.'];
    usort($r, function ($a, $b) { return $a[0] <=> $b[0]; });
    return array_map(function ($x) { return ['p' => $x[0], 'title' => $x[1], 'body' => $x[2]]; }, $r);
}
function ssf_limits() {
    return ['It cannot tell you how the attacker got in, or close that door. Passwords, vulnerable plugins and nulled code are yours to fix.',
        'It cannot verify premium plugins, custom plugins or themes against an official copy. It only pattern-scans them, and a careful attacker can evade patterns.',
        'It does not change the database. Spam in posts, rogue users and injected settings are reported, not removed.',
        'It does not repair changed WordPress or plugin files. It tells you which ones to reinstall.',
        'It cannot see other hosting accounts, the server itself, or email accounts.',
        'It does not remove the site from blacklists or clean Google results. Use Search Console for that.',
        'It cannot find mistakes in how the site is meant to work: who may see what, whether prices or roles can be changed by a visitor, missing login checks.',
        'It does not audit WordPress plugins, themes or bundled libraries line by line, and it does not yet check library versions against known vulnerabilities.',
        'It cannot see access rules held elsewhere, such as Supabase or Firebase database rules, or what a leaked key was used for.',
        'It tests HTTPS, headers and folder listing only on the domain it was opened from.',
        'A clean result means nothing known was found, not that the site is proven clean or secure.'];
}
function ssf_report_text($scan) {
    $s = ssf_summary($scan); $o = [];
    $o[] = 'SEO SPAM FIX REPORT'; $o[] = str_repeat('=', 72);
    $o[] = 'Host: ' . $scan['meta']['host']; $o[] = 'Scanned folder: ' . $scan['meta']['base'];
    $o[] = 'Finished: ' . gmdate('Y-m-d H:i', $scan['meta']['finished']) . ' UTC   Files: ' . $scan['meta']['files'] . '   Own PHP files audited: ' . ($scan['meta']['audited'] ?? 0) . '   PHP checked by pattern: ' . $scan['meta']['php'] . '   Verified against official copies: ' . $scan['meta']['verified'];
    $o[] = sprintf('Result: %s (risk %d/100)   Critical %d, high %d, medium %d, low %d   Quarantined so far: %d', $s['label'], $s['risk'], $s['sev']['critical'], $s['sev']['high'], $s['sev']['medium'], $s['sev']['low'], $s['quarantined']);
    $o[] = ''; $o[] = 'SITES'; $o[] = str_repeat('-', 72);
    foreach ($scan['installs'] as $I) $o[] = '  ' . $I['rel'] . '   WordPress ' . ($I['ver'] ?: 'missing') . '   core check: ' . $I['core'] . '   database: ' . $I['db'] . '   admins: ' . implode(', ', array_map(function ($a) { return $a['login']; }, $I['admins']));
    $o[] = ''; $o[] = 'FINDINGS'; $o[] = str_repeat('-', 72);
    foreach ($scan['findings'] as $f) {
        $o[] = '[' . strtoupper($f['sev']) . '] ' . $f['title'] . ($f['state'] !== 'open' ? '   (' . $f['state'] . ')' : '');
        if ($f['path'] !== '') $o[] = '    ' . $f['path'] . (isset($f['ctime']) ? '   changed ' . gmdate('Y-m-d H:i', $f['ctime']) . ' UTC' : '');
        if ($f['site'] !== '' && $f['path'] === '') $o[] = '    site: ' . $f['site'];
        $o[] = '    ' . wordwrap($f['detail'], 100, "\n    ");
        if ($f['evidence'] !== '') $o[] = '    > ' . str_replace("\n", "\n    > ", substr($f['evidence'], 0, 700));
        if (!empty($f['prompt'])) $o[] = '    Instruction for your AI coding tool: ' . wordwrap($f['prompt'], 96, "\n      ");
        $o[] = '';
    }
    $o[] = 'WHAT TO DO NEXT'; $o[] = str_repeat('-', 72);
    foreach (ssf_recommend($scan) as $i => $r) { $o[] = ($i + 1) . '. ' . $r['title']; $o[] = '   ' . wordwrap($r['body'], 100, "\n   "); $o[] = ''; }
    $o[] = 'COULD NOT BE VERIFIED AGAINST AN OFFICIAL COPY'; $o[] = str_repeat('-', 72);
    foreach ($scan['unverified'] as $u) $o[] = sprintf('  %s   %s: %s%s   (%s)', $u['site'], $u['type'], $u['name'], $u['ver'] ? ' ' . $u['ver'] : '', $u['why']);
    if ($scan['notes']) { $o[] = ''; $o[] = 'NOT CHECKED'; $o[] = str_repeat('-', 72); foreach ($scan['notes'] as $n) $o[] = '  - ' . $n; }
    $o[] = ''; $o[] = 'WHAT THIS TOOL CANNOT DO'; $o[] = str_repeat('-', 72);
    foreach (ssf_limits() as $l) $o[] = '  - ' . $l;
    $o[] = ''; $o[] = 'RECENTLY CHANGED PHP AND .htaccess FILES (UTC)'; $o[] = str_repeat('-', 72);
    foreach ($scan['recent'] as $x) $o[] = '  ' . gmdate('Y-m-d H:i', $x[0]) . '   ' . $x[3];
    return implode("\n", $o) . "\n";
}

/* ------------------------------------------------------------------ command line (read-only) */
if (PHP_SAPI === 'cli') {
    $verb = $argv[1] ?? '';
    if ($verb !== 'scan') { fwrite(STDERR, "SEO Spam Fix " . SSF_VERSION . "\nUsage: php " . basename(__FILE__) . " scan [/path/to/scan]\nRead-only. Quarantine and restore are done from the web interface.\n"); exit(1); }
    $r = ssf_start($argv[2] ?? __DIR__);
    if (isset($r['error'])) { fwrite(STDERR, $r['error'] . "\n"); exit(1); }
    do { $p = ssf_step(); if (isset($p['error'])) { fwrite(STDERR, $p['error'] . "\n"); exit(1); } if (empty($p['done'])) fwrite(STDERR, sprintf("\r%3d%%  %d files  %d findings   ", $p['pct'], $p['files'], $p['found'])); } while (empty($p['done']));
    fwrite(STDERR, "\n");
    echo ssf_report_text(ssf_load('scan.json'));
    exit(0);
}
