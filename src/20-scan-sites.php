
/* ------------------------------------------------------------------ scan engine */
function ssf_add(&$st, $f) {
    if (count($st['findings']) >= SSF_MAX_FINDINGS) { $st['truncated'] = true; return; }
    $f += ['site' => '', 'path' => '', 'kind' => 'none', 'cat' => 'integrity', 'sev' => 'medium', 'title' => '', 'detail' => '', 'evidence' => '', 'fix' => 'manual', 'tick' => false, 'state' => 'open'];
    if ($f['path'] !== '' && $f['kind'] !== 'none') {
        $s = @lstat($st['base'] . '/' . $f['path']);
        if ($s) { $f['size'] = $s['size']; $f['mtime'] = $s['mtime']; $f['ctime'] = $s['ctime']; }
    }
    $f['id'] = count($st['findings']) + 1;
    $st['findings'][] = $f;
}
function ssf_rel($st, $p) { return $p === $st['base'] ? '.' : substr($p, strlen($st['base']) + 1); }
function ssf_inst_for($st, $p) {
    static $sorted = null, $n = -1;
    if ($sorted === null || $n !== count($st['installs'])) { $sorted = array_keys($st['installs']); usort($sorted, function ($a, $b) { return strlen($b) - strlen($a); }); $n = count($sorted); }
    foreach ($sorted as $ip) if ($p === $ip || strpos($p, $ip . '/') === 0) return $ip;
    return null;
}
function ssf_start($base) {
    $base = rtrim((string) realpath($base), '/');
    if ($base === '' || !is_dir($base) || !is_readable($base)) return ['error' => 'That folder does not exist or cannot be read.'];
    if (!ssf_data_dir()) return ['error' => 'No writable folder for scan data. Make the account home folder or this folder writable.'];
    $found = [];
    foreach (['', '/*', '/*/*', '/*/*/*'] as $pat) {
        foreach (array_merge(@glob($base . $pat . '/wp-includes/version.php') ?: [], @glob($base . $pat . '/wp-config.php') ?: []) as $w) {
            $dn = basename($w) === 'version.php' ? dirname(dirname($w)) : dirname($w);
            if (is_link($dn) || strpos($dn . '/', ssf_data_dir() . '/') === 0) continue;
            $found[$dn] = 1;
        }
    }
    $installs = [];
    foreach (array_keys($found) as $ip) {
        $ver = ''; $loc = 'en_US';
        $vc = (string) @file_get_contents($ip . '/wp-includes/version.php');
        if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', $vc, $m)) $ver = $m[1];
        if (preg_match('/\$wp_local_package\s*=\s*[\'"]([^\'"]+)/', $vc, $m)) $loc = $m[1];
        $installs[$ip] = ['path' => $ip, 'rel' => $ip === $base ? '.' : substr($ip, strlen($base) + 1), 'label' => basename($ip), 'ver' => $ver, 'locale' => $loc, 'config' => is_file($ip . '/wp-config.php'), 'core' => 'pending', 'themes' => [], 'admins' => [], 'db' => 'pending'];
    }
    $st = ['v' => 1, 'base' => $base, 'started' => time(), 'phase' => 'pre', 'pre' => array_keys($installs), 'queue' => [$base], 'qi' => 0, 'files' => 0, 'php' => 0, 'verified' => 0,
        'installs' => $installs, 'findings' => [], 'plugins' => [], 'skip' => [], 'recent' => [], 'notes' => [], 'core_mod' => [], 'core_extra' => [], 'upl' => [], 'arch' => [], 'net' => true, 'latest' => '', 'truncated' => false, 'current' => '', 'env' => false, 'logs' => [], 'perms' => [], 'srcexp' => [], 'baas' => []];
    ssf_save('state.json', $st);
    return ['ok' => true, 'installs' => count($installs)];
}
function ssf_db($ip) {
    $cfg = (string) @file_get_contents($ip . '/wp-config.php');
    if ($cfg === '') return [null, 'wp_', 'no wp-config.php'];
    $g = function ($k) use ($cfg) { return preg_match('/define\(\s*[\'"]' . $k . '[\'"]\s*,\s*([\'"])(.*?)\1\s*\)/s', $cfg, $m) ? $m[2] : null; };
    $px = preg_match('/\$table_prefix\s*=\s*[\'"]([^\'"]+)/', $cfg, $m) ? $m[1] : 'wp_';
    if (!preg_match('/^[A-Za-z0-9_]+$/', $px)) return [null, $px, 'unusual table prefix'];
    if (!extension_loaded('mysqli')) return [null, $px, 'mysqli is not available'];
    if ($g('DB_NAME') === null) return [null, $px, 'database settings not readable'];
    mysqli_report(MYSQLI_REPORT_OFF);
    $host = (string) $g('DB_HOST'); $port = null; $sock = null;
    if (strpos($host, ':') !== false) { list($host, $rest) = explode(':', $host, 2); if (ctype_digit($rest)) $port = (int) $rest; else $sock = $rest; }
    $db = @mysqli_connect($host ?: 'localhost', (string) $g('DB_USER'), (string) $g('DB_PASSWORD'), (string) $g('DB_NAME'), $port ?: 3306, $sock);
    if (!$db) return [null, $px, 'could not connect: ' . ssf_one_line((string) mysqli_connect_error(), 80)];
    return [$db, $px, ''];
}
function ssf_q($db, $sql) { $r = @mysqli_query($db, $sql); if (!$r || $r === true) return []; $o = []; while ($row = mysqli_fetch_assoc($r)) $o[] = $row; return $o; }

function ssf_pre_install(&$st, $ip) {
    $I = &$st['installs'][$ip];
    $site = $I['rel'];
    $rp = function ($p) use ($st) { return ssf_rel($st, $p); };
    /* core checksums + latest version */
    if ($I['ver'] && $st['net']) {
        $cf = 'cache-core-' . preg_replace('/[^A-Za-z0-9._-]/', '', $I['ver'] . '-' . $I['locale']) . '.json';
        if (!ssf_load($cf)) {
            list($code, $body) = ssf_http('https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($I['ver']) . '&locale=' . rawurlencode($I['locale']), 15);
            $j = json_decode($body, true);
            if ($code === 0) $st['net'] = false;
            if (is_array($j) && !empty($j['checksums']) && is_array($j['checksums'])) ssf_save($cf, $j['checksums']);
        }
        $I['core'] = ssf_load($cf) ? 'ok' : 'unavailable';
        if ($st['latest'] === '' && $st['net']) {
            list($code, $body) = ssf_http('https://api.wordpress.org/core/version-check/1.7/');
            $j = json_decode($body, true);
            $st['latest'] = isset($j['offers'][0]['version']) ? (string) $j['offers'][0]['version'] : '-';
        }
    } else { $I['core'] = $I['ver'] ? 'unavailable' : 'none'; }
    if ($I['core'] === 'unavailable') $st['notes'][] = "$site: could not download the official WordPress file list, so core files were checked by pattern only.";
    if ($I['ver'] && preg_match('/^\d/', $st['latest']) && version_compare($I['ver'], $st['latest'], '<')) {
        $maj = function ($v) { $p = explode('.', $v); return (int) $p[0] * 100 + (int) ($p[1] ?? 0); };
        ssf_add($st, ['site' => $site, 'cat' => 'outdated', 'sev' => $maj($st['latest']) - $maj($I['ver']) >= 2 ? 'high' : 'medium', 'title' => 'WordPress ' . $I['ver'] . ' is out of date', 'detail' => 'Latest is ' . $st['latest'] . '. Old versions have published security holes.']);
    }
    if (!$I['ver']) ssf_add($st, ['site' => $site, 'cat' => 'outdated', 'sev' => 'medium', 'title' => 'Incomplete WordPress install', 'detail' => 'wp-config.php exists but WordPress itself is missing or broken. Abandoned installs are easy targets; remove the folder if the site is not used.']);

    /* database */
    list($db, $px, $err) = ssf_db($ip);
    $slugs = [];
    if (!$db) { $I['db'] = 'unchecked'; if ($I['config']) $st['notes'][] = "$site: database not checked ($err)."; }
    else {
        $I['db'] = 'checked';
        foreach (ssf_q($db, "SELECT post_name FROM `{$px}posts` WHERE post_status='publish' AND post_parent=0 AND post_type NOT IN ('revision','attachment','nav_menu_item','custom_css','oembed_cache','wp_navigation','elementor_library') LIMIT 5000") as $r) $slugs[strtolower($r['post_name'])] = 1;
        $admins = ssf_q($db, "SELECT u.ID,u.user_login,u.user_email,u.user_registered FROM `{$px}users` u JOIN `{$px}usermeta` m ON m.user_id=u.ID WHERE m.meta_key='{$px}capabilities' AND m.meta_value LIKE '%administrator%' ORDER BY u.user_registered");
        $recent = [];
        foreach ($admins as $a) {
            $em = (string) $a['user_email']; $at = strpos($em, '@');
            $I['admins'][] = ['login' => ssf_clean($a['user_login']), 'email' => $at === false ? '***' : substr($em, 0, 2) . '***' . substr($em, $at), 'registered' => (string) $a['user_registered']];
            if (strtotime((string) $a['user_registered']) > time() - 120 * 86400) $recent[] = ssf_clean($a['user_login']);
        }
        $names = implode(', ', array_map(function ($a) { return $a['login']; }, $I['admins']));
        ssf_add($st, ['site' => $site, 'cat' => 'access', 'sev' => $recent ? 'medium' : 'info', 'title' => count($I['admins']) . ' administrator account' . (count($I['admins']) === 1 ? '' : 's') . ($recent ? ', ' . count($recent) . ' created in the last 4 months' : ''), 'detail' => 'Confirm you recognise every one: ' . $names . '. Delete any you do not.' . ($recent ? ' Recently created: ' . implode(', ', $recent) . '.' : '')]);
        $rx = 'slot gacor|togel|judi online|situs slot|slot88|maxwin|sbobet|bandar togel|buy viagra|cialis online';
        $sp = ssf_q($db, "SELECT ID, LEFT(post_title,60) t FROM `{$px}posts` WHERE post_status IN ('publish','draft','private') AND post_type NOT IN ('revision') AND (post_content REGEXP '$rx' OR post_title REGEXP '$rx') LIMIT 25");
        if ($sp) ssf_add($st, ['site' => $site, 'cat' => 'database', 'sev' => 'critical', 'title' => count($sp) . (count($sp) >= 25 ? '+' : '') . ' posts or pages in the database contain spam', 'detail' => 'These live in the database, not in files, so this tool cannot quarantine them. Delete or clean them in WordPress admin.', 'evidence' => ssf_one_line(implode(' | ', array_map(function ($r) { return '#' . $r['ID'] . ' ' . $r['t']; }, $sp)), 500)]);
        $codeRx = 'eval\\\\(|gzinflate\\\\(|base64_decode\\\\(';
        $op = ssf_q($db, "SELECT option_name n FROM `{$px}options` WHERE option_value REGEXP '$codeRx' AND option_name NOT LIKE '\\_transient%' AND option_name NOT LIKE '\\_site\\_transient%' LIMIT 15");
        if ($op) ssf_add($st, ['site' => $site, 'cat' => 'database', 'sev' => 'medium', 'title' => count($op) . ' database settings contain executable-looking code', 'detail' => 'Often legitimate (page builders, snippets plugins) but worth a look.', 'evidence' => ssf_one_line(implode(', ', array_map(function ($r) { return $r['n']; }, $op)), 400)]);
        $o = [];
        foreach (ssf_q($db, "SELECT option_name n, option_value v FROM `{$px}options` WHERE option_name IN ('users_can_register','default_role','siteurl','home')") as $r) $o[$r['n']] = (string) $r['v'];
        if (($o['users_can_register'] ?? '0') === '1' && ($o['default_role'] ?? '') === 'administrator') ssf_add($st, ['site' => $site, 'cat' => 'database', 'sev' => 'critical', 'title' => 'Anyone can register as an administrator', 'detail' => 'Settings > General: turn off "Anyone can register" and set the default role to Subscriber.']);
        if (isset($o['siteurl'], $o['home']) && parse_url($o['siteurl'], PHP_URL_HOST) !== parse_url($o['home'], PHP_URL_HOST)) ssf_add($st, ['site' => $site, 'cat' => 'database', 'sev' => 'high', 'title' => 'Site address and WordPress address point to different domains', 'detail' => 'siteurl = ' . ssf_clean($o['siteurl']) . ', home = ' . ssf_clean($o['home'])]);
        mysqli_close($db);
    }

    /* folders in the site root */
    $stdDirs = ['wp-admin' => 1, 'wp-content' => 1, 'wp-includes' => 1, 'cgi-bin' => 1, '.well-known' => 1];
    foreach ((@scandir($ip) ?: []) as $en) {
        if ($en === '.' || $en === '..' || isset($stdDirs[$en])) continue;
        $p = "$ip/$en";
        if (!is_dir($p) || is_link($p) || isset($st['installs'][$p]) || strpos($p . '/', ssf_data_dir() . '/') === 0) continue;
        if ($en === '.tmb' || $en === '.quarantine') {
            if ($en === '.tmb') ssf_add($st, ['site' => $site, 'path' => $rp($p), 'kind' => 'dir', 'cat' => 'access', 'sev' => 'medium', 'title' => 'A file-manager tool has been used on this site', 'detail' => 'The .tmb folder is created by elFinder-based file managers (WP File Manager, File Manager Advanced and similar). Attackers use these to upload files. If you did not use one, treat it as a sign of intrusion.']);
            continue;
        }
        $idx = '';
        foreach (['index.php', 'index.html', 'index.htm'] as $cand) if (is_file("$p/$cand")) { $idx = "$p/$cand"; break; }
        if (!$idx) continue;
        $c = ssf_read($idx);
        list($spam, $terms) = ssf_spam($c);
        $title = preg_match('/<title[^>]*>([^<]*)/i', $c, $m) ? trim($m[1]) : '';
        $loadsWp = (bool) preg_match('/wp-blog-header\.php|wp-load\.php/', $c);
        $shadow = isset($slugs[strtolower($en)]);
        if ($spam) {
            ssf_add($st, ['site' => $site, 'path' => $rp($p), 'kind' => 'dir', 'cat' => 'doorway', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true,
                'title' => 'Spam page folder' . ($shadow ? ' covering a real page' : ''), 'detail' => ($shadow ? 'A published WordPress page uses the address /' . $en . '/. This folder is served instead of it; once moved, the real page shows again. ' : 'This folder is not part of WordPress and serves spam content. ') . 'Page title: "' . ssf_one_line($title, 80) . '".', 'evidence' => 'keywords: ' . implode(', ', $terms)]);
            $st['skip'][$p] = 1;
        } elseif ($shadow && !$loadsWp) {
            ssf_add($st, ['site' => $site, 'path' => $rp($p), 'kind' => 'dir', 'cat' => 'doorway', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => false,
                'title' => 'Folder is hiding a real WordPress page', 'detail' => 'A published page uses the address /' . $en . '/ but visitors get this folder instead. No spam keywords were found in it, so check what it shows before moving it. Page title: "' . ssf_one_line($title, 80) . '".']);
        }
    }

    /* wp-config.php */
    if ($I['config']) {
        $c = (string) @file_get_contents("$ip/wp-config.php");
        list($sc, $labels, $snip) = ssf_score($c, strlen($c));
        if ($sc >= 5 || preg_match('/^\s*(?:@?\s*(?:include|require)(?:_once)?)\b(?![^;]*wp-settings\.php)(?![^;]*wp-salt)[^;]*;/m', preg_replace('#/\*.*?\*/#s', '', $c), $m)) {
            ssf_add($st, ['site' => $site, 'path' => $rp("$ip/wp-config.php"), 'kind' => 'file', 'cat' => 'implant', 'sev' => $sc >= 8 ? 'critical' : 'medium', 'title' => 'wp-config.php contains unusual code', 'detail' => 'This file should only hold settings. Do not quarantine it (the site would stop). Open it and remove anything that is not a setting. ' . ($labels ? 'Signs: ' . implode('; ', $labels) . '.' : 'It loads another file.'), 'evidence' => $snip ?: ssf_one_line($m[0] ?? '', 200)]);
        }
        $perm = @fileperms("$ip/wp-config.php") & 0777;
        if ($perm & 0002) ssf_add($st, ['site' => $site, 'path' => $rp("$ip/wp-config.php"), 'kind' => 'file', 'cat' => 'exposure', 'sev' => 'medium', 'title' => 'wp-config.php is writable by everyone', 'detail' => 'Permissions are ' . sprintf('%04o', $perm) . '. Set to 0600 or 0640 in File Manager.']);
    }
    foreach (['.user.ini', 'php.ini'] as $ini) {
        $c = (string) @file_get_contents("$ip/$ini");
        if ($c !== '' && preg_match('/auto_(prepend|append)_file\s*=\s*[\'"]?([^\'"\s]+)/i', $c, $m) && !preg_match('/wordfence-waf\.php|malcare|ignitor\.php|none$/i', $m[2]))
            ssf_add($st, ['site' => $site, 'path' => $rp("$ip/$ini"), 'kind' => 'file', 'cat' => 'implant', 'sev' => 'high', 'title' => "$ini loads a file before every page", 'detail' => 'auto_' . $m[1] . '_file is a common way to run malware on every request. Check the file it points to.', 'evidence' => ssf_one_line($m[2], 200)]);
    }

    /* plugins and themes inventory */
    $risky = ['wp-file-manager' => 'file manager', 'wp-file-manager-pro' => 'file manager', 'file-manager-advanced' => 'file manager', 'file-manager' => 'file manager', 'filester' => 'file manager', 'filebird-document-library' => '', 'wpide' => 'code editor', 'insert-php' => 'runs custom PHP', 'worker' => 'remote management (ManageWP)', 'mainwp-child' => 'remote management (MainWP)', 'iwp-client' => 'remote management (InfiniteWP)', 'blogvault-real-time-backup' => 'remote management (BlogVault)', 'malcare-security' => 'remote management (MalCare)'];
    foreach ((@scandir("$ip/wp-content/plugins") ?: []) as $en) {
        if (!isset($risky[$en]) || $risky[$en] === '' || !is_dir("$ip/wp-content/plugins/$en")) continue;
        $fm = strpos($risky[$en], 'file manager') !== false || strpos($risky[$en], 'editor') !== false;
        ssf_add($st, ['site' => $site, 'path' => $rp("$ip/wp-content/plugins/$en"), 'kind' => 'dir', 'cat' => 'access', 'sev' => $fm ? 'high' : 'info', 'title' => ($fm ? 'File-manager plugin installed: ' : 'Remote-control plugin installed: ') . $en, 'detail' => $fm ? 'Gives anyone with an admin login (or an exploit for the plugin) full access to the files on this account. Remove it unless it is in daily use.' : 'A ' . $risky[$en] . ' connection can run code on this site by design. Fine if you use that service; remove it if nobody does.']);
    }
    foreach ((@scandir("$ip/wp-content/themes") ?: []) as $en) if ($en[0] !== '.' && is_dir("$ip/wp-content/themes/$en")) $I['themes'][] = $en;
    unset($I);
}
