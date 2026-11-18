
function ssf_core_map($I) {
    static $cache = [];
    if ($I['core'] !== 'ok') return null;
    $k = preg_replace('/[^A-Za-z0-9._-]/', '', $I['ver'] . '-' . $I['locale']);
    if (!array_key_exists($k, $cache)) $cache[$k] = ssf_load('cache-core-' . $k . '.json');
    return $cache[$k];
}
function ssf_plugin(&$st, $ip, $slug) {
    static $maps = [];
    $key = $ip . '|' . $slug;
    if (!isset($st['plugins'][$key])) {
        $dir = "$ip/wp-content/plugins/$slug"; $ver = ''; $name = $slug;
        foreach ((@glob("$dir/*.php") ?: []) as $f) {
            $hd = (string) @file_get_contents($f, false, null, 0, 8192);
            if (preg_match('/^[ \t\/*#@]*Plugin Name:\s*(.+)$/mi', $hd, $m)) { $name = trim($m[1]); if (preg_match('/^[ \t\/*#@]*Version:\s*([^\s*]+)/mi', $hd, $v)) $ver = trim($v[1]); break; }
        }
        $status = 'unverifiable';
        if ($ver !== '' && preg_match('/^[A-Za-z0-9._-]+$/', $slug . $ver)) {
            $cf = "cache-plug-$slug-$ver.json";
            $map = ssf_load($cf);
            if ($map === null && $st['net']) {
                list($code, $body) = ssf_http("https://downloads.wordpress.org/plugin-checksums/$slug/$ver.json");
                $j = json_decode($body, true);
                if ($code === 0) { $st['net'] = false; }
                elseif ($code === 200 && isset($j['files']) && is_array($j['files'])) {
                    $map = [];
                    foreach ($j['files'] as $path => $h) { $md = is_array($h) ? ($h['md5'] ?? null) : $h; if ($md !== null) $map[$path] = (array) $md; }
                    ssf_save($cf, $map);
                } elseif ($code === 404) { $map = ['__none' => 1]; ssf_save($cf, $map); }
            }
            if ($map === null) $status = 'unchecked';
            elseif (isset($map['__none'])) $status = 'unverifiable';
            else $status = 'ok';
        }
        $st['plugins'][$key] = ['site' => $st['installs'][$ip]['rel'], 'slug' => $slug, 'name' => ssf_one_line($name, 60), 'ver' => $ver, 'status' => $status, 'mod' => 0, 'extra' => 0, 'files' => 0, 'samples' => [], 'xsamples' => []];
    }
    $P = $st['plugins'][$key];
    if ($P['status'] !== 'ok') return null;
    $mk = $slug . '-' . $P['ver'];
    if (!array_key_exists($mk, $maps)) $maps[$mk] = ssf_load("cache-plug-$mk.json");
    return $maps[$mk];
}
function ssf_file(&$st, $p, $name, $ip) {
    static $PHPEXT = ['php' => 1, 'php3' => 1, 'php4' => 1, 'php5' => 1, 'php7' => 1, 'php8' => 1, 'phtml' => 1, 'pht' => 1, 'phar' => 1, 'suspected' => 1];
    static $MEDIA = ['jpg' => 1, 'jpeg' => 1, 'png' => 1, 'gif' => 1, 'webp' => 1, 'ico' => 1, 'bmp' => 1, 'avif' => 1, 'svg' => 1];
    static $ARCH = ['zip' => 1, 'gz' => 1, 'tgz' => 1, 'tar' => 1, 'rar' => 1, '7z' => 1, 'sql' => 1, 'wpress' => 1, 'bak' => 1];
    static $STDROOT = ['index.php' => 1, 'wp-activate.php' => 1, 'wp-blog-header.php' => 1, 'wp-comments-post.php' => 1, 'wp-config.php' => 1, 'wp-config-sample.php' => 1, 'wp-cron.php' => 1, 'wp-links-opml.php' => 1, 'wp-load.php' => 1, 'wp-login.php' => 1, 'wp-mail.php' => 1, 'wp-settings.php' => 1, 'wp-signup.php' => 1, 'wp-trackback.php' => 1, 'xmlrpc.php' => 1, 'wordfence-waf.php' => 1];
    static $DROPINS = ['index.php' => 1, 'advanced-cache.php' => 1, 'object-cache.php' => 1, 'db.php' => 1, 'sunrise.php' => 1, 'maintenance.php' => 1, 'php-error.php' => 1, 'fatal-error-handler.php' => 1, 'blog-deleted.php' => 1, 'blog-inactive.php' => 1, 'blog-suspended.php' => 1, 'install.php' => 1, 'db-error.php' => 1];
    $MUKNOWN = '/^(index\.php|0-worker\.php|automation-by-installatron\.php|gd-system-plugin\.php|wp-toolkit.*\.php|endurance-.*\.php|sso\.php|wpcomsh-loader\.php|health-check-troubleshooting-mode\.php|mu-plugin\.php|kinsta-mu-plugins\.php|wpengine-.*\.php|malcare-.*\.php|aaa-wp-cerber\.php)$/i';

    $s = @lstat($p);
    if (!$s) return;
    $size = $s['size'];
    $st['files']++;
    if ($p === __FILE__ || ssf_is_self($s)) return;
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $isPhp = isset($PHPEXT[$ext]);
    $rel = ssf_rel($st, $p);
    $irel = $ip !== null ? substr($p, strlen($ip) + 1) : null;
    $site = $ip !== null ? $st['installs'][$ip]['rel'] : '';
    if ($isPhp || $name === '.htaccess') { $st['recent'][] = [$s['ctime'], $s['mtime'], $size, $rel]; if (count($st['recent']) > 400) { rsort($st['recent']); $st['recent'] = array_slice($st['recent'], 0, 40); } }

    /* location */
    $loc = 'outside'; $slug = '';
    if ($irel !== null) {
        if (strpos($irel, '/') === false) $loc = 'root';
        elseif (strpos($irel, 'wp-admin/') === 0 || strpos($irel, 'wp-includes/') === 0) $loc = 'core';
        elseif (preg_match('#^wp-content/plugins/([^/]+)/#', $irel, $m)) { $loc = 'plugin'; $slug = $m[1]; }
        elseif (strpos($irel, 'wp-content/plugins/') === 0) $loc = 'pluginsroot';
        elseif (strpos($irel, 'wp-content/themes/') === 0) $loc = 'theme';
        elseif (strpos($irel, 'wp-content/uploads/') === 0) $loc = 'uploads';
        elseif (strpos($irel, 'wp-content/mu-plugins/') === 0) $loc = 'mu';
        elseif (preg_match('#^wp-content/[^/]+$#', $irel)) $loc = 'content';
        else $loc = 'other';
    }
    $add = function ($f) use (&$st, $site, $rel) { ssf_add($st, $f + ['site' => $site, 'path' => $rel, 'kind' => 'file']); };

    /* security audit: exposed files, leaked secrets, weaknesses in the site's own code */
    if ($name !== '.htaccess' && ssf_audit_file($st, $p, $name, $ext, $size, $rel, $site, $loc, $isPhp)) return;

    /* .htaccess */
    if ($name === '.htaccess') {
        $c = (string) @file_get_contents($p, false, null, 0, 200000);
        list($blocks, $flags) = ssf_ht_analyze($c);
        if ($blocks) $add(['cat' => 'htaccess', 'sev' => 'critical', 'fix' => 'htaccess', 'tick' => true, 'title' => 'Search engines are being redirected', 'detail' => 'This .htaccess sends Google and other crawlers (or visitors arriving from them) somewhere else, which replaces your pages in search results. The fix removes only the block shown and keeps a copy of the original file.', 'evidence' => ssf_clean(substr(implode("\n...\n", array_map(function ($b) { return $b[2]; }, $blocks)), 0, 1500))]);
        foreach ($flags as $fl) $add(['cat' => 'htaccess', 'sev' => 'high', 'title' => 'Suspicious .htaccess rule', 'detail' => 'Review this line and remove it if you did not add it.', 'evidence' => $fl]);
        return;
    }

    /* official checksums: core */
    $map = $ip !== null ? ssf_core_map($st['installs'][$ip]) : null;
    if ($map && isset($map[$irel])) {
        if (@md5_file($p) === $map[$irel]) { $st['verified']++; return; }
        if ($loc === 'core' || $loc === 'root') { if (!isset($st['core_mod'][$ip])) $st['core_mod'][$ip] = []; if (count($st['core_mod'][$ip]) < 40) $st['core_mod'][$ip][] = $irel; return; }
    }
    /* official checksums: plugins */
    $pmap = null; $pkey = $ip . '|' . $slug; $inPmap = false;
    if ($loc === 'plugin') {
        $pmap = ssf_plugin($st, $ip, $slug);
        $st['plugins'][$pkey]['files']++;
        if ($pmap) {
            $prel = substr($irel, strlen("wp-content/plugins/$slug/"));
            if (isset($pmap[$prel])) {
                $inPmap = true;
                if (in_array(@md5_file($p), $pmap[$prel], true)) { $st['verified']++; return; }
                $st['plugins'][$pkey]['mod']++;
                if (count($st['plugins'][$pkey]['samples']) < 8) $st['plugins'][$pkey]['samples'][] = $prel;
            }
        }
    }

    if ($isPhp) {
        $st['php']++;
        $safeSpot = in_array($loc, ['root', 'core', 'content', 'uploads', 'mu', 'outside', 'pluginsroot'], true);
        if ($size === 0) {
            if ($name === 'index.php') return;
            $add(['cat' => 'leftover', 'sev' => 'low', 'fix' => 'quarantine', 'tick' => $safeSpot, 'title' => 'Empty PHP file with an odd name', 'detail' => 'Usually a backdoor that a malware scanner emptied during an earlier clean-up. Harmless now, but it shows this site was broken into before.' . ($safeSpot ? '' : ' It sits inside a plugin or theme, so it is left unticked in case that code expects the file to exist.')]);
            return;
        }
        $c = ssf_read($p, $size);
        if ($name === 'index.php' && $size < 300 && preg_match('/^<\?php\s*(?:\/\/[^\n]*|#[^\n]*|\/\*.*?\*\/)?\s*(?:\?>)?\s*$/s', $c)) return;
        list($sc, $labels, $snip, $certain) = ssf_score($c, $size);
        $why = $labels ? 'Signs: ' . implode('; ', $labels) . '.' : '';
        $sevOf = function ($sc, $certain) { return ($sc >= 14 || $certain) ? 'critical' : 'high'; };
        $bd = function ($title, $detail, $tick, $sev = null) use ($add, $sc, $certain, $why, $snip, $sevOf) { $add(['cat' => 'implant', 'sev' => $sev ?: $sevOf($sc, $certain), 'fix' => 'quarantine', 'tick' => $tick, 'title' => $title, 'detail' => trim($detail . ' ' . $why), 'evidence' => $snip]); };
        $standalone = (bool) preg_match('/^([a-f0-9]{6,}|[a-z0-9]{1,3}|wp-[a-z]{2,8}|[a-z]+\d+)\.php$/i', $name);

        if ($loc === 'core') {
            if ($map) {
                if ($sc >= 5 || $size > 1048576) $bd('Unknown file hidden among WordPress system files', 'This file is not part of WordPress ' . $st['installs'][$ip]['ver'] . '.' . ($size > 1048576 ? ' It is unusually large (' . ssf_hsize($size) . ').' : ''), true, $sc >= 8 || $certain ? 'critical' : 'high');
                else { $st['core_extra'][$ip] = ($st['core_extra'][$ip] ?? 0) + 1; }
            } elseif ($sc >= 8) $bd('Suspicious code among WordPress system files', 'Core files could not be verified against the official list for this site.', $certain);
            return;
        }
        if ($loc === 'root') {
            if (isset($STDROOT[$name])) { if ($sc >= 8 && !$map) $bd('Suspicious code in a WordPress root file', 'Replace this file from a fresh WordPress download rather than moving it.', false); return; }
            if (preg_match('/^bv_connector_[0-9a-f]+\.php$/i', $name)) { $add(['cat' => 'access', 'sev' => 'info', 'title' => 'BlogVault / MalCare connector file', 'detail' => 'Lets that service manage the site remotely. Delete it if nobody uses BlogVault or MalCare.']); return; }
            if ($sc >= 5) $bd('Suspicious PHP file in the site root', 'Not a WordPress file.', true);
            else $add(['cat' => 'integrity', 'sev' => 'low', 'fix' => 'quarantine', 'tick' => false, 'title' => 'Unrecognised PHP file in the site root', 'detail' => 'Not part of WordPress and nothing suspicious was detected in it. Confirm you know what it is.']);
            return;
        }
        if ($loc === 'plugin') {
            if ($pmap && !$inPmap) {
                $st['plugins'][$pkey]['extra']++;
                if ($sc >= 5) $bd('Unknown file inside a verified plugin (' . $slug . ')', 'The official release of this plugin does not contain this file.', true);
                elseif (count($st['plugins'][$pkey]['xsamples']) < 8) $st['plugins'][$pkey]['xsamples'][] = substr($irel, strlen("wp-content/plugins/$slug/"));
                return;
            }
            if ($sc >= 8) $bd($inPmap ? 'Plugin file changed and contains suspicious code (' . $slug . ')' : 'Suspicious code in plugin ' . $slug, $inPmap ? 'Reinstall the plugin from WordPress.org rather than moving this file.' : 'This plugin cannot be checked against an official copy (premium or custom). If this is one of the plugin\'s own files, reinstall the plugin from its vendor instead of moving it.', !$inPmap && $certain && $standalone);
            return;
        }
        if ($loc === 'uploads') {
            $dated = (bool) preg_match('#^wp-content/uploads/(?:sites/\d+/)?\d{4}/\d{2}/#', $irel);
            if ($sc >= 5 || $dated) $bd('PHP file in the uploads folder', 'Uploads should only hold media. ' . ($dated ? 'A PHP file in a dated media folder is almost never legitimate.' : ''), true, $sc >= 8 || $certain ? 'critical' : 'high');
            else {
                $sub = explode('/', substr($irel, strlen('wp-content/uploads/')))[0];
                $k = $ip . '|' . $sub;
                if (!isset($st['upl'][$k])) $st['upl'][$k] = ['site' => $site, 'sub' => $sub, 'n' => 0, 'samples' => []];
                $st['upl'][$k]['n']++;
                if (count($st['upl'][$k]['samples']) < 5) $st['upl'][$k]['samples'][] = $rel;
            }
            return;
        }
        if ($loc === 'mu') {
            if (preg_match($MUKNOWN, $name) && $sc < 8) return;
            if ($sc >= 5) $bd('Suspicious must-use plugin', 'Files in mu-plugins run on every page and do not appear in the normal plugin list.', true);
            else $add(['cat' => 'access', 'sev' => 'medium', 'fix' => 'quarantine', 'tick' => false, 'title' => 'Must-use plugin you should recognise', 'detail' => 'Files in mu-plugins run on every page and do not appear in the normal plugin list. Nothing suspicious was detected; confirm you know what installed it.']);
            return;
        }
        if ($loc === 'content') {
            if (isset($DROPINS[$name])) { if ($sc >= 8) $bd('Suspicious code in a WordPress drop-in file', 'Drop-ins are loaded automatically. Check which plugin owns this file.', false); return; }
            if ($sc >= 5) $bd('Suspicious PHP file in wp-content', 'Not a standard WordPress file.', true);
            else $add(['cat' => 'integrity', 'sev' => 'low', 'fix' => 'quarantine', 'tick' => false, 'title' => 'Unrecognised PHP file in wp-content', 'detail' => 'Nothing suspicious was detected in it. Confirm you know what it is.']);
            return;
        }
        if ($sc >= 8) $bd($loc === 'theme' ? 'Suspicious code in a theme file' : 'Suspicious PHP file', $loc === 'theme' ? 'Themes cannot be checked against an official copy. If this is one of the theme\'s own files (functions.php, header.php), clean or reinstall the theme instead of moving it.' : '', $certain && ($standalone || $loc === 'outside' || $loc === 'pluginsroot'));
        return;
    }

    /* non-PHP files */
    if (isset($MEDIA[$ext])) {
        if ($size > 0 && strpos((string) @file_get_contents($p, false, null, 0, 4096), '<?php') !== false) $add(['cat' => 'implant', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => 'PHP code hidden inside an image file', 'detail' => 'Malware stores code in files that look like images and loads it from another script.']);
        return;
    }
    if (preg_match('/^wp-config.*\.(zip|bak|old|txt|save|orig|swp|gz|tar|tgz|rar|7z|backup|copy)$|^wp-config\.php[.~_-].+$/i', $name) && $name !== 'wp-config-sample.php') {
        $add(['cat' => 'exposure', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Copy of wp-config downloadable by anyone', 'detail' => 'This copy can be fetched from the web and contains the database password. Move it, then change the database password.']);
        return;
    }
    if (($ext === 'html' || $ext === 'htm') && $size > 0) {
        if ($loc === 'root' && preg_match('/^(google[0-9a-f]{10,}|yandex_[0-9a-f]+)\.html$/i', $name)) { $add(['cat' => 'access', 'sev' => 'medium', 'fix' => 'quarantine', 'tick' => false, 'title' => 'Search-engine ownership file', 'detail' => 'This file proves to Google or Yandex that someone owns the site. Attackers add their own so they can submit spam pages. If it was created around the time of the infection and you did not add it, move it and remove the unknown owner in Search Console.']); return; }
        list($spam, $terms) = ssf_spam(ssf_read($p, $size));
        if ($spam) $add(['cat' => 'doorway', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Stand-alone spam page', 'detail' => 'An HTML page with gambling or pharmacy spam content.', 'evidence' => 'keywords: ' . implode(', ', $terms)]);
        return;
    }
    if (isset($ARCH[$ext]) && ($size >= 1048576 || ($ext === 'sql' && $size > 50000))) {
        if ($loc === 'root') $add(['cat' => 'exposure', 'sev' => 'medium', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Archive in the site root, downloadable by anyone (' . ssf_hsize($size) . ')', 'detail' => 'If this is a backup it can contain the database and passwords. Moving it does not affect the site.']);
        elseif ($loc === 'pluginsroot') $add(['cat' => 'exposure', 'sev' => 'low', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Loose plugin archive (' . ssf_hsize($size) . ')', 'detail' => 'A zip left in the plugins folder, often from a manual upload of a premium or nulled plugin.']);
        elseif (count($st['arch']) < 40) $st['arch'][] = $rel . ' (' . ssf_hsize($size) . ')';
    }
}
function ssf_step() {
    $st = ssf_load('state.json');
    if (!$st) return ['error' => 'No scan in progress.'];
    @set_time_limit(60);
    $t0 = microtime(true);
    $left = function () use ($t0) { return (microtime(true) - $t0) < SSF_STEP_SECONDS; };
    if ($st['phase'] === 'pre') {
        if (empty($st['env'])) { $st['current'] = 'Checking server settings'; ssf_audit_env($st); $st['env'] = true; }
        while ($st['pre']) { $ip = array_shift($st['pre']); $st['current'] = 'Checking ' . $st['installs'][$ip]['label']; ssf_pre_install($st, $ip); if (!$left()) break; }
        if (!$st['pre']) $st['phase'] = 'walk';
    }
    if ($st['phase'] === 'walk' && ($left() || !isset($ip))) {
        $data = ssf_data_dir();
        $first = true;
        while ($st['qi'] < count($st['queue']) && ($first || $left())) {
            $first = false;
            $dir = $st['queue'][$st['qi']++];
            if (isset($st['skip'][$dir])) continue;
            $ip = ssf_inst_for($st, $dir);
            $st['current'] = ssf_rel($st, $dir);
            foreach ((@scandir($dir) ?: []) as $en) {
                if ($en === '.' || $en === '..') continue;
                $p = $dir . '/' . $en;
                if (is_link($p)) continue;
                if (is_dir($p)) { if ($p !== $data && strpos($p . '/', $data . '/') !== 0 && !ssf_audit_dir($st, $p, $en, $ip)) $st['queue'][] = $p; }
                else { try { ssf_file($st, $p, $en, $ip); } catch (Throwable $e) { /* unreadable */ } }
            }
            if ($st['qi'] > 4000) { $st['queue'] = array_slice($st['queue'], $st['qi']); $st['done'] = ($st['done'] ?? 0) + $st['qi']; $st['qi'] = 0; }
        }
        if ($st['qi'] >= count($st['queue'])) $st['phase'] = 'final';
    }
    $done = ($st['done'] ?? 0) + $st['qi'];
    $total = ($st['done'] ?? 0) + count($st['queue']);
    if ($st['phase'] === 'final') { $scan = ssf_finalize($st); @unlink(ssf_data_dir() . '/state.json'); return ['done' => true, 'files' => $scan['meta']['files']]; }
    ssf_save('state.json', $st);
    return ['done' => false, 'phase' => $st['phase'], 'pct' => $st['phase'] === 'pre' ? 3 : min(98, 5 + (int) round(93 * $done / max(1, $total))), 'files' => $st['files'], 'found' => count($st['findings']), 'current' => ssf_clean($st['current'])];
}
function ssf_finalize($st) {
    foreach ($st['core_mod'] as $ip => $files) ssf_add($st, ['site' => $st['installs'][$ip]['rel'], 'cat' => 'integrity', 'sev' => 'critical', 'title' => count($files) . (count($files) >= 40 ? '+' : '') . ' WordPress system file' . (count($files) === 1 ? ' has' : 's have') . ' been changed', 'detail' => 'These do not match the official WordPress ' . $st['installs'][$ip]['ver'] . ' files. Do not quarantine them (the site would stop). Reinstall WordPress from Dashboard > Updates > "Re-install", which replaces them with clean copies.', 'evidence' => ssf_one_line(implode(', ', $files), 900)]);
    foreach ($st['core_extra'] as $ip => $n) ssf_add($st, ['site' => $st['installs'][$ip]['rel'], 'cat' => 'integrity', 'sev' => 'info', 'title' => $n . ' extra PHP file' . ($n === 1 ? '' : 's') . ' among WordPress system files, nothing suspicious in them', 'detail' => 'Usually leftovers from older WordPress versions. A clean reinstall of WordPress into an empty folder removes them.']);
    foreach ($st['plugins'] as $P) {
        if ($P['mod'] > 0) { $many = $P['mod'] >= 20 && $P['mod'] / max(1, $P['files']) > 0.3; ssf_add($st, ['site' => $P['site'], 'cat' => 'integrity', 'sev' => $many ? 'medium' : 'high', 'title' => 'Plugin "' . $P['name'] . '": ' . $P['mod'] . ' file' . ($P['mod'] === 1 ? ' differs' : 's differ') . ' from the official release', 'detail' => ($many ? 'So many files differ that the installed copy is probably a different build of version ' . $P['ver'] . '. ' : 'Someone or something edited this plugin after it was installed. ') . 'Delete the plugin and install it again from WordPress.org; your settings are kept in the database.', 'evidence' => ssf_one_line(implode(', ', $P['samples']), 600)]); }
        if ($P['xsamples']) ssf_add($st, ['site' => $P['site'], 'cat' => 'integrity', 'sev' => 'low', 'title' => 'Plugin "' . $P['name'] . '": ' . $P['extra'] . ' PHP file' . ($P['extra'] === 1 ? '' : 's') . ' not in the official release', 'detail' => 'Nothing suspicious was detected in them. Reinstalling the plugin removes them.', 'evidence' => ssf_one_line(implode(', ', $P['xsamples']), 600)]);
    }
    foreach ($st['upl'] as $g) ssf_add($st, ['site' => $g['site'], 'cat' => 'uploads', 'sev' => 'medium', 'title' => $g['n'] . ' PHP file' . ($g['n'] === 1 ? '' : 's') . ' in uploads/' . ssf_clean($g['sub']), 'detail' => 'The uploads folder should only hold media. Nothing suspicious was detected in these, and some plugins do store PHP here, but it is where attackers hide backdoors. Remove them if you do not need them, and block PHP from running in uploads.', 'evidence' => ssf_one_line(implode(', ', $g['samples']), 600)]);
    if ($st['arch']) ssf_add($st, ['cat' => 'exposure', 'sev' => 'low', 'title' => count($st['arch']) . (count($st['arch']) >= 40 ? '+' : '') . ' archives or database dumps inside the web folders', 'detail' => 'Anything here can be downloaded by someone who guesses the address, unless the folder is protected. Move backups out of public_html.', 'evidence' => ssf_one_line(implode(', ', array_slice($st['arch'], 0, 12)), 900)]);
    ssf_audit_final($st);
    $live = count($st['installs']);
    if ($live >= 2) ssf_add($st, ['cat' => 'access', 'sev' => 'medium', 'title' => $live . ' WordPress sites share this hosting account', 'detail' => 'They run as the same user, so a break-in on any one of them can reach all the others. Clean them together, and remove the ones that are no longer used.']);
    $st['notes'][] = 'Scheduled tasks (cron) are not read by this tool. Attackers use them to re-create files after a clean-up: check cPanel > Cron Jobs for anything you do not recognise.';
    if (!$st['net']) $st['notes'][] = 'This server could not reach WordPress.org for every check, so some files were checked by pattern only, not against official copies.';
    if ($st['truncated']) $st['notes'][] = 'More than ' . SSF_MAX_FINDINGS . ' findings; the list was cut off.';

    $order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
    $f = $st['findings'];
    usort($f, function ($a, $b) use ($order) { return [$order[$a['sev']], $a['site'], $a['cat'], $a['path']] <=> [$order[$b['sev']], $b['site'], $b['cat'], $b['path']]; });
    foreach ($f as $i => &$x) $x['id'] = $i + 1;
    unset($x);
    rsort($st['recent']);
    $unv = [];
    foreach ($st['plugins'] as $P) if ($P['status'] !== 'ok') $unv[] = ['site' => $P['site'], 'type' => 'plugin', 'name' => $P['name'], 'ver' => $P['ver'], 'why' => $P['status'] === 'unchecked' ? 'WordPress.org could not be reached' : 'not on WordPress.org (premium or custom)'];
    $installs = [];
    foreach ($st['installs'] as $I) { foreach ($I['themes'] as $t) $unv[] = ['site' => $I['rel'], 'type' => 'theme', 'name' => $t, 'ver' => '', 'why' => 'themes have no official file list']; $installs[] = $I; }
    $scan = ['meta' => ['base' => $st['base'], 'started' => $st['started'], 'finished' => time(), 'files' => $st['files'], 'php' => $st['php'], 'verified' => $st['verified'], 'audited' => (int) ($st['audited'] ?? 0), 'version' => SSF_VERSION, 'host' => ssf_srv('HTTP_HOST') ?? (string) gethostname()],
        'installs' => $installs, 'findings' => $f, 'unverified' => $unv, 'recent' => array_slice($st['recent'], 0, 40), 'notes' => array_values(array_unique($st['notes']))];
    ssf_save('scan.json', $scan);
    return $scan;
}
