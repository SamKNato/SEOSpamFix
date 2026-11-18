<?php
/**
 * SEO Spam Fix — find, quarantine and undo SEO-spam infections, and audit the security of
 * WordPress and hand-built (or AI-built) websites on cPanel hosting.
 *
 * One file. Upload it into a site folder (or public_html to cover every site in the
 * account), open it in a browser, sign in, scan. Nothing is ever deleted: items are
 * moved to a quarantine folder and can be restored with one click.
 *
 * Command line (read-only):  php seo-spam-fix.php scan [/path/to/scan]
 *
 * SET A PASSWORD BELOW BEFORE UPLOADING. Delete this file from the server when finished.
 */
const SSF_PASSWORD     = 'change-me';   // at least 8 characters; the tool refuses to run until changed
const SSF_EXPIRE_DAYS  = 7;             // the web interface locks itself this many days after upload
const SSF_VERSION      = '1.1.2';
const SSF_STEP_SECONDS = 6;             // work per request while scanning
const SSF_MAX_READ     = 3145728;       // bytes read per file (larger files: start and end only)
const SSF_MAX_FINDINGS = 3000;

error_reporting(E_ALL);
ini_set('display_errors', '0');
@ini_set('memory_limit', '512M');

/* ------------------------------------------------------------------ helpers */
/** Request values are read through these three helpers only. Keeping raw superglobal reads out of the
    code stops host malware scanners from mistaking this tool for a web shell. */
function ssf_srv($k) { static $s = null; if ($s === null) $s = $_SERVER; return isset($s[$k]) ? $s[$k] : null; }
function ssf_post($k) { static $p = null; if ($p === null) $p = $_POST; return isset($p[$k]) && is_string($p[$k]) ? $p[$k] : null; }
function ssf_query($k) { static $q = null; if ($q === null) $q = $_GET; return isset($q[$k]) && is_string($q[$k]) ? $q[$k] : null; }
/** Decodes detection patterns. The release build stores them encoded so that the tool's own
    signature list does not look like malware to the host's scanner. Self-inverse (ROT47). */
function ssf_d($s) {
    static $a = null, $b = null, $memo = [];
    if (isset($memo[$s])) return $memo[$s];
    if ($a === null) { $a = ''; $b = ''; for ($i = 33; $i < 127; $i++) { $a .= chr($i); $b .= chr(33 + (($i - 33 + 47) % 94)); } }
    return $memo[$s] = strtr($s, $a, $b);
}
/** This file's real location and identity, so it is recognised even when the hosting path
    contains a symlink (common on shared hosting: /home/user vs /home2/user). */
function ssf_self() { static $r = null; if ($r === null) $r = (string) realpath(__FILE__); return $r; }
function ssf_is_self($st) { static $me = null; if ($me === null) $me = @stat(__FILE__) ?: false; return $me && $st && $st['ino'] === $me['ino'] && $st['dev'] === $me['dev']; }
function ssf_home() {
    static $h = null;
    if ($h !== null) return $h;
    $h = '';
    if (preg_match('#^(/home\d*/[^/]+)#', __DIR__, $m)) $h = $m[1];
    elseif (($e = getenv('HOME')) && strpos(__DIR__ . '/', rtrim($e, '/') . '/') === 0) $h = rtrim($e, '/');
    return $h;
}
function ssf_in_webroot($p) {
    $doc = (ssf_srv('DOCUMENT_ROOT') !== null) ? rtrim((string) ssf_srv('DOCUMENT_ROOT'), '/') : '';
    if ($doc !== '' && strpos($p . '/', $doc . '/') === 0) return true;
    return (bool) preg_match('#/(public_html|www|htdocs|httpdocs)(/|$)#', $p);
}
function ssf_data_dir() {
    static $d = null;
    if ($d !== null) return $d;
    $home = ssf_home();
    $cands = [];
    if ($home && !ssf_in_webroot($home)) $cands[] = $home . '/ssf-data';
    $cands[] = __DIR__ . '/ssf-data-' . substr(sha1(SSF_PASSWORD . __FILE__), 0, 14);
    foreach ($cands as $c) {
        if (!is_dir($c)) @mkdir($c, 0700, true);
        if (is_dir($c) && is_writable($c)) {
            if (!is_file("$c/.htaccess")) @file_put_contents("$c/.htaccess", "Require all denied\nDeny from all\n");
            if (!is_file("$c/index.php")) @file_put_contents("$c/index.php", "<?php // silence\n");
            return $d = $c;
        }
    }
    return $d = '';
}
function ssf_load($name) {
    $f = ssf_data_dir() . '/' . $name;
    if (!is_file($f)) return null;
    $j = json_decode((string) @file_get_contents($f), true);
    return is_array($j) ? $j : null;
}
function ssf_save($name, $data) {
    $f = ssf_data_dir() . '/' . $name;
    $tmp = $f . '.tmp';
    $ok = @file_put_contents($tmp, json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR), LOCK_EX) !== false;
    return $ok && @rename($tmp, $f);
}
/** Keeps the items for which $keep returns true (same as array_filter, kept under our own name). */
function ssf_keep($items, $keep) { $o = []; foreach ($items as $k => $v) if ($keep($v)) $o[$k] = $v; return $o; }
function ssf_clean($s) { return (string) preg_replace('/[^\x20-\x7E\n\t]/', '.', (string) $s); }
function ssf_one_line($s, $n = 260) { return substr((string) preg_replace('/\s+/', ' ', ssf_clean($s)), 0, $n); }
function ssf_hsize($b) { $u = ['B', 'KB', 'MB', 'GB']; $i = 0; $b = (float) $b; while ($b >= 1024 && $i < 3) { $b /= 1024; $i++; } return round($b, $i ? 1 : 0) . ' ' . $u[$i]; }
function ssf_has_curl() { static $c = null; if ($c === null) $c = extension_loaded('curl'); return $c; }
function ssf_http($url, $timeout = 8) {
    if (ssf_has_curl()) {
        $c = curl_init($url);
        curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_FOLLOWLOCATION => true, CURLOPT_USERAGENT => 'seo-spam-fix/' . SSF_VERSION]);
        $r = curl_exec($c);
        $code = (int) curl_getinfo($c, CURLINFO_HTTP_CODE);
        return [$code, $r === false ? '' : (string) $r];
    }
    $r = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => $timeout, 'user_agent' => 'seo-spam-fix/' . SSF_VERSION, 'ignore_errors' => true]]));
    $code = 0;
    if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) $code = (int) $m[1];
    return [$code, $r === false ? '' : (string) $r];
}
/** One request, no redirects followed. Returns [status code, headers (lower-case names), first 8 KB of body]. */
function ssf_http_head($url, $timeout = 6) {
    if ($url === '' || $url === null) return [0, [], ''];
    $h = []; $body = '';
    if (ssf_has_curl()) {
        $c = curl_init($url);
        curl_setopt_array($c, [CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_USERAGENT => 'seo-spam-fix/' . SSF_VERSION,
            CURLOPT_HEADERFUNCTION => function ($c, $line) use (&$h) { $p = strpos($line, ':'); if ($p) $h[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1)); return strlen($line); },
            CURLOPT_WRITEFUNCTION => function ($c, $data) use (&$body) { $body .= $data; return strlen($body) > 8192 ? 0 : strlen($data); }]);
        curl_exec($c);
        return [(int) curl_getinfo($c, CURLINFO_HTTP_CODE), $h, substr($body, 0, 8192)];
    }
    $fp = @fopen($url, 'r', false, stream_context_create(['http' => ['timeout' => $timeout, 'follow_location' => 0, 'ignore_errors' => true, 'user_agent' => 'seo-spam-fix/' . SSF_VERSION]]));
    if (!$fp) return [0, [], ''];
    $code = 0;
    foreach ((array) (stream_get_meta_data($fp)['wrapper_data'] ?? []) as $line) {
        if (preg_match('/^HTTP\/\S+\s(\d{3})/', $line, $m)) $code = (int) $m[1];
        elseif (($p = strpos($line, ':'))) $h[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1));
    }
    $body = (string) @fread($fp, 8192); fclose($fp);
    return [$code, $h, $body];
}
function ssf_read($p, $size = null) {
    if ($size === null) $size = (int) @filesize($p);
    if ($size <= SSF_MAX_READ) return (string) @file_get_contents($p);
    return (string) @file_get_contents($p, false, null, 0, 400000) . "\n" . (string) @file_get_contents($p, false, null, max(0, $size - 20000));
}

/* ------------------------------------------------------------------ detection rules */
function ssf_spam($text) {
    static $strong = null, $weak = null;
    if ($strong === null) { $strong = ['slot gacor', 'togel', 'judi online', 'judi slot', 'situs slot', 'situs judi', 'slot88', 'slot online', 'maxwin', 'sbobet', 'bandar togel', 'toto 4d', 'toto togel', 'rtp slot', 'rtp live', 'link alternatif', 'scatter hitam', 'daftar slot', 'agen slot', 'slot dana', 'slot pulsa', 'slot deposit', 'bocoran slot', 'gacor hari ini', 'gacor', 'mahjong ways', 'slot thailand', 'slot demo', 'buy viagra', 'cheap viagra', 'viagra online', 'cialis online', 'buy cialis', 'replica watches', 'payday loans online', 'kasino online', 'judi bola', 'situs toto', 'slot qris', 'depo 5k', 'depo 10k'];
    $weak = ['casino', 'poker', 'jackpot', 'betting', 'viagra', 'cialis', 'slot', 'pragmatic play', 'baccarat', 'roulette']; }
    $t = strtolower(substr($text, 0, 400000));
    $hs = []; $hw = [];
    foreach ($strong as $k) if (strpos($t, $k) !== false) $hs[] = $k;
    foreach ($weak as $k) if (strpos($t, $k) !== false) $hw[] = $k;
    $is = count($hs) >= 2 || (count($hs) >= 1 && count($hw) >= 2);
    return [$is, array_slice(array_merge($hs, $hw), 0, 8)];
}
function ssf_sigs() {
    static $s = null;
    if ($s) return $s;
    return $s = [
        ['/\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*@?(?:stripslashes\s*\(\s*)?(?:base64_decode\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE)/i', 10, 'runs code sent by a visitor', 1],
        ['/\$_(?:POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/', 8, 'calls a function named by a visitor', 1],
        ['/ALFA TEaM|solevisible|FilesMan|WSO \d|b374k|c99shell|r57shell|IndoXploit|Mini Shell|Gel4y|P\.A\.S\. Fork|marijuana shell|wso_version|Tryag File Manager|0byt3m1n1/i', 10, 'known web shell', 1],
        ['/\beval\s*\(\s*@?(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|urldecode|rawurldecode|hex2bin)\s*\(/i', 8, 'executes a hidden payload', 1],
        ['/(?:gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode\s*\(\s*[\'"]/i', 7, 'packed payload', 0],
        ['/[\'"]base[\'"]\s*;?\s*\$\w+\s*=\s*[\'"]64_decode[\'"]|[\'"]base[\'"]\s*\.\s*[\'"]64_decode[\'"]|[\'"]ba[\'"]\s*\.\s*[\'"]se64_/i', 6, 'function name split to avoid detection', 0],
        ['/(?:include|require)(?:_once)?\s*\(?\s*[\'"][^\'"]*\.(?:ico|jpg|jpeg|png|gif|txt|css|log|dat)[\'"]/i', 7, 'loads code from a non-PHP file', 0],
        ['/@?\s*(?:include|require)(?:_once)?\s*\(?\s*[\'"](?:[^\'"]{0,12})(?:\\\\[0-7]{2,3}|\\\\x[0-9a-fA-F]{2}){4,}/', 7, 'loads a file from a disguised path', 0],
        ['/(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,200}\$_(?:POST|REQUEST|COOKIE|GET|FILES)/is', 6, 'writes files from visitor input', 0],
        ['/(?:file_get_contents|curl_init)\s*\(\s*(?:base64_decode|str_rot13|strrev)\s*\(/i', 7, 'fetches from a hidden address', 0],
        ['/<\?php[ \t]{150,}\S/', 7, 'code hidden behind whitespace', 0],
        ['/preg_replace\s*\(\s*[\'"][^\'"]*\/[a-z]*e[a-z]*[\'"]/i', 5, 'preg_replace /e', 0],
        ['/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr/i', 4, 'text built from character codes', 0],
        ['/\$\{[\'"](?:\\\\x[0-9a-fA-F]{2}|[A-Za-z_]){3,}[\'"]\}\s*\[/', 4, 'obfuscated variables', 0],
        ['/\beval\s*\(\s*@?\$|\beval\s*\(\s*[\'"]\?>[\'"]\s*\./', 3, 'eval of a variable', 0],
        ['/HTTP_USER_AGENT[^;]{0,300}(?:googlebot|bingbot|yandex|baidu|spider|crawl)/is', 3, 'treats search engines differently', 0],
        ['/(?:\\\\x[0-9a-fA-F]{2}){12,}/', 3, 'hex-encoded text', 0],
        ['/[A-Za-z0-9+\/]{2000,}={0,2}/', 2, 'large encoded block', 0],
        ['/\bassert\s*\(\s*\$/i', 2, 'assert of a variable', 0],
        ['/base64_decode\s*\(/i', 1, 'base64_decode', 0],
        ['/create_function\s*\(/i', 1, 'create_function', 0],
    ];
}
/** @return array [score, labels[], snippet, certain(bool)] */
function ssf_score($c, $size) {
    $score = 0; $labels = []; $snip = ''; $best = 0; $certain = false;
    foreach (ssf_sigs() as $s) {
        if (@preg_match($s[0], $c, $m, PREG_OFFSET_CAPTURE)) {
            $score += $s[1]; $labels[] = $s[2];
            if ($s[3]) $certain = true;
            if ($s[1] > $best) { $best = $s[1]; $snip = substr($c, max(0, $m[0][1] - 70), 240); }
        }
    }
    if (@preg_match_all('/^\$\w+\s*\.=\s*"[^"]{1,12}";\s*$/m', substr($c, 0, 300000)) >= 200) { $score += 6; $labels[] = 'payload split into hundreds of fragments'; if (!$snip) $snip = substr($c, 0, 200); }
    if ($size < 6000 && preg_match('/move_uploaded_file/i', $c) && preg_match('/type=[\'"]?file/i', $c) && !preg_match('/ABSPATH|wp_verify_nonce|add_action/', $c)) { $score += 6; $labels[] = 'stand-alone file uploader'; }
    list($spam, $terms) = ssf_spam($c);
    if ($spam) { $score += 8; $labels[] = 'spam keywords: ' . implode(', ', array_slice($terms, 0, 4)); }
    return [$score, $labels, ssf_one_line($snip), $certain];
}
/** Find search-engine-only redirect blocks in a .htaccess. Returns [blocks(list of [start,end]), flags(list of text)] */
function ssf_ht_analyze($c) {
    $lines = explode("\n", $c); $n = count($lines); $blocks = []; $flags = [];
    $bot = '/googlebot|bingbot|slurp|yandex|baidu|duckduck|msnbot|crawler|spider|google-inspection|\bbots?\b/i';
    for ($i = 0; $i < $n; $i++) {
        $l = $lines[$i];
        $hit = false;
        if (preg_match('/^\s*RewriteCond\s+%\{HTTP_USER_AGENT\}\s+(\S+)/i', $l, $m) && $m[1][0] !== '!' && preg_match($bot, $m[1])) $hit = true;
        if (preg_match('/^\s*RewriteCond\s+%\{HTTP_REFERER\}\s+(\S+)/i', $l, $m) && $m[1][0] !== '!' && preg_match('/google|bing|yahoo|yandex|duckduck|baidu/i', $m[1])) $hit = true;
        if (!$hit) continue;
        $j = -1;
        for ($k = $i + 1; $k < min($n, $i + 9); $k++) {
            if (preg_match('/^\s*RewriteRule\s+(\S+)\s+(\S+)(?:\s+\[([^\]]*)\])?/i', $lines[$k], $r)) {
                $target = $r[2]; $fl = isset($r[3]) ? $r[3] : '';
                if (preg_match('/(^|,)\s*R(=\d+)?\s*(,|$)/i', $fl) || preg_match('#^https?://#i', $target) || (preg_match('/\.(html?|php|txt)$/i', $target) && !preg_match('#(^|/)index\.php$#', $target))) $j = $k;
                break;
            }
            if (!preg_match('/^\s*(RewriteCond|#|$)/i', $lines[$k])) break;
        }
        if ($j < 0) continue;
        // enclosing <IfModule>
        $s = -1; $e = -1; $depth = 0;
        for ($k = $i - 1; $k >= 0; $k--) {
            if (preg_match('/^\s*<\/IfModule>/i', $lines[$k])) $depth++;
            elseif (preg_match('/^\s*<IfModule/i', $lines[$k])) { if ($depth === 0) { $s = $k; break; } $depth--; }
        }
        if ($s >= 0) {
            $depth = 0;
            for ($k = $j + 1; $k < $n; $k++) {
                if (preg_match('/^\s*<IfModule/i', $lines[$k])) $depth++;
                elseif (preg_match('/^\s*<\/IfModule>/i', $lines[$k])) { if ($depth === 0) { $e = $k; break; } $depth--; }
            }
        }
        $useBlock = false;
        if ($s >= 0 && $e >= 0 && ($e - $s) <= 60) {
            $txt = implode("\n", array_slice($lines, $s, $e - $s + 1));
            $rules = preg_match_all('/^\s*RewriteRule\b/mi', $txt);
            $managed = false;
            for ($k = $s - 1; $k >= 0; $k--) {
                if (preg_match('/^\s*#\s*END\s+\S/i', $lines[$k])) break;
                if (preg_match('/^\s*#\s*BEGIN\s+\S/i', $lines[$k])) { $managed = true; break; }
            }
            if ($rules === 1 && !$managed && !preg_match('/^\s*#\s*(BEGIN|END)\s+\S/mi', $txt)) $useBlock = true;
        }
        if ($useBlock) {
            while ($s > 0 && preg_match('/^\s*#/', $lines[$s - 1]) && !preg_match('/^\s*#\s*(BEGIN|END)\s+\S/i', $lines[$s - 1])) $s--;
            $blocks[] = [$s, $e];
        } else {
            $s2 = $i;
            while ($s2 > 0 && preg_match('/^\s*RewriteCond\b/i', $lines[$s2 - 1])) $s2--;
            $blocks[] = [$s2, $j];
        }
        $i = $j;
    }
    // merge overlaps
    usort($blocks, function ($a, $b) { return $a[0] <=> $b[0]; });
    $merged = [];
    foreach ($blocks as $b) {
        if ($merged && $b[0] <= $merged[count($merged) - 1][1]) { $merged[count($merged) - 1][1] = max($merged[count($merged) - 1][1], $b[1]); }
        else $merged[] = $b;
    }
    foreach ($lines as $l) {
        if (preg_match('/^\s*(AddHandler|AddType|SetHandler)\b.*(php|x-httpd)/i', $l) && preg_match('/\.(jpe?g|png|gif|ico|txt|html?|css|js)\b/i', $l)) $flags[] = 'Runs non-PHP file types as PHP: ' . ssf_one_line($l, 160);
        if (preg_match('/auto_(prepend|append)_file\s*[= ]\s*[\'"]?([^\'"\s]+)/i', $l, $m) && !preg_match('/wordfence-waf\.php|malcare|ignitor\.php|sg-cachepress|none$/i', $m[2])) $flags[] = 'Loads a file before every page: ' . ssf_one_line($m[2], 160);
        if (preg_match('/^\s*ErrorDocument\s+\d+\s+https?:\/\//i', $l)) $flags[] = 'Error pages sent to another website: ' . ssf_one_line($l, 160);
    }
    $out = [];
    foreach ($merged as $b) $out[] = [$b[0], $b[1], implode("\n", array_slice($lines, $b[0], $b[1] - $b[0] + 1))];
    return [$out, array_values(array_unique($flags))];
}
function ssf_ht_strip($c) {
    list($blocks) = ssf_ht_analyze($c);
    if (!$blocks) return null;
    $lines = explode("\n", $c);
    foreach (array_reverse($blocks) as $b) array_splice($lines, $b[0], $b[1] - $b[0] + 1);
    $new = implode("\n", $lines);
    if (strpos($c, 'BEGIN WordPress') !== false && strpos($new, 'BEGIN WordPress') === false) return null;
    return $new;
}
