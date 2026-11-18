<?php

const SSF_PASSWORD     = 'change-me';   // at least 8 characters; the tool refuses to run until changed
const SSF_EXPIRE_DAYS  = 7;             
const SSF_VERSION      = '1.1.2';
const SSF_STEP_SECONDS = 6;             // work per request while scanning
const SSF_MAX_READ     = 3145728;       // bytes read per file (larger files: start and end only)
const SSF_MAX_FINDINGS = 3000;

error_reporting(E_ALL);
ini_set('display_errors', '0');
@ini_set('memory_limit', '512M');

/* ------------------------------------------------------------------ helpers */

function ssf_srv($k) { static $s = null; if ($s === null) $s = $_SERVER; return isset($s[$k]) ? $s[$k] : null; }
function ssf_post($k) { static $p = null; if ($p === null) $p = $_POST; return isset($p[$k]) && is_string($p[$k]) ? $p[$k] : null; }
function ssf_query($k) { static $q = null; if ($q === null) $q = $_GET; return isset($q[$k]) && is_string($q[$k]) ? $q[$k] : null; }

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
    elseif (($e = getenv('HOME')) && strpos(__DIR__ .'/', rtrim($e, '/') .'/') === 0) $h = rtrim($e, '/');
    return $h;
}
function ssf_in_webroot($p) {
    $doc = (ssf_srv('DOCUMENT_ROOT') !== null) ? rtrim((string) ssf_srv('DOCUMENT_ROOT'), '/') : '';
    if ($doc !== '' && strpos($p .'/', $doc .'/') === 0) return true;
    return (bool) preg_match('#/(public_html|www|htdocs|httpdocs)(/|$)#', $p);
}
function ssf_data_dir() {
    static $d = null;
    if ($d !== null) return $d;
    $home = ssf_home();
    $cands = [];
    if ($home && !ssf_in_webroot($home)) $cands[] = $home .'/ssf-data';
    $cands[] = __DIR__ .'/ssf-data-' .substr(sha1(SSF_PASSWORD .__FILE__), 0, 14);
    foreach ($cands as $c) {
        if (!is_dir($c)) @mkdir($c, 0700, true);
        if (is_dir($c) && is_writable($c)) {
            if (!is_file("$c/.htaccess")) @file_put_contents("$c/.htaccess", ssf_d('#6BF:C6 2== 56?:65
s6?J 7C@> 2==
'));
            if (!is_file("$c/index.php")) @file_put_contents("$c/index.php", "<?php // silence\n");
            return $d = $c;
        }
    }
    return $d = '';
}
function ssf_load($name) {
    $f = ssf_data_dir() .'/' .$name;
    if (!is_file($f)) return null;
    $j = json_decode((string) @file_get_contents($f), true);
    return is_array($j) ? $j : null;
}
function ssf_save($name, $data) {
    $f = ssf_data_dir() .'/' .$name;
    $tmp = $f .'.tmp';
    $ok = @file_put_contents($tmp, json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR), LOCK_EX) !== false;
    return $ok && @rename($tmp, $f);
}
/** Keeps the items for which $keep returns true (same as array_filter, kept under our own name). */
function ssf_keep($items, $keep) { $o = []; foreach ($items as $k => $v) if ($keep($v)) $o[$k] = $v; return $o; }
function ssf_clean($s) { return (string) preg_replace(ssf_d('^,/-Ia_\\-Ift-?-E.^'), '.', (string) $s); }
function ssf_one_line($s, $n = 260) { return substr((string) preg_replace('/\s+/', ' ', ssf_clean($s)), 0, $n); }
function ssf_hsize($b) { $u = ['B', 'KB', 'MB', 'GB']; $i = 0; $b = (float) $b; while ($b >= 1024 && $i < 3) { $b /= 1024; $i++; } return round($b, $i ? 1 : 0) .' ' .$u[$i]; }
function ssf_has_curl() { static $c = null; if ($c === null) $c = extension_loaded('curl'); return $c; }
function ssf_http($url, $timeout = 8) {
    if (ssf_has_curl()) {
        $c = curl_init($url);
        curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_FOLLOWLOCATION => true, CURLOPT_USERAGENT => ssf_d('D6@\\DA2>\\7:I^') .SSF_VERSION]);
        $r = curl_exec($c);
        $code = (int) curl_getinfo($c, CURLINFO_HTTP_CODE);
        return [$code, $r === false ? '' : (string) $r];
    }
    $r = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => $timeout, 'user_agent' => ssf_d('D6@\\DA2>\\7:I^') .SSF_VERSION, 'ignore_errors' => true]]));
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
        curl_setopt_array($c, [CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_USERAGENT => ssf_d('D6@\\DA2>\\7:I^') .SSF_VERSION,
            CURLOPT_HEADERFUNCTION => function ($c, $line) use (&$h) { $p = strpos($line, ':'); if ($p) $h[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1)); return strlen($line); },
            CURLOPT_WRITEFUNCTION => function ($c, $data) use (&$body) { $body .= $data; return strlen($body) > 8192 ? 0 : strlen($data); }]);
        curl_exec($c);
        return [(int) curl_getinfo($c, CURLINFO_HTTP_CODE), $h, substr($body, 0, 8192)];
    }
    $fp = @fopen($url, 'r', false, stream_context_create(['http' => ['timeout' => $timeout, 'follow_location' => 0, 'ignore_errors' => true, 'user_agent' => ssf_d('D6@\\DA2>\\7:I^') .SSF_VERSION]]));
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
    return (string) @file_get_contents($p, false, null, 0, 400000) ."\n" .(string) @file_get_contents($p, false, null, max(0, $size - 20000));
}

/* ------------------------------------------------------------------ detection rules */
function ssf_spam($text) {
    static $strong = null, $weak = null;
    if ($strong === null) { $strong = [ssf_d('D=@E 824@C'), ssf_d('E@86='), ssf_d(';F5: @?=:?6'), ssf_d(';F5: D=@E'), ssf_d('D:EFD D=@E'), ssf_d('D:EFD ;F5:'), ssf_d('D=@Egg'), ssf_d('D=@E @?=:?6'), ssf_d('>2IH:?'), ssf_d('D3@36E'), ssf_d('32?52C E@86='), ssf_d('E@E@ c5'), ssf_d('E@E@ E@86='), ssf_d('CEA D=@E'), 'rtp live', 'link alternatif', 'scatter hitam', ssf_d('527E2C D=@E'), ssf_d('286? D=@E'), ssf_d('D=@E 52?2'), ssf_d('D=@E AF=D2'), ssf_d('D=@E 56A@D:E'), ssf_d('3@4@C2? D=@E'), ssf_d('824@C 92C: :?:'), ssf_d('824@C'), 'mahjong ways', ssf_d('D=@E E92:=2?5'), ssf_d('D=@E 56>@'), ssf_d('3FJ G:28C2'), ssf_d('4962A G:28C2'), ssf_d('G:28C2 @?=:?6'), ssf_d('4:2=:D @?=:?6'), ssf_d('3FJ 4:2=:D'), 'replica watches', 'payday loans online', 'kasino online', ssf_d(';F5: 3@=2'), ssf_d('D:EFD E@E@'), ssf_d('D=@E BC:D'), 'depo 5k', 'depo 10k'];
    $weak = [ssf_d('42D:?@'), ssf_d('A@<6C'), ssf_d(';24<A@E'), ssf_d('36EE:?8'), ssf_d('G:28C2'), ssf_d('4:2=:D'), ssf_d('D=@E'), ssf_d('AC28>2E:4 A=2J'), ssf_d('32442C2E'), ssf_d('C@F=6EE6')]; }
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
        [ssf_d('^-3Wni6G2=M2DD6CEMDJDE6>MA2DDE9CFMD96==06I64M6I64MA@A6?MAC@40@A6?X-DY-W-DYonWniDEC:AD=2D96D-DY-W-DYXnWni32D6ec0564@56-DY-W-DYXn-S0Wni!~$%Mvt%M#t"&t$%Mr~~zxtX^:'), 10, 'runs code sent by a visitor', 1],
        [ssf_d('^-S0Wni!~$%Mvt%M#t"&t$%Mr~~zxtX-DY-,,/-..L`[c_N-.-DY-W^'), 8, 'calls a function named by a visitor', 1],
        [ssf_d('^p{up %t2|MD@=6G:D:3=6Mu:=6D|2?M($~ -5M3bfc<M4hhD96==MCdfD96==Mx?5@)A=@:EM|:?: $96==Mv6=cJM!-]p-]$-] u@C<M>2C:;F2?2 D96==MHD@0G6CD:@?M%CJ28 u:=6 |2?286CM_3JEb>`?`^:'), 10, ssf_d('<?@H? H63 D96=='), 1],
        [ssf_d('^-36G2=-DY-W-DYonWni32D6ec0564@56M8K:?7=2E6M8KF?4@>AC6DDMDEC0C@E`bMDECC6GMFC=564@56MC2HFC=564@56M96Ia3:?X-DY-W^:'), 8, ssf_d('6I64FE6D 2 9:556? A2J=@25'), 1],
        [ssf_d('^Wni8K:?7=2E6M8KF?4@>AC6DDMDEC0C@E`bX-DY-W-DY32D6ec0564@56-DY-W-DY,VQ.^:'), 7, ssf_d('A24<65 A2J=@25'), 0],
        ['/[\'"]base[\'"]\s*;?\s*\$\w+\s*=\s*[\'"]64_decode[\'"]|[\'"]base[\'"]\s*\.\s*[\'"]64_decode[\'"]|[\'"]ba[\'"]\s*\.\s*[\'"]se64_/i', 6, 'function name split to avoid detection', 0],
        [ssf_d('^Wni:?4=F56MC6BF:C6XWni0@?46Xn-DY-Wn-DY,VQ.,/VQ.Y-]Wni:4@M;A8M;A68MA?8M8:7MEIEM4DDM=@8M52EX,VQ.^:'), 7, 'loads code from a non-PHP file', 0],
        [ssf_d('^on-DYWni:?4=F56MC6BF:C6XWni0@?46Xn-DY-Wn-DY,VQ.Wni,/VQ.L_[`aNXWni--,_\\f.La[bNM--I,_\\h2\\7p\\u.LaNXLc[N^'), 7, 'loads a file from a disguised path', 0],
        [ssf_d('^Wni7:=60AFE04@?E6?EDM7HC:E6M7AFEDX-DY-W,/j.L_[a__N-S0Wni!~$%M#t"&t$%Mr~~zxtMvt%Mux{t$X^:D'), 6, 'writes files from visitor input', 0],
        [ssf_d('^Wni7:=6086E04@?E6?EDM4FC=0:?:EX-DY-W-DYWni32D6ec0564@56MDEC0C@E`bMDECC6GX-DY-W^:'), 7, 'fetches from a hidden address', 0],
        ['/<\?php[ \t]{150,}\S/', 7, 'code hidden behind whitespace', 0],
        [ssf_d('^AC680C6A=246-DY-W-DY,VQ.,/VQ.Y-^,2\\K.Y6,2\\K.Y,VQ.^:'), 5, ssf_d('AC680C6A=246 ^6'), 0],
        ['/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr/i', 4, 'text built from character codes', 0],
        [ssf_d('^-S-L,VQ.Wni--I,_\\h2\\7p\\u.LaNM,p\\+2\\K0.XLb[N,VQ.-N-DY-,^'), 4, ssf_d('@37FD42E65 G2C:23=6D'), 0],
        [ssf_d('^-36G2=-DY-W-DYon-SM-36G2=-DY-W-DY,VQ.-nm,VQ.-DY-]^'), 3, ssf_d('6G2= @7 2 G2C:23=6'), 0],
        [ssf_d('^w%%!0&$t#0pvt}%,/j.L_[b__NWni8@@8=63@EM3:?83@EMJ2?56IM32:5FMDA:56CM4C2H=X^:D'), 3, 'treats search engines differently', 0],
        [ssf_d('^Wni--I,_\\h2\\7p\\u.LaNXL`a[N^'), 3, 'hex-encoded text', 0],
        ['/[A-Za-z0-9+\/]{2000,}={0,2}/', 2, 'large encoded block', 0],
        [ssf_d('^-32DD6CE-DY-W-DY-S^:'), 2, ssf_d('2DD6CE @7 2 G2C:23=6'), 0],
        [ssf_d('^32D6ec0564@56-DY-W^:'), 1, ssf_d('32D6ec0564@56'), 0],
        [ssf_d('^4C62E607F?4E:@?-DY-W^:'), 1, ssf_d('4C62E607F?4E:@?'), 0],
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
    if (@preg_match_all('/^\$\w+\s*\.=\s*"[^"]{1,12}";\s*$/m', substr($c, 0, 300000)) >= 200) { $score += 6; $labels[] = ssf_d('A2J=@25 DA=:E :?E@ 9F?5C65D @7 7C28>6?ED'); if (!$snip) $snip = substr($c, 0, 200); }
    if ($size < 6000 && preg_match(ssf_d('^>@G60FA=@256507:=6^:'), $c) && preg_match('/type=[\'"]?file/i', $c) && !preg_match('/ABSPATH|wp_verify_nonce|add_action/', $c)) { $score += 6; $labels[] = ssf_d('DE2?5\\2=@?6 7:=6 FA=@256C'); }
    list($spam, $terms) = ssf_spam($c);
    if ($spam) { $score += 8; $labels[] = ssf_d('DA2> <6JH@C5Di ') .implode(', ', array_slice($terms, 0, 4)); }
    return [$score, $labels, ssf_one_line($snip), $certain];
}
/** Find search-engine-only redirect blocks in a .htaccess. Returns [blocks(list of [start,end]), flags(list of text)] */
function ssf_ht_analyze($c) {
    $lines = explode("\n", $c); $n = count($lines); $blocks = []; $flags = [];
    $bot = ssf_d('^8@@8=63@EM3:?83@EMD=FCAMJ2?56IM32:5FM5F4<5F4<M>D?3@EM4C2H=6CMDA:56CM8@@8=6\\:?DA64E:@?M-33@EDn-3^:');
    for ($i = 0; $i < $n; $i++) {
        $l = $lines[$i];
        $hit = false;
        if (preg_match('/^\s*RewriteCond\s+%\{HTTP_USER_AGENT\}\s+(\S+)/i', $l, $m) && $m[1][0] !== '!' && preg_match($bot, $m[1])) $hit = true;
        if (preg_match('/^\s*RewriteCond\s+%\{HTTP_REFERER\}\s+(\S+)/i', $l, $m) && $m[1][0] !== '!' && preg_match(ssf_d('^8@@8=6M3:?8MJ29@@MJ2?56IM5F4<5F4<M32:5F^:'), $m[1])) $hit = true;
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
        if (preg_match(ssf_d('^/-DYWp55w2?5=6CMp55%JA6M$6Ew2?5=6CX-3]YWA9AMI\\9EEA5X^:'), $l) && preg_match('/\.(jpe?g|png|gif|ico|txt|html?|css|js)\b/i', $l)) $flags[] = 'Runs non-PHP file types as PHP: ' .ssf_one_line($l, 160);
        if (preg_match(ssf_d('^2FE@0WAC6A6?5M2AA6?5X07:=6-DY,l .-DY,VQ.nW,/VQ-D.ZX^:'), $l, $m) && !preg_match('/wordfence-waf\.php|malcare|ignitor\.php|sg-cachepress|none$/i', $m[2])) $flags[] = 'Loads a file before every page: ' .ssf_one_line($m[2], 160);
        if (preg_match('/^\s*ErrorDocument\s+\d+\s+https?:\/\//i', $l)) $flags[] = 'Error pages sent to another website: ' .ssf_one_line($l, 160);
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

/* ------------------------------------------------------------------ scan engine */
function ssf_add(&$st, $f) {
    if (count($st['findings']) >= SSF_MAX_FINDINGS) { $st['truncated'] = true; return; }
    $f += ['site' => '', 'path' => '', 'kind' => 'none', 'cat' => 'integrity', 'sev' => 'medium', 'title' => '', 'detail' => '', 'evidence' => '', 'fix' => 'manual', 'tick' => false, 'state' => 'open'];
    if ($f['path'] !== '' && $f['kind'] !== 'none') {
        $s = @lstat($st['base'] .'/' .$f['path']);
        if ($s) { $f['size'] = $s['size']; $f['mtime'] = $s['mtime']; $f['ctime'] = $s['ctime']; }
    }
    $f['id'] = count($st['findings']) + 1;
    $st['findings'][] = $f;
}
function ssf_rel($st, $p) { return $p === $st['base'] ? '.' : substr($p, strlen($st['base']) + 1); }
function ssf_inst_for($st, $p) {
    static $sorted = null, $n = -1;
    if ($sorted === null || $n !== count($st['installs'])) { $sorted = array_keys($st['installs']); usort($sorted, function ($a, $b) { return strlen($b) - strlen($a); }); $n = count($sorted); }
    foreach ($sorted as $ip) if ($p === $ip || strpos($p, $ip .'/') === 0) return $ip;
    return null;
}
function ssf_start($base) {
    $base = rtrim((string) realpath($base), '/');
    if ($base === '' || !is_dir($base) || !is_readable($base)) return ['error' => 'That folder does not exist or cannot be read.'];
    if (!ssf_data_dir()) return ['error' => 'No writable folder for scan data. Make the account home folder or this folder writable.'];
    $found = [];
    foreach (['', '/*', '/*/*', '/*/*/*'] as $pat) {
        foreach (array_merge(@glob($base .$pat .ssf_d('^HA\\:?4=F56D^G6CD:@?]A9A')) ?: [], @glob($base .$pat .'/wp-config.php') ?: []) as $w) {
            $dn = basename($w) === 'version.php' ? dirname(dirname($w)) : dirname($w);
            if (is_link($dn) || strpos($dn .'/', ssf_data_dir() .'/') === 0) continue;
            $found[$dn] = 1;
        }
    }
    $installs = [];
    foreach (array_keys($found) as $ip) {
        $ver = ''; $loc = 'en_US';
        $vc = (string) @file_get_contents($ip .ssf_d('^HA\\:?4=F56D^G6CD:@?]A9A'));
        if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', $vc, $m)) $ver = $m[1];
        if (preg_match('/\$wp_local_package\s*=\s*[\'"]([^\'"]+)/', $vc, $m)) $loc = $m[1];
        $installs[$ip] = ['path' => $ip, 'rel' => $ip === $base ? '.' : substr($ip, strlen($base) + 1), 'label' => basename($ip), 'ver' => $ver, 'locale' => $loc, 'config' => is_file($ip .'/wp-config.php'), 'core' => 'pending', 'themes' => [], 'admins' => [], 'db' => 'pending'];
    }
    $st = ['v' => 1, 'base' => $base, 'started' => time(), 'phase' => 'pre', 'pre' => array_keys($installs), 'queue' => [$base], 'qi' => 0, 'files' => 0, 'php' => 0, 'verified' => 0,
        'installs' => $installs, 'findings' => [], 'plugins' => [], 'skip' => [], 'recent' => [], 'notes' => [], 'core_mod' => [], 'core_extra' => [], 'upl' => [], 'arch' => [], 'net' => true, 'latest' => '', 'truncated' => false, 'current' => '', 'env' => false, 'logs' => [], 'perms' => [], 'srcexp' => [], 'baas' => []];
    ssf_save('state.json', $st);
    return ['ok' => true, 'installs' => count($installs)];
}
function ssf_db($ip) {
    $cfg = (string) @file_get_contents($ip .'/wp-config.php');
    if ($cfg === '') return [null, 'wp_', 'no wp-config.php'];
    $g = function ($k) use ($cfg) { return preg_match('/define\(\s*[\'"]' .$k .'[\'"]\s*,\s*([\'"])(.*?)\1\s*\)/s', $cfg, $m) ? $m[2] : null; };
    $px = preg_match('/\$table_prefix\s*=\s*[\'"]([^\'"]+)/', $cfg, $m) ? $m[1] : 'wp_';
    if (!preg_match('/^[A-Za-z0-9_]+$/', $px)) return [null, $px, 'unusual table prefix'];
    if (!extension_loaded('mysqli')) return [null, $px, 'mysqli is not available'];
    if ($g('DB_NAME') === null) return [null, $px, 'database settings not readable'];
    mysqli_report(MYSQLI_REPORT_OFF);
    $host = (string) $g('DB_HOST'); $port = null; $sock = null;
    if (strpos($host, ':') !== false) { list($host, $rest) = explode(':', $host, 2); if (ctype_digit($rest)) $port = (int) $rest; else $sock = $rest; }
    $db = @mysqli_connect($host ?: 'localhost', (string) $g('DB_USER'), (string) $g(ssf_d('sq0!p$$(~#s')), (string) $g('DB_NAME'), $port ?: 3306, $sock);
    if (!$db) return [null, $px, 'could not connect: ' .ssf_one_line((string) mysqli_connect_error(), 80)];
    return [$db, $px, ''];
}
function ssf_q($db, $sql) { $r = @mysqli_query($db, $sql); if (!$r || $r === true) return []; $o = []; while ($row = mysqli_fetch_assoc($r)) $o[] = $row; return $o; }

function ssf_pre_install(&$st, $ip) {
    $I = &$st['installs'][$ip];
    $site = $I['rel'];
    $rp = function ($p) use ($st) { return ssf_rel($st, $p); };
    /* core checksums + latest version */
    if ($I['ver'] && $st['net']) {
        $cf = 'cache-core-' .preg_replace('/[^A-Za-z0-9._-]/', '', $I['ver'] .'-' .$I['locale']) .'.json';
        if (!ssf_load($cf)) {
            list($code, $body) = ssf_http('https://api.wordpress.org/core/checksums/1.0/?version=' .rawurlencode($I['ver']) .'&locale=' .rawurlencode($I['locale']), 15);
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
        ssf_add($st, ['site' => $site, 'cat' => 'outdated', 'sev' => $maj($st['latest']) - $maj($I['ver']) >= 2 ? 'high' : 'medium', 'title' => 'WordPress ' .$I['ver'] .' is out of date', 'detail' => 'Latest is ' .$st['latest'] .'. Old versions have published security holes.']);
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
            $I['admins'][] = ['login' => ssf_clean($a['user_login']), 'email' => $at === false ? '***' : substr($em, 0, 2) .'***' .substr($em, $at), 'registered' => (string) $a['user_registered']];
            if (strtotime((string) $a['user_registered']) > time() - 120 * 86400) $recent[] = ssf_clean($a['user_login']);
        }
        $names = implode(', ', array_map(function ($a) { return $a['login']; }, $I['admins']));
        ssf_add($st, ['site' => $site, 'cat' => 'access', 'sev' => $recent ? 'medium' : 'info', 'title' => count($I['admins']) .' administrator account' .(count($I['admins']) === 1 ? '' : 's') .($recent ? ', ' .count($recent) .' created in the last 4 months' : ''), 'detail' => 'Confirm you recognise every one: ' .$names .'. Delete any you do not.' .($recent ? ' Recently created: ' .implode(', ', $recent) .'.' : '')]);
        $rx = ssf_d('D=@E 824@CME@86=M;F5: @?=:?6MD:EFD D=@EMD=@EggM>2IH:?MD3@36EM32?52C E@86=M3FJ G:28C2M4:2=:D @?=:?6');
        $sp = ssf_q($db, "SELECT ID, LEFT(post_title,60) t FROM `{$px}posts` WHERE post_status IN ('publish','draft','private') AND post_type NOT IN ('revision') AND (post_content REGEXP '$rx' OR post_title REGEXP '$rx') LIMIT 25");
        if ($sp) ssf_add($st, ['site' => $site, 'cat' => 'database', 'sev' => 'critical', 'title' => count($sp) .(count($sp) >= 25 ? '+' : '') .ssf_d(' A@DED @C A286D :? E96 52E232D6 4@?E2:? DA2>'), 'detail' => 'These live in the database, not in files, so this tool cannot quarantine them. Delete or clean them in WordPress admin.', 'evidence' => ssf_one_line(implode(' | ', array_map(function ($r) { return '#' .$r['ID'] .' ' .$r['t']; }, $sp)), 500)]);
        $codeRx = ssf_d('6G2=--WM8K:?7=2E6--WM32D6ec0564@56--W');
        $op = ssf_q($db, "SELECT option_name n FROM `{$px}options` WHERE option_value REGEXP '$codeRx' AND option_name NOT LIKE '\\_transient%' AND option_name NOT LIKE '\\_site\\_transient%' LIMIT 15");
        if ($op) ssf_add($st, ['site' => $site, 'cat' => 'database', 'sev' => 'medium', 'title' => count($op) .ssf_d(' 52E232D6 D6EE:?8D 4@?E2:? 6I64FE23=6\\=@@<:?8 4@56'), 'detail' => 'Often legitimate (page builders, snippets plugins) but worth a look.', 'evidence' => ssf_one_line(implode(', ', array_map(function ($r) { return $r['n']; }, $op)), 400)]);
        $o = [];
        foreach (ssf_q($db, "SELECT option_name n, option_value v FROM `{$px}options` WHERE option_name IN ('users_can_register','default_role','siteurl','home')") as $r) $o[$r['n']] = (string) $r['v'];
        if (($o['users_can_register'] ?? '0') === '1' && ($o['default_role'] ?? '') === 'administrator') ssf_add($st, ['site' => $site, 'cat' => 'database', 'sev' => 'critical', 'title' => 'Anyone can register as an administrator', 'detail' => 'Settings > General: turn off "Anyone can register" and set the default role to Subscriber.']);
        if (isset($o['siteurl'], $o['home']) && parse_url($o['siteurl'], PHP_URL_HOST) !== parse_url($o['home'], PHP_URL_HOST)) ssf_add($st, ['site' => $site, 'cat' => 'database', 'sev' => 'high', 'title' => 'Site address and WordPress address point to different domains', 'detail' => 'siteurl = ' .ssf_clean($o['siteurl']) .', home = ' .ssf_clean($o['home'])]);
        mysqli_close($db);
    }

    /* folders in the site root */
    $stdDirs = ['wp-admin' => 1, 'wp-content' => 1, ssf_d('HA\\:?4=F56D') => 1, 'cgi-bin' => 1, '.well-known' => 1];
    foreach ((@scandir($ip) ?: []) as $en) {
        if ($en === '.' || $en === '..' || isset($stdDirs[$en])) continue;
        $p = "$ip/$en";
        if (!is_dir($p) || is_link($p) || isset($st['installs'][$p]) || strpos($p .'/', ssf_data_dir() .'/') === 0) continue;
        if ($en === '.tmb' || $en === '.quarantine') {
            if ($en === '.tmb') ssf_add($st, ['site' => $site, 'path' => $rp($p), 'kind' => 'dir', 'cat' => 'access', 'sev' => 'medium', 'title' => 'A file-manager tool has been used on this site', 'detail' => ssf_d('%96 ]E>3 7@=56C :D 4C62E65 3J 6=u:?56C\\32D65 7:=6 >2?286CD W(! u:=6 |2?286C[ u:=6 |2?286C p5G2?465 2?5 D:>:=2CX] pEE24<6CD FD6 E96D6 E@ FA=@25 7:=6D] x7 J@F 5:5 ?@E FD6 @?6[ EC62E :E 2D 2 D:8? @7 :?ECFD:@?]')]);
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
                'title' => ssf_d('$A2> A286 7@=56C') .($shadow ? ' covering a real page' : ''), 'detail' => ($shadow ? 'A published WordPress page uses the address /' .$en .'/. This folder is served instead of it; once moved, the real page shows again. ' : ssf_d('%9:D 7@=56C :D ?@E A2CE @7 (@C5!C6DD 2?5 D6CG6D DA2> 4@?E6?E] ')) .'Page title: "' .ssf_one_line($title, 80) .'".', 'evidence' => 'keywords: ' .implode(', ', $terms)]);
            $st['skip'][$p] = 1;
        } elseif ($shadow && !$loadsWp) {
            ssf_add($st, ['site' => $site, 'path' => $rp($p), 'kind' => 'dir', 'cat' => 'doorway', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => false,
                'title' => 'Folder is hiding a real WordPress page', 'detail' => 'A published page uses the address /' .$en .ssf_d('^ 3FE G:D:E@CD 86E E9:D 7@=56C :?DE625] }@ DA2> <6JH@C5D H6C6 7@F?5 :? :E[ D@ 4964< H92E :E D9@HD 367@C6 >@G:?8 :E] !286 E:E=6i Q') .ssf_one_line($title, 80) .'".']);
        }
    }

    /* wp-config.php */
    if ($I['config']) {
        $c = (string) @file_get_contents("$ip/wp-config.php");
        list($sc, $labels, $snip) = ssf_score($c, strlen($c));
        if ($sc >= 5 || preg_match(ssf_d('^/-DYWnion-DYWni:?4=F56MC6BF:C6XWni0@?46XnX-3WnP,/j.YHA\\D6EE:?8D-]A9AXWnP,/j.YHA\\D2=EX,/j.Yj^>'), preg_replace('#/\*.*?\*/#s', '', $c), $m)) {
            ssf_add($st, ['site' => $site, 'path' => $rp("$ip/wp-config.php"), 'kind' => 'file', 'cat' => 'implant', 'sev' => $sc >= 8 ? 'critical' : 'medium', 'title' => 'wp-config.php contains unusual code', 'detail' => 'This file should only hold settings. Do not quarantine it (the site would stop). Open it and remove anything that is not a setting. ' .($labels ? 'Signs: ' .implode('; ', $labels) .'.' : 'It loads another file.'), 'evidence' => $snip ?: ssf_one_line($m[0] ?? '', 200)]);
        }
        $perm = @fileperms("$ip/wp-config.php") & 0777;
        if ($perm & 0002) ssf_add($st, ['site' => $site, 'path' => $rp("$ip/wp-config.php"), 'kind' => 'file', 'cat' => 'exposure', 'sev' => 'medium', 'title' => 'wp-config.php is writable by everyone', 'detail' => 'Permissions are ' .sprintf('%04o', $perm) .'. Set to 0600 or 0640 in File Manager.']);
    }
    foreach (['.user.ini', 'php.ini'] as $ini) {
        $c = (string) @file_get_contents("$ip/$ini");
        if ($c !== '' && preg_match(ssf_d('^2FE@0WAC6A6?5M2AA6?5X07:=6-DYl-DY,VQ.nW,/VQ-D.ZX^:'), $c, $m) && !preg_match('/wordfence-waf\.php|malcare|ignitor\.php|none$/i', $m[2]))
            ssf_add($st, ['site' => $site, 'path' => $rp("$ip/$ini"), 'kind' => 'file', 'cat' => 'implant', 'sev' => 'high', 'title' => "$ini loads a file before every page", 'detail' => 'auto_' .$m[1] .ssf_d('07:=6 :D 2 4@>>@? H2J E@ CF? >2=H2C6 @? 6G6CJ C6BF6DE] r964< E96 7:=6 :E A@:?ED E@]'), 'evidence' => ssf_one_line($m[2], 200)]);
    }

    /* plugins and themes inventory */
    $risky = ['wp-file-manager' => 'file manager', 'wp-file-manager-pro' => 'file manager', 'file-manager-advanced' => 'file manager', 'file-manager' => 'file manager', 'filester' => 'file manager', 'filebird-document-library' => '', 'wpide' => 'code editor', 'insert-php' => 'runs custom PHP', 'worker' => 'remote management (ManageWP)', 'mainwp-child' => 'remote management (MainWP)', 'iwp-client' => 'remote management (InfiniteWP)', 'blogvault-real-time-backup' => 'remote management (BlogVault)', 'malcare-security' => 'remote management (MalCare)'];
    foreach ((@scandir("$ip/wp-content/plugins") ?: []) as $en) {
        if (!isset($risky[$en]) || $risky[$en] === '' || !is_dir("$ip/wp-content/plugins/$en")) continue;
        $fm = strpos($risky[$en], 'file manager') !== false || strpos($risky[$en], 'editor') !== false;
        ssf_add($st, ['site' => $site, 'path' => $rp("$ip/wp-content/plugins/$en"), 'kind' => 'dir', 'cat' => 'access', 'sev' => $fm ? 'high' : 'info', 'title' => ($fm ? 'File-manager plugin installed: ' : 'Remote-control plugin installed: ') .$en, 'detail' => $fm ? ssf_d('v:G6D 2?J@?6 H:E9 2? 25>:? =@8:? W@C 2? 6IA=@:E 7@C E96 A=F8:?X 7F== 2446DD E@ E96 7:=6D @? E9:D 244@F?E] #6>@G6 :E F?=6DD :E :D :? 52:=J FD6]') : 'A ' .$risky[$en] .' connection can run code on this site by design. Fine if you use that service; remove it if nobody does.']);
    }
    foreach ((@scandir("$ip/wp-content/themes") ?: []) as $en) if ($en[0] !== '.' && is_dir("$ip/wp-content/themes/$en")) $I['themes'][] = $en;
    unset($I);
}

function ssf_core_map($I) {
    static $cache = [];
    if ($I['core'] !== 'ok') return null;
    $k = preg_replace('/[^A-Za-z0-9._-]/', '', $I['ver'] .'-' .$I['locale']);
    if (!array_key_exists($k, $cache)) $cache[$k] = ssf_load('cache-core-' .$k .'.json');
    return $cache[$k];
}
function ssf_plugin(&$st, $ip, $slug) {
    static $maps = [];
    $key = $ip .'|' .$slug;
    if (!isset($st['plugins'][$key])) {
        $dir = "$ip/wp-content/plugins/$slug"; $ver = ''; $name = $slug;
        foreach ((@glob("$dir/*.php") ?: []) as $f) {
            $hd = (string) @file_get_contents($f, false, null, 0, 8192);
            if (preg_match('/^[ \t\/*#@]*Plugin Name:\s*(.+)$/mi', $hd, $m)) { $name = trim($m[1]); if (preg_match('/^[ \t\/*#@]*Version:\s*([^\s*]+)/mi', $hd, $v)) $ver = trim($v[1]); break; }
        }
        $status = 'unverifiable';
        if ($ver !== '' && preg_match('/^[A-Za-z0-9._-]+$/', $slug .$ver)) {
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
    $mk = $slug .'-' .$P['ver'];
    if (!array_key_exists($mk, $maps)) $maps[$mk] = ssf_load("cache-plug-$mk.json");
    return $maps[$mk];
}
function ssf_file(&$st, $p, $name, $ip) {
    static $PHPEXT = ['php' => 1, 'php3' => 1, 'php4' => 1, 'php5' => 1, 'php7' => 1, 'php8' => 1, 'phtml' => 1, 'pht' => 1, 'phar' => 1, 'suspected' => 1];
    static $MEDIA = ['jpg' => 1, 'jpeg' => 1, 'png' => 1, 'gif' => 1, 'webp' => 1, 'ico' => 1, 'bmp' => 1, 'avif' => 1, 'svg' => 1];
    static $ARCH = ['zip' => 1, 'gz' => 1, 'tgz' => 1, 'tar' => 1, 'rar' => 1, '7z' => 1, 'sql' => 1, 'wpress' => 1, 'bak' => 1];
    static $STDROOT = ['index.php' => 1, 'wp-activate.php' => 1, 'wp-blog-header.php' => 1, 'wp-comments-post.php' => 1, 'wp-config.php' => 1, 'wp-config-sample.php' => 1, 'wp-cron.php' => 1, 'wp-links-opml.php' => 1, 'wp-load.php' => 1, 'wp-login.php' => 1, 'wp-mail.php' => 1, 'wp-settings.php' => 1, 'wp-signup.php' => 1, 'wp-trackback.php' => 1, 'xmlrpc.php' => 1, 'wordfence-waf.php' => 1];
    static $DROPINS = ['index.php' => 1, 'advanced-cache.php' => 1, 'object-cache.php' => 1, 'db.php' => 1, 'sunrise.php' => 1, 'maintenance.php' => 1, 'php-error.php' => 1, 'fatal-error-handler.php' => 1, 'blog-deleted.php' => 1, 'blog-inactive.php' => 1, 'blog-suspended.php' => 1, 'install.php' => 1, 'db-error.php' => 1];
    $MUKNOWN = ssf_d('^/W:?56I-]A9AM_\\H@C<6C-]A9AM2FE@>2E:@?\\3J\\:?DE2==2EC@?-]A9AM85\\DJDE6>\\A=F8:?-]A9AMHA\\E@@=<:E]Y-]A9AM6?5FC2?46\\]Y-]A9AMDD@-]A9AMHA4@>D9\\=@256C-]A9AM962=E9\\4964<\\EC@F3=6D9@@E:?8\\>@56-]A9AM>F\\A=F8:?-]A9AM<:?DE2\\>F\\A=F8:?D-]A9AMHA6?8:?6\\]Y-]A9AM>2=42C6\\]Y-]A9AM222\\HA\\46C36C-]A9AXS^:');

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
        elseif (strpos($irel, 'wp-admin/') === 0 || strpos($irel, ssf_d('HA\\:?4=F56D^')) === 0) $loc = 'core';
        elseif (preg_match('#^wp-content/plugins/([^/]+)/#', $irel, $m)) { $loc = 'plugin'; $slug = $m[1]; }
        elseif (strpos($irel, 'wp-content/plugins/') === 0) $loc = 'pluginsroot';
        elseif (strpos($irel, 'wp-content/themes/') === 0) $loc = 'theme';
        elseif (strpos($irel, ssf_d('HA\\4@?E6?E^FA=@25D^')) === 0) $loc = ssf_d('FA=@25D');
        elseif (strpos($irel, 'wp-content/mu-plugins/') === 0) $loc = 'mu';
        elseif (preg_match('#^wp-content/[^/]+$#', $irel)) $loc = 'content';
        else $loc = 'other';
    }
    $add = function ($f) use (&$st, $site, $rel) { ssf_add($st, $f + ['site' => $site, 'path' => $rel, 'kind' => 'file']); };

    
    if ($name !== '.htaccess' && ssf_audit_file($st, $p, $name, $ext, $size, $rel, $site, $loc, $isPhp)) return;

    /* .htaccess */
    if ($name === '.htaccess') {
        $c = (string) @file_get_contents($p, false, null, 0, 200000);
        list($blocks, $flags) = ssf_ht_analyze($c);
        if ($blocks) $add(['cat' => 'htaccess', 'sev' => 'critical', 'fix' => 'htaccess', 'tick' => true, 'title' => 'Search engines are being redirected', 'detail' => ssf_d('%9:D ]9E2446DD D6?5D v@@8=6 2?5 @E96C 4C2H=6CD W@C G:D:E@CD 2CC:G:?8 7C@> E96>X D@>6H96C6 6=D6[ H9:49 C6A=246D J@FC A286D :? D62C49 C6DF=ED] %96 7:I C6>@G6D @?=J E96 3=@4< D9@H? 2?5 <66AD 2 4@AJ @7 E96 @C:8:?2= 7:=6]'), 'evidence' => ssf_clean(substr(implode("\n...\n", array_map(function ($b) { return $b[2]; }, $blocks)), 0, 1500))]);
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
    $pmap = null; $pkey = $ip .'|' .$slug; $inPmap = false;
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
        $safeSpot = in_array($loc, ['root', 'core', 'content', ssf_d('FA=@25D'), 'mu', 'outside', 'pluginsroot'], true);
        if ($size === 0) {
            if ($name === 'index.php') return;
            $add(['cat' => 'leftover', 'sev' => 'low', 'fix' => 'quarantine', 'tick' => $safeSpot, 'title' => 'Empty PHP file with an odd name', 'detail' => ssf_d('&DF2==J 2 324<5@@C E92E 2 >2=H2C6 D42??6C 6>AE:65 5FC:?8 2? 62C=:6C 4=62?\\FA] w2C>=6DD ?@H[ 3FE :E D9@HD E9:D D:E6 H2D 3C@<6? :?E@ 367@C6]') .($safeSpot ? '' : ' It sits inside a plugin or theme, so it is left unticked in case that code expects the file to exist.')]);
            return;
        }
        $c = ssf_read($p, $size);
        if ($name === 'index.php' && $size < 300 && preg_match('/^<\?php\s*(?:\/\/[^\n]*|#[^\n]*|\/\*.*?\*\/)?\s*(?:\?>)?\s*$/s', $c)) return;
        list($sc, $labels, $snip, $certain) = ssf_score($c, $size);
        $why = $labels ? 'Signs: ' .implode('; ', $labels) .'.' : '';
        $sevOf = function ($sc, $certain) { return ($sc >= 14 || $certain) ? 'critical' : 'high'; };
        $bd = function ($title, $detail, $tick, $sev = null) use ($add, $sc, $certain, $why, $snip, $sevOf) { $add(['cat' => 'implant', 'sev' => $sev ?: $sevOf($sc, $certain), 'fix' => 'quarantine', 'tick' => $tick, 'title' => $title, 'detail' => trim($detail .' ' .$why), 'evidence' => $snip]); };
        $standalone = (bool) preg_match('/^([a-f0-9]{6,}|[a-z0-9]{1,3}|wp-[a-z]{2,8}|[a-z]+\d+)\.php$/i', $name);

        if ($loc === 'core') {
            if ($map) {
                if ($sc >= 5 || $size > 1048576) $bd(ssf_d('&?<?@H? 7:=6 9:556? 2>@?8 (@C5!C6DD DJDE6> 7:=6D'), 'This file is not part of WordPress ' .$st['installs'][$ip]['ver'] .'.' .($size > 1048576 ? ' It is unusually large (' .ssf_hsize($size) .').' : ''), true, $sc >= 8 || $certain ? 'critical' : 'high');
                else { $st['core_extra'][$ip] = ($st['core_extra'][$ip] ?? 0) + 1; }
            } elseif ($sc >= 8) $bd(ssf_d('$FDA:4:@FD 4@56 2>@?8 (@C5!C6DD DJDE6> 7:=6D'), 'Core files could not be verified against the official list for this site.', $certain);
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
                if ($sc >= 5) $bd('Unknown file inside a verified plugin (' .$slug .')', 'The official release of this plugin does not contain this file.', true);
                elseif (count($st['plugins'][$pkey]['xsamples']) < 8) $st['plugins'][$pkey]['xsamples'][] = substr($irel, strlen("wp-content/plugins/$slug/"));
                return;
            }
            if ($sc >= 8) $bd($inPmap ? 'Plugin file changed and contains suspicious code (' .$slug .')' : 'Suspicious code in plugin ' .$slug, $inPmap ? 'Reinstall the plugin from WordPress.org rather than moving this file.' : 'This plugin cannot be checked against an official copy (premium or custom). If this is one of the plugin\'s own files, reinstall the plugin from its vendor instead of moving it.', !$inPmap && $certain && $standalone);
            return;
        }
        if ($loc === ssf_d('FA=@25D')) {
            $dated = (bool) preg_match(ssf_d('R/HA\\4@?E6?E^FA=@25D^WniD:E6D^-5Z^Xn-5LcN^-5LaN^R'), $irel);
            if ($sc >= 5 || $dated) $bd(ssf_d('!w! 7:=6 :? E96 FA=@25D 7@=56C'), ssf_d('&A=@25D D9@F=5 @?=J 9@=5 >65:2] ') .($dated ? 'A PHP file in a dated media folder is almost never legitimate.' : ''), true, $sc >= 8 || $certain ? 'critical' : 'high');
            else {
                $sub = explode('/', substr($irel, strlen(ssf_d('HA\\4@?E6?E^FA=@25D^'))))[0];
                $k = $ip .'|' .$sub;
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
        if ($size > 0 && strpos((string) @file_get_contents($p, false, null, 0, 4096), '<?php') !== false) $add(['cat' => 'implant', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => 'PHP code hidden inside an image file', 'detail' => ssf_d('|2=H2C6 DE@C6D 4@56 :? 7:=6D E92E =@@< =:<6 :>286D 2?5 =@25D :E 7C@> 2?@E96C D4C:AE]')]);
        return;
    }
    if (preg_match('/^wp-config.*\.(zip|bak|old|txt|save|orig|swp|gz|tar|tgz|rar|7z|backup|copy)$|^wp-config\.php[.~_-].+$/i', $name) && $name !== 'wp-config-sample.php') {
        $add(['cat' => 'exposure', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Copy of wp-config downloadable by anyone', 'detail' => ssf_d('%9:D 4@AJ 42? 36 76E4965 7C@> E96 H63 2?5 4@?E2:?D E96 52E232D6 A2DDH@C5] |@G6 :E[ E96? 492?86 E96 52E232D6 A2DDH@C5]')]);
        return;
    }
    if (($ext === 'html' || $ext === 'htm') && $size > 0) {
        if ($loc === 'root' && preg_match(ssf_d('^/W8@@8=6,_\\h2\\7.L`_[NMJ2?56I0,_\\h2\\7.ZX-]9E>=S^:'), $name)) { $add(['cat' => 'access', 'sev' => 'medium', 'fix' => 'quarantine', 'tick' => false, 'title' => 'Search-engine ownership file', 'detail' => ssf_d('%9:D 7:=6 AC@G6D E@ v@@8=6 @C *2?56I E92E D@>6@?6 @H?D E96 D:E6] pEE24<6CD 255 E96:C @H? D@ E96J 42? DF3>:E DA2> A286D] x7 :E H2D 4C62E65 2C@F?5 E96 E:>6 @7 E96 :?764E:@? 2?5 J@F 5:5 ?@E 255 :E[ >@G6 :E 2?5 C6>@G6 E96 F?<?@H? @H?6C :? $62C49 r@?D@=6]')]); return; }
        list($spam, $terms) = ssf_spam(ssf_read($p, $size));
        if ($spam) $add(['cat' => 'doorway', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => ssf_d('$E2?5\\2=@?6 DA2> A286'), 'detail' => ssf_d('p? w%|{ A286 H:E9 82>3=:?8 @C A92C>24J DA2> 4@?E6?E]'), 'evidence' => 'keywords: ' .implode(', ', $terms)]);
        return;
    }
    if (isset($ARCH[$ext]) && ($size >= 1048576 || ($ext === 'sql' && $size > 50000))) {
        if ($loc === 'root') $add(['cat' => 'exposure', 'sev' => 'medium', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Archive in the site root, downloadable by anyone (' .ssf_hsize($size) .')', 'detail' => ssf_d('x7 E9:D :D 2 324<FA :E 42? 4@?E2:? E96 52E232D6 2?5 A2DDH@C5D] |@G:?8 :E 5@6D ?@E 27764E E96 D:E6]')]);
        elseif ($loc === 'pluginsroot') $add(['cat' => 'exposure', 'sev' => 'low', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Loose plugin archive (' .ssf_hsize($size) .')', 'detail' => ssf_d('p K:A =67E :? E96 A=F8:?D 7@=56C[ @7E6? 7C@> 2 >2?F2= FA=@25 @7 2 AC6>:F> @C ?F==65 A=F8:?]')]);
        elseif (count($st['arch']) < 40) $st['arch'][] = $rel .' (' .ssf_hsize($size) .')';
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
        while ($st['pre']) { $ip = array_shift($st['pre']); $st['current'] = 'Checking ' .$st['installs'][$ip]['label']; ssf_pre_install($st, $ip); if (!$left()) break; }
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
                $p = $dir .'/' .$en;
                if (is_link($p)) continue;
                if (is_dir($p)) { if ($p !== $data && strpos($p .'/', $data .'/') !== 0 && !ssf_audit_dir($st, $p, $en, $ip)) $st['queue'][] = $p; }
                else { try { ssf_file($st, $p, $en, $ip); } catch (Throwable $e) { /* unreadable */ } }
            }
            if ($st['qi'] > 4000) { $st['queue'] = array_slice($st['queue'], $st['qi']); $st['done'] = ($st['done'] ?? 0) + $st['qi']; $st['qi'] = 0; }
        }
        if ($st['qi'] >= count($st['queue'])) $st['phase'] = 'final';
    }
    $done = ($st['done'] ?? 0) + $st['qi'];
    $total = ($st['done'] ?? 0) + count($st['queue']);
    if ($st['phase'] === 'final') { $scan = ssf_finalize($st); @unlink(ssf_data_dir() .'/state.json'); return ['done' => true, 'files' => $scan['meta']['files']]; }
    ssf_save('state.json', $st);
    return ['done' => false, 'phase' => $st['phase'], 'pct' => $st['phase'] === 'pre' ? 3 : min(98, 5 + (int) round(93 * $done / max(1, $total))), 'files' => $st['files'], 'found' => count($st['findings']), 'current' => ssf_clean($st['current'])];
}
function ssf_finalize($st) {
    foreach ($st['core_mod'] as $ip => $files) ssf_add($st, ['site' => $st['installs'][$ip]['rel'], 'cat' => 'integrity', 'sev' => 'critical', 'title' => count($files) .(count($files) >= 40 ? '+' : '') .ssf_d(' (@C5!C6DD DJDE6> 7:=6') .(count($files) === 1 ? ' has' : 's have') .' been changed', 'detail' => 'These do not match the official WordPress ' .$st['installs'][$ip]['ver'] .' files. Do not quarantine them (the site would stop). Reinstall WordPress from Dashboard > Updates > "Re-install", which replaces them with clean copies.', 'evidence' => ssf_one_line(implode(', ', $files), 900)]);
    foreach ($st['core_extra'] as $ip => $n) ssf_add($st, ['site' => $st['installs'][$ip]['rel'], 'cat' => 'integrity', 'sev' => 'info', 'title' => $n .' extra PHP file' .($n === 1 ? '' : 's') .ssf_d(' 2>@?8 (@C5!C6DD DJDE6> 7:=6D[ ?@E9:?8 DFDA:4:@FD :? E96>'), 'detail' => 'Usually leftovers from older WordPress versions. A clean reinstall of WordPress into an empty folder removes them.']);
    foreach ($st['plugins'] as $P) {
        if ($P['mod'] > 0) { $many = $P['mod'] >= 20 && $P['mod'] / max(1, $P['files']) > 0.3; ssf_add($st, ['site' => $P['site'], 'cat' => 'integrity', 'sev' => $many ? 'medium' : 'high', 'title' => 'Plugin "' .$P['name'] .'": ' .$P['mod'] .' file' .($P['mod'] === 1 ? ' differs' : 's differ') .' from the official release', 'detail' => ($many ? 'So many files differ that the installed copy is probably a different build of version ' .$P['ver'] .'. ' : 'Someone or something edited this plugin after it was installed. ') .'Delete the plugin and install it again from WordPress.org; your settings are kept in the database.', 'evidence' => ssf_one_line(implode(', ', $P['samples']), 600)]); }
        if ($P['xsamples']) ssf_add($st, ['site' => $P['site'], 'cat' => 'integrity', 'sev' => 'low', 'title' => 'Plugin "' .$P['name'] .'": ' .$P['extra'] .' PHP file' .($P['extra'] === 1 ? '' : 's') .' not in the official release', 'detail' => 'Nothing suspicious was detected in them. Reinstalling the plugin removes them.', 'evidence' => ssf_one_line(implode(', ', $P['xsamples']), 600)]);
    }
    foreach ($st['upl'] as $g) ssf_add($st, ['site' => $g['site'], 'cat' => ssf_d('FA=@25D'), 'sev' => 'medium', 'title' => $g['n'] .' PHP file' .($g['n'] === 1 ? '' : 's') .ssf_d(' :? FA=@25D^') .ssf_clean($g['sub']), 'detail' => ssf_d('%96 FA=@25D 7@=56C D9@F=5 @?=J 9@=5 >65:2] }@E9:?8 DFDA:4:@FD H2D 56E64E65 :? E96D6[ 2?5 D@>6 A=F8:?D 5@ DE@C6 !w! 96C6[ 3FE :E :D H96C6 2EE24<6CD 9:56 324<5@@CD] #6>@G6 E96> :7 J@F 5@ ?@E ?665 E96>[ 2?5 3=@4< !w! 7C@> CF??:?8 :? FA=@25D]'), 'evidence' => ssf_one_line(implode(', ', $g['samples']), 600)]);
    if ($st['arch']) ssf_add($st, ['cat' => 'exposure', 'sev' => 'low', 'title' => count($st['arch']) .(count($st['arch']) >= 40 ? '+' : '') .ssf_d(' 2C49:G6D @C 52E232D6 5F>AD :?D:56 E96 H63 7@=56CD'), 'detail' => 'Anything here can be downloaded by someone who guesses the address, unless the folder is protected. Move backups out of public_html.', 'evidence' => ssf_one_line(implode(', ', array_slice($st['arch'], 0, 12)), 900)]);
    ssf_audit_final($st);
    $live = count($st['installs']);
    if ($live >= 2) ssf_add($st, ['cat' => 'access', 'sev' => 'medium', 'title' => $live .' WordPress sites share this hosting account', 'detail' => 'They run as the same user, so a break-in on any one of them can reach all the others. Clean them together, and remove the ones that are no longer used.']);
    $st['notes'][] = 'Scheduled tasks (cron) are not read by this tool. Attackers use them to re-create files after a clean-up: check cPanel > Cron Jobs for anything you do not recognise.';
    if (!$st['net']) $st['notes'][] = 'This server could not reach WordPress.org for every check, so some files were checked by pattern only, not against official copies.';
    if ($st['truncated']) $st['notes'][] = 'More than ' .SSF_MAX_FINDINGS .' findings; the list was cut off.';

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

/* ------------------------------------------------------------------ security audit: rules
   Everything in this block is the "audit" side of the tool: mistakes in a site's own code and
   set-up, as opposed to things an attacker planted. To add a check, add a row to one of the
   tables below; no other code needs to change. */
function ssf_secret_rules() {
    // [label, regex, severity, advice]
    return [
        [ssf_d('!C:G2E6 <6J'), ssf_d('^\\\\\\\\\\qtvx} Wni#$p Mtr Ms$p M~!t}$$w M!v! Xn!#x\'p%t zt*Wni q{~rzXn\\\\\\\\\\^'), 'critical', 'Generate a new key pair and remove this one from every server that trusts it.'],
        [ssf_d('$EC:A6 ^ !2JDE24< =:G6 D64C6E <6J'), '/\b[sr]k_live_[0-9a-zA-Z]{20,}\b/', 'critical', ssf_d('#@== E96 <6J :? E96 A2J>6?E 52D93@2C5 ?@H] $64C6E <6JD >FDE @?=J 36 FD65 7C@> D6CG6C\\D:56 4@56]')],
        [ssf_d('u=FEE6CH2G6 D64C6E <6J'), '/\bFLWSECK-[A-Za-z0-9]{20,}-X\b/', 'critical', 'Regenerate the key in the Flutterwave dashboard and keep it in server-side code only.'],
        ['Anthropic API key', ssf_d('^-3D<\\2?E\\,p\\+2\\K_\\h0\\.Lba[N^'), 'critical', 'Revoke the key in the Anthropic console. Call the API from your server, never from the browser.'],
        ['OpenAI API key', ssf_d('^-3D<\\WniAC@;\\MDG4244E\\Xn,p\\+2\\K_\\h0\\.Lba[N^'), 'critical', 'Revoke the key in the OpenAI dashboard. Call the API from your server, never from the browser.'],
        ['AWS access key', ssf_d('^-3WnipzxpMp$xpX,_\\hp\\+.L`eN-3^'), 'critical', 'Deactivate the key in AWS IAM and check the account for activity you do not recognise.'],
        [ssf_d('v:EwF3 E@<6?'), '/\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/', 'critical', ssf_d('#6G@<6 E96 E@<6? :? v:EwF3 D6EE:?8D]')],
        [ssf_d('$=24< E@<6?'), ssf_d('^-3I@I,32ACD.\\,p\\+2\\K_\\h\\.La_[N^'), 'high', ssf_d('#6G@<6 E96 E@<6? :? E96 $=24< 2AA D6EE:?8D]')],
        ['SendGrid API key', '/\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/', 'high', 'Delete the key in SendGrid and create a new one for server-side use.'],
        ['Mailgun API key', '/\bkey-[0-9a-f]{32}\b/', 'high', 'Rotate the key in Mailgun.'],
        [ssf_d('%6=68C2> 3@E E@<6?'), '/\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/', 'high', ssf_d('#6G@<6 E96 E@<6? H:E9 oq@Eu2E96C]')],
        [ssf_d('s2E232D6 4@??64E:@? DEC:?8 H:E9 A2DDH@C5'), '/\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis):\/\/[^:\s"\'<>\/]{1,64}:[^@\s"\'<>]{3,}@[A-Za-z0-9.\-]+/', 'critical', ssf_d('r92?86 E92E 52E232D6 A2DDH@C5 2?5 <66A 4@??64E:@? 56E2:=D :? D6CG6C\\D:56 4@56]')],
        ['Google API key', '/\bAIza[0-9A-Za-z_-]{35}\b/', 'low', 'Keys for Maps and Firebase are meant to be public, but only if restricted. In Google Cloud console, limit this key to your website address and to the APIs it needs.'],
    ];
}
function ssf_code_rules() {
    $in = ssf_d('-S0Wnivt%M!~$%M#t"&t$%Mr~~zxtX-3');
    // [id, severity, title, regex, safe-if-matched-text-contains, explanation, prompt]
    return [
        ['lfi', 'critical', 'A visitor can choose which file the page loads', ssf_d('^-3Wni:?4=F56MC6BF:C6XWni0@?46Xn-3,/j.L_[a__Nn') .$in .'/', '/basename\s*\(|in_array\s*\(/', ssf_d('\':D:E@C :?AFE 8@6D :?E@ :?4=F56^C6BF:C6] p? 2EE24<6C 42? >2<6 E96 D:E6 CF? 2 7:=6 @7 E96:C 49@@D:?8]'), ssf_d('?6G6C A2DD G:D:E@C :?AFE E@ :?4=F56 @C C6BF:C6] |2A E96 :?AFE E@ 2 7:I65 =:DE @7 2==@H65 A286 ?2>6D W2 H9:E6=:DE 2CC2JX 2?5 =@25 @?=J 7C@> E92E =:DE]')],
        [ssf_d('4>5'), 'critical', ssf_d('\':D:E@C :?AFE :D A2DD65 E@ 2 DJDE6> 4@>>2?5'), ssf_d('^-3WniDJDE6>M6I64MD96==06I64MA2DDE9CFMA@A6?MAC@40@A6?X-DY-W,/j.L_[a__Nn') .$in .'/', ssf_d('^6D42A6D96==2C8-DY-W^'), ssf_d('\':D:E@C :?AFE C62496D 2 D96== 4@>>2?5[ H9:49 =6ED 2? 2EE24<6C CF? 4@>>2?5D @? E96 D6CG6C]'), ssf_d('C6>@G6 E96 D96== 4@>>2?5 :7 2 !w! 7F?4E:@? 42? 5@ E96 ;@3j @E96CH:D6 G2=:52E6 E96 :?AFE 282:?DE 2 DEC:4E H9:E6=:DE 2?5 HC2A 6G6CJ 2C8F>6?E :? 6D42A6D96==2C8WX]')],
        ['sqli', 'high', ssf_d('$"{ :?;64E:@?i G:D:E@C :?AFE A=2465 DEC2:89E :?E@ 2 52E232D6 BF6CJ'), ssf_d('^Wni>JDB=:0BF6CJM>JDB=0BF6CJMA80BF6CJM\\mBF6CJM\\m6I64M\\m>F=E:0BF6CJM\\mAC6A2C6X-DY-W,/j.L_[c__Nn') .$in .'/', '/real_escape_string|intval\s*\(|\(int\)/', 'The query text contains raw visitor input, so a visitor can read or change anything in the database.', 'rewrite these queries as prepared statements with bound parameters (PDO or mysqli). Do not build SQL by joining strings.'],
        ['sqlcat', 'medium', 'Database query built by joining text and variables', '/["\']\s*(?:SELECT\b[^"\';]{0,300}\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[`\w]+\s+SET\b|DELETE\s+FROM\b)[^;]{0,400}?(?:["\']\s*\.\s*\$\w|\{\$\w|=\s*\'?\$\w|\'%?\$\w)/i', ssf_d('^C62=06D42A60DEC:?8M:?EG2=-DY-WM-W:?E-XM\\mBF@E6-DY-WM6D40DB=M-SHA53\\mAC6A2C6M-S0Wnivt%M!~$%M#t"&t$%Mr~~zxtX^'), ssf_d('p G2C:23=6 :D :?D6CE65 :?E@ E96 $"{ E6IE] x7 E92E G2=F6 42? 6G6C 4@>6 7C@> 2 G:D:E@C[ E9:D :D $"{ :?;64E:@?] xE ?665D 4964<:?8 6G6? :7 :E :D D276 E@52J]'), 'rewrite these queries as prepared statements with bound parameters (PDO or mysqli) so no variable is ever placed inside the SQL text.'],
        ['path', 'high', 'A visitor can choose which file is read, written or deleted', ssf_d('^-3Wni7:=6086E04@?E6?EDMC6257:=6M7@A6?M7:=6MF?=:?<M7:=60AFE04@?E6?EDM4@AJMC6?2>6MC>5:CMD42?5:CM@A6?5:CX-DY-W,/j.L_[a__Nn') .$in .'/', '/basename\s*\(|realpath\s*\(|in_array\s*\(/', ssf_d('\':D:E@C :?AFE :D FD65 2D 2 7:=6 A2E9] (:E9 Q]]^Q 2? 2EE24<6C 42? C6249 7:=6D @FED:56 E96 :?E6?565 7@=56C[ :?4=F5:?8 4@?7:8FC2E:@? 7:=6D]'), 'take only basename() of the input, join it to a fixed folder, and check with realpath() that the result is still inside that folder before using it.'],
        ['unser', 'high', ssf_d('\':D:E@C :?AFE :D A2DD65 E@ F?D6C:2=:K6WX'), ssf_d('^-3F?D6C:2=:K6-DY-W,/j.L_[`a_Nn') .$in .'/', '/allowed_classes/', ssf_d('&?D6C:2=:K:?8 G:D:E@C 52E2 42? 4C62E6 2C3:EC2CJ @3;64ED 2?5 =625 E@ 4@56 6I64FE:@?]'), ssf_d('FD6 ;D@?0564@56WX :?DE625 @7 F?D6C:2=:K6WX 7@C 2?JE9:?8 E92E 4@>6D 7C@> 2 G:D:E@C]')],
        ['hardpw', 'high', ssf_d('!2DDH@C5 HC:EE6? :?E@ E96 4@56'), ssf_d('^-S0Wni!~$%M#t"&t$%X-,-DY,VQ.WniA2DDMA2DDH@C5MAH5MA2DDH5MA:?MA2DD4@56X,VQ.-DY-.-DYWnilllnMPllnX-DY,VQ.,/VQ.Lb[N,VQ.M,VQ.,/VQ.Lb[N,VQ.-DYWnilllnMPllnX-DY-S0Wni!~$%M#t"&t$%X-,-DY,VQ.WniA2DDMA2DDH@C5MAH5MA2DDH5X,VQ.-DY-.^:'), null, ssf_d('%96 =@8:? 4@>A2C6D 282:?DE 2 A2DDH@C5 EJA65 :?E@ E96 D@FC46 7:=6] p?J@?6 H9@ D66D E96 4@56[ 2 324<FA @7 :E @C E96 C6A@D:E@CJ 92D E96 A2DDH@C5]'), ssf_d('DE@C6 2 A2DDH@C5092D9WX G2=F6 @FED:56 E96 H63 7@=56C W@C :? E96 52E232D6X 2?5 4964< =@8:?D H:E9 A2DDH@C50G6C:7JWX] %96? 492?86 E96 A2DDH@C5[ D:?46 E96 @=5 @?6 92D 366? 6IA@D65]')],
        ['xss', 'high', 'Visitor input shown on the page without escaping (XSS)', '/(?:\becho\b|\bprint\b|<\?=)[^;]{0,200}?' .$in .'[^;?]{0,120}/', '/htmlspecialchars|htmlentities|strip_tags|intval\s*\(|\(int\)|json_encode|urlencode|esc_html|esc_attr|filter_var|filter_input/', 'Whatever a visitor puts in the address or a form is written into the page, so an attacker can run script in other visitors\' browsers.', 'wrap every value that is output in htmlspecialchars($value, ENT_QUOTES, \'UTF-8\').'],
        ['xss2', 'medium', 'Page address shown on the page without escaping (XSS)', ssf_d('^Wni-3649@-3Mk-nlX,/j.L_[g_Nn-S0$t#\'t#-,-DY,VQ.Wni!w!0$t{uM#t"&t$%0&#xM"&t#*0$%#x}vMw%%!0#tut#t#Mw%%!0&$t#0pvt}%X,VQ.-DY-.,/jn.L_[g_N^'), '/htmlspecialchars|htmlentities|urlencode|esc_url|esc_attr|filter_var/', 'These server values are controlled by the visitor and are written into the page as-is.', 'wrap these values in htmlspecialchars($value, ENT_QUOTES, \'UTF-8\'), or use a fixed form action instead of PHP_SELF.'],
        ['redirect', 'medium', 'A visitor can choose where the page redirects', '/header\s*\(\s*[\'"]Location:\s*[\'"]?\s*\.\s*' .$in .ssf_d('M96256C-DY-W-DY,VQ.{@42E:@?i-DY-Ln-S0Wnivt%M!~$%M#t"&t$%X^:'), null, ssf_d('{:?<D E@ J@FC D:E6 42? 36 >256 E@ 3@F?46 E@ 2 A9:D9:?8 A286]'), 'only redirect to paths on this site: check the value against a list of allowed destinations, or reject anything that does not start with a single "/".'],
        ['extract', 'medium', 'extract() on visitor input', '/\bextract\s*\(\s*' .$in .'/', null, 'extract() lets a visitor overwrite any variable in the script, including ones used for logins and permissions.', 'remove extract() and read each expected field by name.'],
        ['weakhash', 'medium', ssf_d('!2DDH@C5D 92D965 H:E9 |sd @C $wp\\`'), ssf_d('^-3Wni>5dMD92`X-DY-W-DY-SWni0Wni!~$%M#t"&t$%X-,-DY,VQ.WniA2DDMA2DDH@C5MAH5MA2DDH5X,VQ.-DY-.MA2DDWniH@C5MH5Xn-3MAH5-3X^:'), null, ssf_d('|sd 2?5 $wp\\` A2DDH@C5 92D96D 2C6 4C24<65 :? D64@?5D :7 E96 52E232D6 =62<D]'), ssf_d('DE@C6 A2DDH@C5D H:E9 A2DDH@C5092D9WX 2?5 4964< E96> H:E9 A2DDH@C50G6C:7JWX] #6\\92D9 6249 FD6CVD A2DDH@C5 E96 ?6IE E:>6 E96J =@8 :?]')],
        ['showerr', 'low', 'Error messages are switched on for visitors', ssf_d('^:?:0D6E-DY-W-DY,VQ.5:DA=2J06CC@CD,VQ.-DY[-DYWni`MECF6M,VQ.Wni`M@?MECF6X,VQ.X-DY-X^:'), null, ssf_d('tCC@C >6DD286D C6G62= 7:=6 A2E9D[ BF6C:6D 2?5 D@>6E:>6D A2DDH@C5D]'), 'turn display_errors off on the live site and log errors to a file outside the web folder.'],
    ];
}
function ssf_js_rules() {
    return [
        ['jspw', 'high', ssf_d('!2DDH@C5 4964<65 :? E96 3C@HD6C'), ssf_d('^-3WniA2DDH@C5MA2DDH5MAH5MA2DD4@56X-HY-DYWnilllnMPllnX-DY,VQ1.,/VQ1-D.Lb[N,VQ1.M,VQ1.,/VQ1-D.Lb[N,VQ1.-DYllln-DY-HYWniA2DDH@C5MA2DDH5MAH5X-HY-3WnP-DY,]W.X^:'), null, ssf_d('%96 A2DDH@C5 :D :? 2 7:=6 6G6CJ G:D:E@C 5@H?=@25D[ 2?5 E96 4964< 42? 36 D<:AA65 7C@> E96 3C@HD6C 4@?D@=6] %9:D AC@E64ED ?@E9:?8]'), ssf_d('>@G6 E96 =@8:? 4964< E@ D6CG6C\\D:56 4@56i E96 3C@HD6C D6?5D E96 A2DDH@C5[ E96 D6CG6C G6C:7:6D :E H:E9 A2DDH@C50G6C:7JWX 2?5 DE2CED 2 D6DD:@?[ 2?5 6G6CJ AC@E64E65 A286 4964<D E92E D6DD:@? @? E96 D6CG6C]')],
        [ssf_d(';D6G2='), 'high', 'Part of the page address is run as code', ssf_d('^-36G2=-DY-W,/j-?.L_[a__NWni=@42E:@?-]M5@4F>6?E-]&#{M-]92D9-3M-]D62C49-3MD62C49!2C2>DX^'), null, 'A crafted link can run any script in a visitor\'s browser.', ssf_d('C6>@G6 6G2=WX] !2CD6 E96 G2=F6 2D 52E2 Wy$~}]A2CD6[ &#{$62C49!2C2>DX :?DE625]')],
        ['domxss', 'medium', 'Part of the page address is written into the page as HTML', ssf_d('^-]:??6Cw%|{-DY-Znl,/j-?.L_[a__NWni=@42E:@?-]Wni92D9MD62C49M9C67XM5@4F>6?E-]&#{M5@4F>6?E-]C676CC6CM&#{$62C49!2C2>DMD62C49!2C2>D-]86EXM5@4F>6?E-]HC:E6-DY-W,/j-?.L_[a__NWni=@42E:@?-]M5@4F>6?E-]&#{M5@4F>6?E-]C676CC6CX^'), '/DOMPurify|encodeURIComponent|escapeHtml/', ssf_d('p 4C27E65 =:?< 42? :?;64E D4C:AE :?E@ E96 A286 Ws~| )$$X]'), ssf_d('FD6 E6IEr@?E6?E :?DE625 @7 :??6Cw%|{ 7@C G2=F6D E2<6? 7C@> E96 255C6DD[ @C D2?:E:D6 E96> 7:CDE]')],
    ];
}
function ssf_mask($s) { $s = (string) $s; $n = strlen($s); return $n <= 12 ? substr($s, 0, 3) .'...' : substr($s, 0, 7) .'...' .substr($s, -3) ." ($n chars)"; }
function ssf_line_of($c, $off) { return substr_count($c, "\n", 0, $off) + 1; }
function ssf_line_text($c, $off) { $s = strrpos(substr($c, 0, $off), "\n"); $s = $s === false ? 0 : $s + 1; $e = strpos($c, "\n", $off); return ssf_one_line(substr($c, $s, ($e === false ? strlen($c) : $e) - $s), 180); }
function ssf_prompt($rel, $lines, $what, $how) {
    return 'Security problem in the file ' .$rel .($lines ? ' (around line' .(count($lines) === 1 ? ' ' : 's ') .implode(', ', $lines) .')' : '') .': ' .rtrim($what, '.') .'. Please fix it: ' .$how .' Keep the page working exactly as before, change nothing else, and show me the lines you changed.';
}
/** URL for a file if it sits under the document root of the site this tool was opened on. */
function ssf_url_for($abs) {
    if (PHP_SAPI === 'cli' || empty(ssf_srv('HTTP_HOST')) || empty(ssf_srv('DOCUMENT_ROOT'))) return null;
    $doc = rtrim((string) realpath(ssf_srv('DOCUMENT_ROOT')), '/');
    if ($doc === '' || strpos($abs, $doc .'/') !== 0) return null;
    $https = !empty(ssf_srv('HTTPS')) && ssf_srv('HTTPS') !== 'off';
    return ($https ? 'https://' : 'http://') .ssf_srv('HTTP_HOST') .implode('/', array_map('rawurlencode', explode('/', substr($abs, strlen($doc)))));
}
function ssf_probe(&$st, $abs) {
    if (($st['probes'] ?? 0) >= 14) return '';
    $u = ssf_url_for($abs);
    if (!$u) return '';
    $st['probes'] = ($st['probes'] ?? 0) + 1;
    list($code) = ssf_http_head($u);
    if ($code === 200) return ' Confirmed: it can be downloaded from the web right now.';
    if ($code === 403 || $code === 404) return ' The server currently refuses to serve it, but that depends on settings that can change.';
    return '';
}

/* ------------------------------------------------------------------ security audit: environment (once per scan) */
function ssf_audit_env(&$st) {
    $eol = ['8.2' => '2026-12-31', '8.3' => '2027-12-31', '8.4' => '2028-12-31', '8.5' => '2029-12-31'];
    $mm = PHP_MAJOR_VERSION .'.' .PHP_MINOR_VERSION;
    $where = ' This is the PHP that runs the folder this tool sits in; other sites on the account can be set differently.';
    if (version_compare($mm, '8.2', '<')) ssf_add($st, ['cat' => 'config', 'sev' => 'high', 'title' => 'PHP ' .PHP_VERSION .' no longer gets security fixes', 'detail' => 'This PHP version is past its end of life, so newly found holes in PHP itself are never patched. In cPanel open "Select PHP Version" or "MultiPHP Manager" and choose 8.3 or newer, then test the site.' .$where]);
    elseif (isset($eol[$mm]) && time() > strtotime($eol[$mm] .' -120 days')) ssf_add($st, ['cat' => 'config', 'sev' => time() > strtotime($eol[$mm]) ? 'high' : 'low', 'title' => 'PHP ' .$mm .(time() > strtotime($eol[$mm]) ? ' no longer gets security fixes' : ' stops getting security fixes on ' .date('j F Y', strtotime($eol[$mm]))), 'detail' => 'Plan the move to a newer PHP version in cPanel ("Select PHP Version" or "MultiPHP Manager"), then test the site.' .$where]);
    if (in_array(strtolower((string) ini_get('display_errors')), ['1', 'on', 'stdout', 'true'], true)) ssf_add($st, ['cat' => 'config', 'sev' => 'medium', 'title' => 'PHP error messages are shown to visitors', 'detail' => ssf_d('tCC@CD C6G62= 7:=6 A2E9D[ 52E232D6 BF6C:6D 2?5 D@>6E:>6D A2DDH@C5D] x? 4!2?6= @A6? Q|F=E:!w! x}x t5:E@CQ 2?5 EFC? 5:DA=2J06CC@CD @77j <66A =@806CC@CD @?]') .$where]);
    if (in_array(strtolower((string) ini_get(ssf_d('2==@H0FC=0:?4=F56'))), ['1', 'on', 'true'], true)) ssf_add($st, ['cat' => 'config', 'sev' => 'high', 'title' => ssf_d('!w! >2J =@25 4@56 7C@> @E96C H63D:E6D W2==@H0FC=0:?4=F56X'), 'detail' => ssf_d('%9:D D6EE:?8 EFC?D >2?J D>2== 3F8D :?E@ 7F== E2<6@G6CD] %FC? 2==@H0FC=0:?4=F56 @77 :? 4!2?6= Q|F=E:!w! x}x t5:E@CQ]') .$where]);
    if (PHP_SAPI === 'cli' || empty(ssf_srv('HTTP_HOST'))) { $st['notes'][] = 'Run from the command line, so nothing was tested over the web: HTTPS, security headers and directory listing were not checked.'; return; }
    $host = ssf_srv('HTTP_HOST');
    list($code, $h) = ssf_http_head('http://' .$host .'/');
    if ($code === 0) { $st['notes'][] = 'The server could not open its own website, so HTTPS, security headers and directory listing were not checked.'; return; }
    $loc = $h['location'] ?? '';
    if ($code >= 200 && $code < 300) ssf_add($st, ['cat' => 'config', 'sev' => 'medium', 'title' => 'The site opens without HTTPS', 'detail' => 'http://' .$host .'/ answers directly instead of sending visitors to https://. Logins and forms sent this way can be read on the network. Turn on "Force HTTPS Redirect" for the domain in cPanel > Domains (an SSL certificate must be installed first).']);
    list($code2, $h2) = ssf_http_head('https://' .$host .'/');
    if ($code2 >= 200 && $code2 < 400) {
        $miss = [];
        if (empty($h2['x-content-type-options'])) $miss[] = 'X-Content-Type-Options';
        if (empty($h2['x-frame-options']) && stripos($h2['content-security-policy'] ?? '', 'frame-ancestors') === false) $miss[] = 'X-Frame-Options';
        if (empty($h2['referrer-policy'])) $miss[] = 'Referrer-Policy';
        $st['hdr_missing'] = $miss;
        $st['hsts'] = !empty($h2['strict-transport-security']);
    }
    // directory listing: find a folder under the document root with files and no index page
    $doc = rtrim((string) realpath(ssf_srv('DOCUMENT_ROOT') ?? ''), '/');
    if ($doc !== '') {
        $tries = 0;
        foreach (array_merge(@glob($doc .'/*', GLOB_ONLYDIR) ?: [], @glob($doc .'/*/*', GLOB_ONLYDIR) ?: []) as $dname) {
            if ($tries >= 3) break;
            if (is_link($dname) || (@glob($dname .'/index.*') ?: []) || !(@glob($dname .'/*.*') ?: []) || preg_match(ssf_d('R^W48:\\3:?M-]H6==\\<?@H?MHA\\25>:?MHA\\:?4=F56DXW^MSXR'), $dname)) continue;
            $tries++;
            list($c3, , $body) = ssf_http_head(ssf_url_for($dname .'/x') ? substr(ssf_url_for($dname .'/x'), 0, -1) : '');
            if ($c3 === 200 && stripos($body, 'Index of /') !== false) { $st['listing'] = substr($dname, strlen($doc)) .'/'; break; }
        }
    }
}

/* ------------------------------------------------------------------ security audit: folders and files */
/** Called for every folder the walk meets. Returns true if the walk should not go inside. */
function ssf_audit_dir(&$st, $p, $name, $ip) {
    $site = $ip !== null ? $st['installs'][$ip]['rel'] : '';
    $rel = ssf_rel($st, $p);
    if ((@fileperms($p) & 0002) && $name !== '.tmb') { if (count($st['perms']) < 300) $st['perms'][] = $rel; $st['perms_n'] = ($st['perms_n'] ?? 0) + 1; }
    if ($name === ssf_d(']8:E') && (is_file("$p/HEAD") || is_dir("$p/objects"))) {
        ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'exposure', 'sev' => 'high', 'title' => 'Git repository inside the web folder', 'detail' => ssf_d('x7 ^]8:E^ 42? 36 C624965 7C@> E96 H63[ 2?J@?6 42? 5@H?=@25 E96 7F== D@FC46 4@56 2?5 :ED 9:DE@CJ[ :?4=F5:?8 A2DDH@C5D E92E H6C6 6G6C 4@>>:EE65]') .ssf_probe($st, "$p/HEAD") .ssf_d(' %96 QAC@E64E 7:=6DQ CF=6 3=@4<D :Ej 36EE6C DE:==[ 56A=@J H:E9@FE E96 ]8:E 7@=56C]')]);
        $st['harden_need'] = true;
        return true;
    }
    if ($name === '.svn' || $name === '.hg') { ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'exposure', 'sev' => 'medium', 'title' => 'Version-control folder inside the web folder', 'detail' => 'It can expose the source code. The "protect files" rule blocks it.']); $st['harden_need'] = true; return true; }
    if ($name === 'node_modules') { ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'exposure', 'sev' => 'low', 'title' => ssf_d('?@560>@5F=6D FA=@2565 E@ E96 H63 7@=56C'), 'detail' => ssf_d('qF:=5 E@@=D 2?5 E96:C E9@FD2?5D @7 7:=6D 5@ ?@E 36=@?8 @? E96 =:G6 D:E6] &A=@25 @?=J E96 3F:=E @FEAFE WFDF2==J E96 5:DE @C 3F:=5 7@=56CX]')]); return true; }
    if ($name === ssf_d('5FA\\:?DE2==6C')) { ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'exposure', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => ssf_d('sFA=:42E@C :?DE2==6C =67E 369:?5'), 'detail' => ssf_d('{67E@G6C :?DE2==6C 7:=6D =6E 2 DEC2?86C C6:?DE2== E96 D:E6 @G6C :ED6=7 2?5 E2<6 :E @G6C]')]); return true; }
    if (preg_match(ssf_d('^/WA9A>J25>:?MA>2M>J25>:?M25>:?6CXS^:'), $name) && (is_file("$p/index.php"))) ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'access', 'sev' => 'medium', 'title' => 'Database admin tool inside the web folder', 'detail' => ssf_d('p 4@AJ @7 A9A|Jp5>:? @C p5>:?6C 96C6 :D 2 =@8:? A286 E@ E96 52E232D6 7@C E96 H9@=6 :?E6C?6E] &D6 E96 @?6 :? 4!2?6= :?DE625 2?5 C6>@G6 E9:D 7@=56C]')]);
    return false;
}
/** Called for every file. Returns true when the file has been fully dealt with. */
function ssf_audit_file(&$st, $p, $name, $ext, $size, $rel, $site, $loc, $isPhp) {
    static $TEXT = ['js' => 1, 'mjs' => 1, 'cjs' => 1, 'html' => 1, 'htm' => 1, 'json' => 1, 'txt' => 1, 'xml' => 1, 'yml' => 1, 'yaml' => 1, 'ini' => 1, 'conf' => 1, 'cfg' => 1, 'config' => 1, 'ts' => 1, 'tsx' => 1, 'jsx' => 1, 'vue' => 1, 'svelte' => 1, 'map' => 1, 'env' => 1, 'toml' => 1, 'properties' => 1, 'py' => 1];
    $add = function ($f) use (&$st, $site, $rel) { ssf_add($st, $f + ['site' => $site, 'path' => $rel, 'kind' => 'file']); };
    $lname = strtolower($name);

    /* --- exposed by name: applies everywhere --- */
    if (preg_match(ssf_d('^/-]6?GW-]WnP6I2>A=6SMD2>A=6SM5:DESME6>A=2E6SX,-H]\\.ZXnS^:'), $name)) {
        $pr = ssf_probe($st, $p);
        $add(['cat' => ssf_d('D64C6ED'), 'sev' => strpos($pr, 'Confirmed') !== false ? 'critical' : 'high', 'title' => ssf_d('t?G:C@?>6?E 7:=6 W]6?GX :?D:56 E96 H63 7@=56C'), 'detail' => ssf_d('%9:D 7:=6 FDF2==J 9@=5D 52E232D6 A2DDH@C5D 2?5 p!x <6JD]') .$pr .ssf_d(' s@ ?@E >@G6 :E WE96 2AA C625D :EX] pAA=J E96 QAC@E64E 7:=6DQ CF=6[ 2?5 :7 :E H2D 6G6C 5@H?=@2523=6[ 492?86 6G6CJ A2DDH@C5 2?5 <6J :? :E] q6DE @7 2==[ <66A :E @?6 =6G6= 23@G6 AF3=:409E>=]')]);
        $st['harden_need'] = true; return true;
    }
    if ($isPhp && $size < 400 && preg_match(ssf_d('^/-DYk-nWniA9AXn-DYWni649@-DZXnA9A:?7@-DY-W-DY-X-DYjn-DYWni-nmXn-DYS^:'), (string) @file_get_contents($p))) { $add(['cat' => 'exposure', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => true, 'title' => ssf_d('A9A:?7@WX E6DE A286 =67E @? E96 D:E6'), 'detail' => 'It shows visitors the full server configuration, paths and loaded modules, which is a map for an attacker.']); return true; }
    if ($isPhp && preg_match(ssf_d('^/25>:?6CW,\\]-H.YX-]A9AS^:'), $name)) { $add(['cat' => 'access', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => true, 'title' => ssf_d('p5>:?6C 52E232D6 E@@= =67E @? E96 D:E6'), 'detail' => 'A single-file database manager: anyone who finds it gets a login page to your database, and old versions have known holes. Use phpMyAdmin in cPanel instead.']); return true; }
    if ($isPhp && preg_match(ssf_d('^/:?DE2==6CW\\324<FAXn-]A9AS^:'), $name) && stripos((string) @file_get_contents($p, false, null, 0, 20000), ssf_d('5FA=:42E@C')) !== false) { $add(['cat' => 'exposure', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => ssf_d('sFA=:42E@C :?DE2==6C =67E 369:?5'), 'detail' => ssf_d('{67E@G6C :?DE2==6C 7:=6D =6E 2 DEC2?86C C6:?DE2== E96 D:E6 @G6C :ED6=7 2?5 E2<6 :E @G6C]')]); return true; }
    if (preg_match(ssf_d('RW/M^XG6?5@C^A9AF?:E^A9AF?:E^DC4^&E:=^!w!^6G2=\\DE5:?-]A9ASR'), $rel)) { $add(['cat' => 'exposure', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => ssf_d('!w!&?:E E6DE 96=A6C C624923=6 7C@> E96 H63'), 'detail' => ssf_d('%9:D 56G6=@A>6?E 7:=6 CF?D 2?J 4@56 D6?E E@ :E Wr\'t\\a_`f\\hgc`X 2?5 :D D42??65 7@C 4@?DE2?E=J] %96 H9@=6 G6?5@C^A9AF?:E 7@=56C D9@F=5 ?@E 36 @? 2 =:G6 D:E6j :?DE2== H:E9 Q4@>A@D6C :?DE2== \\\\?@\\56GQ]')]); return true; }
    if (preg_match('/\.(?:php\d?|phtml|inc)(?:\.(?:bak|old|orig|save|swp|swo|txt|copy|backup|tmp|\d+)|~|_bak|_old|-bak|-old)$/i', $name) && !preg_match('/^wp-config/i', $name)) {
        $add(['cat' => 'exposure', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Backup copy of a PHP file, readable as plain text', 'detail' => ssf_d('%96 D6CG6C 5@6D ?@E CF? E9:D 2D !w![ :E D6?5D E96 D@FC46 4@56 E@ 2?J@?6 H9@ 2D<D[ :?4=F5:?8 2?J A2DDH@C5D :? :E]') .ssf_probe($st, $p)]);
        $st['harden_need'] = true; return true;
    }
    if ($ext === 'sql' && $size > 2000) { $add(['cat' => 'exposure', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => true, 'title' => ssf_d('s2E232D6 5F>A :? E96 H63 7@=56C W') .ssf_hsize($size) .')', 'detail' => ssf_d('p 4@AJ @7 E96 52E232D6 E92E 2?J@?6 H9@ 8F6DD6D E96 ?2>6 42? 5@H?=@25i FD6CD[ A2DDH@C5 92D96D[ 4FDE@>6C 56E2:=D]') .ssf_probe($st, $p)]); $st['harden_need'] = true; return true; }
    if (in_array($ext, [ssf_d('DB=:E6'), ssf_d('DB=:E6b'), 'db'], true) && $size > 100 && strpos((string) @file_get_contents($p, false, null, 0, 16), ssf_d('$"{:E6 7@C>2E')) === 0) { $add(['cat' => 'exposure', 'sev' => 'high', 'title' => ssf_d('$"{:E6 52E232D6 7:=6 :?D:56 E96 H63 7@=56C'), 'detail' => 'The whole database can be downloaded as one file.' .ssf_probe($st, $p) .' Do not move it if the app uses it; apply the "protect files" rule, and move the database above public_html when you can.']); $st['harden_need'] = true; return true; }
    if (preg_match(ssf_d('^/W:50CD2M:5065add`hM:505D2XSM-]WA6>M<6JMA`aMA7IMAA<XS^:'), $name) && $size > 0 && $size < 20000) {
        $c = (string) @file_get_contents($p);
        if ($ext === 'p12' || $ext === 'pfx' || $ext === 'ppk' || strpos($c, ssf_d('!#x\'p%t zt*')) !== false) { $add(['cat' => ssf_d('D64C6ED'), 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => false, 'title' => ssf_d('!C:G2E6 <6J 7:=6 :?D:56 E96 H63 7@=56C'), 'detail' => ssf_d('p AC:G2E6 <6J E92E 42? 36 76E4965 7C@> E96 H63 >FDE 36 EC62E65 2D DE@=6?i C6A=246 E96 <6J A2:C] {67E F?E:4<65 :? 42D6 E96 D:E6 C625D E9:D 7:=6]')]); $st['harden_need'] = true; return true; }
    }
    if (preg_match(ssf_d('^/W4C656?E:2=DMD64C6EDnMD6CG:46,\\0.n244@F?EX,-H]\\.Y-]W;D@?MJ2n>=MEIEXS^:'), $name) || $lname === ssf_d(']9EA2DDH5') || $lname === ssf_d(']32D909:DE@CJ') || $lname === '.npmrc' || $lname === '.netrc') { $add(['cat' => ssf_d('D64C6ED'), 'sev' => 'high', 'title' => ssf_d('rC656?E:2=D 7:=6 :?D:56 E96 H63 7@=56C'), 'detail' => 'By its name this file holds logins or keys.' .ssf_probe($st, $p) .' Move it above public_html, and apply the "protect files" rule in the meantime.']); $st['harden_need'] = true; return true; }
    if ($lname === 'debug.log' && $loc === 'content') { $add(['cat' => 'exposure', 'sev' => 'medium', 'fix' => 'quarantine', 'tick' => true, 'title' => 'WordPress debug log readable from the web', 'detail' => 'It reveals paths, plugin errors and sometimes personal data. Also set WP_DEBUG_LOG to false in wp-config.php, or WordPress will create it again.']); $st['harden_need'] = true; return true; }
    if ($lname === 'error_log' || ($ext === 'log' && $size > 0)) { $st['logs'][] = $rel; if (count($st['logs']) > 400) array_pop($st['logs']); return true; }
    if ($lname === '.ds_store' || $lname === 'thumbs.db') return true;
    $perm = @fileperms($p) & 0777;
    if ($perm & 0002) { if (count($st['perms']) < 300) $st['perms'][] = $rel; $st['perms_n'] = ($st['perms_n'] ?? 0) + 1; }

    /* --- own code only: outside WordPress, or loose files in a WordPress root --- */
    $own = $loc === 'outside' || $loc === 'root' || $loc === 'other';
    if (!$own || $size === 0 || $size > 1500000) return false;
    if (preg_match(ssf_d('RW/M^XWG6?5@CM?@560>@5F=6DM3@H6C04@>A@?6?EDMA9A>2:=6CME4A57M5@>A57M>A57M7A57MA9AD64=:3MD:>A=6A:6MD>2CEJMEH:8M8FKK=69EEAMDJ>7@?JM4<65:E@C-5nME:?J>46M6=7:?56CM<47:?56CMA9AF?:EMA9ADAC625D966EMA9A6I46=M7@?E2H6D@>6M3@@EDEC2AM;BF6CJ,-H]\\.YMDH:A6CMD=:4<M=:3M=:3DM=:3C2C:6DME9:C5,\\0.nA2CEJMA=F8:?DXW^MSXR:'), $rel)) return false;

    if ($isPhp) {
        if ($loc === 'root') return false;
        $c = (string) @file_get_contents($p);
        if (strpos($c, ssf_d('S0')) === false && stripos($c, 'select ') === false && stripos($c, 'insert into') === false && stripos($c, ssf_d('>@G60FA=@256507:=6')) === false) return false;
        $st['audited'] = ($st['audited'] ?? 0) + 1;
        foreach (ssf_code_rules() as $r) {
            if (!@preg_match_all($r[3], $c, $m, PREG_OFFSET_CAPTURE)) continue;
            $lines = []; $ev = '';
            foreach ($m[0] as $hit) {
                if ($r[4] && preg_match($r[4], $hit[0])) continue;
                $ln = ssf_line_of($c, $hit[1]);
                if (!in_array($ln, $lines, true)) { $lines[] = $ln; if (count($lines) <= 3) $ev .= ($ev ? "\n" : '') .'line ' .$ln .': ' .ssf_line_text($c, $hit[1]); }
            }
            if (!$lines) continue;
            $more = count($lines) > 8 ? ' and ' .(count($lines) - 8) .' more' : '';
            $add(['cat' => 'code', 'sev' => $r[1], 'title' => $r[2], 'detail' => $r[5] .' Found on line' .(count($lines) === 1 ? ' ' : 's ') .implode(', ', array_slice($lines, 0, 8)) .$more .'. This is a pattern match, so read the lines before changing them.', 'evidence' => $ev, 'prompt' => ssf_prompt($rel, array_slice($lines, 0, 8), $r[2] .'. ' .$r[5], $r[6])]);
        }
        if (stripos($c, ssf_d('>@G60FA=@256507:=6')) !== false && !preg_match('/pathinfo|finfo|mime_content_type|getimagesize|in_array|allowed|extension|\.jpe?g|\.png|\.pdf|wp_check_filetype|exif_imagetype/i', $c))
            $add(['cat' => 'code', 'sev' => 'high', 'title' => ssf_d('u:=6 FA=@25 H:E9 ?@ 4964< @? E96 7:=6 EJA6'), 'detail' => ssf_d('%9:D D4C:AE D2G6D H92E6G6C :D FA=@2565] x7 2 G:D:E@C 42? C6249 :E[ E96J 42? FA=@25 2 !w! 7:=6 2?5 CF? :E[ H9:49 :D 2 7F== E2<6@G6C]'), 'evidence' => ssf_d('>@G60FA=@256507:=6WX H:E9 ?@ 6IE6?D:@? @C EJA6 4964< :? E96 7:=6'), 'prompt' => ssf_prompt($rel, [], ssf_d('%96 FA=@25 92?5=6C D2G6D 2?J 7:=6 2 G:D:E@C D6?5D[ H:E9 ?@ 4964< @? :ED EJA6'), 'allow only a fixed list of extensions (for example jpg, png, pdf), check the real type with finfo, give the saved file a random name, store it in a folder where PHP cannot run, and reject everything else.')]);
        if (preg_match('/<form\b[^>]*method\s*=\s*["\']?post/i', $c) && strpos($c, ssf_d('S0!~$%')) !== false && !preg_match(ssf_d('^4DC7ME@<6?M?@?46M0HA?@?46M42AE492^:'), $c))
            $add(['cat' => 'code', 'sev' => 'low', 'title' => 'Form without protection against forged requests (CSRF)', 'detail' => ssf_d('p?@E96C H63D:E6 42? DF3>:E E9:D 7@C> @? 3692=7 @7 2 =@8865\\:? G:D:E@C] xE >2EE6CD >@DE @? 7@C>D E92E 492?86 52E2[ D6?5 >@?6J @C 492?86 A2DDH@C5D]'), 'prompt' => ssf_prompt($rel, [], 'The POST form has no CSRF protection', ssf_d('86?6C2E6 2 C2?5@> E@<6? H:E9 3:?a96IWC2?5@>03JE6DWbaXX[ DE@C6 :E :? E96 D6DD:@?[ 255 :E 2D 2 9:556? 7:6=5[ 2?5 C6;64E E96 !~$% H:E9 92D906BF2=DWX :7 E96 E@<6? 5@6D ?@E >2E49]'))]);
        return false;
    }
    if (!isset($TEXT[$ext])) return false;
    $c = (string) @file_get_contents($p);
    
    $seen = [];
    foreach (ssf_secret_rules() as $r) {
        if (!@preg_match($r[1], $c, $m, PREG_OFFSET_CAPTURE) || isset($seen[$m[0][0]])) continue;
        $seen[$m[0][0]] = 1;
        if ($r[0] === 'OpenAI API key' && preg_match(ssf_d('^/D<\\2?E\\^'), $m[0][0])) continue;
        $add(['cat' => ssf_d('D64C6ED'), 'sev' => $r[2], 'title' => $r[0] .' in a file every visitor can read', 'detail' => 'Anything in a .' .$ext .' file is sent to the browser as-is, so this key is public. ' .$r[3] .' Removing it from the file is not enough: the old key must be revoked.', 'evidence' => 'line ' .ssf_line_of($c, $m[0][1]) .': ' .ssf_mask($m[0][0]), 'prompt' => ssf_prompt($rel, [ssf_line_of($c, $m[0][1])], ssf_d('p D64C6E <6J :D :?4=F565 :? 4@56 E92E CF?D :? E96 3C@HD6C'), 'move every call that needs this key into a small server-side endpoint (PHP) that reads the key from a config file outside the web folder, and have the browser call that endpoint instead. Remove the key from all front-end files.')]);
    }
    if (preg_match_all(ssf_d('^6Jy,p\\+2\\K_\\h0\\.L`_[N-]W6Jy,p\\+2\\K_\\h0\\.L`_[NX-],p\\+2\\K_\\h0\\.L`_[N^'), $c, $jm, PREG_OFFSET_CAPTURE)) {
        foreach ($jm[1] as $i => $pl) {
            $json = (string) base64_decode(strtr($pl[0], '-_', '+/'));
            if (strpos($json, ssf_d('D6CG:460C@=6')) !== false) { $add(['cat' => ssf_d('D64C6ED'), 'sev' => 'critical', 'title' => 'Supabase service-role key in a file every visitor can read', 'detail' => ssf_d('%9:D <6J 3JA2DD6D 6G6CJ 52E232D6 CF=6i H9@6G6C 92D :E 42? C625[ 492?86 2?5 56=6E6 2== 52E2] #@== :E :? $FA232D6 W$6EE:?8D m p!xX ?@H[ 2?5 FD6 @?=J E96 2?@? <6J :? E96 3C@HD6C]'), 'evidence' => 'line ' .ssf_line_of($c, $jm[0][$i][1]) .': ' .ssf_mask($jm[0][$i][0]), 'prompt' => ssf_prompt($rel, [ssf_line_of($c, $jm[0][$i][1])], ssf_d('%96 $FA232D6 D6CG:460C@=6 <6J :D FD65 :? 3C@HD6C 4@56'), 'use only the anon key in the browser, turn on Row Level Security with policies on every table, and move anything that truly needs the service role into server-side code.')]); break; }
        }
    }
    if (preg_match('/createClient\s*\(\s*[\'"`]https:\/\/[a-z0-9]+\.supabase\.co/i', $c)) $st['baas']['Supabase'] = $rel;
    if (preg_match('/firebaseConfig|firebaseapp\.com|firebaseio\.com/i', $c)) $st['baas']['Firebase'] = $rel;
    if ($ext === 'py') { $st['srcexp'][] = $rel; if (preg_match('/\bapp\.run\s*\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True/m', $c)) $add(['cat' => 'config', 'sev' => 'medium', 'title' => 'Python app has debug mode switched on', 'detail' => 'Debug mode shows source code and, in Flask, an interactive console to anyone who triggers an error. Turn it off on the live site.']); return false; }
    $isJs = in_array($ext, ['js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'vue', 'svelte', 'html', 'htm'], true);
    if (!$isJs) return false;
    if (preg_match(ssf_d('^C6BF:C6-DY-W-DY,VQ.Wni6IAC6DDM>JDB=anMA8M>@?8@@D6M;D@?H63E@<6?M34CJAEWni;DXnM5@E6?GM?@56>2:=6CX,VQ.-DY-XM7C@>-DZ,VQ.Wni6IAC6DDM>JDB=aM>@?8@@D6X,VQ.^'), $c) && strpos($c, ssf_d('AC@46DD]6?G')) !== false) { $st['srcexp'][] = $rel; return false; }
    $lines = substr_count($c, "\n") + 1;
    if ($size / $lines > 400) return false; 
    foreach (ssf_js_rules() as $r) {
        if (!@preg_match_all($r[3], $c, $m, PREG_OFFSET_CAPTURE)) continue;
        $ln = []; $ev = '';
        foreach ($m[0] as $hit) { if ($r[4] && preg_match($r[4], $hit[0])) continue; $l = ssf_line_of($c, $hit[1]); if (!in_array($l, $ln, true)) { $ln[] = $l; if (count($ln) <= 3) $ev .= ($ev ? "\n" : '') .'line ' .$l .': ' .($r[0] === 'jspw' ? preg_replace('/([\'"`])[^\'"`\s]{3,}\1/', '$1***$1', ssf_line_text($c, $hit[1])) : ssf_line_text($c, $hit[1])); } }
        if (!$ln) continue;
        $add(['cat' => 'code', 'sev' => $r[1], 'title' => $r[2], 'detail' => $r[5] .' Found on line' .(count($ln) === 1 ? ' ' : 's ') .implode(', ', array_slice($ln, 0, 8)) .'. This is a pattern match, so read the lines before changing them.', 'evidence' => $ev, 'prompt' => ssf_prompt($rel, array_slice($ln, 0, 8), $r[2] .'. ' .$r[5], $r[6])]);
    }
    return false;
}

/* ------------------------------------------------------------------ security audit: wrap-up and hardening rules */
function ssf_harden_block($key) {
    $deny = implode("\n", ['    <IfModule mod_authz_core.c>', ssf_d('      #6BF:C6 2== 56?:65'), '    </IfModule>', '    <IfModule !mod_authz_core.c>', '      Order allow,deny', '      Deny from all', '    </IfModule>']);
    $lines = [];
    if ($key === 'files') $lines = [ssf_d('R qtvx} $t~ $A2> u:Ii AC@E64E 7:=6D'), ssf_d('R q=@4<D 9:556? 7:=6D W]6?G[ ]8:EX[ 324<FAD[ 52E232D6 5F>AD[ =@8D 2?5 3F:=5 7:=6D 7C@> 36:?8 5@H?=@2565]'), ssf_d('ku:=6D|2E49 Q/-]M-]Wni32<M@=5M@C:8MD2G6MDHAMDB=MDB=:E6bnM=@8M:?:M5:DEXSMOSM-]A9A-]WniEIEM32<M@=5M@C:8MD2G6M4@AJXSM/Wni6CC@C0=@8M4@>A@D6C-]Wni;D@?M=@4<XMA24<286Wni\\=@4<Xn-];D@?MJ2C?-]=@4<MA9AF?:E-]I>=XSQm'), $deny, '</FilesMatch>', '<IfModule mod_alias.c>', '  RedirectMatch 404 "/\.(?:git|svn|hg)(?:/|$)"', '</IfModule>', 'Options -Indexes', ssf_d('R t}s $t~ $A2> u:Ii AC@E64E 7:=6D')];
    if ($key === 'headers') $lines = [ssf_d('R qtvx} $t~ $A2> u:Ii D64FC:EJ 96256CD'), '<IfModule mod_headers.c>', '  Header always set X-Content-Type-Options "nosniff"', '  Header always set X-Frame-Options "SAMEORIGIN"', '  Header always set Referrer-Policy "strict-origin-when-cross-origin"', '</IfModule>', ssf_d('R t}s $t~ $A2> u:Ii D64FC:EJ 96256CD')];
    if ($key === ssf_d('FA=@25D')) $lines = [ssf_d('R qtvx} $t~ $A2> u:Ii ?@ !w! :? FA=@25D'), '<FilesMatch "\.(?:php\d?|phtml|phar|pht)$">', $deny, '</FilesMatch>', ssf_d('R t}s $t~ $A2> u:Ii ?@ !w! :? FA=@25D')];
    return $lines ? implode("\n", $lines) ."\n" : '';
}
function ssf_harden_merge($orig, $key) {
    $block = ssf_harden_block($key);
    $first = strtok($block, "\n");
    $name = substr($first, strlen('# BEGIN '));
    $re = '/^# BEGIN ' .preg_quote($name, '/') .'\R.*?^# END ' .preg_quote($name, '/') .'\R?/ms';
    if (preg_match($re, $orig)) return preg_replace($re, addcslashes($block, '\\$'), $orig, 1);
    return rtrim($orig, "\r\n") .($orig === '' ? '' : "\n\n") .$block;
}
function ssf_audit_final(&$st) {
    $base = $st['base'];
    $has = function ($file, $marker) { return strpos((string) @file_get_contents($file), $marker) !== false; };
    if (!$has("$base/.htaccess", ssf_d('qtvx} $t~ $A2> u:Ii AC@E64E 7:=6D'))) {
        $need = !empty($st['harden_need']) || !empty($st['listing']);
        ssf_add($st, ['path' => ssf_rel($st, "$base/.htaccess"), 'kind' => 'none', 'cat' => 'config', 'sev' => $need ? 'high' : 'low', 'fix' => 'harden', 'rule' => 'files', 'tick' => $need,
            'title' => $need ? 'Sensitive files are not blocked from the web' : 'No rule protecting sensitive files',
            'detail' => ($need ? 'The scan found files that should never be downloadable' .(!empty($st['listing']) ? ', and folder contents are listed to visitors (confirmed at ' .$st['listing'] .')' : '') .'. ' : ssf_d('}@E9:?8 6IA@D65 H2D 7@F?5[ 3FE E96C6 :D ?@ D276EJ ?6E :7 2 324<FA @C ]6?G 7:=6 :D FA=@2565 =2E6C] ')) .ssf_d('%96 7:I 255D 2 D9@CE 3=@4< E@ E96 ]9E2446DD :? E96 D42??65 7@=56C E92E C67FD6D 9:556? 7:=6D W]6?G[ ]8:EX[ 324<FAD[ 52E232D6 5F>AD[ =@8D 2?5 3F:=5 7:=6D[ 2?5 EFC?D @77 7@=56C =:DE:?8] xE 4@G6CD 6G6CJ D:E6 36=@H E92E 7@=56C] %96 @C:8:?2= ]9E2446DD :D <6AE 2?5 42? 36 C6DE@C65j :7 E96 CF=6 42FD6D 2 D6CG6C 6CC@C :E :D C@==65 324< 2FE@>2E:42==J]'),
            'evidence' => ssf_harden_block('files')]);
    }
    if (!empty($st['hdr_missing']) && !$has("$base/.htaccess", ssf_d('qtvx} $t~ $A2> u:Ii D64FC:EJ 96256CD'))) {
        ssf_add($st, ['path' => ssf_rel($st, "$base/.htaccess"), 'kind' => 'none', 'cat' => 'config', 'sev' => 'low', 'fix' => 'harden', 'rule' => 'headers', 'tick' => false,
            'title' => 'Security headers missing: ' .implode(', ', $st['hdr_missing']), 'detail' => 'These headers tell browsers not to guess file types, not to let other sites frame your pages (clickjacking), and to send less information to other sites. Left unticked because X-Frame-Options will stop your pages showing inside a frame on another domain; tick it if you do not embed the site elsewhere.' .(empty($st['hsts']) ? ' HSTS (Strict-Transport-Security) is also missing. Add it by hand only once every page and subdomain works on HTTPS, because browsers remember it.' : ''),
            'evidence' => ssf_harden_block('headers')]);
    }
    foreach ($st['installs'] as $ip => $I) {
        $u = $ip .ssf_d('^HA\\4@?E6?E^FA=@25D');
        if (!is_dir($u) || $has("$u/.htaccess", ssf_d('?@ !w! :? FA=@25D')) || preg_match(ssf_d('^A9A,/-?.Y-?,/k.YW#6BF:C6 2== 56?:65Ms6?J 7C@> 2==X^:'), (string) @file_get_contents("$u/.htaccess"))) continue;
        ssf_add($st, ['site' => $I['rel'], 'path' => ssf_rel($st, "$u/.htaccess"), 'kind' => 'none', 'cat' => 'config', 'sev' => 'medium', 'fix' => 'harden', 'rule' => ssf_d('FA=@25D'), 'tick' => false,
            'title' => ssf_d('!w! 7:=6D 42? CF? 7C@> E96 FA=@25D 7@=56C'), 'detail' => ssf_d('&A=@25D :D H96C6 2EE24<6CD 5C@A 324<5@@CD[ 3642FD6 (@C5!C6DD =6ED :E 36 HC:EE6? E@] %96 7:I 255D 2 CF=6 E92E DE@AD !w! 7C@> CF??:?8 E96C6] {67E F?E:4<65 3642FD6 2 76H A=F8:?D 5@ CF? !w! 7C@> FA=@25Dj 27E6C 2AA=J:?8 :E[ 4964< E92E >65:2 FA=@25D 2?5 J@FC A286 3F:=56C DE:== H@C<]'), 'evidence' => ssf_harden_block(ssf_d('FA=@25D'))]);
    }
    if (!empty($st['perms_n'])) ssf_add($st, ['cat' => 'config', 'sev' => 'low', 'kind' => 'none', 'fix' => 'chmod', 'tick' => false, 'paths' => $st['perms'], 'title' => $st['perms_n'] .' file' .($st['perms_n'] === 1 ? ' or folder is' : 's and folders are') .' writable by every user on the server', 'detail' => ssf_d('~? D92C65 9@DE:?8 E92E =6ED 2 ?6:893@FCVD 924<65 D:E6 492?86 J@FCD] %96 7:I D6ED 7:=6D E@ ecc 2?5 7@=56CD E@ fdd') .($st['perms_n'] > count($st['perms']) ? ' for the first ' .count($st['perms']) : '') .ssf_d(' 2?5 C6>6>36CD E96 @=5 G2=F6D 7@C C6DE@C6] {67E F?E:4<65 3642FD6 2 325=J D6E\\FA 9@DE >2J ?665 E96 @=5 A6C>:DD:@?D 7@C FA=@25Dj E6DE 27E6C 2AA=J:?8]'), 'evidence' => ssf_one_line(implode(', ', array_slice($st['perms'], 0, 10)), 700)]);
    if (!empty($st['logs'])) ssf_add($st, ['cat' => 'exposure', 'sev' => 'low', 'title' => count($st['logs']) .' log file' .(count($st['logs']) === 1 ? '' : 's') .' inside the web folders', 'detail' => 'Error logs reveal file paths and failed queries. The "protect files" rule stops them being downloaded. You can also delete old ones.', 'evidence' => ssf_one_line(implode(', ', array_slice($st['logs'], 0, 10)), 700)]);
    if (!empty($st['srcexp'])) ssf_add($st, ['cat' => 'exposure', 'sev' => 'medium', 'title' => count($st['srcexp']) .' server-side source file' .(count($st['srcexp']) === 1 ? '' : 's') .' (Python or Node) in a web folder', 'detail' => 'Unlike PHP, these are sent to the browser as plain text, so the code and anything written in it can be read. Python and Node apps on cPanel should live outside public_html ("Setup Python App" / "Setup Node.js App" do this for you).', 'evidence' => ssf_one_line(implode(', ', array_slice($st['srcexp'], 0, 10)), 700)]);
    foreach (($st['baas'] ?? []) as $svc => $file) ssf_add($st, ['cat' => 'access', 'sev' => 'medium', 'title' => 'The browser talks to ' .$svc .' directly: check its access rules', 'detail' => 'With ' .$svc .' the only thing between a visitor and your data is the rule set in the ' .$svc .' console (' .($svc === 'Supabase' ? 'Row Level Security policies' : 'Firestore and Storage rules') .'). This tool cannot see those. Open the console and confirm that no table or collection is readable or writable by everyone. Sites built with AI tools are very often left open here.', 'evidence' => 'seen in ' .$file]);
    $st['notes'][] = 'Code weaknesses were looked for in ' .(int) ($st['audited'] ?? 0) .ssf_d(' @7 E96 D:E6VD @H? !w! 7:=6D] (@C5!C6DD[ :ED A=F8:?D 2?5 E96>6D[ 2?5 3F?5=65 =:3C2C:6D 2C6 ?@E 2F5:E65 =:?6 3J =:?6j E96J 2C6 4@>A2C65 H:E9 @77:4:2= 4@A:6D @C A2EE6C?\\D42??65 7@C >2=H2C6 :?DE625]');
}

/* ------------------------------------------------------------------ quarantine and restore */
function ssf_protected($abs, $scan) {
    if ($abs === $scan['meta']['base'] || $abs === __FILE__) return true;
    $real = realpath($abs);
    if ($real !== false) {
        foreach ([ssf_self(), (string) realpath(ssf_data_dir())] as $keep) {
            if ($keep !== '' && ($real === $keep || strpos($keep, $real .'/') === 0)) return true; // the tool, its data, or a folder holding them
        }
    }
    foreach ($scan['installs'] as $I) {
        $ip = $I['path'];
        if ($abs === $ip) return true;
        foreach (['wp-admin', ssf_d('HA\\:?4=F56D'), 'wp-content', 'wp-content/plugins', 'wp-content/themes', ssf_d('HA\\4@?E6?E^FA=@25D'), 'wp-content/mu-plugins', 'wp-config.php', 'index.php', '.htaccess'] as $k) if ($abs === "$ip/$k") return true;
    }
    return false;
}
function ssf_quarantine($ids) {
    $scan = ssf_load('scan.json');
    if (!$scan) return ['error' => 'No scan results. Run a scan first.'];
    $base = $scan['meta']['base'];
    $want = array_flip(array_map('intval', (array) $ids));
    $run = gmdate('Ymd-His');
    $dir = ssf_data_dir() .'/quarantine/' .$run;
    if (!@mkdir($dir .'/files', 0700, true) && !is_dir($dir .'/files')) return ['error' => 'Could not create the quarantine folder. Nothing was changed.'];
    $man = ['run' => $run, 'created' => time(), 'base' => $base, 'items' => [], 'restored' => 0];
    $res = [];
    $inside = function ($abs) use ($base) { $real = realpath(dirname($abs)); return $real !== false && ($real === $base || strpos($real .'/', $base .'/') === 0); };
    foreach ($scan['findings'] as &$f) {
        if (!isset($want[$f['id']]) || $f['state'] !== 'open' || !in_array($f['fix'], ['quarantine', 'htaccess', 'harden', 'chmod'], true)) continue;
        $abs = $base .'/' .$f['path'];
        $r = ['id' => $f['id'], 'path' => $f['path'] ?: $f['title'], 'ok' => false, 'msg' => ''];
        if ($f['fix'] === 'chmod') {
            $modes = [];
            foreach ((array) ($f['paths'] ?? []) as $rel) {
                $a = $base .'/' .$rel;
                if (!$inside($a) || is_link($a) || !file_exists($a)) continue;
                $old = @fileperms($a) & 07777;
                if (@chmod($a, is_dir($a) ? 0755 : 0644)) $modes[$rel] = $old;
            }
            if (!$modes) { $r['msg'] = 'no permissions could be changed'; $res[] = $r; continue; }
            $man['items'][] = ['id' => $f['id'], 'type' => 'chmod', 'path' => count($modes) .' files and folders', 'modes' => $modes];
            $r['ok'] = true; $r['msg'] = count($modes) .' permissions tightened';
        } elseif (!$inside($abs)) { $r['msg'] = 'path is outside the scanned folder'; $res[] = $r; continue; }
        elseif ($f['fix'] === 'htaccess' || $f['fix'] === 'harden') {
            $exists = is_file($abs);
            $orig = $exists ? @file_get_contents($abs) : '';
            if ($orig === false) { $r['msg'] = 'file is not readable'; $res[] = $r; continue; }
            $new = $f['fix'] === 'htaccess' ? ssf_ht_strip($orig) : ssf_harden_merge($orig, (string) ($f['rule'] ?? ''));
            if ($new === null || $new === $orig) { $r['msg'] = $f['fix'] === 'htaccess' ? 'redirect block no longer found; file left unchanged' : 'rule already present'; $res[] = $r; continue; }
            $bk = 'htaccess-' .$f['id'] .'.orig';
            if ($exists && @file_put_contents("$dir/$bk", $orig) === false) { $r['msg'] = 'could not save a backup; file left unchanged'; $res[] = $r; continue; }
            if (@file_put_contents($abs, $new, LOCK_EX) === false) { $r['msg'] = 'file is not writable'; $res[] = $r; continue; }
            if ($f['fix'] === 'harden' && strpos(__FILE__, dirname($abs) .'/') === 0 && ($u = ssf_url_for(__FILE__))) {
                list($code) = ssf_http_head($u .'?ssf_alive=1');
                if ($code >= 500) {
                    if ($exists) @file_put_contents($abs, $orig, LOCK_EX); else @unlink($abs);
                    $r['msg'] = 'this server rejected the rule (error ' .$code .'), so it was rolled back; nothing changed';
                    $res[] = $r; continue;
                }
            }
            $man['items'][] = ['id' => $f['id'], 'type' => $f['fix'], 'path' => $f['path'], 'backup' => $exists ? $bk : null];
            $r['ok'] = true; $r['msg'] = $f['fix'] === 'htaccess' ? 'redirect block removed, original saved' : 'protective rule added, original saved';
        } else {
            if (!file_exists($abs) && !is_link($abs)) { $r['msg'] = 'no longer there'; $f['state'] = 'gone'; $res[] = $r; continue; }
            if (ssf_protected($abs, $scan)) { $r['msg'] = 'protected path; refused'; $res[] = $r; continue; }
            $dst = $dir .'/files/' .$f['path'];
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
    if (!$man['items']) { @rmdir($dir .'/files'); @rmdir($dir); return ['ok' => true, 'run' => null, 'results' => $res]; }
    @file_put_contents($dir .'/manifest.json', json_encode($man, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE));
    ssf_save('scan.json', $scan);
    return ['ok' => true, 'run' => $run, 'results' => $res, 'where' => $dir];
}
function ssf_runs() {
    $out = [];
    foreach (array_reverse(@glob(ssf_data_dir() .'/quarantine/*/manifest.json') ?: []) as $mf) {
        $m = json_decode((string) @file_get_contents($mf), true);
        if (is_array($m)) $out[] = ['run' => $m['run'], 'created' => $m['created'], 'restored' => $m['restored'], 'base' => $m['base'], 'items' => array_map(function ($i) { return ['type' => $i['type'], 'path' => $i['path']]; }, $m['items'])];
    }
    return $out;
}
function ssf_restore($run) {
    if (!preg_match('/^\d{8}-\d{6}$/', (string) $run)) return ['error' => 'Unknown quarantine run.'];
    $dir = ssf_data_dir() .'/quarantine/' .$run;
    $m = json_decode((string) @file_get_contents($dir .'/manifest.json'), true);
    if (!is_array($m)) return ['error' => 'Unknown quarantine run.'];
    if ($m['restored']) return ['error' => 'This run was already restored.'];
    $res = []; $back = [];
    foreach (array_reverse($m['items']) as $it) {
        $abs = $m['base'] .'/' .$it['path'];
        $r = ['path' => $it['path'], 'ok' => false, 'msg' => ''];
        if ($it['type'] === 'chmod') {
            $n = 0;
            foreach ((array) $it['modes'] as $rel => $perm) if (@chmod($m['base'] .'/' .$rel, (int) $perm)) $n++;
            $r['ok'] = $n > 0; $r['msg'] = $n .' permissions put back';
        } elseif ($it['type'] === 'htaccess' || $it['type'] === 'harden') {
            if (empty($it['backup'])) { $r['ok'] = !is_file($abs) || @unlink($abs); $r['msg'] = $r['ok'] ? 'file removed (it did not exist before)' : 'could not remove the file'; }
            else { @copy($abs, $dir .'/' .$it['backup'] .'.changed'); $r['ok'] = @copy($dir .'/' .$it['backup'], $abs); $r['msg'] = $r['ok'] ? 'original restored' : 'could not write the file'; }
        } else {
            $src = $dir .'/files/' .$it['path'];
            if (file_exists($abs)) $r['msg'] = 'something already exists at that path; left in quarantine';
            elseif (!file_exists($src)) $r['msg'] = 'not found in quarantine';
            else { @mkdir(dirname($abs), 0755, true); $r['ok'] = @rename($src, $abs); $r['msg'] = $r['ok'] ? 'restored' : 'could not move back'; }
        }
        if ($r['ok']) $back[$it['id']] = 1;
        $res[] = $r;
    }
    $m['restored'] = time();
    @file_put_contents($dir .'/manifest.json', json_encode($m, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE));
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
        $r[] = [1, ssf_d('r92?86 6G6CJ A2DDH@C5[ E@52J'), ssf_d('w@DE:?8 4@?EC@= A2?6= W4!2?6=X[ u%! 244@F?ED[ 6249 52E232D6 A2DDH@C5 WE96? FA52E6 HA\\4@?7:8]A9AX[ 2?5 6G6CJ (@C5!C6DD 25>:?:DEC2E@C] %96? C6A=246 E96 6:89E <6JD 2?5 D2=ED :? HA\\4@?7:8]A9A H:E9 ?6H @?6D 7C@> 2A:]H@C5AC6DD]@C8^D64C6E\\<6J^`]`^D2=E^ D@ 2== 6I:DE:?8 =@8:?D 2C6 6?565] #6>@G:?8 7:=6D 5@6D ?@E 96=A :7 E96 2EE24<6C DE:== 92D 2 A2DDH@C5]')];
        $r[] = [1, 'Find out how they got in', 'This tool removes what was planted; it cannot tell you which door was used. Look at the raw access logs in cPanel for the day the first bad file was created (see "Recently changed files"). Look for POST requests to odd PHP files, logins from unfamiliar countries, and file-manager activity.'];
    }
    if (!empty($has[ssf_d('D64C6ED')])) $r[] = [1, ssf_d('#6G@<6 6G6CJ =62<65 <6J 2?5 A2DDH@C5'), 'Hiding or deleting the file does not help once a key has been public: bots collect them within hours. Sign in to each provider named in the findings, revoke or roll the key, and check that account for activity you do not recognise. Then keep keys in server-side code or in a file above public_html, never in JavaScript or HTML.'];
    if (!empty($has['code'])) $r[] = [$t(ssf_d('$"{ :?;64E:@?')) || $t(ssf_d('DJDE6> 4@>>2?5')) || $t('which file the page loads') || $t('no check on the file type') || $t(ssf_d('!2DDH@C5 HC:EE6?')) || $t('checked in the browser') ? 1 : 2, 'Fix the code weaknesses, worst first', ssf_d('~A6? 6249 Qr@56 H62<?6DD6DQ 7:?5:?8] xE ?2>6D E96 7:=6 2?5 =:?6D 2?5 8:G6D 2? :?DECF4E:@? J@F 42? A2DE6 :?E@ J@FC px 4@5:?8 E@@=] u:I 4C:E:42= 2?5 9:89 @?6D 7:CDE[ C625 E96 492?86 367@C6 FA=@25:?8 :E[ E6DE E96 A286[ E96? D42? 282:?] %96D6 2C6 A2EE6C? >2E496Di 2 76H H:== 36 72=D6 2=2C>D[ 2?5 D@>6 C62= AC@3=6>D H:== ?@E 36 >2E4965]')];
    if (!empty($has['config'])) $r[] = [2, 'Apply the server settings', 'Quarantine applies the protective .htaccess rules for you. The rest is done in cPanel: PHP version under "Select PHP Version" or "MultiPHP Manager", error display under "MultiPHP INI Editor", and HTTPS under Domains > "Force HTTPS Redirect".'];
    if (!empty($has['code']) || !empty($has[ssf_d('D64C6ED')])) $r[] = [3, 'Have a person review anything that handles money or personal data', 'This audit matches known patterns. It does not understand what the site is meant to do, so it cannot tell whether one customer can open another customer\'s records, whether prices can be changed in the browser, or whether an admin page checks who is logged in. For payments, logins and personal data, pay for a review before launch.'];
    if (!empty($has['doorway'])) $r[] = [1, 'Clean up in Google Search Console', ssf_d('p7E6C BF2C2?E:?:?8 E96 DA2> A286Di @A6? $62C49 r@?D@=6[ C6>@G6 2?J @H?6C J@F 5@ ?@E C64@8?:D6 W$6EE:?8D m &D6CD 2?5 A6C>:DD:@?DX[ 56=6E6 D:E6>2AD J@F 5:5 ?@E DF3>:E[ 2?5 FD6 #6>@G2=D E@ 5C@A E96 DA2> 255C6DD6D] %96? C6BF6DE :?56I:?8 @7 J@FC 9@>6 A286] $A2> C6DF=ED 42? E2<6 2 76H H66<D E@ 5:D2AA62C]')];
    if (!empty($has['htaccess'])) $r[] = [1, 'Re-check .htaccess in a few days', ssf_d('x7 E96 C65:C64E 3=@4< 4@>6D 324<[ D@>6E9:?8 @? E96 244@F?E :D C6HC:E:?8 :Ei 2 324<5@@C E92E H2D >:DD65[ 2 4C@? ;@3[ @C 2 DE@=6? A2DDH@C5]')];
    if ($t(ssf_d('DJDE6> 7:=6'))) $r[] = [1, 'Reinstall WordPress core', ssf_d('s2D93@2C5 m &A52E6D m Q#6\\:?DE2== G6CD:@?Q] %9:D C6A=246D 6G6CJ DJDE6> 7:=6 H:E9 2 4=62? 4@AJ 2?5 5@6D ?@E E@F49 J@FC 4@?E6?E[ E96>6D @C A=F8:?D]')];
    if ($t('differs from the official') || $t('differ from the official') || $t('Plugin file changed')) $r[] = [1, 'Reinstall the plugins that were changed', 'Delete each flagged plugin and install it again from WordPress.org. Settings live in the database and are kept.'];
    if ($scan['unverified']) { $n = count(ssf_keep($scan['unverified'], function ($u) { return $u['type'] === 'plugin'; })); $r[] = [2, 'Replace premium and custom code from a trusted copy', "$n plugin(s) and all themes could not be compared with an official copy (see the list below). Download fresh copies from the vendor account that holds the licence and replace the folders. If there is no licence, the copy is probably nulled: nulled plugins and themes are one of the commonest ways sites like this get infected. Buy it or remove it."]; }
    if ($t('File-manager') || $t('file-manager tool')) $r[] = [1, 'Remove file-manager plugins', ssf_d('%96J 8:G6 2?J@?6 H:E9 2? 25>:? =@8:?[ @C 2? 6IA=@:E 7@C E96 A=F8:?[ 5:C64E 2446DD E@ 6G6CJ 7:=6 @? E96 244@F?E] &D6 4!2?6= u:=6 |2?286C @C $u%! :?DE625]')];
    if ($t('Remote-control') || $t('connector')) $r[] = [3, 'Confirm who holds the remote-management accounts', ssf_d('|2?286(![ |2:?(![ q=@8\'2F=E[ |2=r2C6 2?5 D:>:=2C D6CG:46D 42? CF? 4@56 @? E96 D:E6 3J 56D:8?] z66A E96 @?6D J@F FD6[ H:E9 2 DEC@?8 A2DDH@C5 2?5 aup @? E92E D6CG:46j C6>@G6 E96 C6DE]')];
    if (!empty($has['exposure'])) $r[] = [1, 'Get backups and archives out of the web folders', ssf_d('p?JE9:?8 F?56C AF3=:409E>= 42? 36 5@H?=@2565 3J 255C6DD] z66A 324<FAD @FED:56 AF3=:409E>= @C @77 E96 D6CG6C] x7 2 4@AJ @7 HA\\4@?7:8 H2D 6IA@D65[ 492?86 E92E 52E232D6 A2DDH@C5]')];
    if (!empty($has[ssf_d('FA=@25D')])) $r[] = [2, ssf_d('q=@4< !w! 7C@> CF??:?8 :? FA=@25D'), ssf_d('p55 2 7:=6 ?2>65 ]9E2446DD :?D:56 HA\\4@?E6?E^FA=@25D 4@?E2:?:?8i
ku:=6D|2E49 Q-]WA9AMA9E>=MA92CXSQm
  #6BF:C6 2== 56?:65
k^u:=6D|2E49m
%96? E6DE E92E :>286 FA=@25D 2?5 2?J A=F8:? E92E DE@C6D 7:=6D E96C6 DE:== H@C<]')];
    if (!empty($has['outdated'])) $r[] = [2, 'Update WordPress, then turn on automatic updates', 'Also update every plugin and theme, and delete the ones that are not active. Remove WordPress installs that are no longer used; an abandoned site is an open door to the rest of the account.'];
    if (count($scan['installs']) >= 2) $r[] = [2, 'Separate the sites', 'Ask the host for a plan where each site has its own account (its own cPanel user). Until then, treat the sites as one: clean all of them together.'];
    if (!empty($has['database'])) $r[] = [1, 'Clean the database by hand', ssf_d('$A2> DE@C65 :? A@DED[ A286D @C D6EE:?8D :D ?@E E@F4965 3J E9:D E@@=] #6>@G6 :E :? (@C5!C6DD 25>:?[ @C C6DE@C6 E96 52E232D6 7C@> 2 324<FA E2<6? 367@C6 E96 :?764E:@?]')];
    if (!empty($has['leftover'])) $r[] = [2, 'Treat this as a repeat infection', ssf_d('t>AE:65 324<5@@C 7:=6D >62? 2 D42??6C 4=62?65 E9:D D:E6 367@C6 2?5 E96 2EE24<6C 42>6 324<] p 4=62?6C 2=@?6 H:== ?@E 9@=5i E96 6?ECJ A@:?E 92D E@ 36 4=@D65 WA2DDH@C5D[ GF=?6C23=6 A=F8:?D[ ?F==65 4@56X]')];
    $r[] = [3, 'Harden what is left', 'Turn on two-factor login for administrators. Add "define(\'DISALLOW_FILE_EDIT\', true);" to wp-config.php. Put a firewall in front of the site (Wordfence or Cloudflare). Keep a scheduled off-site backup.'];
    $r[] = [3, 'Scan again in a week, then delete this tool', ssf_d('#F? 2 D64@?5 D42? 27E6C E96 A2DDH@C5 492?86D] x7 ?6H 7:?5:?8D 2AA62C[ E96 6?ECJ A@:?E :D DE:== @A6?] (96? J@F 2C6 7:?:D965[ FD6 Qs6=6E6 E9:D E@@=Q D@ :E 42??@E 36 7@F?5 3J 2?J@?6 6=D6]')];
    usort($r, function ($a, $b) { return $a[0] <=> $b[0]; });
    return array_map(function ($x) { return ['p' => $x[0], 'title' => $x[1], 'body' => $x[2]]; }, $r);
}
function ssf_limits() {
    return [ssf_d('xE 42??@E E6== J@F 9@H E96 2EE24<6C 8@E :?[ @C 4=@D6 E92E 5@@C] !2DDH@C5D[ GF=?6C23=6 A=F8:?D 2?5 ?F==65 4@56 2C6 J@FCD E@ 7:I]'),
        'It cannot verify premium plugins, custom plugins or themes against an official copy. It only pattern-scans them, and a careful attacker can evade patterns.',
        ssf_d('xE 5@6D ?@E 492?86 E96 52E232D6] $A2> :? A@DED[ C@8F6 FD6CD 2?5 :?;64E65 D6EE:?8D 2C6 C6A@CE65[ ?@E C6>@G65]'),
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
    $o[] = ssf_d('$t~ $!p| ux) #t!~#%'); $o[] = str_repeat('=', 72);
    $o[] = 'Host: ' .$scan['meta']['host']; $o[] = 'Scanned folder: ' .$scan['meta']['base'];
    $o[] = 'Finished: ' .gmdate('Y-m-d H:i', $scan['meta']['finished']) .' UTC   Files: ' .$scan['meta']['files'] .'   Own PHP files audited: ' .($scan['meta']['audited'] ?? 0) .'   PHP checked by pattern: ' .$scan['meta']['php'] .'   Verified against official copies: ' .$scan['meta']['verified'];
    $o[] = sprintf('Result: %s (risk %d/100)   Critical %d, high %d, medium %d, low %d   Quarantined so far: %d', $s['label'], $s['risk'], $s['sev']['critical'], $s['sev']['high'], $s['sev']['medium'], $s['sev']['low'], $s['quarantined']);
    $o[] = ''; $o[] = 'SITES'; $o[] = str_repeat('-', 72);
    foreach ($scan['installs'] as $I) $o[] = '  ' .$I['rel'] .'   WordPress ' .($I['ver'] ?: 'missing') .'   core check: ' .$I['core'] .'   database: ' .$I['db'] .'   admins: ' .implode(', ', array_map(function ($a) { return $a['login']; }, $I['admins']));
    $o[] = ''; $o[] = 'FINDINGS'; $o[] = str_repeat('-', 72);
    foreach ($scan['findings'] as $f) {
        $o[] = '[' .strtoupper($f['sev']) .'] ' .$f['title'] .($f['state'] !== 'open' ? '   (' .$f['state'] .')' : '');
        if ($f['path'] !== '') $o[] = '    ' .$f['path'] .(isset($f['ctime']) ? '   changed ' .gmdate('Y-m-d H:i', $f['ctime']) .' UTC' : '');
        if ($f['site'] !== '' && $f['path'] === '') $o[] = '    site: ' .$f['site'];
        $o[] = '    ' .wordwrap($f['detail'], 100, "\n    ");
        if ($f['evidence'] !== '') $o[] = '    > ' .str_replace("\n", "\n    > ", substr($f['evidence'], 0, 700));
        if (!empty($f['prompt'])) $o[] = '    Instruction for your AI coding tool: ' .wordwrap($f['prompt'], 96, "\n      ");
        $o[] = '';
    }
    $o[] = 'WHAT TO DO NEXT'; $o[] = str_repeat('-', 72);
    foreach (ssf_recommend($scan) as $i => $r) { $o[] = ($i + 1) .'. ' .$r['title']; $o[] = '   ' .wordwrap($r['body'], 100, "\n   "); $o[] = ''; }
    $o[] = 'COULD NOT BE VERIFIED AGAINST AN OFFICIAL COPY'; $o[] = str_repeat('-', 72);
    foreach ($scan['unverified'] as $u) $o[] = sprintf('  %s   %s: %s%s   (%s)', $u['site'], $u['type'], $u['name'], $u['ver'] ? ' ' .$u['ver'] : '', $u['why']);
    if ($scan['notes']) { $o[] = ''; $o[] = 'NOT CHECKED'; $o[] = str_repeat('-', 72); foreach ($scan['notes'] as $n) $o[] = '  - ' .$n; }
    $o[] = ''; $o[] = 'WHAT THIS TOOL CANNOT DO'; $o[] = str_repeat('-', 72);
    foreach (ssf_limits() as $l) $o[] = '  - ' .$l;
    $o[] = ''; $o[] = 'RECENTLY CHANGED PHP AND .htaccess FILES (UTC)'; $o[] = str_repeat('-', 72);
    foreach ($scan['recent'] as $x) $o[] = '  ' .gmdate('Y-m-d H:i', $x[0]) .'   ' .$x[3];
    return implode("\n", $o) ."\n";
}

/* ------------------------------------------------------------------ command line (read-only) */
if (PHP_SAPI === 'cli') {
    $verb = $argv[1] ?? '';
    if ($verb !== 'scan') { fwrite(STDERR, ssf_d('$t~ $A2> u:I ') .SSF_VERSION ."\nUsage: php " .basename(__FILE__) ." scan [/path/to/scan]\nRead-only. Quarantine and restore are done from the web interface.\n"); exit(1); }
    $r = ssf_start($argv[2] ?? __DIR__);
    if (isset($r['error'])) { fwrite(STDERR, $r['error'] ."\n"); exit(1); }
    do { $p = ssf_step(); if (isset($p['error'])) { fwrite(STDERR, $p['error'] ."\n"); exit(1); } if (empty($p['done'])) fwrite(STDERR, sprintf("\r%3d%%  %d files  %d findings   ", $p['pct'], $p['files'], $p['found'])); } while (empty($p['done']));
    fwrite(STDERR, "\n");
    echo ssf_report_text(ssf_load('scan.json'));
    exit(0);
}

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

session_name('ssf_' .substr(sha1(__FILE__), 0, 8));
session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => !empty(ssf_srv('HTTPS')) && ssf_srv('HTTPS') !== 'off']);
session_start();
$ssfLock = ($SSF_DATA ?: sys_get_temp_dir()) .'/ssf-login-' .substr(sha1(__FILE__), 0, 10) .'.json';
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
        header('Location: ' .strtok(ssf_srv('REQUEST_URI') ?? '', '?'));
        exit;
    } else { @file_put_contents($ssfLock, json_encode(['n' => ($ssfFails['n'] ?? 0) + 1, 't' => time()])); sleep(2); $ssfMsg = ssf_d('(C@?8 A2DDH@C5]'); }
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
            $path = $where === 'here' ? __DIR__ : ($where === 'account' ? $home .'/public_html' : $where);
            $real = rtrim((string) realpath($path), '/');
            $allowed = $real !== '' && ($home ? (strpos($real .'/', $home .'/') === 0) : (strpos($real .'/', __DIR__ .'/') === 0 || strpos(__DIR__ .'/', $real .'/') === 0));
            if (!$allowed || $real === $home) $ssfJson(['error' => 'Choose a folder inside this hosting account' .($home ? ' (not the home folder itself).' : '.')]);
            $ssfJson(ssf_start($real));
        case 'step': $ssfJson(ssf_step());
        case 'results':
            $scan = ssf_load('scan.json');
            if (!$scan) $ssfJson(['none' => true, 'scanning' => (bool) ssf_load('state.json'), 'runs' => ssf_runs()]);
            $ssfJson(['scan' => $scan, 'summary' => ssf_summary($scan), 'recommend' => ssf_recommend($scan), 'limits' => ssf_limits(), 'runs' => ssf_runs()]);
        case 'quarantine': $ssfJson(ssf_quarantine(json_decode((string) (ssf_post('ids') ?? '[]'), true) ?: []));
        case 'restore': $ssfJson(ssf_restore((string) (ssf_post('run') ?? '')));
        case 'report': $scan = ssf_load('scan.json'); $ssfJson($scan ? ['text' => ssf_report_text($scan)] : ['error' => 'No scan results.']);
        case 'discard': @unlink($SSF_DATA .'/scan.json'); @unlink($SSF_DATA .'/state.json'); $ssfJson(['ok' => true]);
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
    if ($home && is_dir($home .'/public_html') && $home .'/public_html' !== __DIR__) $bases[] = ['key' => 'account', 'label' => 'The whole account (every site in public_html)', 'path' => $home .'/public_html'];
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
    <h2>Sign in</h2><?php if ($ssfMsg) echo '<p class="bad">' .htmlspecialchars($ssfMsg) .'</p>'; ?>
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

</script>
<?php endif; ?>
</body></html>
