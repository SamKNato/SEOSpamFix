
/* ------------------------------------------------------------------ security audit: rules
   Everything in this block is the "audit" side of the tool: mistakes in a site's own code and
   set-up, as opposed to things an attacker planted. To add a check, add a row to one of the
   tables below; no other code needs to change. */
function ssf_secret_rules() {
    // [label, regex, severity, advice]
    return [
        ['Private key', '/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/', 'critical', 'Generate a new key pair and remove this one from every server that trusts it.'],
        ['Stripe / Paystack live secret key', '/\b[sr]k_live_[0-9a-zA-Z]{20,}\b/', 'critical', 'Roll the key in the payment dashboard now. Secret keys must only be used from server-side code.'],
        ['Flutterwave secret key', '/\bFLWSECK-[A-Za-z0-9]{20,}-X\b/', 'critical', 'Regenerate the key in the Flutterwave dashboard and keep it in server-side code only.'],
        ['Anthropic API key', '/\bsk-ant-[A-Za-z0-9_-]{32,}/', 'critical', 'Revoke the key in the Anthropic console. Call the API from your server, never from the browser.'],
        ['OpenAI API key', '/\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/', 'critical', 'Revoke the key in the OpenAI dashboard. Call the API from your server, never from the browser.'],
        ['AWS access key', '/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/', 'critical', 'Deactivate the key in AWS IAM and check the account for activity you do not recognise.'],
        ['GitHub token', '/\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/', 'critical', 'Revoke the token in GitHub settings.'],
        ['Slack token', '/\bxox[baprs]-[A-Za-z0-9-]{20,}/', 'high', 'Revoke the token in the Slack app settings.'],
        ['SendGrid API key', '/\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/', 'high', 'Delete the key in SendGrid and create a new one for server-side use.'],
        ['Mailgun API key', '/\bkey-[0-9a-f]{32}\b/', 'high', 'Rotate the key in Mailgun.'],
        ['Telegram bot token', '/\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/', 'high', 'Revoke the token with @BotFather.'],
        ['Database connection string with password', '/\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis):\/\/[^:\s"\'<>\/]{1,64}:[^@\s"\'<>]{3,}@[A-Za-z0-9.\-]+/', 'critical', 'Change that database password and keep connection details in server-side code.'],
        ['Google API key', '/\bAIza[0-9A-Za-z_-]{35}\b/', 'low', 'Keys for Maps and Firebase are meant to be public, but only if restricted. In Google Cloud console, limit this key to your website address and to the APIs it needs.'],
    ];
}
function ssf_code_rules() {
    $in = '\$_(?:GET|POST|REQUEST|COOKIE)\b';
    // [id, severity, title, regex, safe-if-matched-text-contains, explanation, prompt]
    return [
        ['lfi', 'critical', 'A visitor can choose which file the page loads', '/\b(?:include|require)(?:_once)?\b[^;]{0,200}?' . $in . '/', '/basename\s*\(|in_array\s*\(/', 'Visitor input goes into include/require. An attacker can make the site run a file of their choosing.', 'never pass visitor input to include or require. Map the input to a fixed list of allowed page names (a whitelist array) and load only from that list.'],
        ['cmd', 'critical', 'Visitor input is passed to a system command', '/\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]{0,200}?' . $in . '/', '/escapeshellarg\s*\(/', 'Visitor input reaches a shell command, which lets an attacker run commands on the server.', 'remove the shell command if a PHP function can do the job; otherwise validate the input against a strict whitelist and wrap every argument in escapeshellarg().'],
        ['sqli', 'high', 'SQL injection: visitor input placed straight into a database query', '/(?:mysqli_query|mysql_query|pg_query|->query|->exec|->multi_query|->prepare)\s*\([^;]{0,400}?' . $in . '/', '/real_escape_string|intval\s*\(|\(int\)/', 'The query text contains raw visitor input, so a visitor can read or change anything in the database.', 'rewrite these queries as prepared statements with bound parameters (PDO or mysqli). Do not build SQL by joining strings.'],
        ['sqlcat', 'medium', 'Database query built by joining text and variables', '/["\']\s*(?:SELECT\b[^"\';]{0,300}\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[`\w]+\s+SET\b|DELETE\s+FROM\b)[^;]{0,400}?(?:["\']\s*\.\s*\$\w|\{\$\w|=\s*\'?\$\w|\'%?\$\w)/i', '/real_escape_string|intval\s*\(|\(int\)|->quote\s*\(|esc_sql|\$wpdb->prepare|\$_(?:GET|POST|REQUEST|COOKIE)/', 'A variable is inserted into the SQL text. If that value can ever come from a visitor, this is SQL injection. It needs checking even if it is safe today.', 'rewrite these queries as prepared statements with bound parameters (PDO or mysqli) so no variable is ever placed inside the SQL text.'],
        ['path', 'high', 'A visitor can choose which file is read, written or deleted', '/\b(?:file_get_contents|readfile|fopen|file|unlink|file_put_contents|copy|rename|rmdir|scandir|opendir)\s*\([^;]{0,200}?' . $in . '/', '/basename\s*\(|realpath\s*\(|in_array\s*\(/', 'Visitor input is used as a file path. With "../" an attacker can reach files outside the intended folder, including configuration files.', 'take only basename() of the input, join it to a fixed folder, and check with realpath() that the result is still inside that folder before using it.'],
        ['unser', 'high', 'Visitor input is passed to unserialize()', '/\bunserialize\s*\([^;]{0,120}?' . $in . '/', '/allowed_classes/', 'Unserializing visitor data can create arbitrary objects and lead to code execution.', 'use json_decode() instead of unserialize() for anything that comes from a visitor.'],
        ['hardpw', 'high', 'Password written into the code', '/\$_(?:POST|REQUEST)\[\s*[\'"](?:pass|password|pwd|passwd|pin|passcode)[\'"]\s*\]\s*(?:===?|!==?)\s*[\'"][^\'"]{3,}[\'"]|[\'"][^\'"]{3,}[\'"]\s*(?:===?|!==?)\s*\$_(?:POST|REQUEST)\[\s*[\'"](?:pass|password|pwd|passwd)[\'"]\s*\]/i', null, 'The login compares against a password typed into the source file. Anyone who sees the code, a backup of it or the repository has the password.', 'store a password_hash() value outside the web folder (or in the database) and check logins with password_verify(). Then change the password, since the old one has been exposed.'],
        ['xss', 'high', 'Visitor input shown on the page without escaping (XSS)', '/(?:\becho\b|\bprint\b|<\?=)[^;]{0,200}?' . $in . '[^;?]{0,120}/', '/htmlspecialchars|htmlentities|strip_tags|intval\s*\(|\(int\)|json_encode|urlencode|esc_html|esc_attr|filter_var|filter_input/', 'Whatever a visitor puts in the address or a form is written into the page, so an attacker can run script in other visitors\' browsers.', 'wrap every value that is output in htmlspecialchars($value, ENT_QUOTES, \'UTF-8\').'],
        ['xss2', 'medium', 'Page address shown on the page without escaping (XSS)', '/(?:\becho\b|<\?=)[^;]{0,80}?\$_SERVER\[\s*[\'"](?:PHP_SELF|REQUEST_URI|QUERY_STRING|HTTP_REFERER|HTTP_USER_AGENT)[\'"]\s*\][^;?]{0,80}/', '/htmlspecialchars|htmlentities|urlencode|esc_url|esc_attr|filter_var/', 'These server values are controlled by the visitor and are written into the page as-is.', 'wrap these values in htmlspecialchars($value, ENT_QUOTES, \'UTF-8\'), or use a fixed form action instead of PHP_SELF.'],
        ['redirect', 'medium', 'A visitor can choose where the page redirects', '/header\s*\(\s*[\'"]Location:\s*[\'"]?\s*\.\s*' . $in . '|header\s*\(\s*[\'"]Location:\s*\{?\$_(?:GET|POST|REQUEST)/i', null, 'Links to your site can be made to bounce to a phishing page.', 'only redirect to paths on this site: check the value against a list of allowed destinations, or reject anything that does not start with a single "/".'],
        ['extract', 'medium', 'extract() on visitor input', '/\bextract\s*\(\s*' . $in . '/', null, 'extract() lets a visitor overwrite any variable in the script, including ones used for logins and permissions.', 'remove extract() and read each expected field by name.'],
        ['weakhash', 'medium', 'Passwords hashed with MD5 or SHA-1', '/\b(?:md5|sha1)\s*\(\s*\$(?:_(?:POST|REQUEST)\[\s*[\'"](?:pass|password|pwd|passwd)[\'"]\s*\]|pass(?:word|wd)?\b|pwd\b)/i', null, 'MD5 and SHA-1 password hashes are cracked in seconds if the database leaks.', 'store passwords with password_hash() and check them with password_verify(). Re-hash each user\'s password the next time they log in.'],
        ['showerr', 'low', 'Error messages are switched on for visitors', '/ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*(?:1|true|[\'"](?:1|on|true)[\'"])\s*\)/i', null, 'Error messages reveal file paths, queries and sometimes passwords.', 'turn display_errors off on the live site and log errors to a file outside the web folder.'],
    ];
}
function ssf_js_rules() {
    return [
        ['jspw', 'high', 'Password checked in the browser', '/\b(?:password|passwd|pwd|passcode)\w*\s*(?:===?|!==?)\s*[\'"`][^\'"`\s]{3,}[\'"`]|[\'"`][^\'"`\s]{3,}[\'"`]\s*===?\s*\w*(?:password|passwd|pwd)\w*\b(?!\s*[.(])/i', null, 'The password is in a file every visitor downloads, and the check can be skipped from the browser console. This protects nothing.', 'move the login check to server-side code: the browser sends the password, the server verifies it with password_verify() and starts a session, and every protected page checks that session on the server.'],
        ['jseval', 'high', 'Part of the page address is run as code', '/\beval\s*\([^;\n]{0,200}(?:location\.|document\.URL|\.hash\b|\.search\b|searchParams)/', null, 'A crafted link can run any script in a visitor\'s browser.', 'remove eval(). Parse the value as data (JSON.parse, URLSearchParams) instead.'],
        ['domxss', 'medium', 'Part of the page address is written into the page as HTML', '/\.innerHTML\s*\+?=[^;\n]{0,200}(?:location\.(?:hash|search|href)|document\.URL|document\.referrer|URLSearchParams|searchParams\.get)|document\.write\s*\([^;\n]{0,200}(?:location\.|document\.URL|document\.referrer)/', '/DOMPurify|encodeURIComponent|escapeHtml/', 'A crafted link can inject script into the page (DOM XSS).', 'use textContent instead of innerHTML for values taken from the address, or sanitise them first.'],
    ];
}
function ssf_mask($s) { $s = (string) $s; $n = strlen($s); return $n <= 12 ? substr($s, 0, 3) . '...' : substr($s, 0, 7) . '...' . substr($s, -3) . " ($n chars)"; }
function ssf_line_of($c, $off) { return substr_count($c, "\n", 0, $off) + 1; }
function ssf_line_text($c, $off) { $s = strrpos(substr($c, 0, $off), "\n"); $s = $s === false ? 0 : $s + 1; $e = strpos($c, "\n", $off); return ssf_one_line(substr($c, $s, ($e === false ? strlen($c) : $e) - $s), 180); }
function ssf_prompt($rel, $lines, $what, $how) {
    return 'Security problem in the file ' . $rel . ($lines ? ' (around line' . (count($lines) === 1 ? ' ' : 's ') . implode(', ', $lines) . ')' : '') . ': ' . rtrim($what, '.') . '. Please fix it: ' . $how . ' Keep the page working exactly as before, change nothing else, and show me the lines you changed.';
}
/** URL for a file if it sits under the document root of the site this tool was opened on. */
function ssf_url_for($abs) {
    if (PHP_SAPI === 'cli' || empty(ssf_srv('HTTP_HOST')) || empty(ssf_srv('DOCUMENT_ROOT'))) return null;
    $doc = rtrim((string) realpath(ssf_srv('DOCUMENT_ROOT')), '/');
    if ($doc === '' || strpos($abs, $doc . '/') !== 0) return null;
    $https = !empty(ssf_srv('HTTPS')) && ssf_srv('HTTPS') !== 'off';
    return ($https ? 'https://' : 'http://') . ssf_srv('HTTP_HOST') . implode('/', array_map('rawurlencode', explode('/', substr($abs, strlen($doc)))));
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
    $mm = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    $where = ' This is the PHP that runs the folder this tool sits in; other sites on the account can be set differently.';
    if (version_compare($mm, '8.2', '<')) ssf_add($st, ['cat' => 'config', 'sev' => 'high', 'title' => 'PHP ' . PHP_VERSION . ' no longer gets security fixes', 'detail' => 'This PHP version is past its end of life, so newly found holes in PHP itself are never patched. In cPanel open "Select PHP Version" or "MultiPHP Manager" and choose 8.3 or newer, then test the site.' . $where]);
    elseif (isset($eol[$mm]) && time() > strtotime($eol[$mm] . ' -120 days')) ssf_add($st, ['cat' => 'config', 'sev' => time() > strtotime($eol[$mm]) ? 'high' : 'low', 'title' => 'PHP ' . $mm . (time() > strtotime($eol[$mm]) ? ' no longer gets security fixes' : ' stops getting security fixes on ' . date('j F Y', strtotime($eol[$mm]))), 'detail' => 'Plan the move to a newer PHP version in cPanel ("Select PHP Version" or "MultiPHP Manager"), then test the site.' . $where]);
    if (in_array(strtolower((string) ini_get('display_errors')), ['1', 'on', 'stdout', 'true'], true)) ssf_add($st, ['cat' => 'config', 'sev' => 'medium', 'title' => 'PHP error messages are shown to visitors', 'detail' => 'Errors reveal file paths, database queries and sometimes passwords. In cPanel open "MultiPHP INI Editor" and turn display_errors off; keep log_errors on.' . $where]);
    if (in_array(strtolower((string) ini_get('allow_url_include')), ['1', 'on', 'true'], true)) ssf_add($st, ['cat' => 'config', 'sev' => 'high', 'title' => 'PHP may load code from other websites (allow_url_include)', 'detail' => 'This setting turns many small bugs into full takeovers. Turn allow_url_include off in cPanel "MultiPHP INI Editor".' . $where]);
    if (PHP_SAPI === 'cli' || empty(ssf_srv('HTTP_HOST'))) { $st['notes'][] = 'Run from the command line, so nothing was tested over the web: HTTPS, security headers and directory listing were not checked.'; return; }
    $host = ssf_srv('HTTP_HOST');
    list($code, $h) = ssf_http_head('http://' . $host . '/');
    if ($code === 0) { $st['notes'][] = 'The server could not open its own website, so HTTPS, security headers and directory listing were not checked.'; return; }
    $loc = $h['location'] ?? '';
    if ($code >= 200 && $code < 300) ssf_add($st, ['cat' => 'config', 'sev' => 'medium', 'title' => 'The site opens without HTTPS', 'detail' => 'http://' . $host . '/ answers directly instead of sending visitors to https://. Logins and forms sent this way can be read on the network. Turn on "Force HTTPS Redirect" for the domain in cPanel > Domains (an SSL certificate must be installed first).']);
    list($code2, $h2) = ssf_http_head('https://' . $host . '/');
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
        foreach (array_merge(@glob($doc . '/*', GLOB_ONLYDIR) ?: [], @glob($doc . '/*/*', GLOB_ONLYDIR) ?: []) as $dname) {
            if ($tries >= 3) break;
            if (is_link($dname) || (@glob($dname . '/index.*') ?: []) || !(@glob($dname . '/*.*') ?: []) || preg_match('#/(cgi-bin|\.well-known|wp-admin|wp-includes)(/|$)#', $dname)) continue;
            $tries++;
            list($c3, , $body) = ssf_http_head(ssf_url_for($dname . '/x') ? substr(ssf_url_for($dname . '/x'), 0, -1) : '');
            if ($c3 === 200 && stripos($body, 'Index of /') !== false) { $st['listing'] = substr($dname, strlen($doc)) . '/'; break; }
        }
    }
}

/* ------------------------------------------------------------------ security audit: folders and files */
/** Called for every folder the walk meets. Returns true if the walk should not go inside. */
function ssf_audit_dir(&$st, $p, $name, $ip) {
    $site = $ip !== null ? $st['installs'][$ip]['rel'] : '';
    $rel = ssf_rel($st, $p);
    if ((@fileperms($p) & 0002) && $name !== '.tmb') { if (count($st['perms']) < 300) $st['perms'][] = $rel; $st['perms_n'] = ($st['perms_n'] ?? 0) + 1; }
    if ($name === '.git' && (is_file("$p/HEAD") || is_dir("$p/objects"))) {
        ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'exposure', 'sev' => 'high', 'title' => 'Git repository inside the web folder', 'detail' => 'If /.git/ can be reached from the web, anyone can download the full source code and its history, including passwords that were ever committed.' . ssf_probe($st, "$p/HEAD") . ' The "protect files" rule blocks it; better still, deploy without the .git folder.']);
        $st['harden_need'] = true;
        return true;
    }
    if ($name === '.svn' || $name === '.hg') { ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'exposure', 'sev' => 'medium', 'title' => 'Version-control folder inside the web folder', 'detail' => 'It can expose the source code. The "protect files" rule blocks it.']); $st['harden_need'] = true; return true; }
    if ($name === 'node_modules') { ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'exposure', 'sev' => 'low', 'title' => 'node_modules uploaded to the web folder', 'detail' => 'Build tools and their thousands of files do not belong on the live site. Upload only the built output (usually the dist or build folder).']); return true; }
    if ($name === 'dup-installer') { ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'exposure', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Duplicator installer left behind', 'detail' => 'Leftover installer files let a stranger reinstall the site over itself and take it over.']); return true; }
    if (preg_match('/^(phpmyadmin|pma|myadmin|adminer)$/i', $name) && (is_file("$p/index.php"))) ssf_add($st, ['site' => $site, 'path' => $rel, 'kind' => 'dir', 'cat' => 'access', 'sev' => 'medium', 'title' => 'Database admin tool inside the web folder', 'detail' => 'A copy of phpMyAdmin or Adminer here is a login page to the database for the whole internet. Use the one in cPanel instead and remove this folder.']);
    return false;
}
/** Called for every file. Returns true when the file has been fully dealt with. */
function ssf_audit_file(&$st, $p, $name, $ext, $size, $rel, $site, $loc, $isPhp) {
    static $TEXT = ['js' => 1, 'mjs' => 1, 'cjs' => 1, 'html' => 1, 'htm' => 1, 'json' => 1, 'txt' => 1, 'xml' => 1, 'yml' => 1, 'yaml' => 1, 'ini' => 1, 'conf' => 1, 'cfg' => 1, 'config' => 1, 'ts' => 1, 'tsx' => 1, 'jsx' => 1, 'vue' => 1, 'svelte' => 1, 'map' => 1, 'env' => 1, 'toml' => 1, 'properties' => 1, 'py' => 1];
    $add = function ($f) use (&$st, $site, $rel) { ssf_add($st, $f + ['site' => $site, 'path' => $rel, 'kind' => 'file']); };
    $lname = strtolower($name);

    /* --- exposed by name: applies everywhere --- */
    if (preg_match('/^\.env(\.(?!example$|sample$|dist$|template$)[\w.-]+)?$/i', $name)) {
        $pr = ssf_probe($st, $p);
        $add(['cat' => 'secrets', 'sev' => strpos($pr, 'Confirmed') !== false ? 'critical' : 'high', 'title' => 'Environment file (.env) inside the web folder', 'detail' => 'This file usually holds database passwords and API keys.' . $pr . ' Do not move it (the app reads it). Apply the "protect files" rule, and if it was ever downloadable, change every password and key in it. Best of all, keep it one level above public_html.']);
        $st['harden_need'] = true; return true;
    }
    if ($isPhp && $size < 400 && preg_match('/^\s*<\?(?:php)?\s*(?:echo\s+)?phpinfo\s*\(\s*\)\s*;?\s*(?:\?>)?\s*$/i', (string) @file_get_contents($p))) { $add(['cat' => 'exposure', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => true, 'title' => 'phpinfo() test page left on the site', 'detail' => 'It shows visitors the full server configuration, paths and loaded modules, which is a map for an attacker.']); return true; }
    if ($isPhp && preg_match('/^adminer([-.\w]*)\.php$/i', $name)) { $add(['cat' => 'access', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Adminer database tool left on the site', 'detail' => 'A single-file database manager: anyone who finds it gets a login page to your database, and old versions have known holes. Use phpMyAdmin in cPanel instead.']); return true; }
    if ($isPhp && preg_match('/^installer(-backup)?\.php$/i', $name) && stripos((string) @file_get_contents($p, false, null, 0, 20000), 'duplicator') !== false) { $add(['cat' => 'exposure', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Duplicator installer left behind', 'detail' => 'Leftover installer files let a stranger reinstall the site over itself and take it over.']); return true; }
    if (preg_match('#(^|/)vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php$#', $rel)) { $add(['cat' => 'exposure', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => true, 'title' => 'PHPUnit test helper reachable from the web', 'detail' => 'This development file runs any code sent to it (CVE-2017-9841) and is scanned for constantly. The whole vendor/phpunit folder should not be on a live site; install with "composer install --no-dev".']); return true; }
    if (preg_match('/\.(?:php\d?|phtml|inc)(?:\.(?:bak|old|orig|save|swp|swo|txt|copy|backup|tmp|\d+)|~|_bak|_old|-bak|-old)$/i', $name) && !preg_match('/^wp-config/i', $name)) {
        $add(['cat' => 'exposure', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Backup copy of a PHP file, readable as plain text', 'detail' => 'The server does not run this as PHP, it sends the source code to anyone who asks, including any passwords in it.' . ssf_probe($st, $p)]);
        $st['harden_need'] = true; return true;
    }
    if ($ext === 'sql' && $size > 2000) { $add(['cat' => 'exposure', 'sev' => 'high', 'fix' => 'quarantine', 'tick' => true, 'title' => 'Database dump in the web folder (' . ssf_hsize($size) . ')', 'detail' => 'A copy of the database that anyone who guesses the name can download: users, password hashes, customer details.' . ssf_probe($st, $p)]); $st['harden_need'] = true; return true; }
    if (in_array($ext, ['sqlite', 'sqlite3', 'db'], true) && $size > 100 && strpos((string) @file_get_contents($p, false, null, 0, 16), 'SQLite format') === 0) { $add(['cat' => 'exposure', 'sev' => 'high', 'title' => 'SQLite database file inside the web folder', 'detail' => 'The whole database can be downloaded as one file.' . ssf_probe($st, $p) . ' Do not move it if the app uses it; apply the "protect files" rule, and move the database above public_html when you can.']); $st['harden_need'] = true; return true; }
    if (preg_match('/^(id_rsa|id_ed25519|id_dsa)$|\.(pem|key|p12|pfx|ppk)$/i', $name) && $size > 0 && $size < 20000) {
        $c = (string) @file_get_contents($p);
        if ($ext === 'p12' || $ext === 'pfx' || $ext === 'ppk' || strpos($c, 'PRIVATE KEY') !== false) { $add(['cat' => 'secrets', 'sev' => 'critical', 'fix' => 'quarantine', 'tick' => false, 'title' => 'Private key file inside the web folder', 'detail' => 'A private key that can be fetched from the web must be treated as stolen: replace the key pair. Left unticked in case the site reads this file.']); $st['harden_need'] = true; return true; }
    }
    if (preg_match('/^(credentials|secrets?|service[-_]?account)[\w.-]*\.(json|ya?ml|txt)$/i', $name) || $lname === '.htpasswd' || $lname === '.bash_history' || $lname === '.npmrc' || $lname === '.netrc') { $add(['cat' => 'secrets', 'sev' => 'high', 'title' => 'Credentials file inside the web folder', 'detail' => 'By its name this file holds logins or keys.' . ssf_probe($st, $p) . ' Move it above public_html, and apply the "protect files" rule in the meantime.']); $st['harden_need'] = true; return true; }
    if ($lname === 'debug.log' && $loc === 'content') { $add(['cat' => 'exposure', 'sev' => 'medium', 'fix' => 'quarantine', 'tick' => true, 'title' => 'WordPress debug log readable from the web', 'detail' => 'It reveals paths, plugin errors and sometimes personal data. Also set WP_DEBUG_LOG to false in wp-config.php, or WordPress will create it again.']); $st['harden_need'] = true; return true; }
    if ($lname === 'error_log' || ($ext === 'log' && $size > 0)) { $st['logs'][] = $rel; if (count($st['logs']) > 400) array_pop($st['logs']); return true; }
    if ($lname === '.ds_store' || $lname === 'thumbs.db') return true;
    $perm = @fileperms($p) & 0777;
    if ($perm & 0002) { if (count($st['perms']) < 300) $st['perms'][] = $rel; $st['perms_n'] = ($st['perms_n'] ?? 0) + 1; }

    /* --- own code only: outside WordPress, or loose files in a WordPress root --- */
    $own = $loc === 'outside' || $loc === 'root' || $loc === 'other';
    if (!$own || $size === 0 || $size > 1500000) return false;
    if (preg_match('#(^|/)(vendor|node_modules|bower_components|phpmailer|tcpdf|dompdf|mpdf|fpdf|phpseclib|simplepie|smarty|twig|guzzlehttp|symfony|ckeditor\d?|tinymce|elfinder|kcfinder|phpunit|phpspreadsheet|phpexcel|fontawesome|bootstrap|jquery[\w.-]*|swiper|slick|lib|libs|libraries|third[-_]?party|plugins)(/|$)#i', $rel)) return false;

    if ($isPhp) {
        if ($loc === 'root') return false;
        $c = (string) @file_get_contents($p);
        if (strpos($c, '$_') === false && stripos($c, 'select ') === false && stripos($c, 'insert into') === false && stripos($c, 'move_uploaded_file') === false) return false;
        $st['audited'] = ($st['audited'] ?? 0) + 1;
        foreach (ssf_code_rules() as $r) {
            if (!@preg_match_all($r[3], $c, $m, PREG_OFFSET_CAPTURE)) continue;
            $lines = []; $ev = '';
            foreach ($m[0] as $hit) {
                if ($r[4] && preg_match($r[4], $hit[0])) continue;
                $ln = ssf_line_of($c, $hit[1]);
                if (!in_array($ln, $lines, true)) { $lines[] = $ln; if (count($lines) <= 3) $ev .= ($ev ? "\n" : '') . 'line ' . $ln . ': ' . ssf_line_text($c, $hit[1]); }
            }
            if (!$lines) continue;
            $more = count($lines) > 8 ? ' and ' . (count($lines) - 8) . ' more' : '';
            $add(['cat' => 'code', 'sev' => $r[1], 'title' => $r[2], 'detail' => $r[5] . ' Found on line' . (count($lines) === 1 ? ' ' : 's ') . implode(', ', array_slice($lines, 0, 8)) . $more . '. This is a pattern match, so read the lines before changing them.', 'evidence' => $ev, 'prompt' => ssf_prompt($rel, array_slice($lines, 0, 8), $r[2] . '. ' . $r[5], $r[6])]);
        }
        if (stripos($c, 'move_uploaded_file') !== false && !preg_match('/pathinfo|finfo|mime_content_type|getimagesize|in_array|allowed|extension|\.jpe?g|\.png|\.pdf|wp_check_filetype|exif_imagetype/i', $c))
            $add(['cat' => 'code', 'sev' => 'high', 'title' => 'File upload with no check on the file type', 'detail' => 'This script saves whatever is uploaded. If a visitor can reach it, they can upload a PHP file and run it, which is a full takeover.', 'evidence' => 'move_uploaded_file() with no extension or type check in the file', 'prompt' => ssf_prompt($rel, [], 'The upload handler saves any file a visitor sends, with no check on its type', 'allow only a fixed list of extensions (for example jpg, png, pdf), check the real type with finfo, give the saved file a random name, store it in a folder where PHP cannot run, and reject everything else.')]);
        if (preg_match('/<form\b[^>]*method\s*=\s*["\']?post/i', $c) && strpos($c, '$_POST') !== false && !preg_match('/csrf|token|nonce|_wpnonce|captcha/i', $c))
            $add(['cat' => 'code', 'sev' => 'low', 'title' => 'Form without protection against forged requests (CSRF)', 'detail' => 'Another website can submit this form on behalf of a logged-in visitor. It matters most on forms that change data, send money or change passwords.', 'prompt' => ssf_prompt($rel, [], 'The POST form has no CSRF protection', 'generate a random token with bin2hex(random_bytes(32)), store it in the session, add it as a hidden field, and reject the POST with hash_equals() if the token does not match.')]);
        return false;
    }
    if (!isset($TEXT[$ext])) return false;
    $c = (string) @file_get_contents($p);
    /* secrets in files that the server hands out as-is */
    $seen = [];
    foreach (ssf_secret_rules() as $r) {
        if (!@preg_match($r[1], $c, $m, PREG_OFFSET_CAPTURE) || isset($seen[$m[0][0]])) continue;
        $seen[$m[0][0]] = 1;
        if ($r[0] === 'OpenAI API key' && preg_match('/^sk-ant-/', $m[0][0])) continue;
        $add(['cat' => 'secrets', 'sev' => $r[2], 'title' => $r[0] . ' in a file every visitor can read', 'detail' => 'Anything in a .' . $ext . ' file is sent to the browser as-is, so this key is public. ' . $r[3] . ' Removing it from the file is not enough: the old key must be revoked.', 'evidence' => 'line ' . ssf_line_of($c, $m[0][1]) . ': ' . ssf_mask($m[0][0]), 'prompt' => ssf_prompt($rel, [ssf_line_of($c, $m[0][1])], 'A secret key is included in code that runs in the browser', 'move every call that needs this key into a small server-side endpoint (PHP) that reads the key from a config file outside the web folder, and have the browser call that endpoint instead. Remove the key from all front-end files.')]);
    }
    if (preg_match_all('/eyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/', $c, $jm, PREG_OFFSET_CAPTURE)) {
        foreach ($jm[1] as $i => $pl) {
            $json = (string) base64_decode(strtr($pl[0], '-_', '+/'));
            if (strpos($json, 'service_role') !== false) { $add(['cat' => 'secrets', 'sev' => 'critical', 'title' => 'Supabase service-role key in a file every visitor can read', 'detail' => 'This key bypasses every database rule: whoever has it can read, change and delete all data. Roll it in Supabase (Settings > API) now, and use only the anon key in the browser.', 'evidence' => 'line ' . ssf_line_of($c, $jm[0][$i][1]) . ': ' . ssf_mask($jm[0][$i][0]), 'prompt' => ssf_prompt($rel, [ssf_line_of($c, $jm[0][$i][1])], 'The Supabase service_role key is used in browser code', 'use only the anon key in the browser, turn on Row Level Security with policies on every table, and move anything that truly needs the service role into server-side code.')]); break; }
        }
    }
    if (preg_match('/createClient\s*\(\s*[\'"`]https:\/\/[a-z0-9]+\.supabase\.co/i', $c)) $st['baas']['Supabase'] = $rel;
    if (preg_match('/firebaseConfig|firebaseapp\.com|firebaseio\.com/i', $c)) $st['baas']['Firebase'] = $rel;
    if ($ext === 'py') { $st['srcexp'][] = $rel; if (preg_match('/\bapp\.run\s*\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True/m', $c)) $add(['cat' => 'config', 'sev' => 'medium', 'title' => 'Python app has debug mode switched on', 'detail' => 'Debug mode shows source code and, in Flask, an interactive console to anyone who triggers an error. Turn it off on the live site.']); return false; }
    $isJs = in_array($ext, ['js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'vue', 'svelte', 'html', 'htm'], true);
    if (!$isJs) return false;
    if (preg_match('/require\s*\(\s*[\'"](?:express|mysql2?|pg|mongoose|jsonwebtoken|bcrypt(?:js)?|dotenv|nodemailer)[\'"]\s*\)|from\s+[\'"](?:express|mysql2|mongoose)[\'"]/', $c) && strpos($c, 'process.env') !== false) { $st['srcexp'][] = $rel; return false; }
    $lines = substr_count($c, "\n") + 1;
    if ($size / $lines > 400) return false; // minified bundle: secret checks above still ran
    foreach (ssf_js_rules() as $r) {
        if (!@preg_match_all($r[3], $c, $m, PREG_OFFSET_CAPTURE)) continue;
        $ln = []; $ev = '';
        foreach ($m[0] as $hit) { if ($r[4] && preg_match($r[4], $hit[0])) continue; $l = ssf_line_of($c, $hit[1]); if (!in_array($l, $ln, true)) { $ln[] = $l; if (count($ln) <= 3) $ev .= ($ev ? "\n" : '') . 'line ' . $l . ': ' . ($r[0] === 'jspw' ? preg_replace('/([\'"`])[^\'"`\s]{3,}\1/', '$1***$1', ssf_line_text($c, $hit[1])) : ssf_line_text($c, $hit[1])); } }
        if (!$ln) continue;
        $add(['cat' => 'code', 'sev' => $r[1], 'title' => $r[2], 'detail' => $r[5] . ' Found on line' . (count($ln) === 1 ? ' ' : 's ') . implode(', ', array_slice($ln, 0, 8)) . '. This is a pattern match, so read the lines before changing them.', 'evidence' => $ev, 'prompt' => ssf_prompt($rel, array_slice($ln, 0, 8), $r[2] . '. ' . $r[5], $r[6])]);
    }
    return false;
}

/* ------------------------------------------------------------------ security audit: wrap-up and hardening rules */
function ssf_harden_block($key) {
    $deny = implode("\n", ['    <IfModule mod_authz_core.c>', '      Require all denied', '    </IfModule>', '    <IfModule !mod_authz_core.c>', '      Order allow,deny', '      Deny from all', '    </IfModule>']);
    $lines = [];
    if ($key === 'files') $lines = ['# BEGIN SEO Spam Fix: protect files', '# Blocks hidden files (.env, .git), backups, database dumps, logs and build files from being downloaded.', '<FilesMatch "^\.|\.(?:bak|old|orig|save|swp|sql|sqlite3?|log|ini|dist)$|~$|\.php\.(?:txt|bak|old|orig|save|copy)$|^(?:error_log|composer\.(?:json|lock)|package(?:-lock)?\.json|yarn\.lock|phpunit\.xml)$">', $deny, '</FilesMatch>', '<IfModule mod_alias.c>', '  RedirectMatch 404 "/\.(?:git|svn|hg)(?:/|$)"', '</IfModule>', 'Options -Indexes', '# END SEO Spam Fix: protect files'];
    if ($key === 'headers') $lines = ['# BEGIN SEO Spam Fix: security headers', '<IfModule mod_headers.c>', '  Header always set X-Content-Type-Options "nosniff"', '  Header always set X-Frame-Options "SAMEORIGIN"', '  Header always set Referrer-Policy "strict-origin-when-cross-origin"', '</IfModule>', '# END SEO Spam Fix: security headers'];
    if ($key === 'uploads') $lines = ['# BEGIN SEO Spam Fix: no PHP in uploads', '<FilesMatch "\.(?:php\d?|phtml|phar|pht)$">', $deny, '</FilesMatch>', '# END SEO Spam Fix: no PHP in uploads'];
    return $lines ? implode("\n", $lines) . "\n" : '';
}
function ssf_harden_merge($orig, $key) {
    $block = ssf_harden_block($key);
    $first = strtok($block, "\n");
    $name = substr($first, strlen('# BEGIN '));
    $re = '/^# BEGIN ' . preg_quote($name, '/') . '\R.*?^# END ' . preg_quote($name, '/') . '\R?/ms';
    if (preg_match($re, $orig)) return preg_replace($re, addcslashes($block, '\\$'), $orig, 1);
    return rtrim($orig, "\r\n") . ($orig === '' ? '' : "\n\n") . $block;
}
function ssf_audit_final(&$st) {
    $base = $st['base'];
    $has = function ($file, $marker) { return strpos((string) @file_get_contents($file), $marker) !== false; };
    if (!$has("$base/.htaccess", 'BEGIN SEO Spam Fix: protect files')) {
        $need = !empty($st['harden_need']) || !empty($st['listing']);
        ssf_add($st, ['path' => ssf_rel($st, "$base/.htaccess"), 'kind' => 'none', 'cat' => 'config', 'sev' => $need ? 'high' : 'low', 'fix' => 'harden', 'rule' => 'files', 'tick' => $need,
            'title' => $need ? 'Sensitive files are not blocked from the web' : 'No rule protecting sensitive files',
            'detail' => ($need ? 'The scan found files that should never be downloadable' . (!empty($st['listing']) ? ', and folder contents are listed to visitors (confirmed at ' . $st['listing'] . ')' : '') . '. ' : 'Nothing exposed was found, but there is no safety net if a backup or .env file is uploaded later. ') . 'The fix adds a short block to the .htaccess in the scanned folder that refuses hidden files (.env, .git), backups, database dumps, logs and build files, and turns off folder listing. It covers every site below that folder. The original .htaccess is kept and can be restored; if the rule causes a server error it is rolled back automatically.',
            'evidence' => ssf_harden_block('files')]);
    }
    if (!empty($st['hdr_missing']) && !$has("$base/.htaccess", 'BEGIN SEO Spam Fix: security headers')) {
        ssf_add($st, ['path' => ssf_rel($st, "$base/.htaccess"), 'kind' => 'none', 'cat' => 'config', 'sev' => 'low', 'fix' => 'harden', 'rule' => 'headers', 'tick' => false,
            'title' => 'Security headers missing: ' . implode(', ', $st['hdr_missing']), 'detail' => 'These headers tell browsers not to guess file types, not to let other sites frame your pages (clickjacking), and to send less information to other sites. Left unticked because X-Frame-Options will stop your pages showing inside a frame on another domain; tick it if you do not embed the site elsewhere.' . (empty($st['hsts']) ? ' HSTS (Strict-Transport-Security) is also missing. Add it by hand only once every page and subdomain works on HTTPS, because browsers remember it.' : ''),
            'evidence' => ssf_harden_block('headers')]);
    }
    foreach ($st['installs'] as $ip => $I) {
        $u = $ip . '/wp-content/uploads';
        if (!is_dir($u) || $has("$u/.htaccess", 'no PHP in uploads') || preg_match('/php[^\n]*\n[^<]*(Require all denied|Deny from all)/i', (string) @file_get_contents("$u/.htaccess"))) continue;
        ssf_add($st, ['site' => $I['rel'], 'path' => ssf_rel($st, "$u/.htaccess"), 'kind' => 'none', 'cat' => 'config', 'sev' => 'medium', 'fix' => 'harden', 'rule' => 'uploads', 'tick' => false,
            'title' => 'PHP files can run from the uploads folder', 'detail' => 'Uploads is where attackers drop backdoors, because WordPress lets it be written to. The fix adds a rule that stops PHP from running there. Left unticked because a few plugins do run PHP from uploads; after applying it, check that media uploads and your page builder still work.', 'evidence' => ssf_harden_block('uploads')]);
    }
    if (!empty($st['perms_n'])) ssf_add($st, ['cat' => 'config', 'sev' => 'low', 'kind' => 'none', 'fix' => 'chmod', 'tick' => false, 'paths' => $st['perms'], 'title' => $st['perms_n'] . ' file' . ($st['perms_n'] === 1 ? ' or folder is' : 's and folders are') . ' writable by every user on the server', 'detail' => 'On shared hosting that lets a neighbour\'s hacked site change yours. The fix sets files to 644 and folders to 755' . ($st['perms_n'] > count($st['perms']) ? ' for the first ' . count($st['perms']) : '') . ' and remembers the old values for restore. Left unticked because a badly set-up host may need the old permissions for uploads; test after applying.', 'evidence' => ssf_one_line(implode(', ', array_slice($st['perms'], 0, 10)), 700)]);
    if (!empty($st['logs'])) ssf_add($st, ['cat' => 'exposure', 'sev' => 'low', 'title' => count($st['logs']) . ' log file' . (count($st['logs']) === 1 ? '' : 's') . ' inside the web folders', 'detail' => 'Error logs reveal file paths and failed queries. The "protect files" rule stops them being downloaded. You can also delete old ones.', 'evidence' => ssf_one_line(implode(', ', array_slice($st['logs'], 0, 10)), 700)]);
    if (!empty($st['srcexp'])) ssf_add($st, ['cat' => 'exposure', 'sev' => 'medium', 'title' => count($st['srcexp']) . ' server-side source file' . (count($st['srcexp']) === 1 ? '' : 's') . ' (Python or Node) in a web folder', 'detail' => 'Unlike PHP, these are sent to the browser as plain text, so the code and anything written in it can be read. Python and Node apps on cPanel should live outside public_html ("Setup Python App" / "Setup Node.js App" do this for you).', 'evidence' => ssf_one_line(implode(', ', array_slice($st['srcexp'], 0, 10)), 700)]);
    foreach (($st['baas'] ?? []) as $svc => $file) ssf_add($st, ['cat' => 'access', 'sev' => 'medium', 'title' => 'The browser talks to ' . $svc . ' directly: check its access rules', 'detail' => 'With ' . $svc . ' the only thing between a visitor and your data is the rule set in the ' . $svc . ' console (' . ($svc === 'Supabase' ? 'Row Level Security policies' : 'Firestore and Storage rules') . '). This tool cannot see those. Open the console and confirm that no table or collection is readable or writable by everyone. Sites built with AI tools are very often left open here.', 'evidence' => 'seen in ' . $file]);
    $st['notes'][] = 'Code weaknesses were looked for in ' . (int) ($st['audited'] ?? 0) . ' of the site\'s own PHP files. WordPress, its plugins and themes, and bundled libraries are not audited line by line; they are compared with official copies or pattern-scanned for malware instead.';
}
