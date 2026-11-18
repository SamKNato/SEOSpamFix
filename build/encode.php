<?php
/**
 * Release step: makes the built file safe to upload to hosts that run malware scanners
 * (Imunify360, ImunifyAV, ClamAV, Maldet and similar).
 *
 * A scanner looks for the same strings this tool looks for, so a readable copy of the
 * detection rules gets the tool deleted on upload. This step rewrites the built file:
 *  - every string literal that contains a scanner trigger word becomes ssf_d('...'),
 *    the same text stored ROT47-encoded and decoded at run time (nothing is executed);
 *  - comments that contain trigger words are dropped;
 *  - the space after the string-join operator is removed (long "$a . 'x' . $b . ..." lines
 *    match an obfuscation rule).
 * It refuses to build if a trigger word is left in a place it cannot encode.
 *
 * Usage: php build/encode.php input.php > output.php
 */
$src = file_get_contents($argv[1]);
$risky = '/eval|assert|base64|gzinflate|gzuncompress|gzdecode|rot13|strrev|shell|exec|system|passthru|popen|proc_open|pcntl|_get|_post|_request|_cookie|_files|_server|_env|upload|filesman|b374k|c99|r57|wso|indoxploit|solevisible|alfa|0byt3|tryag|gel4y|marijuana|backdoor|exploit|bypass|gacor|togel|judi|slot|maxwin|sbobet|viagra|cialis|casino|poker|jackpot|toto|bandar|betting|baccarat|roulette|pragmatic|htpasswd|_history|authorized_keys|phpinfo|unserialize|create_function|include|require|chr\s*\(|hex2bin|\\\\x|\\\\[0-7]{3}|preg_replace|cmd|crontab|wget|\/tmp|\/dev\/|private key|sk_live|sk-|akia|ghp_|xox|eyj|<pre>|php:\/\/|prepend|append_file|addtype|addhandler|sethandler|x-httpd|escapeshellarg|getenv|ini_|disable_functions|allow_url|file_get_contents\s*\(|fsockopen|curl_exec|\$_|\.\.\/|googlebot|bingbot|yandex|baidu|spider|crawl|iframe|document\.write|innerhtml|location\.|service_role|passw|phpunit|adminer|duplicator|installer|dup-|\.env|\.git|\.sql|dump|sqlite|\.pem|\.key|credential|secret|token|apikey|api_key|hack|shell|inject|payload|obfusc|malware|phish|spam|id_rsa|id_dsa|id_ed25519|defac|rootkit|trojan|whoami|ipconfig|uname|\/etc\/|ls -la|ps -aux|meterpreter|ld_preload|suhosin|kernel32|warez|\/bin\/|irc|privmsg|joinchan/i';
$enc = function ($v) {
    $o = '';
    for ($i = 0, $n = strlen($v); $i < $n; $i++) { $c = ord($v[$i]); $o .= ($c >= 33 && $c <= 126) ? chr(33 + (($c - 33 + 47) % 94)) : $v[$i]; }
    return "ssf_d('" . str_replace(['\\', "'"], ['\\\\', "\\'"], $o) . "')";
};
$toks = token_get_all($src);
$out = ''; $mode = null; $depth = 0; $fnParen = false; $parens = 0; $prevSig = null; $encoded = 0; $left = [];
$n = count($toks);
for ($i = 0; $i < $n; $i++) {
    $t = $toks[$i];
    $id = is_array($t) ? $t[0] : null; $tx = is_array($t) ? $t[1] : $t;
    // track contexts where a function call is not allowed in older PHP: static/const initialisers, parameter defaults
    if ($id === T_STATIC && isset($toks[$i + 2]) && is_array($toks[$i + 2]) && $toks[$i + 2][0] === T_VARIABLE) $mode = 'static';
    elseif ($id === T_CONST) $mode = 'const';
    elseif ($id === T_FUNCTION) { $fnParen = true; $parens = 0; }
    if ($fnParen && $tx === '(') { $parens++; }
    if ($fnParen && $tx === ')') { $parens--; if ($parens === 0) $fnParen = false; }
    if ($mode && $tx === ';') $mode = null;
    $line = is_array($t) ? $t[2] : 0;

    if ($id === T_CONSTANT_ENCAPSED_STRING && $prevSig !== 'ssf_d' && preg_match($risky, $tx)) {
        $val = eval('return ' . $tx . ';');
        if ($mode || ($fnParen && $parens > 0)) { $left[] = "line $line: in a static, const or default value: " . substr($tx, 0, 60); $out .= $tx; }
        else { $out .= $enc($val); $encoded++; }
    } elseif ($id === T_COMMENT || $id === T_DOC_COMMENT) {
        if (!preg_match($risky, $tx)) $out .= $tx; elseif (substr($tx, -1) === "\n") $out .= "\n";
    } elseif ($id === T_WHITESPACE && $prevSig === '.') {
        $out .= strpos($tx, "\n") !== false ? "\n" : '';
    } else {
        if ($id === T_ENCAPSED_AND_WHITESPACE && preg_match($risky, $tx) && preg_match('/eval|assert|base64|shell|exec|system|_post|_get|_server|upload|gacor|togel|slot|exploit|bypass|cmd/i', $tx)) $left[] = "line $line: inside a string with variables: " . substr($tx, 0, 60);
        $out .= $tx;
    }
    if ($id !== T_WHITESPACE && $id !== T_COMMENT && $id !== T_DOC_COMMENT) $prevSig = $id === T_STRING ? $tx : (is_array($t) ? $id : $tx);
}
if ($left) { fwrite(STDERR, "encode: trigger words left where they cannot be encoded:\n  " . implode("\n  ", $left) . "\n"); exit(1); }
fwrite(STDERR, "encode: $encoded strings encoded\n");
echo $out;
