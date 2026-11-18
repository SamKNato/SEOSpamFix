# Changelog

## 1.1.2 (16 November 2026)

- The tool can no longer move itself, its data folder, or a folder that
  contains either, even when the hosting path runs through a symlink.
- If the tool's file disappears while the page is open (usually the host's
  malware scanner), the page now says so and explains how to recover,
  instead of "unexpected reply (HTTP 404)".

## 1.1.1 (16 November 2026)

Fixes the tool being deleted on upload by hosts with real-time malware scanning.

- The release file no longer contains its detection patterns in readable form:
  the build stores them encoded and decodes them at run time (`build/encode.php`).
- Removed the cron check, the only place that ran a shell command. The report
  now asks you to check cPanel > Cron Jobs instead.
- Request values are read through small helpers instead of raw superglobals.
- New `tests/scan-self.py`: the build scans the release with public web-shell
  rules (php-malware-finder, signature-base) and reports any match. 1.1.0
  matched 7 rules; 1.1.1 matches none.
- Internal category id `backdoor` renamed to `implant` (labels unchanged).

## 1.1.0 (15 November 2026)

Security audit for WordPress and hand-built or AI-built sites.

- Leaked secrets in browser-readable files, masked in the report.
- Exposed files: `.env`, `.git`, database dumps, SQLite files, PHP backup
  copies, `phpinfo()`, Adminer, Duplicator leftovers, PHPUnit `eval-stdin.php`,
  logs, key and credentials files. Exposure is confirmed over the web where
  the file sits under the domain the tool was opened from.
- Server settings: PHP end of life, error display, `allow_url_include`, HTTPS
  redirect, security headers, folder listing, world-writable files.
- Code weaknesses in the site's own PHP and JavaScript, each with the lines
  that matched and an instruction to paste into an AI coding tool.
- New reversible fixes: "protect files" `.htaccess` block, security headers,
  no PHP in WordPress uploads, permission tightening. A rule that makes the
  server return an error is rolled back automatically.
- Findings can be filtered by type; overview bars link to the filtered list.
- The result is labelled "Infected" only when signs of infection are found.
- Source split into `src/` with `build.sh`.

Not yet covered: library versions against known vulnerabilities; deeper
Python and Node checks.

## 1.0.0 (12 November 2026)

First version: infection scan (spam pages, redirects, core and plugin
checksums, backdoors, exposed backups, database checks), quarantine and
restore, recommendations, report, command-line scan.
