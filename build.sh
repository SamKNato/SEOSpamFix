#!/bin/sh
# Builds the single-file release from the parts in src/.
#   1. joins the parts
#   2. encodes detection patterns so host malware scanners do not delete the tool (build/encode.php)
#   3. syntax-checks the result
#   4. if python3 with yara-python is installed, scans the result with public web-shell rules (tests/scan-self.py)
set -e
cd "$(dirname "$0")"
cat src/10-helpers-rules.php src/20-scan-sites.php src/30-scan-files.php src/35-audit.php src/40-actions-report.php src/50-web.php src/60-app.js src/70-end.php > build/joined.php
php -l build/joined.php > /dev/null
php build/encode.php build/joined.php > seo-spam-fix.php
rm -f build/joined.php
php -l seo-spam-fix.php
if python3 -c "import yara" 2>/dev/null; then python3 tests/scan-self.py seo-spam-fix.php; else echo "yara-python not installed: skipped the malware-rule self-check"; fi
