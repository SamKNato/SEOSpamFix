#!/usr/bin/env python3
"""Scans the built release with public web-shell rules, the kind host scanners use.

Needs: pip install yara-python, plus two rule sets cloned next to the repo:
  git clone --depth 1 https://github.com/jvoisin/php-malware-finder.git ../rules/php-malware-finder
  git clone --depth 1 https://github.com/Neo23x0/signature-base.git ../rules/signature-base
Rule paths can also be given with SSF_RULES=/path/to/rules.

A clean result here does not guarantee that a commercial scanner (Imunify360, ClamAV with
paid signatures) will accept the file, but any hit here almost certainly means it will not.
Exit code 1 if anything matches.
"""
import glob, os, sys
import yara

here = os.path.dirname(os.path.abspath(__file__))
roots = [os.environ.get('SSF_RULES', ''), os.path.join(here, '..', '..', 'rules'), os.path.join(here, '..', 'rules'), '/home/claude/scanners']
files = []
for r in roots:
    if not r or not os.path.isdir(r):
        continue
    files += glob.glob(os.path.join(r, '**', 'php.yar'), recursive=True)
    files += [f for f in glob.glob(os.path.join(r, '**', 'yara', '*.yar'), recursive=True) if 'webshell' in f or 'php' in os.path.basename(f)]
    if files:
        break
if not files:
    print('scan-self: no rule sets found, skipped (see the comment at the top of tests/scan-self.py)')
    sys.exit(0)
ext = {'filename': '', 'filepath': '', 'extension': '', 'filetype': '', 'owner': ''}
target = sys.argv[1]
data = open(target, 'rb').read()
hits = []
for f in files:
    try:
        r = yara.compile(filepath=f, externals=ext)
    except Exception:
        continue
    for m in r.match(data=data, externals={'filename': os.path.basename(target), 'filepath': target, 'extension': '.php', 'filetype': 'php', 'owner': ''}):
        hits.append(f"{os.path.basename(f)}: {m.rule}")
if hits:
    print('scan-self: the release matches malware rules and is likely to be deleted by host scanners:')
    for h in hits:
        print('  ' + h)
    sys.exit(1)
print(f'scan-self: clean against {len(files)} rule files')
