"""
Helper script called by build.bat
Reads VERSION from vaultkey.py and writes version.json
"""
import re, json, sys

try:
    with open('vaultkey.py', 'r', encoding='utf-8') as f:
        content = f.read()

    match = re.search(r"VERSION\s*=\s*[\"']([\d.]+)[\"']", content)
    if not match:
        print('[ERROR] Could not find VERSION in vaultkey.py')
        sys.exit(1)

    version = match.group(1)

    with open('version.json', 'w', encoding='utf-8') as f:
        json.dump({"version": version}, f, indent=2)

    print('[OK] Version ' + version + ' written to version.json')

except FileNotFoundError:
    print('[ERROR] vaultkey.py not found. Make sure you run build.bat from the vaultkey folder.')
    sys.exit(1)
