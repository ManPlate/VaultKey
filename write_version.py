"""
Helper script called by build.bat
1. Reads VERSION and CHANGELOG from marai.py
2. Writes version.json
3. Auto-updates the version table in README.md
"""
import re, json, sys

try:
    with open('marai.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # ── Read version ──────────────────────────────────────────────────────
    version_match = re.search(r"VERSION\s*=\s*[\"']([\d.]+)[\"']", content)
    if not version_match:
        print('[ERROR] Could not find VERSION in marai.py')
        sys.exit(1)
    version = version_match.group(1)

    # ── Read changelog ────────────────────────────────────────────────────
    changelog = re.findall(r'\("([\d.]+)",\s*"([^"]+)"\)', content)
    if not changelog:
        print('[ERROR] Could not find CHANGELOG in marai.py')
        sys.exit(1)

    # ── Write version.json ────────────────────────────────────────────────
    with open('version.json', 'w', encoding='utf-8') as f:
        json.dump({"version": version}, f, indent=2)
    print('[OK] version.json updated to v' + version)

    # ── Build version table ───────────────────────────────────────────────
    rows = ['| Version | What\'s New |', '|---|---|']
    for ver, note in changelog:
        tag = f' ← current' if ver == version else ''
        rows.append(f'| **v{ver}**{tag} | {note} |')
    table = '\n'.join(rows)

    new_block = (
        '<!-- VERSION_TABLE_START -->\n'
        + table + '\n'
        + '<!-- VERSION_TABLE_END -->'
    )

    # ── Update README.md ──────────────────────────────────────────────────
    with open('README.md', 'r', encoding='utf-8') as f:
        readme = f.read()

    updated_readme = re.sub(
        r'<!-- VERSION_TABLE_START -->.*?<!-- VERSION_TABLE_END -->',
        new_block,
        readme,
        flags=re.DOTALL
    )

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(updated_readme)
    print('[OK] README.md version table updated to v' + version)

except FileNotFoundError as e:
    print(f'[ERROR] File not found: {e}')
    print('Make sure you run build.bat from the marai folder.')
    sys.exit(1)
