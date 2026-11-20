"""Match checked-in WOFF2 bytes and notice coverage to locked npm archives."""

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
from urllib.request import urlopen


PACKAGES = ('@fontsource-variable/jetbrains-mono', '@fontsource-variable/space-grotesk')
ARCHIVE_LIMIT = 1 << 20
EXPANDED_LIMIT = 2 << 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def inspect_archive(raw, name, version, integrity):
    calculated = 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode('ascii')
    require(calculated == integrity, 'Font publication integrity differs from the lock')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        expanded = stream.read(EXPANDED_LIMIT + 1)
    require(0 < len(expanded) <= EXPANDED_LIMIT, 'Font archive expansion limit')
    members, fonts, notices = set(), {}, {}
    manifest = None
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        for entry in archive:
            path = entry.name.rstrip('/') if entry.isdir() else entry.name
            require(len(members) < 256 and path not in members and (path == 'package' or path.startswith('package/'))
                and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', part) and part not in ('.', '..')
                    for part in path.split('/')), 'Font archive member path or limit')
            members.add(path)
            if entry.isdir():
                require(entry.size == 0, 'Unexpected font archive directory payload')
                continue
            require(entry.isfile() and 0 <= entry.size <= ARCHIVE_LIMIT, 'Expected a regular font archive member')
            member = path.removeprefix('package/')
            if member == 'package.json' or member.endswith('.woff2') or (
                    '/' not in member and re.match(r'(?i)^(license|licence|ofl|notice)', member)):
                body = archive.extractfile(entry).read()
                require(len(body) == entry.size, 'Truncated font archive member')
                if member == 'package.json':
                    manifest = json.loads(body)
                elif member.endswith('.woff2'):
                    require(body.startswith(b'wOF2'), 'Invalid WOFF2 publication member')
                    fonts[member] = pin(body)
                else:
                    notices[member] = pin(body)
    require(manifest and (manifest.get('name'), manifest.get('version'), manifest.get('license'))
        == (name, version, 'OFL-1.1'), 'Font package identity or license declaration differs')
    require(fonts and notices, 'Font publication lacks font or notice members')
    return {'archive': pin(raw), 'fonts': fonts, 'notices': notices}


def publication(name, row):
    version = row['version']
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version), 'Invalid locked font version')
    url = f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{version}.tgz"
    require(row['resolved'] == url and re.fullmatch(r'sha512-[A-Za-z0-9+/]{86}==', row['integrity']),
        'Invalid locked font publication')
    with urlopen(url, timeout=20) as stream:
        require(stream.status == 200 and stream.geturl() == url, 'Unexpected font publication response')
        raw = stream.read(ARCHIVE_LIMIT + 1)
    require(0 < len(raw) <= ARCHIVE_LIMIT, 'Font archive transport limit')
    return {'name': name, 'version': version, 'url': url, 'integrity': row['integrity'],
        **inspect_archive(raw, name, version, row['integrity'])}


def git(repo, *args):
    return subprocess.check_output(['git', *args], cwd=repo, timeout=10)


def tracked_inputs(repo):
    lock_path = 'web/ui/package-lock.json'
    lock = git(repo, 'show', 'HEAD:' + lock_path)
    tree = git(repo, 'ls-tree', '-rz', 'HEAD', '--', 'web/dist').split(b'\0')
    outputs = {}
    for entry in filter(None, tree):
        header, name = entry.decode('ascii').split('\t', 1)
        mode, kind, blob = header.split()
        require(mode == '100644' and kind == 'blob' and len(outputs) < 256, 'Unexpected embedded viewer tree entry')
        raw = git(repo, 'cat-file', 'blob', blob)
        require(len(raw) <= 2 << 20, 'Embedded viewer member exceeds the inspection limit')
        if name.endswith('.woff2'):
            require(raw.startswith(b'wOF2'), 'Invalid embedded WOFF2 file')
        outputs[name.removeprefix('web/dist/')] = pin(raw)
    return lock, outputs


def review_outputs(outputs, publications):
    matched = {}
    for path, value in sorted(outputs.items()):
        if not path.endswith('.woff2'):
            continue
        matches = [(row['name'], row['version'], member) for row in publications for member, candidate in row['fonts'].items()
            if candidate == value]
        identities = {(name, version) for name, version, _ in matches}
        require(len(identities) == 1, 'Expected one byte-identical locked font publication for ' + path)
        name, version = next(iter(identities))
        matched[path] = {'name': name, 'version': version, 'archiveMembers': sorted(member for _, _, member in matches),
            **value}
    require(matched, 'No checked-in WOFF2 files matched')
    for row in publications:
        row['embeddedNoticeCopies'] = {name: sorted(path for path, value in outputs.items() if value == notice)
            for name, notice in row['notices'].items()}
    return matched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    raw_lock, outputs = tracked_inputs(repo)
    rows = json.loads(raw_lock)['packages']
    editions = [publication(name, rows['node_modules/' + name]) for name in PACKAGES]
    matched = review_outputs(outputs, editions)
    copies = sum(bool(targets) for row in editions for targets in row['embeddedNoticeCopies'].values())
    source = git(repo, 'rev-parse', 'HEAD').decode().strip()
    data = {'schema': 1, 'sourceCommit': source, 'lock': pin(raw_lock),
        'runId': os.environ.get('GITHUB_RUN_ID'), 'attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
        'embeddedTree': git(repo, 'rev-parse', 'HEAD:web/dist').decode().strip(),
        'embeddedFiles': len(outputs), 'fontFiles': matched, 'archivedFontPublications': editions,
        'embeddedExactNoticeCopies': copies, 'completeDistributionLicenseReview': False}
    with args.report.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print('### Checked-in viewer font provenance\n')
    print(f"Source {source}. Embedded viewer tree {data['embeddedTree']}.")
    print(f"Matched {len(matched)} embedded WOFF2 files to {len(editions)} locked npm publications.")
    for row in editions:
        files = sum(value['name'] == row['name'] for value in matched.values())
        notices = sum(bool(targets) for targets in row['embeddedNoticeCopies'].values())
        print(f"- {row['name']}@{row['version']} accounts for {files} fonts and {notices} exact embedded notice copies.")


if __name__ == '__main__':
    main()
