#!/usr/bin/env python3
"""Record the source inputs and module checksums for one CI-built zcribe binary."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


MODULE = "github.com/Zenoglyphs-VM/zenoglyphs"
CLI = MODULE + "/cmd/zcribe"
ZENON = "github.com/zenon-network/go-zenon"
ZENON_URL = "https://github.com/zenon-network/go-zenon.git"
GO_VERSION = "go1.26.11"
MAX_METADATA = 256 << 10
MAX_BINARY = 128 << 20
OID = re.compile(r"[0-9a-f]{40}")
MODULE_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_~!/-]{0,511}")
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?")
SUM = re.compile(r"h1:[A-Za-z0-9+/]{43}=")


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def capture(command, cwd):
    result = subprocess.run(command, cwd=cwd, check=False, capture_output=True, timeout=20)
    require(result.returncode == 0 and len(result.stdout) <= MAX_METADATA,
            "source or build metadata command failed or exceeded its limit")
    return result.stdout


def git(directory, *args):
    return capture(["git", "--no-optional-locks", *args], directory)


def git_entry(root, path, mode, kind):
    entry = git(root, "ls-tree", "HEAD", "--", path).decode().strip()
    match = re.fullmatch(rf"{mode} {kind} ({OID.pattern})\t{re.escape(path)}", entry)
    require(match is not None, "missing or invalid tracked source input")
    return match[1]


def source_snapshot(root, expected):
    require(OID.fullmatch(expected) and git(root, "rev-parse", "HEAD").decode().strip() == expected,
            "checkout differs from the selected source revision")
    submodule = root / "go-zenon"
    gitlink = git_entry(root, "go-zenon", "160000", "commit")
    url = git(root, "config", "--file", ".gitmodules", "--get", "submodule.go-zenon.url").decode().strip()
    require(url == ZENON_URL, "unexpected go-zenon source URL")
    require(submodule.is_dir() and not submodule.is_symlink()
            and not git(submodule, "rev-parse", "--show-prefix").strip()
            and git(submodule, "rev-parse", "HEAD").decode().strip() == gitlink,
            "go-zenon checkout differs from its recorded gitlink")
    for directory in (root, submodule):
        status = git(directory, "status", "--porcelain=v1", "--untracked-files=all",
                     "--ignored=matching", "--ignore-submodules=none")
        require(not status, "source checkout contains changes or extra files")
    sums = git(root, "show", "HEAD:go.sum")
    return {
        "revision": expected,
        "tree": git(root, "rev-parse", "HEAD^{tree}").decode().strip(),
        "embeddedViewerTree": git_entry(root, "web/dist", "040000", "tree"),
        "goModSHA256": hashlib.sha256(git(root, "show", "HEAD:go.mod")).hexdigest(),
        "goSumSHA256": hashlib.sha256(sums).hexdigest(),
        "goZenon": {
            "module": ZENON, "url": url, "commit": gitlink,
            "tree": git(submodule, "rev-parse", "HEAD^{tree}").decode().strip(),
        },
    }, sums


def unique_fields(pairs):
    values = dict(pairs)
    require(len(values) == len(pairs), "duplicate JSON key in build evidence")
    return values


def build_modules(info, sums, revision):
    require(info["GoVersion"] == GO_VERSION and info["Path"] == CLI
            and info["Main"]["Path"] == MODULE and info["Main"].get("Replace") is None,
            "unexpected zcribe entry point, module or Go toolchain")
    rows = [(row["Key"], row.get("Value", "")) for row in info["Settings"]]
    settings = unique_fields(rows)
    expected = {"vcs": "git", "vcs.revision": revision, "vcs.modified": "false",
                "-buildmode": "exe", "-trimpath": "true", "GOOS": "linux", "GOARCH": "amd64"}
    require(all(settings.get(key) == value for key, value in expected.items())
            and settings.get("CGO_ENABLED") in ("0", "1"), "unexpected binary source or build settings")
    locked = {}
    for line in sums.decode("ascii").splitlines():
        module, version, digest = line.split()
        require(SUM.fullmatch(digest) and (module, version) not in locked, "invalid or duplicate go.sum entry")
        locked[(module, version)] = digest
    modules = {}
    for dep in info["Deps"]:
        path, version = dep["Path"], dep["Version"]
        require(MODULE_PATH.fullmatch(path) and not set(path.split("/")) & {"", ".", ".."}
                and VERSION.fullmatch(version) and path not in modules, "invalid or repeated build module")
        replacement = dep.get("Replace")
        if path == ZENON:
            require(version == "v0.0.0" and replacement == {"Path": "./go-zenon", "Version": "(devel)"},
                    "build did not use the reviewed go-zenon checkout")
            modules[path] = {"module": path, "version": version, "replacement": "./go-zenon"}
        else:
            digest = dep.get("Sum", "")
            require(replacement is None and SUM.fullmatch(digest) and locked.get((path, version)) == digest,
                    "build module does not match the committed go.sum")
            modules[path] = {"module": path, "version": version, "checksum": digest}
    require(ZENON in modules and len(modules) > 1, "binary module list is incomplete")
    platform = {"os": settings["GOOS"], "architecture": settings["GOARCH"],
                "cgoEnabled": settings["CGO_ENABLED"] == "1"}
    return platform, [modules[name] for name in sorted(modules)]


def observe_binary(path, root, sums, revision):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        observed = os.fstat(stream.fileno())
        require(stat.S_ISREG(observed.st_mode) and 0 < observed.st_size <= MAX_BINARY,
                "binary input is outside the supported file profile")
        digest = hashlib.sha256()
        remaining = observed.st_size
        while remaining:
            block = stream.read(min(1 << 20, remaining))
            require(block, "binary input was truncated")
            digest.update(block)
            remaining -= len(block)
        raw = capture(["go", "version", "-m", "-json", str(path)], root)
        final = path.lstat()
        require((final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns) ==
                (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns),
                "binary input changed during observation")
    info = json.loads(raw, object_pairs_hook=unique_fields)
    platform, modules = build_modules(info, sums, revision)
    return {"entryPackage": CLI, "sha256": digest.hexdigest(), "bytes": observed.st_size,
            "goVersion": GO_VERSION, "platform": platform, "selectedModules": modules}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--before", type=Path, help="source snapshot recorded before the build")
    parser.add_argument("--binary", type=Path, help="CI-built zcribe executable")
    args = parser.parse_args()
    if bool(args.before) != bool(args.binary):
        parser.error("--before and --binary must be supplied together")
    try:
        root = Path.cwd()
        source, sums = source_snapshot(root, args.source_commit)
        if args.binary:
            with args.before.open("rb") as stream:
                raw = stream.read(MAX_METADATA + 1)
            require(len(raw) <= MAX_METADATA and json.loads(raw, object_pairs_hook=unique_fields) == source,
                    "source or submodule identity changed after the build")
            binary = observe_binary(args.binary, root, sums, args.source_commit)
            report = {"source": source, "binary": binary}
            print(f"Verified zcribe {binary['sha256']} ({binary['bytes']} bytes, "
                  f"{len(binary['selectedModules'])} selected modules)", file=sys.stderr)
        else:
            report = source
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, AttributeError, OSError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, EvidenceError) else type(error).__name__
        print(f"Go build input check incomplete. {reason}", file=sys.stderr)
        print(json.dumps({"status": "incomplete", "reason": reason}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
