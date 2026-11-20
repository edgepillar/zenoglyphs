#!/usr/bin/env python3
"""Retain original notices for the packages used to build zcribe in CI."""

import argparse
from collections import defaultdict
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from verify_go_inputs import (
    CLI, GO_VERSION, MAX_METADATA, MODULE, MODULE_PATH, ZENON, EvidenceError,
    require, source_snapshot, unique_fields,
)


NOTICE = re.compile(
    r"(?:[a-z0-9.+_-]+[-_.])?(licen[cs]es?|copying|notices?|copyright|patents|legal|unlicense)"
    r"(?:[._-](?:txt|md|markdown|rst|lesser|lib|apache|mit|bsd|gpl|lgpl|mpl|musl|v[0-9]+))*", re.I)
NOTICE_DIRS = {"license", "licenses", "licence", "licences", "notices"}
NOTICE_TEXT_SUFFIXES = {".txt", ".md", ".markdown", ".rst"}
GETH_SECP256K1 = "github.com/ethereum/go-ethereum/crypto/secp256k1"
WHITESPACE = re.compile(r"\s*")
MAX_GRAPH = 4 << 20
MAX_NOTICE = 128 << 10
MAX_TOTAL = 8 << 20


def escape_cache_name(name):
    return re.sub(r"[A-Z]", lambda match: "!" + match[0].lower(), name)


def json_records(raw):
    decoder = json.JSONDecoder(object_pairs_hook=unique_fields)
    text = raw.decode("utf-8")
    offset = WHITESPACE.match(text).end()
    while offset < len(text):
        value, offset = decoder.raw_decode(text, offset)
        yield value
        offset = WHITESPACE.match(text, offset).end()


def go_metadata(args, root):
    env = {**os.environ, "GOPROXY": "off", "GOSUMDB": "off"}
    result = subprocess.run(["go", *args], cwd=root, env=env, capture_output=True, timeout=30)
    require(result.returncode == 0 and 0 < len(result.stdout) <= MAX_GRAPH,
            "Go package metadata command failed or exceeded its limit")
    return result.stdout


def package_locations(rows, modules, root, goroot, cache):
    roots = {MODULE: root, "std": goroot}
    for module, selected in modules.items():
        roots[module] = (root / "go-zenon" if module == ZENON else
                         cache / (escape_cache_name(module) + "@" + escape_cache_name(selected["version"])))
    packages, locations, bundled = {}, defaultdict(set), defaultdict(set)
    for row in rows:
        name = row["ImportPath"]
        require(MODULE_PATH.fullmatch(name) and not set(name.split("/")) & {"", ".", ".."}
                and name not in packages and len(packages) < 4096, "invalid or duplicate selected package")
        metadata = row.get("Module")
        if row.get("Standard") is True:
            module = "std"
            directory = goroot / "src" / name
            require(metadata is None, "standard package has versioned module metadata")
        else:
            module = metadata["Path"]
            require(module in roots and (name == module or name.startswith(module + "/")),
                    "package is outside the verified module selection")
            directory = roots[module] / name[len(module):].lstrip("/")
            if module == MODULE:
                require(metadata.get("Main") is True and not metadata.get("Replace"),
                        "unexpected main module in the package graph")
            else:
                require(metadata["Version"] == modules[module]["version"], "package module version differs")
                replacement = metadata.get("Replace")
                require((replacement is None if module != ZENON else
                         replacement is not None and replacement.get("Path") == "./go-zenon"),
                        "unexpected module replacement in the package graph")
        declared_dir = row.get("Dir", "")
        require(Path(declared_dir) == directory or (name == "unsafe" and not declared_dir),
                "package directory differs from the verified source layout")
        packages[name] = module
        locations[module].add(directory)
        if name == GETH_SECP256K1 and row.get("CgoFiles"):
            bundled[module].add(directory / "libsecp256k1" / "COPYING")
    require(packages.get(CLI) == MODULE and set(locations) == set(roots),
            "package graph does not match the executable's linked modules")
    return roots, packages, locations, bundled


def notice_paths(base, package_dirs):
    directories = {base}
    for path in package_dirs:
        while path != base:
            directories.add(path)
            path = path.parent
    for directory in sorted(directories):
        require(directory.resolve(strict=True) == directory, "notice directory traverses a link")
        for index, entry in enumerate(directory.iterdir()):
            require(index < 4096, "notice directory entry limit exceeded")
            if entry.name.lower() in NOTICE_DIRS and entry.is_dir():
                require(not entry.is_symlink(), "notice directory is a link")
                for notice_index, candidate in enumerate(entry.iterdir()):
                    require(notice_index < 4096, "notice directory entry limit exceeded")
                    if NOTICE.fullmatch(candidate.name) or candidate.suffix.lower() in NOTICE_TEXT_SUFFIXES:
                        yield candidate
            elif NOTICE.fullmatch(entry.name):
                yield entry


def read_notice(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    require(path.resolve(strict=True) == path, "notice path traverses a link")
    with os.fdopen(os.open(path, flags), "rb") as stream:
        first = os.fstat(stream.fileno())
        require(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and 0 < first.st_size <= MAX_NOTICE,
                "notice is empty, oversized or not an independent regular file")
        data = stream.read(MAX_NOTICE + 1)
        last = path.lstat()
        require(len(data) == first.st_size and
                (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns, first.st_ctime_ns) ==
                (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns, last.st_ctime_ns),
                "notice changed while reading")
    return data


def collect(root, receipt):
    binary = receipt["binary"]
    profile = binary["platform"]
    env = json.loads(go_metadata(["env", "-json", "GOVERSION", "GOOS", "GOARCH",
                                  "CGO_ENABLED", "GOROOT", "GOMODCACHE"], root), object_pairs_hook=unique_fields)
    require(binary["entryPackage"] == CLI and binary["goVersion"] == env["GOVERSION"] == GO_VERSION
            and profile == {"os": env["GOOS"], "architecture": env["GOARCH"],
                            "cgoEnabled": env["CGO_ENABLED"] == "1"},
            "notice collection uses a different build profile")
    modules = {row["module"]: row for row in binary["selectedModules"]}
    require(len(modules) == len(binary["selectedModules"]) and 0 < len(modules) <= 1024,
            "invalid binary module inventory")
    graph = go_metadata(["list", "-deps", "-json=ImportPath,Dir,Standard,Module,CgoFiles", "./cmd/zcribe"], root)
    roots, packages, locations, bundled = package_locations(
        json_records(graph), modules, root, Path(env["GOROOT"]), Path(env["GOMODCACHE"]))
    objects, inventories, total, count = {}, [], 0, 0
    for module, base in sorted(roots.items()):
        paths = set(notice_paths(base, locations[module])) | bundled[module]
        notices = []
        for path in sorted(paths):
            relative = path.relative_to(base).as_posix()
            require(MODULE_PATH.fullmatch(relative), "notice path is not portable")
            data = read_notice(path)
            digest = sha256(data).hexdigest()
            if digest not in objects:
                total += len(data)
                require(total <= MAX_TOTAL, "unique notice payload budget exceeded")
                objects[digest] = data
            count += 1
            require(count <= 8192, "notice reference limit exceeded")
            notices.append({"path": relative, "bytes": len(data), "sha256": digest})
        if module in (MODULE, ZENON, "std"):
            require(any(row["path"] == "LICENSE" for row in notices), "required project or SDK license missing")
        inventories.append({"identity": modules.get(module, {"module": module}), "notices": notices})

    manifest = {
        "schema": 1, "status": "SOURCE_NOTICES_RECORDED_REVIEW_REQUIRED",
        "source": receipt["source"], "binarySHA256": binary["sha256"], "binaryBytes": binary["bytes"],
        "goVersion": binary["goVersion"], "platform": profile, "entryPackage": CLI,
        "packages": packages, "modules": inventories,
        "objects": {digest: len(data) for digest, data in objects.items()},
        "modulesWithoutObservedNotices": [row["identity"]["module"] for row in inventories if not row["notices"]],
        "bundledNativeNoticeCount": sum(len(paths) for paths in bundled.values()),
    }
    return manifest, objects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        root = Path.cwd()
        with args.inputs.open("rb") as stream:
            raw = stream.read(MAX_METADATA + 1)
        require(len(raw) <= MAX_METADATA, "build input receipt exceeds its limit")
        receipt = json.loads(raw, object_pairs_hook=unique_fields)
        require(receipt["source"] == source_snapshot(root, args.source_commit)[0],
                "build input receipt differs from the selected checkout")
        manifest, objects = collect(root, receipt)
        manifest["buildInputsSHA256"] = sha256(raw).hexdigest()
        args.output.mkdir(mode=0o700)
        payloads = args.output / "objects"
        payloads.mkdir()
        for digest, data in sorted(objects.items()):
            with (payloads / digest).open("xb") as stream:
                stream.write(data)
        encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("ascii")
        with (args.output / "manifest.json").open("xb") as stream:
            stream.write(encoded)
        missing = manifest["modulesWithoutObservedNotices"]
        summary = {"sourceCommit": args.source_commit, "binarySHA256": manifest["binarySHA256"],
                   "manifestSHA256": sha256(encoded).hexdigest(), "packageCount": len(manifest["packages"]),
                   "moduleCount": len(manifest["modules"]), "noticeReferences": sum(
                       len(row["notices"]) for row in manifest["modules"]),
                   "objectCount": len(objects), "objectBytes": sum(map(len, objects.values())),
                   "bundledNativeNoticeCount": manifest["bundledNativeNoticeCount"],
                   "missingModuleCount": len(missing), "missingModules": missing[:8]}
        print("::notice title=Zcribe Go source notices::" + json.dumps(summary, separators=(",", ":")))
        return 0
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, EvidenceError) else type(error).__name__
        print(f"Go source notice collection incomplete. {reason}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
