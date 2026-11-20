"""Compare govulncheck observations for the zcribe source and the CI binary."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

from verify_go_inputs import (
    CLI, GO_VERSION, MAX_METADATA, MODULE, MODULE_PATH, VERSION, EvidenceError,
    capture, observe_binary, require, source_snapshot, unique_fields,
)


SCANNER = "golang.org/x/vuln"
SCANNER_VERSION = "v1.10.0"
SCANNER_SUM = "h1:W/Im35AGknunDiqBysVe9VoMfaeTJE7lptrD+1s//aE="
DATABASE = "https://vuln.go.dev"
DATABASE_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z")
GO_ID = re.compile(r"GO-\d{4}-\d{4,}")
LIMITS = {"stdout": 8 << 20, "stderr": 128 << 10}
REVIEW_NOTICE_BYTES = 4096


def run_scan(argv, root, env, seconds):
    deadline = time.monotonic() + seconds
    buffers = {channel: bytearray() for channel in LIMITS}
    eof = set()
    stop = None
    process = subprocess.Popen(argv, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout, selectors.EVENT_READ, "stdout")
            poll.register(process.stderr, selectors.EVENT_READ, "stderr")
            while poll.get_map() and stop is None:
                ready = poll.select(max(0, deadline - time.monotonic()))
                if not ready or time.monotonic() >= deadline:
                    stop = "deadline_exceeded"
                    break
                for key, _ in ready:
                    channel = key.data
                    remaining = LIMITS[channel] - len(buffers[channel])
                    block = os.read(key.fd, min(65536, remaining + 1))
                    if not block:
                        eof.add(channel)
                        poll.unregister(key.fileobj)
                    else:
                        buffers[channel].extend(block[:remaining])
                        if len(block) > remaining:
                            stop = channel + "_limit_exceeded"
                            break
        if stop is None:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                stop = "deadline_exceeded"
    finally:
        if stop or process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                stop = "process_termination_unknown"
        process.stdout.close()
        process.stderr.close()
    execution = {"actualExit": process.returncode, "terminationReason": stop,
                 "outputComplete": stop is None and eof == set(LIMITS),
                 "streams": {name: {"bytes": len(raw), "sha256": sha256(raw).hexdigest(), "eof": name in eof}
                             for name, raw in buffers.items()}}
    return bytes(buffers["stdout"]), execution


def messages(raw):
    require(0 < len(raw) <= LIMITS["stdout"], "scanner stream is empty or exceeds its limit")
    decoder = json.JSONDecoder(object_pairs_hook=unique_fields)
    text = raw.decode("utf-8")
    offset = count = 0
    while offset < len(text):
        while offset < len(text) and text[offset] in " \t\r\n":
            offset += 1
        if offset == len(text):
            break
        message, offset = decoder.raw_decode(text, offset)
        count += 1
        require(count <= 20000 and isinstance(message, dict) and len(message) == 1,
                "invalid scanner protocol message")
        kind, value = next(iter(message.items()))
        require(isinstance(value, dict) and (count != 1 or kind == "config"), "invalid initial scanner message")
        yield kind, value


def portable_path(value):
    return (isinstance(value, str) and MODULE_PATH.fullmatch(value)
            and not set(value.split("/")) & {"", ".", ".."})


def inventory(value, mode, linked):
    root = CLI if mode == "source" else MODULE
    require(value.get("go_version") == GO_VERSION and value.get("roots") == [root], "scanner SDK or roots differ")
    records = value["modules"]
    require(isinstance(records, list) and 0 < len(records) <= 4096, "scanner module inventory is invalid")
    seen = {}
    for row in records:
        path, version = row["path"], row.get("version", "")
        require((path == "./go-zenon" or portable_path(path)) and isinstance(version, str)
                and len(version) <= 256, "invalid scanner module identity")
        require(seen.setdefault(path, version) == version, "scanner reported conflicting module versions")
    require(MODULE in seen and "stdlib" in seen and "./go-zenon" in seen, "scanner module inventory is incomplete")
    expected = {item["module"]: item["version"] for item in linked if "replacement" not in item}
    actual = {path: version for path, version in seen.items() if path not in (MODULE, "stdlib", "./go-zenon")}
    return {"root": root, "moduleCount": len(seen), "versionedModulesMatchBinary": actual == expected}


def finding(value, mode):
    advisory = value["osv"]
    trace = value["trace"]
    require(GO_ID.fullmatch(advisory) and isinstance(trace, list) and 0 < len(trace) <= 256,
            "invalid scanner finding")
    frame = trace[0]
    module, package = frame["module"], frame.get("package", "")
    require((module == "./go-zenon" or portable_path(module)) and (not package or portable_path(package)),
            "nonportable scanner finding")
    version, fixed = frame.get("version", ""), value.get("fixed_version", "")
    for item in (version, fixed):
        require(not item or VERSION.fullmatch(item) or re.fullmatch(r"go1\.\d+(?:\.\d+)?", item),
                "invalid finding version")
    function = frame.get("function", "")
    require(isinstance(function, str) and (not function or package), "invalid scanner symbol")
    require(mode == "source" or (len(trace) == 1 and "position" not in frame), "unexpected binary call trace")
    level = "symbol" if function else "package" if package else "module"
    return {"id": advisory, "level": level, "module": module, "version": version,
            "package": package, "fixedVersion": fixed}


def summarize(raw, mode, linked):
    config = scan_inventory = None
    advisories, findings = {}, {}
    for kind, value in messages(raw):
        if kind == "config":
            expected = {"protocol_version": "v1.0.0", "scanner_name": "govulncheck",
                        "scanner_version": SCANNER_VERSION, "db": DATABASE, "scan_mode": mode, "scan_level": "symbol"}
            require(config is None and all(value.get(key) == selected for key, selected in expected.items()),
                    "scanner configuration differs from the reviewed profile")
            require(mode == "binary" or value.get("go_version") == GO_VERSION, "source scanner SDK differs")
            config = value
        elif kind == "SBOM":
            require(scan_inventory is None, "duplicate scanner inventory")
            scan_inventory = inventory(value, mode, linked)
        elif kind == "osv":
            advisory = value["id"]
            require(GO_ID.fullmatch(advisory), "invalid scanner advisory identity")
            digest = sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            require(advisories.setdefault(advisory, digest) == digest, "conflicting scanner advisory records")
        elif kind == "finding":
            row = finding(value, mode)
            findings[tuple(row.values())] = row
        else:
            require(kind == "progress", "unknown scanner message kind")
    require(config is not None and scan_inventory is not None, "scanner report lacks its configuration or inventory")
    modified = config.get("db_last_modified", "")
    require(DATABASE_TIME.fullmatch(modified), "scanner database update time is missing")
    rows = [findings[key] for key in sorted(findings)]
    require(all(row["id"] in advisories for row in rows), "finding lacks its scanner advisory record")
    return {"databaseLastModified": modified, "inventory": scan_inventory, "advisoryDigests": advisories,
            "findings": rows, "advisoriesWithFindings": len({row["id"] for row in rows}),
            "advisoriesWithSymbolEvidence": len({row["id"] for row in rows if row["level"] == "symbol"})}


def compare_symbol_findings(source, binary):
    levels = {None: 0, "module": 1, "package": 2, "symbol": 3}
    groups = {}
    for field, scan in (("sourceLevel", source), ("binaryLevel", binary)):
        for finding in scan["findings"]:
            advisory, module, version = finding["id"], finding["module"], finding["version"]
            if module == "stdlib" and re.fullmatch(r"go1\.\d+\.\d+", version):
                version = "v" + version[2:]
            key = (advisory, module, version)
            row = groups.setdefault(key, {"id": advisory, "module": module, "version": version,
                                          "sourceLevel": None, "binaryLevel": None, "fixedVersions": set()})
            if levels[finding["level"]] > levels[row[field]]:
                row[field] = finding["level"]
            if finding["fixedVersion"]:
                row["fixedVersions"].add(finding["fixedVersion"])
    return [{**row, "fixedVersions": sorted(row["fixedVersions"])} for _, row in sorted(groups.items())
            if "symbol" in (row["sourceLevel"], row["binaryLevel"])]


def review_notice(revision, rows):
    report = {"revision": revision, "symbolReviewCount": len(rows), "symbolReview": rows}
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) <= REVIEW_NOTICE_BYTES:
        return encoded
    return json.dumps({"revision": revision, "symbolReviewCount": len(rows), "details": "artifact"},
                      sort_keys=True, separators=(",", ":"))


def reason(error):
    return str(error) if isinstance(error, EvidenceError) else type(error).__name__


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--scanner", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    root = Path.cwd()
    report = {"schema": 1, "status": "incomplete", "scans": {}}
    errors = (ValueError, AttributeError, KeyError, TypeError, OSError, subprocess.SubprocessError, RecursionError)
    try:
        source, sums = source_snapshot(root, args.source_commit)
        with args.inputs.open("rb") as stream:
            data = stream.read(MAX_METADATA + 1)
        require(len(data) <= MAX_METADATA, "build input evidence exceeds its limit")
        receipt = json.loads(data, object_pairs_hook=unique_fields)
        binary = observe_binary(args.binary, root, sums, args.source_commit)
        require(receipt == {"source": source, "binary": binary}, "scanner inputs differ from the verified build")
        scanner = json.loads(capture(["go", "version", "-m", "-json", str(args.scanner)], root),
                             object_pairs_hook=unique_fields)
        module = scanner["Main"]
        require(scanner["Path"] == SCANNER + "/cmd/govulncheck" and scanner["GoVersion"] == GO_VERSION
                and module == {"Path": SCANNER, "Version": SCANNER_VERSION, "Sum": SCANNER_SUM},
                "scanner binary differs from the pinned Go module")
        report.update(sourceRevision=args.source_commit, binarySHA256=binary["sha256"],
                      buildInputReportSHA256=sha256(data).hexdigest(), scannerVersion=SCANNER_VERSION, database=DATABASE)
        env = {**os.environ, "GOPROXY": "off", "GOSUMDB": "off", "GOMAXPROCS": "2", "GOMEMLIMIT": "1536MiB",
               "GOOS": binary["platform"]["os"], "GOARCH": binary["platform"]["architecture"],
               "CGO_ENABLED": "1" if binary["platform"]["cgoEnabled"] else "0"}
        before = args.binary.lstat()
        for mode, target, timeout in (("source", "./cmd/zcribe", 180), ("binary", str(args.binary), 45)):
            record = report["scans"][mode] = {}
            argv = [str(args.scanner), "-format=json", "-scan=symbol", "-mode=" + mode, "-db=" + DATABASE, target]
            try:
                raw, execution = run_scan(argv, root, env, timeout)
                record["execution"] = execution
                require(execution["outputComplete"] and execution["actualExit"] == 0, "scanner command was incomplete")
                record["observation"] = summarize(raw, mode, binary["selectedModules"])
            except errors as error:
                record["error"] = reason(error)
        after = args.binary.lstat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and source_snapshot(root, args.source_commit)[0] == source, "source or binary changed during scanning")
        selected = [record.get("observation") for record in report["scans"].values()]
        require(len(selected) == 2 and all(selected), "source and binary scans did not both complete")
        source_scan, binary_scan = selected
        common = source_scan["advisoryDigests"].keys() & binary_scan["advisoryDigests"].keys()
        same_database = (source_scan["databaseLastModified"] == binary_scan["databaseLastModified"]
                         and all(source_scan["advisoryDigests"][item] == binary_scan["advisoryDigests"][item]
                                 for item in common))
        report["sameDatabaseRevisionObserved"] = same_database
        require(same_database and all(scan["inventory"]["versionedModulesMatchBinary"] for scan in selected),
                "scan database or module profiles differ")
        report["symbolReview"] = compare_symbol_findings(source_scan, binary_scan)
        report["status"] = "complete"
    except errors as error:
        report["error"] = reason(error)

    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    if report["status"] != "complete":
        print("Go vulnerability scan incomplete. " + report.get("error", ""), file=sys.stderr)
        return 2
    print("::notice title=Zcribe vulnerability scan::"
          f"{args.source_commit}; source advisories {source_scan['advisoriesWithFindings']}, "
          f"source symbols {source_scan['advisoriesWithSymbolEvidence']}; "
          f"binary advisories {binary_scan['advisoriesWithFindings']}, "
          f"binary symbols {binary_scan['advisoriesWithSymbolEvidence']}; "
          f"database {source_scan['databaseLastModified']}")
    print("::notice title=Zcribe symbol review::" + review_notice(args.source_commit, report["symbolReview"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
