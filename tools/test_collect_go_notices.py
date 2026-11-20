import json
from pathlib import Path
import unittest
from unittest.mock import patch

from collect_go_notices import (
    CLI, GETH_SECP256K1, GO_VERSION, MODULE, NOTICE, ZENON, EvidenceError,
    collect, json_records, package_locations,
)


ROOT = Path("/checkout")
SDK = Path("/sdk")
CACHE = Path("/module-cache")
GETH = "github.com/ethereum/go-ethereum"
GETH_DIR = CACHE / "github.com/ethereum/go-ethereum@v1.10.22"
MIXED_CASE = "github.com/Example/Module"


class GoNoticesTest(unittest.TestCase):
    def setUp(self):
        self.modules = {
            ZENON: {"module": ZENON, "version": "v0.0.0", "replacement": "./go-zenon"},
            GETH: {"module": GETH, "version": "v1.10.22", "checksum": "example"},
            MIXED_CASE: {"module": MIXED_CASE, "version": "v1.0.0", "checksum": "example"},
        }
        self.graph = [
            {"ImportPath": "runtime", "Dir": str(SDK / "src/runtime"), "Standard": True},
            {"ImportPath": ZENON + "/common", "Dir": str(ROOT / "go-zenon/common"),
             "Module": {"Path": ZENON, "Version": "v0.0.0", "Replace": {"Path": "./go-zenon"}}},
            {"ImportPath": GETH_SECP256K1, "Dir": str(GETH_DIR / "crypto/secp256k1"),
             "Module": {"Path": GETH, "Version": "v1.10.22"}, "CgoFiles": ["secp256.go"]},
            {"ImportPath": MIXED_CASE, "Dir": str(CACHE / "github.com/!example/!module@v1.0.0"),
             "Module": {"Path": MIXED_CASE, "Version": "v1.0.0"}},
            {"ImportPath": CLI, "Dir": str(ROOT / "cmd/zcribe"), "Module": {"Path": MODULE, "Main": True}},
        ]

    def test_native_notice_follows_the_selected_package(self):
        roots, _, _, bundled = package_locations(self.graph, self.modules, ROOT, SDK, CACHE)
        self.assertEqual(roots[GETH], GETH_DIR)
        self.assertEqual(bundled[GETH], {GETH_DIR / "crypto/secp256k1/libsecp256k1/COPYING"})
        self.graph[2]["CgoFiles"] = []
        self.assertFalse(package_locations(self.graph, self.modules, ROOT, SDK, CACHE)[3])

    def test_declines_substituted_module_and_directory(self):
        self.graph[2]["Module"]["Version"] = "v1.17.10"
        with self.assertRaisesRegex(EvidenceError, "version differs"):
            package_locations(self.graph, self.modules, ROOT, SDK, CACHE)
        self.graph[2]["Module"]["Version"] = "v1.10.22"
        self.graph[2]["Dir"] = str(ROOT / "other")
        with self.assertRaisesRegex(EvidenceError, "source layout"):
            package_locations(self.graph, self.modules, ROOT, SDK, CACHE)
        del self.graph[2]
        with self.assertRaisesRegex(EvidenceError, "linked modules"):
            package_locations(self.graph, self.modules, ROOT, SDK, CACHE)

    def test_original_payload_is_stored_once_and_missing_notices_are_reported(self):
        sdk = {"GOVERSION": GO_VERSION, "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "1",
               "GOROOT": str(SDK), "GOMODCACHE": str(CACHE)}
        receipt = {"source": {"revision": "example"}, "binary": {
            "entryPackage": CLI, "goVersion": GO_VERSION, "sha256": "binary", "bytes": 42,
            "platform": {"os": "linux", "architecture": "amd64", "cgoEnabled": True},
            "selectedModules": list(self.modules.values()),
        }}
        graph = "\n".join(map(json.dumps, self.graph)).encode()
        with patch("collect_go_notices.go_metadata", side_effect=[json.dumps(sdk).encode(), graph]), \
                patch("collect_go_notices.notice_paths",
                      side_effect=lambda base, _: [] if "@v1.0.0" in base.name else [base / "LICENSE"]), \
                patch("collect_go_notices.read_notice", return_value=b"Original notice\n"):
            manifest, objects = collect(ROOT, receipt)
        self.assertEqual(list(objects.values()), [b"Original notice\n"])
        self.assertEqual(manifest["modulesWithoutObservedNotices"], [MIXED_CASE])
        self.assertEqual(manifest["bundledNativeNoticeCount"], 1)
        self.assertEqual(manifest["binarySHA256"], "binary")

    def test_selects_notice_names_and_rejects_ambiguous_metadata(self):
        for path in ("LICENSE", "COPYING.LESSER", "MIT-LICENSE.txt", "NOTICES.md", "LICENSE-APACHE"):
            self.assertIsNotNone(NOTICE.fullmatch(path), path)
        for path in ("license.go", "NOTICE.js", "README", "NOTICE.png"):
            self.assertIsNone(NOTICE.fullmatch(path), path)
        with self.assertRaisesRegex(EvidenceError, "duplicate"):
            list(json_records(b'{"Dir":"a","Dir":"b"}'))


if __name__ == "__main__":
    unittest.main()
