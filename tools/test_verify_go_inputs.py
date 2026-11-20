import copy
import unittest

from verify_go_inputs import CLI, GO_VERSION, MODULE, ZENON, EvidenceError, build_modules


REVISION = "a" * 40
DEPENDENCY = "example.org/lib"
CHECKSUM = "h1:" + "a" * 43 + "="
LOCK = f"{DEPENDENCY} v1.2.3 {CHECKSUM}\n".encode()


class BuildModulesTests(unittest.TestCase):
    def setUp(self):
        settings = {"vcs": "git", "vcs.revision": REVISION, "vcs.modified": "false",
                    "-buildmode": "exe", "-trimpath": "true", "GOOS": "linux", "GOARCH": "amd64",
                    "CGO_ENABLED": "1", "CGO_CFLAGS": "-I/local/runner/headers"}
        self.info = {
            "Path": CLI, "Main": {"Path": MODULE}, "GoVersion": GO_VERSION,
            "Settings": [{"Key": key, "Value": value} for key, value in settings.items()],
            "Deps": [
                {"Path": DEPENDENCY, "Version": "v1.2.3", "Sum": CHECKSUM},
                {"Path": ZENON, "Version": "v0.0.0", "Replace": {"Path": "./go-zenon", "Version": "(devel)"}},
            ],
        }

    def test_exact_lock_and_local_replacement(self):
        platform, modules = build_modules(self.info, LOCK, REVISION)
        self.assertEqual(platform, {"os": "linux", "architecture": "amd64", "cgoEnabled": True})
        self.assertEqual(modules, [
            {"module": DEPENDENCY, "version": "v1.2.3", "checksum": CHECKSUM},
            {"module": ZENON, "version": "v0.0.0", "replacement": "./go-zenon"},
        ])

    def test_versioned_module_needs_the_exact_content_checksum(self):
        for lock in (b"", LOCK.replace(b"1.2.3", b"1.2.4"), LOCK.replace(b"h1:a", b"h1:b"),
                     LOCK.replace(b"1.2.3 ", b"1.2.3/go.mod ")):
            with self.subTest(lock=lock), self.assertRaisesRegex(EvidenceError, "committed go.sum"):
                build_modules(self.info, lock, REVISION)

    def test_local_replacement_must_match_the_checked_out_submodule(self):
        for path in ("../fork", "/local/go-zenon", "github.com/example/fork"):
            changed = copy.deepcopy(self.info)
            changed["Deps"][1]["Replace"]["Path"] = path
            with self.subTest(path=path), self.assertRaisesRegex(EvidenceError, "reviewed go-zenon"):
                build_modules(changed, LOCK, REVISION)

    def test_duplicate_dependencies_and_checksums_are_rejected(self):
        with self.assertRaisesRegex(EvidenceError, "duplicate go.sum"):
            build_modules(self.info, LOCK + LOCK, REVISION)
        self.info["Deps"].append(self.info["Deps"][0])
        with self.assertRaisesRegex(EvidenceError, "repeated build module"):
            build_modules(self.info, LOCK, REVISION)

    def test_dirty_or_different_source_cannot_match_the_receipt(self):
        with self.assertRaisesRegex(EvidenceError, "binary source or build settings"):
            build_modules(self.info, LOCK, "b" * 40)
        changed = next(row for row in self.info["Settings"] if row["Key"] == "vcs.modified")
        changed["Value"] = "true"
        with self.assertRaisesRegex(EvidenceError, "binary source or build settings"):
            build_modules(self.info, LOCK, REVISION)

    def test_duplicate_settings_are_rejected(self):
        self.info["Settings"].append({"Key": "vcs.revision", "Value": REVISION})
        with self.assertRaisesRegex(EvidenceError, "duplicate JSON key"):
            build_modules(self.info, LOCK, REVISION)
