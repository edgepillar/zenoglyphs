import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import review_go_vulnerabilities as review
from verify_go_inputs import CLI, GO_VERSION, MODULE, EvidenceError


DEPENDENCY = "example.org/lib"
ADVISORY = "GO-2026-1234"
LINKED = [{"module": DEPENDENCY, "version": "v1.2.3"}]


def fixture(mode):
    config = {"protocol_version": "v1.0.0", "scanner_name": "govulncheck",
              "scanner_version": review.SCANNER_VERSION, "db": review.DATABASE,
              "db_last_modified": "2026-11-20T04:00:00Z", "scan_mode": mode, "scan_level": "symbol"}
    if mode == "source":
        config["go_version"] = GO_VERSION
    sbom = {"go_version": GO_VERSION, "roots": [CLI if mode == "source" else MODULE],
            "modules": [{"path": MODULE}, {"path": "./go-zenon"}, {"path": "stdlib", "version": GO_VERSION},
                        {"path": DEPENDENCY, "version": "v1.2.3"}]}
    frame = {"module": DEPENDENCY, "version": "v1.2.3", "package": DEPENDENCY, "function": "Example"}
    if mode == "source":
        frame["position"] = {"filename": "/synthetic/runner/file.go", "line": 2}
    return [{"config": config}, {"SBOM": sbom}, {"osv": {"id": ADVISORY}},
            {"finding": {"osv": ADVISORY, "fixed_version": "v1.2.4", "trace": [frame]}}]


def encode(rows):
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()


class ReviewTests(unittest.TestCase):
    def test_both_modes_preserve_the_advisory_and_strip_source_positions(self):
        for mode in ("source", "binary"):
            with self.subTest(mode=mode):
                result = review.summarize(encode(fixture(mode)), mode, LINKED)
                self.assertTrue(result["inventory"]["versionedModulesMatchBinary"])
                self.assertEqual(result["advisoriesWithSymbolEvidence"], 1)
                self.assertEqual(result["findings"][0]["id"], ADVISORY)
                self.assertEqual(result["findings"][0]["fixedVersion"], "v1.2.4")
                self.assertNotIn("/synthetic", json.dumps(result))

    def test_mode_cannot_be_substituted_and_omitted_catalog_is_rejected(self):
        with self.assertRaisesRegex(EvidenceError, "reviewed profile"):
            review.summarize(encode(fixture("source")), "binary", LINKED)
        with self.assertRaisesRegex(EvidenceError, "configuration or inventory"):
            review.summarize(encode(fixture("source")[:1]), "source", LINKED)

    def test_linked_inventory_version_drift_is_recorded(self):
        result = review.summarize(encode(fixture("binary")), "binary",
                                  [{"module": DEPENDENCY, "version": "v1.2.2"}])
        self.assertFalse(result["inventory"]["versionedModulesMatchBinary"])

    def test_a_finding_without_its_advisory_or_with_a_binary_trace_is_rejected(self):
        rows = fixture("binary")
        with self.assertRaisesRegex(EvidenceError, "lacks its scanner advisory"):
            review.summarize(encode(rows[:2] + rows[3:]), "binary", LINKED)
        rows[3]["finding"]["trace"][0]["position"] = {"line": 7}
        with self.assertRaisesRegex(EvidenceError, "binary call trace"):
            review.summarize(encode(rows), "binary", LINKED)

    def test_a_capped_process_records_incomplete_output(self):
        with patch.object(review, "LIMITS", {"stdout": 64, "stderr": 64}):
            output, execution = review.run_scan(
                [sys.executable, "-B", "-c", "print('a' * 1000)"], Path.cwd(), os.environ, 3)
        self.assertEqual(len(output), 64)
        self.assertFalse(execution["outputComplete"])
        self.assertEqual(execution["terminationReason"], "stdout_limit_exceeded")
