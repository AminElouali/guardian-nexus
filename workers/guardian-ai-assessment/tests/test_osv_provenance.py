import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_offline_osv_audit import (  # noqa: E402
    AuditError,
    classify_scan,
    classify_preflight_error,
    count_findings,
    verify_loaded_databases,
)


class OsvProvenanceTests(unittest.TestCase):
    def test_verified_database_paths_and_hashes_are_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected: dict[str, str] = {}
            lines = []
            for name in ("Debian", "PyPI"):
                path = root / "osv-scalibr" / name / "all.zip"
                path.parent.mkdir(parents=True)
                path.write_bytes(f"{name} db fixture".encode())
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                expected[name] = digest
                lines.append(f"Loaded {name} local db from {path}")

            verified = verify_loaded_databases(root, expected, "\n".join(lines))
            self.assertEqual(set(verified), {"Debian", "PyPI"})
            self.assertEqual(verified["Debian"]["status"], "verified")

            with self.assertRaisesRegex(AuditError, "database_hash_mismatch"):
                verify_loaded_databases(root, {**expected, "Debian": "0" * 64}, "\n".join(lines))

    def test_database_from_a_different_cache_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            loaded_root = root / "other-cache"
            lines = []
            expected: dict[str, str] = {}
            for name in ("Debian", "PyPI"):
                for cache in (root, loaded_root):
                    path = cache / "osv-scalibr" / name / "all.zip"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(f"{cache}:{name}".encode())
                actual = root / "osv-scalibr" / name / "all.zip"
                expected[name] = hashlib.sha256(actual.read_bytes()).hexdigest()
                lines.append(
                    f"Loaded {name} local db from "
                    f"{loaded_root / 'osv-scalibr' / name / 'all.zip'}"
                )
            with self.assertRaisesRegex(AuditError, "database_path_mismatch"):
                verify_loaded_databases(root, expected, "\n".join(lines))

    def test_findings_are_not_classified_as_execution_failures(self):
        report = {
            "results": [{
                "packages": [{
                    "package": {"ecosystem": "Debian:13"},
                    "groups": [{"ids": ["DEBIAN-CVE-2099-1234"]}],
                    "vulnerabilities": [{"id": "DEBIAN-CVE-2099-1234"}],
                }]
            }]
        }
        counts = count_findings(report)
        self.assertEqual(counts["matchRecords"], 1)
        self.assertEqual(counts["packageRecordsWithFindings"], 1)
        self.assertEqual(counts["uniqueAdvisoryIds"], 1)
        self.assertEqual(classify_scan(1, counts), "verified_with_findings")
        self.assertEqual(classify_scan(2, counts), "execution_error")

    def test_clean_scan_exit_code_must_match_empty_findings(self):
        counts = count_findings({"results": []})
        self.assertEqual(classify_scan(0, counts), "verified_no_findings")
        self.assertEqual(classify_scan(1, counts), "execution_error_exit_code_and_json_disagree")

    def test_provenance_failures_are_separate_from_execution_failures(self):
        self.assertEqual(
            classify_preflight_error("Debian_database_preflight_hash_mismatch"),
            "provenance_error",
        )
        self.assertEqual(
            classify_preflight_error("scanner_version_mismatch:expected=2.7.0"),
            "provenance_error",
        )
        self.assertEqual(classify_preflight_error("docker_image_not_present_locally"), "execution_error")

    def test_missing_database_load_lines_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(AuditError, "exactly_one_path"):
                verify_loaded_databases(Path(temp), {}, "OSV scan finished")

    def test_duplicate_database_load_lines_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "osv-scalibr" / "Debian" / "all.zip"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"debian")
            line = f"Loaded Debian local db from {path}"
            with self.assertRaisesRegex(AuditError, "exactly_one_path"):
                verify_loaded_databases(root, {}, f"{line}\n{line}")

    def test_match_denominators_count_advisory_records_not_package_groups(self):
        report = {
            "results": [{
                "packages": [{
                    "package": {"ecosystem": "Debian:13"},
                    "groups": [{"ids": ["CVE-A", "CVE-B"]}],
                    "vulnerabilities": [{"id": "CVE-A"}, {"id": "CVE-B"}],
                }]
            }]
        }
        counts = count_findings(report)
        self.assertEqual(counts["matchRecords"], 2)
        self.assertEqual(counts["packageRecordsWithFindings"], 1)
        self.assertEqual(counts["uniqueAdvisoryIds"], 2)


if __name__ == "__main__":
    unittest.main()
