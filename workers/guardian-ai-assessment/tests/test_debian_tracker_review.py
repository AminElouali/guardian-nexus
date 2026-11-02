from __future__ import annotations

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from generate_debian_tracker_review import (
    parse_tracker_page,
    scan_findings,
    validate_scan_provenance,
)


class DebianTrackerReviewTests(unittest.TestCase):
    def valid_manifest(self) -> dict:
        required_flags = [
            "osv-scanner",
            "scan",
            "image",
            "--archive",
            "/tmp/image.tar",
            "--offline",
            "--offline-vulnerabilities",
            "--all-packages",
            "--all-vulns",
            "--format",
            "json",
            "--output-file",
            "/tmp/osv.json",
        ]
        return {
            "status": "verified_with_findings",
            "scanner": {"version": "2.7.0", "binarySha256": "a" * 64},
            "environment": {
                "XDG_CACHE_HOME": "/tmp/osv-cache",
                "networkPolicy": "offline",
            },
            "commands": {"scanner": required_flags},
            "exitCodes": {"scanner": 1, "auditWrapper": 0, "dockerSave": 0},
            "findings": {"advisoryIds": ["DEBIAN-CVE-2099-1234"]},
            "image": {"imageId": "sha256:" + "b" * 64},
            "capturedAt": "2026-11-02T00:00:00Z",
            "databases": {
                name: {
                    "expectedSha256": "c" * 64,
                    "preflightSha256": "c" * 64,
                    "loaded": {
                        "path": f"/tmp/osv-cache/osv-scalibr/{name}/all.zip",
                        "sha256": "c" * 64,
                        "status": "verified",
                    },
                }
                for name in ("Debian", "PyPI")
            },
        }

    def test_scan_manifest_provenance_is_extracted_and_verified(self) -> None:
        findings = {"DEBIAN-CVE-2099-1234": {"id": "DEBIAN-CVE-2099-1234"}}
        provenance = validate_scan_provenance(self.valid_manifest(), findings)
        self.assertEqual(provenance["scannerVersion"], "2.7.0")
        self.assertEqual(provenance["scannerExitCode"], 1)
        self.assertEqual(provenance["auditWrapperExitCode"], 0)
        self.assertTrue(provenance["xdgCacheHome"].endswith("osv-cache"))
        self.assertEqual(provenance["databases"]["Debian"]["status"], "verified")

    def test_wrong_database_hash_fails_closed(self) -> None:
        manifest = self.valid_manifest()
        manifest["databases"]["Debian"]["loaded"]["sha256"] = "d" * 64
        findings = {"DEBIAN-CVE-2099-1234": {"id": "DEBIAN-CVE-2099-1234"}}
        with self.assertRaisesRegex(ValueError, "Debian OSV database provenance"):
            validate_scan_provenance(manifest, findings)

    def test_missing_full_scan_flag_fails_closed(self) -> None:
        manifest = self.valid_manifest()
        manifest["commands"]["scanner"].remove("--all-vulns")
        findings = {"DEBIAN-CVE-2099-1234": {"id": "DEBIAN-CVE-2099-1234"}}
        with self.assertRaisesRegex(ValueError, "missing required options"):
            validate_scan_provenance(manifest, findings)

    def test_keeps_exact_osv_version_evidence_and_range_events(self) -> None:
        scan = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": "sqlite3",
                                "version": "3.46.1-7+deb13u2",
                                "ecosystem": "Debian:13",
                                "purl": "pkg:deb/debian/libsqlite3-0@3.46.1-7%2Bdeb13u2",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "DEBIAN-CVE-2099-1234",
                                    "affected": [
                                        {
                                            "package": {
                                                "ecosystem": "Debian:13",
                                                "name": "sqlite3",
                                                "purl": "pkg:deb/debian/sqlite3?arch=source",
                                            },
                                            "ranges": [
                                                {
                                                    "type": "ECOSYSTEM",
                                                    "events": [{"introduced": "0"}],
                                                }
                                            ],
                                            "versions": ["3.46.1-7+deb13u2"],
                                            "database_specific": {
                                                "source": "https://example.invalid/advisory"
                                            },
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        finding = scan_findings(scan)["DEBIAN-CVE-2099-1234"]
        self.assertEqual(
            finding["observedPackages"][0]["version"], "3.46.1-7+deb13u2"
        )
        self.assertEqual(
            finding["osvAffectedRecords"][0]["ranges"][0]["events"],
            [{"introduced": "0"}],
        )
        self.assertIn(
            "3.46.1-7+deb13u2", finding["osvAffectedRecords"][0]["versions"]
        )

    def test_tracks_tixie_status_and_fixed_version_separately(self) -> None:
        markdown = """# CVE
| **Name** | CVE-2099-1234 |
## Vulnerable and fixed packages
| Source Package | Release | Version | Status |
| --- | --- | --- | --- |
| [sample](https://example.invalid) | bookworm | 1.0 | vulnerable |
|  | trixie | 1.2 | vulnerable |
|  | forky, sid | 1.4 | fixed |

| Package | Type | Release | Fixed Version | Urgency |
| --- | --- | --- | --- | --- |
| sample | source | (unstable) | 1.4 | high |
## Notes
No Trixie fixed version listed.
* * *
"""
        result = parse_tracker_page("2099-1234", markdown)
        self.assertEqual(result["trixieRows"][0]["sourcePackage"], "sample")
        self.assertEqual(result["trixieRows"][0]["version"], "1.2")
        self.assertEqual(
            result["trixieAssessment"], "vulnerable_in_trixie_per_tracker"
        )
        self.assertEqual(result["fixedVersionRows"][0]["fixedVersion"], "1.4")

    def test_not_affected_is_not_mislabeled_as_a_patch(self) -> None:
        markdown = """| **Name** | CVE-2099-5678 |
## Vulnerable and fixed packages
| Source Package | Release | Version | Status |
| --- | --- | --- | --- |
| sqlite3 | trixie | 3.0.0-1 | fixed |

| Package | Type | Release | Fixed Version | Urgency |
| --- | --- | --- | --- | --- |
| sqlite3 | source | (unstable) | (not affected) |  |
## Notes
sqlite3 <not-affected> (Vulnerable code never present in Debian released version)
* * *
"""
        result = parse_tracker_page("2099-5678", markdown)
        self.assertEqual(
            result["trixieAssessment"],
            "not_affected_per_tracker_not_a_package_patch",
        )

    def test_missing_trixie_status_fails_instead_of_assuming_not_affected(self) -> None:
        markdown = """| **Name** | CVE-2099-9999 |
| Source Package | Release | Version | Status |
| --- | --- | --- | --- |
| sample | bookworm | 1.0 | vulnerable |
"""
        with self.assertRaisesRegex(ValueError, "no explicit Trixie row"):
            parse_tracker_page("2099-9999", markdown)


if __name__ == "__main__":
    unittest.main()
