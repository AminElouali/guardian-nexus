from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_offline_osv_sbom_audit import build_command, run_audit  # noqa: E402
from run_offline_osv_audit import AuditError  # noqa: E402


class OfflineOsvSbomAuditTests(unittest.TestCase):
    def test_command_is_offline_sbom_only_and_scans_all_packages(self) -> None:
        command = build_command("/opt/osv-scanner", Path("/input/runtime.cdx.json"), Path("/out/osv.json"))
        self.assertEqual(command[1:4], ["scan", "source", "--sbom"])
        self.assertIn("--offline", command)
        self.assertIn("--offline-vulnerabilities", command)
        self.assertIn("--all-packages", command)
        self.assertIn("--all-vulns", command)
        self.assertNotIn("image", command)

    def test_verified_scan_records_database_and_scanner_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = root / "cache"
            for name in ("Debian", "PyPI"):
                database = cache / "osv-scalibr" / name / "all.zip"
                database.parent.mkdir(parents=True, exist_ok=True)
                database.write_bytes(f"local-{name}".encode())
            db_hashes = {
                name: hashlib.sha256((cache / "osv-scalibr" / name / "all.zip").read_bytes()).hexdigest()
                for name in ("Debian", "PyPI")
            }
            sbom = root / "runtime.cdx.json"
            sbom.write_text(
                json.dumps({
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [
                        {"bom-ref": "pkg:pypi/demo@1.0", "purl": "pkg:pypi/demo@1.0"},
                        {
                            "bom-ref": "urn:guardian:file:sha256:" + "a" * 64,
                            "name": "embedded.so",
                            "type": "file",
                            "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                        },
                    ],
                }),
                encoding="utf-8",
            )
            scanner = root / "fake-osv"
            scanner.write_bytes(b"test-only simulated scanner identity")
            args = Namespace(
                sbom=sbom,
                output_dir=root / "output",
                scanner=str(scanner),
                expected_scanner_sha256=hashlib.sha256(scanner.read_bytes()).hexdigest(),
                xdg_cache_home=cache,
                debian_db_sha256=db_hashes["Debian"],
                pypi_db_sha256=db_hashes["PyPI"],
                expected_scanner_version="2.7.0",
                timeout=30,
            )
            def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
                env = kwargs["env"]
                self.assertEqual(env["XDG_CACHE_HOME"], str(cache.resolve()))
                self.assertNotIn("HOME", env)
                if command[-1] == "--version":
                    return SimpleNamespace(returncode=0, stdout="osv-scanner version: 2.7.0\n", stderr="")
                output_path = Path(command[command.index("--output-file") + 1])
                output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
                stderr = "".join(
                    f"Loaded {name} local db from {cache}/osv-scalibr/{name}/all.zip\n"
                    for name in ("Debian", "PyPI")
                )
                return SimpleNamespace(returncode=0, stdout="", stderr=stderr)

            with patch("run_offline_osv_sbom_audit.subprocess.run", side_effect=fake_run):
                _, manifest = run_audit(args)
            self.assertEqual(manifest["status"], "verified_no_findings")
            self.assertEqual(manifest["scanner"]["binarySha256"], args.expected_scanner_sha256)
            self.assertEqual(manifest["databases"]["Debian"]["sha256"], db_hashes["Debian"])
            self.assertEqual(manifest["environment"]["XDG_CACHE_HOME"], str(cache.resolve()))
            self.assertEqual(manifest["environment"]["HOME"], "unset")
            self.assertEqual(manifest["findings"]["uniqueAdvisoryIds"], 0)
            self.assertEqual(manifest["input"]["coverageStatus"], "partial_identity_coverage")
            self.assertEqual(manifest["input"]["componentsWithoutPurlOrCpe"], 1)

    def test_wrong_database_hash_fails_closed_before_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = root / "cache"
            (cache / "osv-scalibr" / "Debian").mkdir(parents=True)
            (cache / "osv-scalibr" / "PyPI").mkdir(parents=True)
            for name in ("Debian", "PyPI"):
                (cache / "osv-scalibr" / name / "all.zip").write_bytes(name.encode())
            sbom = root / "runtime.cdx.json"
            sbom.write_text(
                json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}),
                encoding="utf-8",
            )
            scanner = root / "fake-osv"
            scanner.write_text(
                "#!" + sys.executable + "\n"
                "import sys\n"
                "print('osv-scanner version: 2.7.0')\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            scanner.chmod(0o755)
            args = Namespace(
                sbom=sbom,
                output_dir=root / "output",
                scanner=str(scanner),
                expected_scanner_sha256=hashlib.sha256(scanner.read_bytes()).hexdigest(),
                xdg_cache_home=cache,
                debian_db_sha256="0" * 64,
                pypi_db_sha256="0" * 64,
                expected_scanner_version="2.7.0",
                timeout=30,
            )
            with self.assertRaisesRegex(AuditError, "Debian_database_preflight_hash_mismatch"):
                run_audit(args)


if __name__ == "__main__":
    unittest.main()
