import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_local_llm_sbom import InventoryError, _wheel_metadata, verify_file  # noqa: E402


class LocalLlmSbomTests(unittest.TestCase):
    def test_wheel_hash_and_embedded_license_are_verified(self):
        import hashlib

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "demo_pkg-1.2.3-py3-none-any.whl"
            metadata = b"Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.2.3\nLicense-Expression: MIT\n"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("demo_pkg-1.2.3.dist-info/METADATA", metadata)
                archive.writestr("demo_pkg-1.2.3.dist-info/licenses/LICENSE.txt", "MIT")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            component, licenses = _wheel_metadata(
                path,
                expected_hash=digest,
                expected_name="demo-pkg",
                expected_version="1.2.3",
            )
            self.assertEqual(component["licenses"], [{"expression": "MIT"}])
            self.assertEqual(licenses[0]["path"], "demo_pkg-1.2.3.dist-info/licenses/LICENSE.txt")
            self.assertEqual(component["hashes"][0]["content"], digest)

    def test_artifact_hash_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "model.bin"
            path.write_bytes(b"local synthetic test")
            with self.assertRaisesRegex(InventoryError, "sha256_mismatch"):
                verify_file(path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
