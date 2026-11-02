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

    def test_long_legacy_license_text_is_hashed_not_misrepresented_as_a_license_name(self):
        import hashlib

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "legacy_pkg-1.0-py3-none-any.whl"
            legacy_text = ("Copyright and license terms " * 40).encode()
            metadata = (
                b"Metadata-Version: 2.1\nName: legacy-pkg\nVersion: 1.0\nLicense: "
                + legacy_text
            )
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("legacy_pkg-1.0.dist-info/METADATA", metadata)
            component, _ = _wheel_metadata(
                path,
                expected_hash=hashlib.sha256(path.read_bytes()).hexdigest(),
                expected_name="legacy-pkg",
                expected_version="1.0",
            )
            self.assertEqual(component["licenses"], [{"license": {"name": "NOASSERTION"}}])
            properties = {item["name"]: item["value"] for item in component["properties"]}
            self.assertEqual(
                properties["guardian:license-evidence"],
                "metadata-license-free-text-hashed-review-required",
            )
            self.assertEqual(
                properties["guardian:declared-license-text-sha256"],
                hashlib.sha256(legacy_text).hexdigest(),
            )
            self.assertNotIn(legacy_text.decode(), json.dumps(component))

    def test_artifact_hash_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "model.bin"
            path.write_bytes(b"local synthetic test")
            with self.assertRaisesRegex(InventoryError, "sha256_mismatch"):
                verify_file(path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
