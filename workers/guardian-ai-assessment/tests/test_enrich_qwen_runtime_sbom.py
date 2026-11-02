from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_local_llm_sbom import InventoryError  # noqa: E402
from enrich_qwen_runtime_sbom import (  # noqa: E402
    _apply_verified_wheel_metadata,
    _image_package_component,
    _parse_lock,
    normalize_name,
)


class EnrichQwenRuntimeSbomTests(unittest.TestCase):
    def test_normalizes_python_distribution_names(self) -> None:
        self.assertEqual(normalize_name("typing_extensions"), "typing-extensions")
        self.assertEqual(normalize_name("MarkupSafe"), "markupsafe")

    def test_parses_hash_pinned_multiline_lock_without_network_assumption(self) -> None:
        result = _parse_lock(
            "numpy==2.3.4 \\\n"
            "    --hash=sha256:" + "a" * 64 + "\n"
        )
        self.assertEqual(result, {"numpy": ("2.3.4", "a" * 64)})

    def test_unpinned_or_unrecognized_lock_entry_fails_closed(self) -> None:
        with self.assertRaisesRegex(InventoryError, "unrecognized_runtime_lock_entry"):
            _parse_lock("numpy>=2.3\n")

    def test_system_package_identity_requires_exact_image_component(self) -> None:
        image_bom = {
            "components": [
                {
                    "type": "library",
                    "name": "libc6",
                    "version": "2.41-1",
                    "purl": "pkg:deb/debian/libc6@2.41-1?arch=amd64&distro=debian-13",
                    "bom-ref": "pkg:deb/debian/libc6@2.41-1?arch=amd64&distro=debian-13",
                    "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                    "properties": [{"name": "guardian:package-architecture", "value": "amd64"}],
                }
            ]
        }
        component = _image_package_component(
            image_bom,
            {"package": "libc6", "version": "2.41-1", "architecture": "amd64"},
        )
        self.assertEqual(component["purl"], image_bom["components"][0]["purl"])
        self.assertNotIn("hashes", component)
        with self.assertRaisesRegex(InventoryError, "system_package_not_uniquely_in_image_sbom"):
            _image_package_component(
                image_bom,
                {"package": "libc6", "version": "2.41-2", "architecture": "amd64"},
            )

    def test_verified_wheel_license_evidence_replaces_stale_metadata_only(self) -> None:
        component = {
            "licenses": [{"license": {"name": "stale"}}],
            "properties": [
                {"name": "guardian:identity-status", "value": "verified"},
                {"name": "guardian:license-evidence", "value": "stale"},
            ],
        }
        verified = {
            "licenses": [{"license": {"name": "NOASSERTION"}}],
            "properties": [
                {"name": "guardian:license-evidence", "value": "metadata-license-free-text-hashed-review-required"},
                {"name": "guardian:wheel-metadata-sha256", "value": "a" * 64},
                {"name": "guardian:declared-license-text-sha256", "value": "b" * 64},
            ],
        }
        _apply_verified_wheel_metadata(component, verified)
        properties = {item["name"]: item["value"] for item in component["properties"]}
        self.assertEqual(component["licenses"], verified["licenses"])
        self.assertEqual(properties["guardian:identity-status"], "verified")
        self.assertEqual(
            properties["guardian:license-evidence"],
            "metadata-license-free-text-hashed-review-required",
        )
        self.assertEqual(properties["guardian:wheel-metadata-sha256"], "a" * 64)


if __name__ == "__main__":
    unittest.main()
