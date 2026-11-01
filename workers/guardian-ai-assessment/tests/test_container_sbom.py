import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import generate_container_sbom as sbom


class ContainerSbomTests(unittest.TestCase):
    def test_debian_component_escapes_version_and_marks_unknown_license(self):
        component = sbom._debian_component(
            "libsample", "1:2.0+dfsg-1", "amd64", Path("/nonexistent")
        )
        self.assertIn("1%3A2.0%2Bdfsg-1", component["purl"])
        self.assertEqual(component["licenses"], [{"license": {"name": "NOASSERTION"}}])
        self.assertEqual(component["properties"][-1]["value"], "false")

    def test_bom_records_inventory_scope_without_claiming_vulnerability_scan(self):
        bom = sbom.build_bom(
            [],
            [("libsample", "1.0-1", "amd64")],
            image_name="guardian-ai-assessment:local",
            image_id="sha256:" + "a" * 64,
            base_image="python:3.13-slim-trixie@sha256:" + "b" * 64,
            timestamp="2026-11-01T00:00:00+00:00",
            documentation_root=Path("/nonexistent"),
        )
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertEqual(len(bom["components"]), 1)
        self.assertEqual(
            bom["metadata"]["component"]["properties"][-1]["value"],
            "not-performed-by-this-inventory",
        )
        self.assertEqual(
            bom["dependencies"][0]["dependsOn"],
            [bom["components"][0]["bom-ref"]],
        )


if __name__ == "__main__":
    unittest.main()
