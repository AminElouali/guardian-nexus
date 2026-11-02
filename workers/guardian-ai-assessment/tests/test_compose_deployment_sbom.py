from __future__ import annotations

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from compose_deployment_sbom import compose


def bom(name: str, component_name: str, component_ref: str, count: int = 1) -> dict:
    components = [
        {
            "type": "library",
            "name": component_name,
            "version": "1.0",
            "purl": component_ref,
            "bom-ref": component_ref,
            "licenses": [{"license": {"id": "MIT"}}],
        }
    ]
    for index in range(1, count):
        ref = f"pkg:pypi/{name}-{index}@1.0"
        components.append(
            {
                "type": "library",
                "name": f"{name}-{index}",
                "version": "1.0",
                "purl": ref,
                "bom-ref": ref,
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {
                "type": "container" if name == "worker" else "application",
                "name": name,
                "bom-ref": f"urn:{name}:root",
            }
        },
        "components": components,
        "dependencies": [
            {
                "ref": f"urn:{name}:root",
                "dependsOn": [component["bom-ref"] for component in components],
            }
        ],
    }


class ComposeDeploymentSbomTests(unittest.TestCase):
    def test_composes_distinct_scopes_without_claiming_full_scan(self) -> None:
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            worker_path = Path(directory) / "worker.json"
            qwen_path = Path(directory) / "qwen.json"
            worker_path.write_text(
                json.dumps(bom("worker", "shared", "pkg:pypi/shared@1.0", 124)),
                encoding="utf-8",
            )
            qwen_path.write_text(
                json.dumps(bom("qwen", "shared", "pkg:pypi/shared@1.0", 13)),
                encoding="utf-8",
            )
            result = compose(worker_path, qwen_path)

        self.assertEqual(len(result["components"]), 139)
        refs = [component["bom-ref"] for component in result["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        shared_components = [
            component
            for component in result["components"]
            if component.get("purl") == "pkg:pypi/shared@1.0"
        ]
        self.assertEqual(len(shared_components), 2)
        self.assertNotEqual(
            shared_components[0]["bom-ref"], shared_components[1]["bom-ref"]
        )
        scopes = {
            prop["value"]
            for component in result["components"]
            for prop in component.get("properties", [])
            if prop.get("name") == "guardian:inventory-scope"
        }
        self.assertEqual(scopes, {"worker-image", "mounted-qwen-runtime"})
        metadata = result["metadata"]["component"]["properties"]
        self.assertIn(
            {
                "name": "guardian:vulnerability-assessment",
                "value": "Image archive and mounted-runtime SBOM are scanned separately; SBOM scan is supplemental and does not assess unidentifiable native files or model weights",
            },
            metadata,
        )
        self.assertEqual(len(result["dependencies"]), 3)

    def test_composes_profile_image_with_explicit_inventory_count(self) -> None:
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            worker_path = Path(directory) / "qwen-profile-image.json"
            qwen_path = Path(directory) / "mounted-qwen.json"
            worker_path.write_text(
                json.dumps(bom("qwen-profile", "shared", "pkg:pypi/shared@1.0", 90)),
                encoding="utf-8",
            )
            qwen_path.write_text(
                json.dumps(bom("qwen-runtime", "llama", "pkg:pypi/llama@1.0", 13)),
                encoding="utf-8",
            )
            result = compose(
                worker_path,
                qwen_path,
                expected_worker_components=90,
                expected_qwen_components=13,
            )

        self.assertEqual(len(result["components"]), 105)

    def test_invalid_component_count_is_rejected(self) -> None:
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            worker_path = Path(directory) / "worker.json"
            qwen_path = Path(directory) / "qwen.json"
            worker_path.write_text(json.dumps(bom("worker", "x", "pkg:pypi/x@1")), encoding="utf-8")
            qwen_path.write_text(json.dumps(bom("qwen", "y", "pkg:pypi/y@1")), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "component count mismatch"):
                compose(worker_path, qwen_path)


if __name__ == "__main__":
    unittest.main()
