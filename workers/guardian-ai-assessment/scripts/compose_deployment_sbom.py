#!/usr/bin/env python3
"""Compose the worker-image and separately mounted Qwen CycloneDX inventories."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_bom(document: dict[str, Any], expected_count: int, label: str) -> None:
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise ValueError(f"{label} must be CycloneDX 1.6")
    if len(document.get("components", [])) != expected_count:
        raise ValueError(
            f"{label} component count mismatch: expected {expected_count}, "
            f"got {len(document.get('components', []))}"
        )
    if not document.get("metadata", {}).get("component"):
        raise ValueError(f"{label} is missing its inventory root component")


def scoped_ref(scope: str, old_ref: str) -> str:
    digest = hashlib.sha256(f"{scope}\0{old_ref}".encode()).hexdigest()[:24]
    return f"urn:guardian-nexus:{scope}:component:{digest}"


def add_scope(
    document: dict[str, Any],
    scope: str,
    source_sha256: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    old_root = document["metadata"]["component"]
    root_source_ref = old_root.get("bom-ref") or old_root.get("purl") or old_root["name"]
    root_ref = scoped_ref(scope, root_source_ref)
    reference_map: dict[str, str] = {root_source_ref: root_ref}
    converted: list[dict[str, Any]] = []

    for source_component in document.get("components", []):
        component = copy.deepcopy(source_component)
        old_ref = (
            component.get("bom-ref")
            or component.get("purl")
            or f"{component.get('name', 'unnamed')}@{component.get('version', '')}"
        )
        new_ref = scoped_ref(scope, old_ref)
        if old_ref in reference_map and reference_map[old_ref] != new_ref:
            raise ValueError(f"duplicate component reference in {scope}: {old_ref}")
        reference_map[old_ref] = new_ref
        if component.get("purl"):
            reference_map[component["purl"]] = new_ref
        properties = component.setdefault("properties", [])
        properties.extend(
            [
                {"name": "guardian:inventory-scope", "value": scope},
                {"name": "guardian:source-bom-sha256", "value": source_sha256},
                {"name": "guardian:source-bom-ref", "value": old_ref},
            ]
        )
        component["bom-ref"] = new_ref
        converted.append(component)

    root = copy.deepcopy(old_root)
    root["bom-ref"] = root_ref
    root.setdefault("properties", []).extend(
        [
            {"name": "guardian:inventory-scope", "value": scope},
            {"name": "guardian:source-bom-sha256", "value": source_sha256},
        ]
    )
    converted.insert(0, root)

    dependencies = []
    for dependency in document.get("dependencies", []):
        old_ref = dependency.get("ref", "")
        if old_ref not in reference_map:
            raise ValueError(f"unmapped dependency ref in {scope}: {old_ref}")
        depends_on = []
        for target in dependency.get("dependsOn", []):
            if target not in reference_map:
                raise ValueError(f"unmapped dependency target in {scope}: {target}")
            depends_on.append(reference_map[target])
        dependencies.append(
            {"ref": reference_map[old_ref], "dependsOn": sorted(set(depends_on))}
        )
    if not dependencies:
        raise ValueError(f"{scope} BOM has no dependency graph")
    return converted, dependencies, root_ref


def compose(worker_path: Path, qwen_path: Path) -> dict[str, Any]:
    worker = json.loads(worker_path.read_text(encoding="utf-8"))
    qwen = json.loads(qwen_path.read_text(encoding="utf-8"))
    require_bom(worker, 124, "worker SBOM")
    require_bom(qwen, 13, "mounted Qwen SBOM")
    worker_hash = sha256_file(worker_path)
    qwen_hash = sha256_file(qwen_path)
    worker_components, worker_dependencies, worker_root = add_scope(
        worker, "worker-image", worker_hash
    )
    qwen_components, qwen_dependencies, qwen_root = add_scope(
        qwen, "mounted-qwen-runtime", qwen_hash
    )
    composition_ref = "urn:guardian-nexus:deployment-composition:worker-plus-qwen"
    components = worker_components + qwen_components
    refs = [component["bom-ref"] for component in components]
    if len(refs) != len(set(refs)):
        raise ValueError("composition contains duplicate bom-ref values")

    dependencies = [
        {
            "ref": composition_ref,
            "dependsOn": sorted([worker_root, qwen_root]),
        },
        *worker_dependencies,
        *qwen_dependencies,
    ]
    valid_refs = {composition_ref, *refs}
    for dependency in dependencies:
        if dependency["ref"] not in valid_refs or not set(dependency["dependsOn"]) <= valid_refs:
            raise ValueError("composition dependency graph contains an unresolved ref")

    serial = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"guardian-nexus:{worker_hash}:{qwen_hash}",
        )
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": composition_ref,
                "name": "Guardian Nexus worker plus mounted Qwen runtime",
                "version": "local-lab-composition",
                "properties": [
                    {
                        "name": "guardian:composition-scope",
                        "value": "worker image plus separately mounted local Qwen runtime",
                    },
                    {
                        "name": "guardian:vulnerability-assessment",
                        "value": "OSV scan covers worker image only; mounted Qwen runtime not scanned",
                    },
                    {
                        "name": "guardian:legal-approval",
                        "value": "not-provided",
                    },
                    {
                        "name": "guardian:worker-source-bom-sha256",
                        "value": worker_hash,
                    },
                    {
                        "name": "guardian:qwen-source-bom-sha256",
                        "value": qwen_hash,
                    },
                ],
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Guardian Nexus SBOM composition script",
                        "version": "1",
                    }
                ]
            },
        },
        "components": components,
        "dependencies": sorted(dependencies, key=lambda item: item["ref"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-sbom", type=Path, required=True)
    parser.add_argument("--qwen-sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        bom = compose(args.worker_sbom, args.qwen_sbom)
    except (OSError, json.JSONDecodeError, ValueError, KeyError) as error:
        print(f"composition_error: {error}")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "composed",
                "componentRecords": len(bom["components"]),
                "dependencyRecords": len(bom["dependencies"]),
                "workerImageVulnerabilityScanOnly": True,
                "qwenRuntimeVulnerabilityScan": "not-performed",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
