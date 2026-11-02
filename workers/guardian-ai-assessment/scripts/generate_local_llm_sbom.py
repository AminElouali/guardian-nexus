#!/usr/bin/env python3
"""Create a hash-verified CycloneDX SBOM for the separately mounted Qwen runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import uuid
import zipfile
from datetime import datetime, timezone
from email import message_from_bytes
from pathlib import Path
from typing import Any
from urllib.parse import quote


class InventoryError(RuntimeError):
    """Mounted runtime files did not match their evidence manifests."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, expected_sha256: str, expected_size: int | None = None) -> str:
    if not path.is_file():
        raise InventoryError(f"artifact_missing:{path}")
    actual_size = path.stat().st_size
    if expected_size is not None and actual_size != expected_size:
        raise InventoryError(f"artifact_size_mismatch:{path}")
    actual = sha256_file(path)
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or actual != expected_sha256:
        raise InventoryError(f"artifact_sha256_mismatch:{path}")
    return actual


def _property(name: str, value: str | int | bool) -> dict[str, str]:
    return {"name": name, "value": str(value).lower() if isinstance(value, bool) else str(value)}


def _pypi_purl(name: str, version: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:pypi/{quote(normalized, safe='.-_~')}@{quote(version, safe='.-_~')}"


def _verify_tar_member_hash(archive_path: Path, expected_hash: str, label: str) -> str:
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                continue
            if sha256_bytes(stream.read()) == expected_hash:
                return member.name
    raise InventoryError(f"source_license_file_hash_not_found:{label}")


def _wheel_metadata(
    wheel_path: Path,
    *,
    expected_hash: str,
    expected_name: str,
    expected_version: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    actual_hash = verify_file(wheel_path, expected_hash)
    with zipfile.ZipFile(wheel_path) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise InventoryError(f"wheel_metadata_count_invalid:{wheel_path.name}")
        metadata = message_from_bytes(archive.read(metadata_names[0]))
        if metadata.get("Name", "").lower().replace("_", "-") != expected_name.lower().replace("_", "-"):
            raise InventoryError(f"wheel_name_mismatch:{wheel_path.name}")
        if metadata.get("Version") != expected_version:
            raise InventoryError(f"wheel_version_mismatch:{wheel_path.name}")

        license_expression = metadata.get("License-Expression")
        license_name = metadata.get("License")
        license_evidence = (
            "metadata-license-expression"
            if license_expression
            else "metadata-license-name"
            if license_name and license_name.strip().upper() not in {"UNKNOWN", "NONE"}
            else "NOASSERTION"
        )
        license_entries = (
            [{"expression": license_expression}]
            if license_expression
            else [{"license": {"name": license_name.strip()}}]
            if license_evidence == "metadata-license-name"
            else [{"license": {"name": "NOASSERTION"}}]
        )
        licenses = [
            name for name in archive.namelist()
            if ".dist-info/licenses/" in name
            and not name.endswith("/")
            and Path(name).name.lower().startswith(("license", "copying", "notice"))
        ]
        license_files = [
            {
                "path": name,
                "sha256": sha256_bytes(archive.read(name)),
            }
            for name in sorted(licenses)
        ]
        component = {
            "type": "library",
            "bom-ref": _pypi_purl(expected_name, expected_version),
            "name": expected_name,
            "version": expected_version,
            "purl": _pypi_purl(expected_name, expected_version),
            "hashes": [{"alg": "SHA-256", "content": actual_hash}],
            "licenses": license_entries,
            "properties": [
                _property("guardian:artifact-role", "mounted-runtime-wheel"),
                _property("guardian:license-evidence", license_evidence),
                _property("guardian:wheel-filename", wheel_path.name),
                _property("guardian:license-files", json.dumps(license_files, sort_keys=True)),
                _property("guardian:wheel-metadata-sha256", sha256_bytes(archive.read(metadata_names[0]))),
            ],
        }
        return component, license_files


def generate(manifest: dict[str, Any], native: dict[str, Any], license_inventory: dict[str, Any],
             *, root: Path, timestamp: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    runtime = manifest["runtime"]
    model = manifest["model"]
    verified_artifacts: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []

    model_path = root / "generated-artifacts/guardian-llm-lab" / model["file"]
    model_hash = verify_file(model_path, model["sha256"], model["sizeBytes"])
    model_ref = f"urn:guardian:file:sha256:{model_hash}"
    components.append({
        "type": "file",
        "bom-ref": model_ref,
        "name": model["file"],
        "version": model["revision"],
        "hashes": [{"alg": "SHA-256", "content": model_hash}],
        "licenses": [{"expression": model["license"]}],
        "properties": [
            _property("guardian:artifact-role", "mounted-model-weights"),
            _property("guardian:license-evidence", "license-declared-by-local-model-manifest"),
            _property("guardian:source", model["source"]),
            _property("guardian:quantization", model["quantization"]),
        ],
    })
    verified_artifacts.append({"path": str(model_path.relative_to(root)), "sha256": model_hash, "status": "verified"})

    source_manifest_path = root / "workers/guardian-ai-assessment/local-llm-build/source-manifest.json"
    source_manifest_hash = sha256_file(source_manifest_path)
    source = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    if source_manifest_hash != native["sourceAndBuild"]["sourceManifestSha256"]:
        raise InventoryError("source_manifest_sha256_mismatch")
    if runtime["wheelSha256"] != native["activeRunnerArtifact"]["sha256"]:
        raise InventoryError("active_wheel_manifest_disagreement")
    if runtime["version"] != native["sourceAndBuild"]["version"]:
        raise InventoryError("runtime_source_version_mismatch")
    if license_inventory["sourceManifestSha256"] != source_manifest_hash:
        raise InventoryError("license_inventory_source_manifest_mismatch")
    active_license_inventory = license_inventory["llamaCppPythonActiveWheel"]
    if active_license_inventory["sha256"] != runtime["wheelSha256"]:
        raise InventoryError("active_wheel_license_inventory_mismatch")

    active_wheel_path = root / "generated-artifacts/guardian-llm-lab/wheelhouse" / runtime["wheel"]
    active_component, active_license_files = _wheel_metadata(
        active_wheel_path,
        expected_hash=runtime["wheelSha256"],
        expected_name="llama-cpp-python",
        expected_version=runtime["version"],
    )
    actual_active_license_files = {item["path"]: item["sha256"] for item in active_license_files}
    expected_active_license_files = {
        item["path"]: item["sha256"] for item in active_license_inventory.get("licenseFiles", [])
    }
    if actual_active_license_files != expected_active_license_files:
        raise InventoryError("active_wheel_license_file_inventory_mismatch")
    active_ref = active_component["bom-ref"]
    active_component["properties"].extend([
        _property("guardian:source-sdist-sha256", source["source"]["sha256"]),
        _property("guardian:source-license-file-path", _verify_tar_member_hash(
            root / "generated-artifacts/guardian-ai-assessment-source-audit" / source["source"]["filename"],
            source["source"]["licenseFileSha256"],
            "llama-cpp-python",
        )),
        _property("guardian:source-license-file-sha256", source["source"]["licenseFileSha256"]),
        _property("guardian:vendored-llama.cpp-commit", source["vendoredNativeLibrary"]["sourceCommit"]),
        _property("guardian:vendored-llama.cpp-declared-license", source["vendoredNativeLibrary"]["license"]),
        _property("guardian:builder-image", native["sourceAndBuild"]["builderImageId"]),
        _property("guardian:compiler", native["sourceAndBuild"]["toolchain"]["gcc"]),
        _property("guardian:build-network", native["sourceAndBuild"]["buildMode"]["network"]),
        _property("guardian:bit-for-bit-reproducibility", False),
    ])
    source_archive_path = root / "generated-artifacts/guardian-ai-assessment-source-audit" / source["source"]["filename"]
    source_archive_hash = verify_file(
        source_archive_path,
        source["source"]["sha256"],
        source["source"]["sizeBytes"],
    )
    verified_artifacts.append({
        "path": str(source_archive_path.relative_to(root)),
        "sha256": source_archive_hash,
        "licenseFileSha256": source["source"]["licenseFileSha256"],
        "status": "verified",
    })
    llama_license_member = _verify_tar_member_hash(
        source_archive_path,
        source["vendoredNativeLibrary"]["licenseFileSha256"],
        "vendored-llama.cpp",
    )
    active_component["properties"].append(
        _property("guardian:vendored-llama.cpp-license-file-path", llama_license_member)
    )
    patch_path = root / "workers/guardian-ai-assessment/local-llm-build" / source["sourcePatch"]["filename"]
    patch_hash = verify_file(patch_path, source["sourcePatch"]["sha256"])
    verified_artifacts.append({
        "path": str(patch_path.relative_to(root)),
        "sha256": patch_hash,
        "status": "verified",
    })
    build_inputs = native["sourceAndBuild"].get("buildInputsManifest")
    if build_inputs:
        build_inputs_path = root / build_inputs["path"]
        build_inputs_hash = verify_file(build_inputs_path, build_inputs["sha256"])
        verified_artifacts.append({
            "path": str(build_inputs_path.relative_to(root)),
            "sha256": build_inputs_hash,
            "status": "verified",
        })
    components.append(active_component)
    verified_artifacts.append({
        "path": str(active_wheel_path.relative_to(root)),
        "sha256": active_component["hashes"][0]["content"],
        "licenseFiles": active_license_files,
        "status": "verified",
    })

    license_by_name = {item["name"].lower().replace("-", "_"): item for item in license_inventory["runtimeDependencies"]}
    dependency_refs = [model_ref, active_ref]
    for dependency in runtime["dependencies"]:
        name = dependency["name"]
        ref_name = name.lower().replace("-", "_")
        inventory_record = license_by_name.get(ref_name)
        if dependency.get("wheel") and inventory_record and inventory_record.get("wheelSha256"):
            if dependency["sha256"] != inventory_record["wheelSha256"]:
                raise InventoryError(f"dependency_wheel_manifest_disagreement:{name}")
            wheel_path = root / "generated-artifacts/guardian-llm-lab/wheelhouse" / dependency["wheel"]
            component, license_files = _wheel_metadata(
                wheel_path,
                expected_hash=dependency["sha256"],
                expected_name=name,
                expected_version=dependency["version"],
            )
            actual_license_files = {item["path"]: item["sha256"] for item in license_files}
            expected_license_files = {
                item["path"]: item["sha256"] for item in inventory_record.get("licenseFiles", [])
            }
            if actual_license_files != expected_license_files:
                raise InventoryError(f"dependency_license_file_inventory_mismatch:{name}")
            components.append(component)
            dependency_refs.append(component["bom-ref"])
            for native_binary in inventory_record.get("nativeBinaries", []):
                member = native_binary["path"]
                with zipfile.ZipFile(wheel_path) as dependency_archive:
                    try:
                        native_payload = dependency_archive.read(member)
                    except KeyError as exc:
                        raise InventoryError(f"dependency_native_object_missing:{member}") from exc
                native_hash = sha256_bytes(native_payload)
                if native_hash != native_binary["sha256"]:
                    raise InventoryError(f"dependency_native_hash_mismatch:{member}")
                native_ref = f"urn:guardian:file:sha256:{native_hash}"
                declared_license = inventory_record.get("licenseFromManifest") or "NOASSERTION"
                components.append({
                    "type": "file",
                    "bom-ref": native_ref,
                    "name": Path(member).name,
                    "hashes": [{"alg": "SHA-256", "content": native_hash}],
                    "licenses": [{"license": {"name": declared_license}}],
                    "properties": [
                        _property("guardian:artifact-role", "native-extension-in-mounted-wheel"),
                        _property("guardian:archive-path", member),
                        _property("guardian:parent-wheel", wheel_path.name),
                        _property("guardian:license-evidence", inventory_record.get("licenseMetadata", ["NOASSERTION"])[0]),
                    ],
                })
                dependency_refs.append(native_ref)
                verified_artifacts.append({
                    "archive": str(wheel_path.relative_to(root)),
                    "member": member,
                    "sha256": native_hash,
                    "status": "verified",
                })
            verified_artifacts.append({
                "path": str(wheel_path.relative_to(root)),
                "sha256": component["hashes"][0]["content"],
                "licenseFiles": license_files,
                "status": "verified",
            })
        else:
            purl = _pypi_purl(name, dependency["version"])
            components.append({
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": dependency["version"],
                "purl": purl,
                "licenses": [{"license": {"name": "NOASSERTION"}}],
                "properties": [
                    _property("guardian:artifact-role", "runtime-package-inherited-from-worker-image"),
                    _property("guardian:provenance", dependency.get("source", "not-separately-inventoried")),
                    _property("guardian:artifact-hash", "unavailable-no-separate-wheel"),
                    _property("guardian:license-evidence", "NOASSERTION"),
                ],
            })
            dependency_refs.append(purl)

    active_wheel = zipfile.ZipFile(active_wheel_path)
    native_refs: list[str] = []
    try:
        for obj in native["activeNativeObjects"]:
            member = obj["file"]
            try:
                payload = active_wheel.read(member)
            except KeyError as exc:
                raise InventoryError(f"native_object_missing_from_active_wheel:{member}") from exc
            actual_hash = sha256_bytes(payload)
            if actual_hash != obj["sha256"]:
                raise InventoryError(f"native_object_hash_mismatch:{member}")
            ref = f"urn:guardian:file:sha256:{actual_hash}"
            components.append({
                "type": "file",
                "bom-ref": ref,
                "name": Path(member).name,
                "hashes": [{"alg": "SHA-256", "content": actual_hash}],
                "licenses": [{"expression": source["vendoredNativeLibrary"]["license"]}],
                "properties": [
                    _property("guardian:artifact-role", "native-library-in-mounted-wheel"),
                    _property("guardian:archive-path", member),
                    _property("guardian:license-evidence", "declared-vendored-llama.cpp-license; legal-review-pending"),
                    _property("guardian:source-commit", source["vendoredNativeLibrary"]["sourceCommit"]),
                    _property("guardian:elf-needed", ",".join(obj["needed"])),
                ],
            })
            native_refs.append(ref)
            verified_artifacts.append({
                "archive": str(active_wheel_path.relative_to(root)),
                "member": member,
                "sha256": actual_hash,
                "status": "verified",
            })
    finally:
        active_wheel.close()

    # Preserve explicit evidence that the SBOM is incomplete where the source
    # artifacts or license decisions do not support a stronger assertion.
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"guardian-qwen-runtime:{model_hash}:{active_ref}")
    root_ref = f"urn:uuid:{serial}"
    all_refs = sorted(component["bom-ref"] for component in components)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{
                "type": "application",
                "name": "guardian-local-llm-runtime-sbom",
                "version": "1.0.0",
            }]},
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "Guardian Nexus mounted Qwen local runtime",
                "version": model["revision"],
                "properties": [
                    _property("guardian:scope", "local model, configured wheel, wheel dependencies and native ELF objects"),
                    _property("guardian:vulnerability-assessment", "not-performed-by-this-sbom"),
                    _property("guardian:legal-approval", "not-provided"),
                    _property("guardian:source-manifest-sha256", source_manifest_hash),
                    _property("guardian:license-inventory-sha256", sha256_file(root / "generated-artifacts/guardian-ai-assessment-offline/native-runtime-license-inventory.json")),
                ],
            },
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
        "dependencies": [
            {"ref": root_ref, "dependsOn": all_refs},
            {"ref": active_ref, "dependsOn": sorted(set(dependency_refs + native_refs))},
        ],
    }
    verification = {
        "schemaVersion": 1,
        "capturedAt": bom["metadata"]["timestamp"],
        "status": "verified_with_explicit_gaps",
        "networkUsed": False,
        "model": {
            "id": model["id"],
            "sha256": model_hash,
            "license": model["license"],
            "licenseEvidence": "declared in local model manifest; full legal review not performed",
        },
        "activeWheel": {
            "version": runtime["version"],
            "sha256": active_component["hashes"][0]["content"],
            "license": source["output"]["runtimeLicense"],
            "sourceManifestSha256": source_manifest_hash,
            "sourceSdistSha256": source["source"]["sha256"],
            "licenseFiles": active_license_files,
        },
        "verifiedArtifacts": verified_artifacts,
        "nativeObjectCount": len(native_refs),
        "componentCount": len(components),
        "gaps": [
            "numpy and typing-extensions are inherited from the worker image and have no separate wheel hash in the local mounted-runtime inventory",
            "langdetect has conflicting MIT and Apache-2.0 evidence and remains unresolved",
            "native license and notice completeness requires legal review",
            "ELF DT_NEEDED system libraries are listed per object but are not independently file-hashed in this mounted-runtime inventory",
            "no signed build attestation or bit-for-bit wheel reproducibility is available",
            "this SBOM is an inventory, not a vulnerability scan or legal approval",
        ],
    }
    return bom, verification


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    worker = root / "workers/guardian-ai-assessment"
    generated = root / "generated-artifacts/guardian-ai-assessment-offline"
    try:
        manifest = json.loads((worker / "local-llm-manifest.json").read_text(encoding="utf-8"))
        native = json.loads((worker / "local-llm-build/native-runtime-inspection.json").read_text(encoding="utf-8"))
        licenses = json.loads((generated / "native-runtime-license-inventory.json").read_text(encoding="utf-8"))
        bom, verification = generate(manifest, native, licenses, root=root)
    except (OSError, KeyError, json.JSONDecodeError, InventoryError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "failed_closed", "error": str(exc)}), file=sys.stderr)
        return 2

    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    bom_path = output_dir / "qwen-mounted-runtime.cdx.json"
    verification_path = output_dir / "verification.json"
    bom_path.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    verification_path.write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    hashes = {
        bom_path.name: sha256_file(bom_path),
        verification_path.name: sha256_file(verification_path),
    }
    (output_dir / "SHA256SUMS.txt").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())),
        encoding="ascii",
    )
    print(json.dumps({
        "status": verification["status"],
        "componentCount": verification["componentCount"],
        "nativeObjectCount": verification["nativeObjectCount"],
        "bomSha256": hashes[bom_path.name],
        "verificationSha256": hashes[verification_path.name],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
