#!/usr/bin/env python3
"""Enrich the mounted-Qwen CycloneDX BOM from locally verified runtime artifacts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from email import message_from_bytes
from pathlib import Path
from typing import Any

from generate_local_llm_sbom import InventoryError, _property, _wheel_metadata


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _property_value(component: dict[str, Any], name: str) -> str | None:
    for item in component.get("properties", []):
        if item.get("name") == name:
            return str(item.get("value"))
    return None


def _parse_lock(text: str) -> dict[str, tuple[str, str]]:
    logical = re.sub(r"\\\s*\n\s*", " ", text)
    entries: dict[str, tuple[str, str]] = {}
    for line in logical.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.match(
            r"^\s*([A-Za-z0-9_.-]+)==([^\s;]+).*?--hash=sha256:([a-f0-9]{64})\s*$",
            line,
        )
        if not match:
            raise InventoryError(f"unrecognized_runtime_lock_entry:{line.strip()[:80]}")
        name, version, digest = match.groups()
        normalized = normalize_name(name)
        if normalized in entries:
            raise InventoryError(f"duplicate_runtime_lock_entry:{normalized}")
        entries[normalized] = (version, digest)
    return entries


def _wheel_requirements(path: Path) -> tuple[str, str, list[str]]:
    with zipfile.ZipFile(path) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise InventoryError(f"wheel_metadata_count_invalid:{path.name}")
        metadata = message_from_bytes(archive.read(metadata_names[0]))
    name, version = metadata.get("Name"), metadata.get("Version")
    if not name or not version:
        raise InventoryError(f"wheel_identity_missing:{path.name}")
    return name, version, metadata.get_all("Requires-Dist", [])


def _elf_info(readelf: str, payload: bytes, member: str) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(prefix="guardian-elf-", suffix=".so") as temporary:
        temporary.write(payload)
        temporary.flush()
        result = subprocess.run(
            [readelf, "-d", temporary.name],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    if result.returncode:
        raise InventoryError(f"readelf_failed:{member}:{result.returncode}")
    needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", result.stdout)
    sonames = re.findall(r"\(SONAME\).*?\[(.*?)\]", result.stdout)
    if len(sonames) > 1:
        raise InventoryError(f"multiple_elf_sonames:{member}")
    return {"needed": needed, "soname": sonames[0] if sonames else None}


def _system_query_script() -> str:
    return r'''
import json, os, re, subprocess, sys
needed = json.loads(sys.argv[1])
ldconfig = subprocess.run(["/sbin/ldconfig", "-p"], capture_output=True, text=True)
if ldconfig.returncode:
    raise SystemExit("ldconfig_failed")
result = []
for soname in needed:
    paths = []
    pattern = re.compile(r"\s*" + re.escape(soname) + r"\s+\([^)]*\)\s+=>\s+(\S+)")
    for line in ldconfig.stdout.splitlines():
        match = pattern.match(line)
        if match:
            paths.append(os.path.realpath(match.group(1)))
    owners = {}
    for path in sorted(set(paths)):
        query = subprocess.run(["dpkg-query", "-S", path], capture_output=True, text=True)
        for row in query.stdout.splitlines():
            package = row.split(": ", 1)[0]
            details = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}|${Version}|${Architecture}|${Status}", package],
                capture_output=True, text=True
            )
            if details.returncode:
                continue
            fields = details.stdout.split("|")
            if len(fields) == 4 and fields[3] == "install ok installed":
                owners[(fields[0], fields[1], fields[2])] = {
                    "package": fields[0], "version": fields[1], "architecture": fields[2],
                    "path": path
                }
    result.append({
        "soname": soname,
        "resolved": len(owners) == 1,
        "paths": sorted(set(paths)),
        "packages": [owners[key] for key in sorted(owners)]
    })
print(json.dumps(result, sort_keys=True))
'''


def _inspect_system_dependencies(
    image: str,
    sonames: list[str],
    docker: str,
) -> tuple[str, list[dict[str, Any]]]:
    inspect = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Id}}", image],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    image_id = inspect.stdout.strip()
    if inspect.returncode or not image_id.startswith("sha256:"):
        raise InventoryError("qwen_image_not_present_locally")
    if not sonames:
        return image_id, []
    command = [
        docker, "run", "--rm", "--pull=never", "--network=none", "--read-only",
        "--cpus=0.5", "--memory=128m", "--memory-swap=128m", "--pids-limit=32",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65532:65532",
        "--log-driver=none", "--entrypoint=python", image, "-c",
        _system_query_script(), json.dumps(sonames),
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=90
    )
    if result.returncode:
        raise InventoryError(f"offline_system_dependency_query_failed:{result.returncode}")
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise InventoryError("offline_system_dependency_query_invalid_json") from error
    if not isinstance(rows, list) or {row.get("soname") for row in rows} != set(sonames):
        raise InventoryError("offline_system_dependency_query_incomplete")
    return image_id, rows


def _image_package_component(
    image_bom: dict[str, Any], package: dict[str, str]
) -> dict[str, Any]:
    matches = [
        item for item in image_bom.get("components", [])
        if item.get("name") == package["package"]
        and item.get("version") == package["version"]
        and _property_value(item, "guardian:package-architecture") == package["architecture"]
        and item.get("purl", "").startswith("pkg:deb/")
    ]
    if len(matches) != 1:
        raise InventoryError(
            f"system_package_not_uniquely_in_image_sbom:{package['package']}:{package['version']}"
        )
    component = copy.deepcopy(matches[0])
    # Debian package components from this inventory do not carry an archive hash.
    component.pop("hashes", None)
    return component


def _apply_verified_wheel_metadata(
    component: dict[str, Any], verified_component: dict[str, Any]
) -> None:
    license_properties = {
        "guardian:license-evidence",
        "guardian:license-files",
        "guardian:wheel-metadata-sha256",
        "guardian:declared-license-text-sha256",
    }
    component["licenses"] = copy.deepcopy(verified_component.get("licenses", []))
    component["properties"] = [
        item for item in component.get("properties", [])
        if item.get("name") not in license_properties
    ] + [
        copy.deepcopy(item)
        for item in verified_component.get("properties", [])
        if item.get("name") in license_properties
    ]


def enrich(
    base_bom: dict[str, Any],
    base_verification: dict[str, Any],
    *,
    base_bom_sha256: str,
    image_bom: dict[str, Any],
    image_bom_sha256: str,
    runtime_manifest_sha256: str,
    native_inspection_sha256: str,
    wheelhouse_manifest: dict[str, Any],
    wheelhouse_manifest_sha256: str,
    image_wheelhouse: Path,
    runtime_wheelhouse: Path,
    runtime_lock: Path,
    runtime: dict[str, Any],
    native: dict[str, Any],
    image: str,
    docker: str = "docker",
    readelf: str = "readelf",
) -> tuple[dict[str, Any], dict[str, Any]]:
    runtime_manifest = runtime
    runtime = runtime_manifest.get("runtime", runtime_manifest)
    if base_bom.get("bomFormat") != "CycloneDX" or base_bom.get("specVersion") != "1.6":
        raise InventoryError("base_bom_must_be_cyclonedx_1_6")
    if wheelhouse_manifest.get("networkUsed") is not False:
        raise InventoryError("image_wheelhouse_network_provenance_not_offline")
    if wheelhouse_manifest.get("verification") != "local-sha256-lock-match":
        raise InventoryError("image_wheelhouse_manifest_not_verified")
    lock_sha = sha256_file(runtime_lock)
    lockfiles = wheelhouse_manifest.get("lockfiles", [])
    if len(lockfiles) != 1 or lockfiles[0].get("sha256") != lock_sha:
        raise InventoryError("image_wheelhouse_lockfile_hash_mismatch")
    locked = _parse_lock(runtime_lock.read_text(encoding="utf-8"))
    artifact_rows = wheelhouse_manifest.get("artifacts", [])
    if wheelhouse_manifest.get("artifactCount") != len(artifact_rows):
        raise InventoryError("image_wheelhouse_artifact_count_mismatch")

    components = copy.deepcopy(base_bom.get("components", []))
    package_components = {
        normalize_name(item.get("name", "")): item
        for item in components
        if item.get("type") == "library" and item.get("purl", "").startswith("pkg:pypi/")
    }
    image_components = {
        (normalize_name(item.get("name", "")), str(item.get("version", ""))): item
        for item in image_bom.get("components", [])
    }
    wheel_records: dict[str, dict[str, Any]] = {}
    runtime_dependencies = {normalize_name(item["name"]): item for item in runtime["dependencies"]}

    for artifact in artifact_rows:
        name, version = normalize_name(artifact["name"]), str(artifact["version"])
        if name not in locked or locked[name] != (version, artifact["sha256"]):
            raise InventoryError(f"wheelhouse_artifact_not_pinned:{name}")
        wheel_path = image_wheelhouse / artifact["filename"]
        actual_sha = sha256_file(wheel_path)
        if actual_sha != artifact["sha256"]:
            raise InventoryError(f"wheelhouse_artifact_hash_mismatch:{name}")
        if wheel_path.stat().st_size != artifact.get("sizeBytes"):
            raise InventoryError(f"wheelhouse_artifact_size_mismatch:{name}")
        component = package_components.get(name)
        if component is None or str(component.get("version")) != version:
            raise InventoryError(f"mounted_runtime_component_missing:{name}")
        image_component = image_components.get((name, version))
        if image_component is None:
            raise InventoryError(f"worker_image_component_missing:{name}")
        if component.get("purl") != image_component.get("purl"):
            raise InventoryError(f"worker_image_purl_mismatch:{name}")
        parsed_name, parsed_version, requires = _wheel_requirements(wheel_path)
        if normalize_name(parsed_name) != name or parsed_version != version:
            raise InventoryError(f"wheel_metadata_identity_mismatch:{name}")
        verified_component, license_files = _wheel_metadata(
            wheel_path,
            expected_hash=artifact["sha256"],
            expected_name=parsed_name,
            expected_version=version,
        )
        component["hashes"] = verified_component["hashes"]
        component["properties"] = [
            item for item in component.get("properties", [])
            if item.get("name") not in {
                "guardian:artifact-hash", "guardian:provenance",
            }
        ]
        _apply_verified_wheel_metadata(component, verified_component)
        component.setdefault("properties", []).extend([
            _property("guardian:artifact-role", "runtime-wheel-in-worker-image"),
            _property("guardian:identity-status", "verified-pypi-purl-and-wheel-sha256"),
            _property("guardian:wheel-sha256", actual_sha),
            _property("guardian:lockfile-sha256", lock_sha),
            _property("guardian:image-wheelhouse-manifest-sha256", wheelhouse_manifest_sha256),
            _property("guardian:worker-image-component-purl", image_component["purl"]),
            _property("guardian:worker-image-metadata-sha256-is-not-wheel-hash", True),
        ])
        wheel_records[name] = {
            "path": wheel_path,
            "sha256": actual_sha,
            "requires": requires,
            "licenseFiles": license_files,
            "component": component,
        }

    # Verify the two mounted dependency wheels against the local runtime manifest.
    for name, dependency in runtime_dependencies.items():
        if not dependency.get("wheel"):
            continue
        wheel_path = runtime_wheelhouse / dependency["wheel"]
        component = package_components.get(name)
        if component is None:
            raise InventoryError(f"runtime_dependency_component_missing:{name}")
        actual_sha = sha256_file(wheel_path)
        if actual_sha != dependency.get("sha256"):
            raise InventoryError(f"runtime_dependency_wheel_hash_mismatch:{name}")
        parsed_name, version, requires = _wheel_requirements(wheel_path)
        if normalize_name(parsed_name) != name or version != str(dependency["version"]):
            raise InventoryError(f"runtime_dependency_wheel_identity_mismatch:{name}")
        verified_component, license_files = _wheel_metadata(
            wheel_path,
            expected_hash=dependency["sha256"],
            expected_name=parsed_name,
            expected_version=version,
        )
        if component.get("purl") != verified_component.get("purl"):
            raise InventoryError(f"runtime_dependency_purl_mismatch:{name}")
        component["hashes"] = verified_component["hashes"]
        _apply_verified_wheel_metadata(component, verified_component)
        component.setdefault("properties", []).extend([
            _property("guardian:identity-status", "verified-pypi-purl-and-wheel-sha256"),
            _property("guardian:wheel-sha256", actual_sha),
        ])
        wheel_records[name] = {
            "path": wheel_path,
            "sha256": actual_sha,
            "requires": requires,
            "licenseFiles": license_files,
            "component": component,
        }

    # Cross-check inherited package identities and provenance from the actual image BOM.
    for name, dependency in runtime_dependencies.items():
        if dependency.get("wheel"):
            continue
        component = package_components.get(name)
        image_component = image_components.get((name, str(dependency["version"])))
        if component is None or image_component is None or component.get("purl") != image_component.get("purl"):
            raise InventoryError(f"inherited_runtime_identity_mismatch:{name}")
        component.setdefault("properties", []).extend([
            _property("guardian:identity-status", "verified-pypi-purl; artifact-sha-from-locked-wheel"),
            _property("guardian:provenance", "local hash-verified wheelhouse and worker image SBOM identity"),
        ])

    # Verify the base image's active wheel and all embedded ELF files.
    active = normalize_name(runtime["name"])
    active_record = {
        "path": runtime_wheelhouse / runtime["wheel"],
        "sha256": runtime["wheelSha256"],
    }
    if sha256_file(active_record["path"]) != active_record["sha256"]:
        raise InventoryError("active_runtime_wheel_hash_mismatch")
    active_component = package_components.get(active)
    if active_component is None:
        raise InventoryError("active_runtime_component_missing")
    active_name, active_version, active_requires = _wheel_requirements(active_record["path"])
    if normalize_name(active_name) != active or active_version != str(runtime["version"]):
        raise InventoryError("active_runtime_wheel_identity_mismatch")
    verified_active_component, active_license_files = _wheel_metadata(
        active_record["path"],
        expected_hash=active_record["sha256"],
        expected_name=active_name,
        expected_version=active_version,
    )
    if active_component.get("purl") != verified_active_component.get("purl"):
        raise InventoryError("active_runtime_wheel_purl_mismatch")
    active_component["hashes"] = verified_active_component["hashes"]
    _apply_verified_wheel_metadata(active_component, verified_active_component)
    active_record["requires"] = active_requires
    active_record["licenseFiles"] = active_license_files
    active_record["component"] = active_component
    wheel_records[active] = active_record

    # Remove stale file entries from the base BOM; regenerate every .so from every mounted wheel.
    retained = [
        item for item in components
        if item.get("type") != "file"
        or not _property_value(item, "guardian:artifact-role")
        or not _property_value(item, "guardian:artifact-role",).startswith("native-")
    ]
    # The model file remains, while prior native file records are replaced below.
    native_by_ref: dict[str, dict[str, Any]] = {}
    readelf_path = shutil.which(readelf) if not os.path.isabs(readelf) else readelf
    if not readelf_path or not Path(readelf_path).is_file():
        raise InventoryError("readelf_missing")
    readelf_version = subprocess.run(
        [readelf_path, "--version"], capture_output=True, text=True, check=False, timeout=15
    )
    if readelf_version.returncode:
        raise InventoryError("readelf_version_failed")
    readelf_sha = sha256_file(Path(readelf_path))
    expected_llama = {
        item["file"]: item["sha256"] for item in native["activeNativeObjects"]
    }
    seen_llama_hashes: set[str] = set()
    for package_name, record in wheel_records.items():
        with zipfile.ZipFile(record["path"]) as archive:
            native_members = [
                item for item in archive.namelist()
                if item.lower().endswith(".so") or ".so." in Path(item).name
            ]
            for member in sorted(native_members):
                payload = archive.read(member)
                digest = sha256_bytes(payload)
                info = _elf_info(readelf_path, payload, member)
                if package_name == active:
                    if digest not in expected_llama.values():
                        raise InventoryError(f"llama_native_inventory_mismatch:{member}")
                    expected_object = next(
                        item for item in native["activeNativeObjects"]
                        if item["sha256"] == digest
                    )
                    if set(info["needed"]) != set(expected_object["needed"]):
                        raise InventoryError(f"llama_dt_needed_mismatch:{member}")
                    seen_llama_hashes.add(digest)
                file_ref = f"urn:guardian:file:sha256:{digest}"
                if file_ref not in native_by_ref:
                    native_by_ref[file_ref] = {
                        "type": "file",
                        "bom-ref": file_ref,
                        "name": Path(member).name,
                        "hashes": [{"alg": "SHA-256", "content": digest}],
                        "licenses": [{"license": {"name": "NOASSERTION"}}],
                        "properties": [
                            _property("guardian:artifact-role", "native-binary-in-mounted-wheel"),
                            _property("guardian:identity-status", "sha256-identified-embedded-file; no-standalone-purl-or-cpe"),
                            _property("guardian:license-evidence", "per-binary-license-not-established; consult parent distribution"),
                            _property("guardian:elf-soname", info["soname"] or "not-declared"),
                            _property("guardian:elf-needed", ",".join(info["needed"])),
                        ],
                    }
                else:
                    existing = native_by_ref[file_ref]
                    if (
                        _property_value(existing, "guardian:elf-soname") != (info["soname"] or "not-declared")
                        or _property_value(existing, "guardian:elf-needed") != ",".join(info["needed"])
                    ):
                        raise InventoryError(f"same_binary_hash_has_conflicting_elf_metadata:{member}")
                properties = native_by_ref[file_ref]["properties"]
                for prop in (
                    _property("guardian:archive-path", member),
                    _property("guardian:parent-package-purl", record["component"]["purl"]),
                    _property("guardian:parent-wheel-sha256", record["sha256"]),
                ):
                    if prop not in properties:
                        properties.append(prop)
                if package_name == active:
                    for prop in (
                        _property("guardian:source-commit", native["sourceAndBuild"]["vendoredLlamaCpp"]["commit"]),
                        _property("guardian:source-library", "llama.cpp"),
                        _property("guardian:declared-source-license", "MIT; legal-review-pending"),
                    ):
                        if prop not in properties:
                            properties.append(prop)
                native_files = record.setdefault("nativeFiles", {})
                if digest not in native_files:
                    native_files[digest] = {
                        "path": member,
                        "paths": [member],
                        "sha256": digest,
                        "soname": info["soname"],
                        "needed": info["needed"],
                        "parentPurl": record["component"]["purl"],
                    }
                elif member not in native_files[digest]["paths"]:
                    native_files[digest]["paths"].append(member)
    if seen_llama_hashes != set(expected_llama.values()):
        raise InventoryError("llama_native_inventory_count_mismatch")

    # System dependencies are mapped in the local, isolated worker image via ldconfig and dpkg-query.
    known_sonames = {
        item["soname"] for record in wheel_records.values()
        for item in record.get("nativeFiles", {}).values() if item.get("soname")
    }
    external_sonames = sorted({
        need for record in wheel_records.values()
        for native_file in record.get("nativeFiles", {}).values()
        for need in native_file["needed"]
        if need not in known_sonames and need != "linux-vdso.so.1"
    })
    image_id, system_rows = _inspect_system_dependencies(image, external_sonames, docker)
    unresolved_system = []
    system_components: dict[str, dict[str, Any]] = {}
    system_map: dict[str, str] = {}
    for row in system_rows:
        if not row.get("resolved") or len(row.get("packages", [])) != 1:
            unresolved_system.append(row["soname"])
            continue
        package = row["packages"][0]
        image_component = _image_package_component(image_bom, package)
        image_ref = image_component.get("bom-ref") or image_component["purl"]
        component = system_components.get(image_ref)
        if component is None:
            component = image_component
            component.setdefault("properties", []).extend([
                _property("guardian:artifact-role", "system-runtime-dependency-in-worker-image"),
                _property("guardian:dependency-source-bom-sha256", image_bom_sha256),
                _property("guardian:artifact-hash", "Debian package archive/file hash not available in local inventory"),
            ])
            system_components[image_ref] = component
        system_map[row["soname"]] = image_ref

    # Mark model and file identities without inventing PURLs/CPEs.
    for component in retained:
        if component.get("name") == runtime_manifest.get("model", {}).get("file"):
            component.setdefault("properties", []).extend([
                _property("guardian:identity-status", "sha256-identified-model-artifact; no-standard-purl-or-cpe-justified"),
                _property("guardian:license-review", "manifest-declared; legal-review-not-performed"),
            ])

    native_records = list(native_by_ref.values())
    components = retained + native_records + list(system_components.values())
    all_refs = [item.get("bom-ref") for item in components]
    if len(all_refs) != len(set(all_refs)) or None in all_refs:
        raise InventoryError("enriched_component_refs_not_unique")
    component_by_ref = {item["bom-ref"]: item for item in components}
    package_ref_by_name = {
        normalize_name(item.get("name", "")): item["bom-ref"]
        for item in components if item.get("type") == "library" and item.get("purl", "").startswith("pkg:pypi/")
    }

    dependencies: dict[str, set[str]] = {}
    root_ref = base_bom["metadata"]["component"]["bom-ref"]
    dependencies[root_ref] = set(all_refs)
    omitted_optional: list[dict[str, str]] = []
    unresolved_python: list[dict[str, str]] = []
    for package_name, record in wheel_records.items():
        package_ref = package_ref_by_name[package_name]
        targets: set[str] = set()
        for requirement in record.get("requires", []):
            match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
            if not match:
                continue
            required_name = normalize_name(match.group(1))
            if "extra ==" in requirement or "extra==" in requirement:
                omitted_optional.append({"package": package_name, "requirement": requirement})
                continue
            target = package_ref_by_name.get(required_name)
            if target and target != package_ref:
                targets.add(target)
            else:
                unresolved_python.append({"package": package_name, "requirement": requirement})
        for native_file in record.get("nativeFiles", {}).values():
            file_ref = f"urn:guardian:file:sha256:{native_file['sha256']}"
            if file_ref not in component_by_ref:
                raise InventoryError(f"native_file_ref_missing:{native_file['path']}")
            elf_targets = set()
            for need in native_file["needed"]:
                embedded = next(
                    (
                        item for other_record in wheel_records.values()
                        for item in other_record.get("nativeFiles", {}).values()
                        if item.get("soname") == need
                    ),
                    None,
                )
                if embedded:
                    elf_targets.add(f"urn:guardian:file:sha256:{embedded['sha256']}")
                elif need in system_map:
                    elf_targets.add(system_map[need])
            dependencies[file_ref] = elf_targets
        if targets:
            dependencies[package_ref] = targets
    for name in ("linux-vdso.so.1",):
        if any(
            name in native_file["needed"]
            for record in wheel_records.values()
            for native_file in record.get("nativeFiles", {}).values()
        ):
            # Kernel-provided objects do not have a package PURL or standalone file hash.
            unresolved_system.append(name)

    # All dependency edges must resolve to a component; no package may depend on itself.
    for ref, targets in dependencies.items():
        if ref not in ({root_ref} | set(component_by_ref)) or not targets <= set(component_by_ref):
            raise InventoryError("enriched_dependency_graph_contains_unresolved_ref")
        if ref in targets:
            raise InventoryError("enriched_dependency_graph_contains_self_edge")
    enriched = copy.deepcopy(base_bom)
    enriched["components"] = sorted(components, key=lambda item: item["bom-ref"])
    enriched["dependencies"] = [
        {"ref": ref, "dependsOn": sorted(targets)}
        for ref, targets in sorted(dependencies.items())
    ]
    root_properties = enriched["metadata"]["component"].setdefault("properties", [])
    root_properties.extend([
        _property("guardian:worker-image-id", image_id),
        _property("guardian:worker-image-sbom-sha256", image_bom_sha256),
        _property("guardian:runtime-sbom-enrichment", "local-wheel-hashes, all wheel ELF files, readelf DT_NEEDED, worker-image Debian package mapping"),
        _property("guardian:vulnerability-assessment", "performed separately; see OSV manifest; this inventory does not itself assert scan coverage"),
    ])

    verification = copy.deepcopy(base_verification)
    verification.update({
        "schemaVersion": 2,
        "status": "verified_with_explicit_gaps",
        "networkUsed": False,
        "componentCount": len(components),
        "purlCount": sum(bool(item.get("purl")) for item in components),
        "cpeCount": sum(bool(item.get("cpe")) for item in components),
        "nativeBinaryFileCount": len(native_records),
        "nativeObjectCount": sum(
            1 for item in native_records
            if _property_value(item, "guardian:parent-package-purl") == active_component["purl"]
        ),
        "systemDependencyPackageCount": len(system_components),
        "systemDependencyInspection": {
            "imageReference": image,
            "imageId": image_id,
            "network": "none",
            "rootFilesystem": "read-only",
            "user": "65532:65532",
            "capabilities": "all dropped",
            "memoryLimit": "128m",
            "cpuLimit": "0.5",
            "pidsLimit": 32,
            "resolution": "ldconfig -p, realpath, dpkg-query -S and exact installed package identity",
        },
        "elfNeededCount": sum(
            len(item.get("needed", []))
            for record in wheel_records.values()
            for item in record.get("nativeFiles", {}).values()
        ),
        "systemDependencies": system_rows,
        "unresolvedSystemDependencies": sorted(set(unresolved_system)),
        "wheelArtifacts": [
            {
                "package": name,
                "version": str(record["component"].get("version")),
                "sha256": record["sha256"],
                "path": str(record["path"]),
                "declaredLicenses": record["component"].get("licenses", []),
                "licenseEvidence": _property_value(
                    record["component"], "guardian:license-evidence"
                ),
                "wheelMetadataSha256": _property_value(
                    record["component"], "guardian:wheel-metadata-sha256"
                ),
                "declaredLicenseTextSha256": _property_value(
                    record["component"], "guardian:declared-license-text-sha256"
                ),
                "nativeBinaryCount": len(record.get("nativeFiles", {})),
                "licenseFiles": record.get("licenseFiles", []),
            }
            for name, record in sorted(wheel_records.items())
        ],
        "declaredRuntimeRequirements": {
            name: record.get("requires", []) for name, record in sorted(wheel_records.items())
        },
        "omittedOptionalRequirements": omitted_optional,
        "unresolvedPythonRequirements": unresolved_python,
        "inputs": {
            "baseSbomSha256": base_bom_sha256,
            "workerImageSbomSha256": image_bom_sha256,
            "runtimeManifestSha256": runtime_manifest_sha256,
            "nativeInspectionSha256": native_inspection_sha256,
            "wheelhouseManifestSha256": wheelhouse_manifest_sha256,
            "runtimeLockSha256": lock_sha,
            "readelfPath": str(Path(readelf_path).resolve()),
            "readelfVersion": readelf_version.stdout.splitlines()[0].strip(),
            "readelfBinarySha256": readelf_sha,
            "workerImageId": image_id,
        },
        "gaps": [
            "No signed build attestation or bit-for-bit wheel reproducibility is available.",
            "Per-binary license mapping inside third-party wheels is not established; package-level metadata and notices are preserved, not treated as legal approval.",
            "The langdetect MIT/Apache-2.0 discrepancy remains unresolved; langdetect is not present in this Qwen runtime profile.",
            "The model is hash-identified but has no justified standardized PURL/CPE; its license remains manifest-declared, not legally approved.",
            "The worker image scan and mounted-runtime SBOM scan are separate; raw ELF/model files without package identifiers are not proven vulnerability-free.",
            "System package identities map to the worker image SBOM; individual Debian shared-library file hashes are not separately available here.",
        ],
    })
    if unresolved_system:
        verification["gaps"].append(
            "Some ELF DT_NEEDED entries could not be mapped to an installed Debian package: "
            + ", ".join(sorted(set(unresolved_system)))
        )
    if unresolved_python:
        verification["gaps"].append(
            "Some unconditional Python Requires-Dist entries are not represented by installed runtime packages."
        )
    return enriched, verification


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--base-bom", type=Path, required=True)
    parser.add_argument("--base-verification", type=Path, required=True)
    parser.add_argument("--image-sbom", type=Path, required=True)
    parser.add_argument("--image-wheelhouse-manifest", type=Path, required=True)
    parser.add_argument("--image-wheelhouse", type=Path, required=True)
    parser.add_argument("--runtime-wheelhouse", type=Path, default=Path("generated-artifacts/guardian-llm-lab/wheelhouse"))
    parser.add_argument("--image", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--readelf", default="readelf")
    args = parser.parse_args()
    root = args.root.resolve()
    worker = root / "workers/guardian-ai-assessment"
    def read_json(path: Path) -> dict[str, Any]:
        actual = path if path.is_absolute() else root / path
        return json.loads(actual.read_text(encoding="utf-8"))
    def resolve(path: Path) -> Path:
        return path if path.is_absolute() else root / path
    try:
        runtime = read_json(Path("workers/guardian-ai-assessment/local-llm-manifest.json"))
        native = read_json(Path("workers/guardian-ai-assessment/local-llm-build/native-runtime-inspection.json"))
        base_bom = read_json(args.base_bom)
        base_verification = read_json(args.base_verification)
        image_bom_path = resolve(args.image_sbom)
        image_bom = read_json(args.image_sbom)
        runtime_manifest_path = worker / "local-llm-manifest.json"
        native_inspection_path = worker / "local-llm-build/native-runtime-inspection.json"
        wheelhouse_manifest_path = resolve(args.image_wheelhouse_manifest)
        wheelhouse_manifest = read_json(args.image_wheelhouse_manifest)
        if not resolve(args.image_wheelhouse).is_dir() or not resolve(args.runtime_wheelhouse).is_dir():
            raise InventoryError("wheelhouse_directory_missing")
    except (OSError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "failed_closed", "error": str(error)}), file=sys.stderr)
        return 2
    try:
        bom, verification = enrich(
            base_bom,
            base_verification,
            image_bom=image_bom,
            base_bom_sha256=sha256_file(resolve(args.base_bom)),
            image_bom_sha256=sha256_file(image_bom_path),
            runtime_manifest_sha256=sha256_file(runtime_manifest_path),
            native_inspection_sha256=sha256_file(native_inspection_path),
            wheelhouse_manifest=wheelhouse_manifest,
            wheelhouse_manifest_sha256=sha256_file(wheelhouse_manifest_path),
            image_wheelhouse=resolve(args.image_wheelhouse),
            runtime_wheelhouse=resolve(args.runtime_wheelhouse),
            runtime_lock=worker / "requirements-qwen-runtime.txt",
            runtime=runtime,
            native=native,
            image=args.image,
            docker=args.docker,
            readelf=args.readelf,
        )
    except (InventoryError, OSError, KeyError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "failed_closed", "error": str(error)}), file=sys.stderr)
        return 2
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    bom_path = output_dir / "qwen-mounted-runtime.cdx.json"
    verification_path = output_dir / "verification.json"
    bom_path.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    verification_path.write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sums = {
        bom_path.name: sha256_file(bom_path),
        verification_path.name: sha256_file(verification_path),
    }
    sums_path = output_dir / "SHA256SUMS.txt"
    sums_path.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())),
        encoding="ascii",
    )
    print(json.dumps({
        "status": verification["status"],
        "componentCount": verification["componentCount"],
        "nativeBinaryFileCount": verification["nativeBinaryFileCount"],
        "systemDependencyPackageCount": verification["systemDependencyPackageCount"],
        "unresolvedSystemDependencies": verification["unresolvedSystemDependencies"],
        "bomSha256": sums[bom_path.name],
        "verificationSha256": sums[verification_path.name],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
