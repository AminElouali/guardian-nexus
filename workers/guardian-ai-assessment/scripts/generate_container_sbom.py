#!/usr/bin/env python3
"""Generate a local CycloneDX inventory from installed Python and Debian packages."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

SBOM_TOOL_VERSION = "guardian-local-container-inventory-1.0.0"
UNKNOWN_LICENSES = {"", "UNKNOWN", "UNKNOWN LICENSE", "NONE", "NOASSERTION"}


def _property(name: str, value: str | int | bool) -> dict[str, str]:
    return {"name": name, "value": str(value).lower() if isinstance(value, bool) else str(value)}


def _license_evidence(metadata: Any) -> tuple[list[dict[str, Any]], str]:
    expression = (metadata.get("License-Expression") or "").strip()
    if expression and len(expression) <= 256:
        return [{"expression": expression}], "reported-license-expression"

    license_name = (metadata.get("License") or "").strip()
    if license_name.upper() not in UNKNOWN_LICENSES and len(license_name) <= 160 and "\n" not in license_name:
        return [{"license": {"name": license_name}}], "reported-un-normalized-license-name"

    return [{"license": {"name": "NOASSERTION"}}], "NOASSERTION"


def _python_component(distribution: Any) -> dict[str, Any]:
    metadata = distribution.metadata
    name = metadata.get("Name") or "unknown"
    version = distribution.version
    normalized_name = re.sub(r"[-_.]+", "-", name).lower()
    encoded_version = quote(version, safe=".-_~")
    purl = f"pkg:pypi/{quote(normalized_name, safe='.-_~')}@{encoded_version}"
    license_entries, license_status = _license_evidence(metadata)

    files = list(distribution.files or [])
    license_file_count = sum(
        1
        for item in files
        if any(
            marker in Path(str(item)).name.lower()
            for marker in ("license", "copying", "notice")
        )
    )
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
        "licenses": license_entries,
        "properties": [
            _property("guardian:license-evidence", license_status),
            _property("guardian:license-files-listed", license_file_count),
        ],
    }
    metadata_file = next((item for item in files if Path(str(item)).name == "METADATA"), None)
    if metadata_file is not None:
        try:
            digest = hashlib.sha256(
                distribution.locate_file(metadata_file).read_bytes()
            ).hexdigest()
            component["hashes"] = [{"alg": "SHA-256", "content": digest}]
        except OSError:
            component["properties"].append(
                _property("guardian:metadata-hash", "unavailable")
            )
    return component


def _debian_component(
    name: str, version: str, architecture: str, documentation_root: Path
) -> dict[str, Any]:
    normalized_name = quote(name.lower(), safe=".-_~")
    encoded_version = quote(version, safe=".-_~")
    encoded_arch = quote(architecture, safe=".-_~")
    purl = (
        f"pkg:deb/debian/{normalized_name}@{encoded_version}"
        f"?arch={encoded_arch}&distro=debian-13"
    )
    copyright_file = documentation_root / name / "copyright"
    return {
        "type": "library",
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
        "licenses": [{"license": {"name": "NOASSERTION"}}],
        "properties": [
            _property("guardian:package-architecture", architecture),
            _property(
                "guardian:license-evidence",
                "Debian copyright file present; license not normalized"
                if copyright_file.is_file()
                else "NOASSERTION",
            ),
            _property("guardian:copyright-file-present", copyright_file.is_file()),
        ],
    }


def build_bom(
    python_distributions: list[Any],
    debian_packages: list[tuple[str, str, str]],
    *,
    image_name: str,
    image_id: str,
    base_image: str,
    os_id: str = "debian",
    os_version: str = "13",
    documentation_root: Path = Path("/usr/share/doc"),
    timestamp: str | None = None,
) -> dict[str, Any]:
    python_components = [_python_component(item) for item in python_distributions]
    debian_components = [
        _debian_component(name, version, architecture, documentation_root)
        for name, version, architecture in debian_packages
    ]
    components = sorted(
        [*python_components, *debian_components],
        key=lambda item: (item["purl"], item["version"]),
    )
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{image_name}:{image_id}")
    timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    root_ref = f"urn:guardian-nexus:container:{serial}"
    root = {
        "type": "container",
        "bom-ref": root_ref,
        "name": image_name,
        "version": image_id.removeprefix("sha256:"),
        "hashes": [{"alg": "SHA-256", "content": image_id.removeprefix("sha256:")}],
        "properties": [
            _property("guardian:base-image", base_image),
            _property("guardian:os", f"{os_id}:{os_version}"),
            _property("guardian:inventory-scope", "installed Debian and Python packages"),
            _property("guardian:vulnerability-assessment", "not-performed-by-this-inventory"),
        ],
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": SBOM_TOOL_VERSION,
                        "version": "1.0.0",
                    }
                ]
            },
            "component": root,
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": [item["bom-ref"] for item in components]}
        ],
    }


def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')
    return result


def _debian_inventory() -> list[tuple[str, str, str]]:
    query = subprocess.run(
        [
            "dpkg-query",
            "-W",
            "-f=${Package}\\t${Version}\\t${Architecture}\\t${Status}\\n",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    packages: list[tuple[str, str, str]] = []
    for line in query.stdout.splitlines():
        name, version, architecture, status = line.split("\t", 3)
        if status == "install ok installed":
            packages.append((name, version, architecture))
    return packages


def collect_bom(args: argparse.Namespace) -> dict[str, Any]:
    os_release = _read_os_release()
    return build_bom(
        list(importlib.metadata.distributions()),
        _debian_inventory(),
        image_name=args.image_name,
        image_id=args.image_id,
        base_image=args.base_image,
        os_id=os_release.get("ID", "unknown"),
        os_version=os_release.get("VERSION_ID", "unknown"),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-name", required=True)
    parser.add_argument("--image-id", required=True, help="Local Docker image config ID")
    parser.add_argument("--base-image", required=True, help="Digest-pinned FROM reference")
    args = parser.parse_args()
    json.dump(collect_bom(args), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
