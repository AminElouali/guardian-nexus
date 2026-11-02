#!/usr/bin/env python3
"""Run a provenance-checked offline OSV scan against a local CycloneDX SBOM."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from run_offline_osv_audit import (
    AuditError,
    classify_preflight_error,
    classify_scan,
    count_findings,
    parse_scanner_version,
    sha256_file,
    verify_loaded_databases,
)


def build_command(
    scanner: str, sbom: Path, output: Path
) -> list[str]:
    return [
        scanner,
        "scan",
        "source",
        "--sbom",
        str(sbom),
        "--offline",
        "--offline-vulnerabilities",
        "--all-packages",
        "--all-vulns",
        "--format",
        "json",
        "--output-file",
        str(output),
    ]


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def run_audit(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    sbom = args.sbom.expanduser().resolve(strict=True)
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    document = json.loads(sbom.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise AuditError("input_sbom_must_be_cyclonedx_1_6")
    components = document.get("components")
    if not isinstance(components, list):
        raise AuditError("input_sbom_components_invalid")
    refs = [component.get("bom-ref") for component in components if isinstance(component, dict)]
    if len(refs) != len(components) or None in refs or len(set(refs)) != len(refs):
        raise AuditError("input_sbom_component_refs_invalid")
    no_package_identifier = [
        {
            "name": component.get("name", "unnamed"),
            "type": component.get("type", "unknown"),
            "sha256": next(
                (
                    item.get("content")
                    for item in component.get("hashes", [])
                    if item.get("alg") == "SHA-256"
                ),
                None,
            ),
        }
        for component in components
        if not component.get("purl") and not component.get("cpe")
    ]
    sbom_sha = sha256_file(sbom)

    scanner_path = args.scanner
    if not Path(scanner_path).is_absolute():
        from shutil import which

        scanner_path = which(scanner_path) or ""
    if not scanner_path or not Path(scanner_path).is_file():
        raise AuditError("scanner_executable_missing")
    scanner_path = str(Path(scanner_path).resolve())
    scanner_hash = sha256_file(Path(scanner_path))
    if scanner_hash != args.expected_scanner_sha256:
        raise AuditError("scanner_binary_hash_mismatch")

    xdg = args.xdg_cache_home.expanduser().resolve(strict=True)
    if not xdg.is_dir():
        raise AuditError("xdg_cache_home_not_directory")
    db_hashes = {"Debian": args.debian_db_sha256, "PyPI": args.pypi_db_sha256}
    for name, expected in db_hashes.items():
        path = (xdg / "osv-scalibr" / name / "all.zip").resolve(strict=True)
        if sha256_file(path) != expected:
            raise AuditError(f"{name}_database_preflight_hash_mismatch")

    env = os.environ.copy()
    env.pop("HOME", None)
    env["XDG_CACHE_HOME"] = str(xdg)
    version_result = subprocess.run(
        [scanner_path, "--version"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=30,
    )
    if version_result.returncode:
        raise AuditError(f"scanner_version_command_failed:{version_result.returncode}")
    version = parse_scanner_version(version_result.stdout + version_result.stderr)
    if version != args.expected_scanner_version:
        raise AuditError(f"scanner_version_mismatch:{version}")

    output_json = output_dir / "osv.json"
    command = build_command(scanner_path, sbom, output_json)
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=args.timeout,
    )
    _write_text(output_dir / "stdout.log", result.stdout)
    _write_text(output_dir / "stderr.log", result.stderr)
    scanner_exit = result.returncode
    if scanner_exit not in (0, 1) or not output_json.is_file():
        raise AuditError(f"scanner_execution_failed:{scanner_exit}")
    scan_document = json.loads(output_json.read_text(encoding="utf-8"))
    databases = verify_loaded_databases(xdg, db_hashes, result.stderr)
    findings = count_findings(scan_document)
    status = classify_scan(scanner_exit, findings)
    if status.startswith("execution_error"):
        raise AuditError(status)

    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "input": {
            "path": str(sbom),
            "sha256": sbom_sha,
            "format": "CycloneDX 1.6",
            "componentCount": len(components),
            "componentsWithPurlOrCpe": len(components) - len(no_package_identifier),
            "componentsWithoutPurlOrCpe": len(no_package_identifier),
            "identityLimitedComponents": no_package_identifier,
            "coverageStatus": "partial_identity_coverage" if no_package_identifier else "package_identity_coverage",
        },
        "scanner": {
            "path": scanner_path,
            "version": version,
            "binarySha256": scanner_hash,
        },
        "environment": {
            "XDG_CACHE_HOME": str(xdg),
            "HOME": "unset",
            "networkPolicy": "OSV --offline and --offline-vulnerabilities; local SBOM input only",
        },
        "databases": databases,
        "command": command,
        "exitCodes": {
            "scanner": scanner_exit,
            "auditWrapper": 0,
        },
        "findings": findings,
        "artifacts": {
            name: {"sha256": sha256_file(output_dir / name)}
            for name in ("osv.json", "stdout.log", "stderr.log")
        },
    }
    _write_text(output_dir / "command.txt", shlex.join(command) + "\n")
    _write_text(
        output_dir / "context.txt",
        "\n".join(
            [
                f"capturedAt={manifest['capturedAt']}",
                f"inputSbom={sbom}",
                f"inputSbomSha256={sbom_sha}",
                f"scannerVersion={version}",
                f"scannerBinarySha256={scanner_hash}",
                f"XDG_CACHE_HOME={xdg}",
                "HOME=unset",
                "flags=--offline --offline-vulnerabilities --all-packages --all-vulns",
                *[
                    f"{name}DatabaseSha256={databases[name]['sha256']}"
                    for name in sorted(databases)
                ],
            ]
        )
        + "\n",
    )
    manifest_path = output_dir / "manifest.json"
    _write_text(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (output_dir / "manifest.sha256").write_text(
        f"{sha256_file(manifest_path)}  manifest.json\n", encoding="ascii"
    )
    evidence_files = sorted(
        path for path in output_dir.iterdir()
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    (output_dir / "SHA256SUMS.txt").write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in evidence_files),
        encoding="ascii",
    )
    return 0, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--xdg-cache-home", required=True, type=Path)
    parser.add_argument("--debian-db-sha256", required=True)
    parser.add_argument("--pypi-db-sha256", required=True)
    parser.add_argument("--expected-scanner-sha256", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--scanner", default="osv-scanner")
    parser.add_argument("--expected-scanner-version", default="2.7.0")
    parser.add_argument("--timeout", type=int, default=2400)
    args = parser.parse_args()
    try:
        _, manifest = run_audit(args)
    except (AuditError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        failure = {
            "schemaVersion": 1,
            "capturedAt": datetime.now(timezone.utc).isoformat(),
            "status": classify_preflight_error(str(error)),
            "error": str(error),
            "requestedSbom": str(args.sbom),
            "requestedXdgCacheHome": str(args.xdg_cache_home),
            "expectedScannerVersion": args.expected_scanner_version,
            "expectedScannerSha256": args.expected_scanner_sha256,
            "expectedDatabaseSha256": {
                "Debian": args.debian_db_sha256,
                "PyPI": args.pypi_db_sha256,
            },
        }
        args.output_dir.mkdir(parents=True, exist_ok=True)
        failure_path = args.output_dir / "preflight-error.json"
        _write_text(failure_path, json.dumps(failure, indent=2, sort_keys=True) + "\n")
        _write_text(
            args.output_dir / "preflight-error.sha256",
            f"{sha256_file(failure_path)}  preflight-error.json\n",
        )
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "scannerExitCode": manifest["exitCodes"]["scanner"],
                "matchRecords": manifest["findings"]["matchRecords"],
                "uniqueAdvisoryIds": manifest["findings"]["uniqueAdvisoryIds"],
                "manifestSha256": Path(args.output_dir, "manifest.sha256").read_text().split()[0],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
