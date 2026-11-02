#!/usr/bin/env python3
"""Run OSV against a local Docker image with fail-closed DB provenance checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_NAMES = ("Debian", "PyPI")
EXPECTED_SCANNER_EXIT_CODES = {0, 1}
LOADED_DB = re.compile(r"^Loaded (Debian|PyPI) local db from (.+)$", re.MULTILINE)
VERSION = re.compile(r"^osv-scanner version:\s*(\S+)", re.MULTILINE)


class AuditError(RuntimeError):
    """A scanner run that cannot be trusted as a provenance-verified result."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_scanner_version(output: str) -> str:
    match = VERSION.search(output)
    if not match:
        raise AuditError("scanner_version_unparseable")
    return match.group(1)


def count_findings(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise AuditError("scanner_json_missing_results")
    ids: set[str] = set()
    match_records = 0
    package_records_with_findings = 0
    pypi_match_records = 0
    for result in document["results"]:
        if not isinstance(result, dict):
            raise AuditError("scanner_json_invalid_result")
        for record in result.get("packages", []):
            if not isinstance(record, dict):
                raise AuditError("scanner_json_invalid_package")
            vulnerabilities = record.get("vulnerabilities", [])
            if vulnerabilities:
                package_records_with_findings += 1
                match_records += len(vulnerabilities)
                package = record.get("package") or {}
                if package.get("ecosystem") == "PyPI":
                    pypi_match_records += len(vulnerabilities)
                for group in record.get("groups", []):
                    ids.update(str(item) for item in group.get("ids", []))
                for vulnerability in vulnerabilities:
                    identifier = vulnerability.get("id")
                    if identifier:
                        ids.add(str(identifier))
    return {
        "matchRecords": match_records,
        "packageRecordsWithFindings": package_records_with_findings,
        "uniqueAdvisoryIds": len(ids),
        "advisoryIds": sorted(ids),
        "pypiMatchRecords": pypi_match_records,
    }


def verify_loaded_databases(
    xdg_cache_home: Path,
    expected_hashes: dict[str, str],
    stderr: str,
) -> dict[str, dict[str, str]]:
    cache_home = xdg_cache_home.expanduser().resolve(strict=True)
    matches = LOADED_DB.findall(stderr)
    if len(matches) != len(DB_NAMES) or {name for name, _ in matches} != set(DB_NAMES):
        raise AuditError("scanner_did_not_report_exactly_one_path_per_local_database")
    reported = {
        name: Path(path.strip()).expanduser()
        for name, path in matches
    }
    loaded = {
        name: path.resolve(strict=True)
        for name, path in reported.items()
    }

    verified: dict[str, dict[str, str]] = {}
    for name in DB_NAMES:
        configured_path = cache_home / "osv-scalibr" / name / "all.zip"
        expected_path = configured_path.resolve(strict=True)
        actual_path = loaded[name]
        if actual_path != expected_path:
            raise AuditError(f"{name}_database_path_mismatch")
        actual_hash = sha256_file(actual_path)
        expected_hash = expected_hashes.get(name, "")
        if not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
            raise AuditError(f"{name}_expected_hash_invalid")
        if actual_hash != expected_hash:
            raise AuditError(f"{name}_database_hash_mismatch")
        verified[name] = {
            "path": str(actual_path),
            "configuredPath": str(configured_path),
            "scannerReportedPath": str(reported[name]),
            "resolvedPath": str(actual_path),
            "sha256": actual_hash,
            "status": "verified",
        }
    return verified


def classify_scan(exit_code: int, counts: dict[str, Any]) -> str:
    if exit_code not in EXPECTED_SCANNER_EXIT_CODES:
        return "execution_error"
    has_findings = counts["matchRecords"] > 0
    if (exit_code == 1) != has_findings:
        return "execution_error_exit_code_and_json_disagree"
    return "verified_with_findings" if has_findings else "verified_no_findings"


def classify_preflight_error(error: str) -> str:
    provenance_markers = (
        "database",
        "xdg_cache",
        "scanner_version_mismatch",
        "scanner_version_unparseable",
        "local_database",
    )
    return "provenance_error" if any(marker in error.lower() for marker in provenance_markers) else "execution_error"


def _run(
    command: list[str],
    *,
    env: dict[str, str],
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )


def run_audit(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    output_dir: Path = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    scanner_path = shutil.which(args.scanner) if not Path(args.scanner).is_absolute() else args.scanner
    if not scanner_path or not Path(scanner_path).is_file():
        raise AuditError("scanner_executable_missing")

    xdg_cache_home = args.xdg_cache_home.expanduser().resolve(strict=True)
    if not xdg_cache_home.is_dir():
        raise AuditError("xdg_cache_home_not_directory")
    db_expected = {"Debian": args.debian_db_sha256, "PyPI": args.pypi_db_sha256}
    db_preflight: dict[str, dict[str, str]] = {}
    for name in DB_NAMES:
        database = (xdg_cache_home / "osv-scalibr" / name / "all.zip").resolve(strict=True)
        actual_hash = sha256_file(database)
        if actual_hash != db_expected[name]:
            raise AuditError(f"{name}_database_preflight_hash_mismatch")
        db_preflight[name] = {"path": str(database), "sha256": actual_hash}

    env = os.environ.copy()
    env.pop("HOME", None)
    env["XDG_CACHE_HOME"] = str(xdg_cache_home)
    scanner_version_result = _run([str(scanner_path), "--version"], env=env, timeout=30)
    if scanner_version_result.returncode != 0:
        raise AuditError(f"scanner_version_command_failed:{scanner_version_result.returncode}")
    version_text = scanner_version_result.stdout + scanner_version_result.stderr
    scanner_version = parse_scanner_version(version_text)
    if scanner_version != args.expected_scanner_version:
        raise AuditError(
            f"scanner_version_mismatch:expected={args.expected_scanner_version}:actual={scanner_version}"
        )
    scanner_hash = sha256_file(Path(scanner_path))

    image_check = _run(
        [args.docker, "image", "inspect", "--format", "{{.Id}}", args.image],
        env=env,
        timeout=30,
    )
    if image_check.returncode != 0 or not image_check.stdout.strip().startswith("sha256:"):
        raise AuditError("docker_image_not_present_locally")
    image_id = image_check.stdout.strip().splitlines()[0]

    stdout_path = output_dir / "stdout.log"
    stderr_path = output_dir / "stderr.log"
    json_path = output_dir / "osv.json"
    docker_save_argv: list[str] = []
    scanner_argv: list[str] = []
    docker_save_exit: int | None = None
    scanner_exit: int | None = None
    stdout = ""
    stderr = ""
    scan_document: dict[str, Any] | None = None
    loaded_databases: dict[str, dict[str, str]] | None = None
    classification = "execution_error"
    error: str | None = None
    archive_digest: str | None = None

    try:
        with tempfile.TemporaryDirectory(prefix="guardian-osv-") as temp_dir:
            archive_path = Path(temp_dir) / "image.tar"
            docker_save_argv = [args.docker, "image", "save", "--output", str(archive_path), args.image]
            docker_save = _run(docker_save_argv, env=env, timeout=180)
            docker_save_exit = docker_save.returncode
            if docker_save.returncode != 0 or not archive_path.is_file():
                error = "docker_save_failed"
                stderr = docker_save.stderr
            else:
                archive_digest = sha256_file(archive_path)
                scanner_argv = [
                    str(scanner_path),
                    "scan",
                    "image",
                    "--archive",
                    str(archive_path),
                    "--offline",
                    "--offline-vulnerabilities",
                    "--all-packages",
                    "--all-vulns",
                    "--format",
                    "json",
                    "--output-file",
                    str(json_path),
                ]
                scan = _run(scanner_argv, env=env, timeout=args.timeout)
                scanner_exit = scan.returncode
                stdout, stderr = scan.stdout, scan.stderr
                stdout_path.write_text(stdout, encoding="utf-8")
                stderr_path.write_text(stderr, encoding="utf-8")
                if scan.returncode not in EXPECTED_SCANNER_EXIT_CODES:
                    error = f"scanner_process_failed:{scan.returncode}"
                elif not json_path.is_file():
                    error = "scanner_json_output_missing"
                else:
                    try:
                        scan_document = json.loads(json_path.read_text(encoding="utf-8"))
                        loaded_databases = verify_loaded_databases(
                            xdg_cache_home,
                            db_expected,
                            stderr,
                        )
                        counts = count_findings(scan_document)
                        classification = classify_scan(scan.returncode, counts)
                        if classification == "execution_error_exit_code_and_json_disagree":
                            error = classification
                    except (OSError, json.JSONDecodeError, AuditError) as exc:
                        error = str(exc)
                        classification = (
                            "provenance_error"
                            if "database" in str(exc) or "local_database" in str(exc)
                            else "execution_error"
                        )
    except subprocess.TimeoutExpired:
        error = "audit_timeout"
        classification = "execution_error"

    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    if scan_document is not None:
        counts = count_findings(scan_document)
    else:
        counts = {
            "matchRecords": None,
            "packageRecordsWithFindings": None,
            "uniqueAdvisoryIds": None,
            "advisoryIds": [],
            "pypiMatchRecords": None,
        }
    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "status": classification,
        "error": error,
        "image": {"reference": args.image, "imageId": image_id, "dockerSaveArchiveSha256": archive_digest},
        "scanner": {
            "path": str(Path(scanner_path).resolve()),
            "version": scanner_version,
            "binarySha256": scanner_hash,
            "versionCommandExitCode": scanner_version_result.returncode,
        },
        "environment": {
            "XDG_CACHE_HOME": str(xdg_cache_home),
            "HOME": "unset",
            "networkPolicy": "OSV --offline and --offline-vulnerabilities; local Docker archive only",
        },
        "databases": {
            name: {
                "expectedSha256": db_expected[name],
                "preflightSha256": db_preflight[name]["sha256"],
                "loaded": loaded_databases.get(name) if loaded_databases else None,
            }
            for name in DB_NAMES
        },
        "commands": {
            "dockerImageInspect": [args.docker, "image", "inspect", "--format", "{{.Id}}", args.image],
            "dockerSave": docker_save_argv,
            "scannerVersion": [str(scanner_path), "--version"],
            "scanner": scanner_argv,
        },
        "exitCodes": {
            "dockerSave": docker_save_exit,
            "scanner": scanner_exit,
            "auditWrapper": 0 if classification.startswith("verified_") else 2,
        },
        "findings": counts,
        "artifacts": {
            "json": {"path": json_path.name, "sha256": sha256_file(json_path) if json_path.is_file() else None},
            "stdout": {"path": stdout_path.name, "sha256": sha256_file(stdout_path)},
            "stderr": {"path": stderr_path.name, "sha256": sha256_file(stderr_path)},
        },
    }
    if classification == "execution_error_exit_code_and_json_disagree":
        manifest["exitCodes"]["auditWrapper"] = 2
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_hash = sha256_file(manifest_path)
    (output_dir / "manifest.sha256").write_text(
        f"{manifest_hash}  manifest.json\n", encoding="ascii"
    )
    return int(manifest["exitCodes"]["auditWrapper"]), manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Must already exist in the local Docker daemon")
    parser.add_argument("--xdg-cache-home", required=True, type=Path)
    parser.add_argument("--debian-db-sha256", required=True)
    parser.add_argument("--pypi-db-sha256", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--scanner", default="osv-scanner")
    parser.add_argument("--expected-scanner-version", default="2.7.0")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--timeout", type=int, default=2400)
    args = parser.parse_args()
    try:
        result, manifest = run_audit(args)
    except (AuditError, OSError, subprocess.SubprocessError) as exc:
        status = classify_preflight_error(str(exc))
        failure = {
            "schemaVersion": 1,
            "capturedAt": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "error": str(exc),
            "requestedImage": args.image,
            "requestedXdgCacheHome": str(args.xdg_cache_home),
            "expectedScannerVersion": args.expected_scanner_version,
            "expectedDatabaseSha256": {
                "Debian": args.debian_db_sha256,
                "PyPI": args.pypi_db_sha256,
            },
        }
        try:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            failure_path = args.output_dir / "preflight-error.json"
            failure_path.write_text(json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            digest = sha256_file(failure_path)
            (args.output_dir / "preflight-error.sha256").write_text(
                f"{digest}  preflight-error.json\n", encoding="ascii"
            )
        except OSError:
            pass
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({
        "status": manifest["status"],
        "scannerExitCode": manifest["exitCodes"]["scanner"],
        "findingCounts": {
            key: manifest["findings"][key]
            for key in ("matchRecords", "packageRecordsWithFindings", "uniqueAdvisoryIds", "pypiMatchRecords")
        },
        "manifestSha256": Path(args.output_dir, "manifest.sha256").read_text().split()[0],
    }, sort_keys=True))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
