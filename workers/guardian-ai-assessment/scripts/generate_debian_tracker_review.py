#!/usr/bin/env python3
"""Join a local OSV image scan with saved Debian Security Tracker page extracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.split("|")[1:-1]]


def clean_markdown_label(value: str) -> str:
    value = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"\s*\(\s*PTS\s*\)", "", value)
    return re.sub(r"\s+", " ", value).strip()


def parse_tracker_page(cve: str, markdown: str) -> dict[str, Any]:
    if f"CVE-{cve}" not in markdown:
        raise ValueError(f"tracker page does not identify CVE-{cve}")

    lines = markdown.splitlines()
    source_header = next(
        (
            index
            for index, line in enumerate(lines)
            if "Source Package" in line and "Status" in line
        ),
        None,
    )
    fixed_header = next(
        (
            index
            for index, line in enumerate(lines)
            if "Fixed Version" in line and "Urgency" in line
        ),
        None,
    )
    if source_header is None:
        raise ValueError(f"missing source package table for CVE-{cve}")

    trixie_rows: list[dict[str, str]] = []
    inherited_source = ""
    for line in lines[source_header + 2 :]:
        if not line.strip().startswith("|"):
            break
        cells = table_cells(line)
        if len(cells) < 4:
            continue
        source = clean_markdown_label(cells[0])
        if source:
            inherited_source = source
        releases = [part.strip().lower() for part in cells[1].split(",")]
        if "trixie" in releases:
            trixie_rows.append(
                {
                    "sourcePackage": source or inherited_source,
                    "release": cells[1],
                    "version": cells[2],
                    "status": cells[3].lower(),
                }
            )
    if not trixie_rows:
        raise ValueError(f"no explicit Trixie row for CVE-{cve}")

    fixed_rows: list[dict[str, str]] = []
    if fixed_header is not None:
        for line in lines[fixed_header + 2 :]:
            if not line.strip().startswith("|"):
                break
            cells = table_cells(line)
            if len(cells) < 5:
                continue
            fixed_rows.append(
                {
                    "package": clean_markdown_label(cells[0]),
                    "type": cells[1],
                    "release": cells[2],
                    "fixedVersion": cells[3],
                    "urgency": cells[4],
                }
            )

    notes = ""
    note_start = next(
        (index for index, line in enumerate(lines) if line.strip() == "## Notes"),
        None,
    )
    if note_start is not None:
        note_lines = []
        for line in lines[note_start + 1 :]:
            if line.strip() == "* * *":
                break
            note_lines.append(line)
        notes = "\n".join(note_lines).strip()

    status_values = sorted({row["status"] for row in trixie_rows})
    if status_values == ["vulnerable"]:
        assessment = "vulnerable_in_trixie_per_tracker"
    elif status_values == ["fixed"]:
        if re.search(r"<not-affected>|not affected", notes, re.IGNORECASE):
            assessment = "not_affected_per_tracker_not_a_package_patch"
        else:
            assessment = "fixed_in_trixie_per_tracker"
    elif status_values == ["undetermined"]:
        assessment = "undetermined_per_tracker"
    else:
        assessment = "mixed_tracker_status_requires_review"

    return {
        "trixieRows": trixie_rows,
        "fixedVersionRows": fixed_rows,
        "notes": notes,
        "trixieAssessment": assessment,
    }


def scan_findings(scan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    findings: dict[str, dict[str, Any]] = {}
    results = scan.get("results")
    if not isinstance(results, list):
        raise ValueError("OSV scan JSON is missing results")

    for result in results:
        for package_record in result.get("packages", []):
            package = package_record.get("package") or {}
            for vulnerability in package_record.get("vulnerabilities", []):
                vulnerability_id = vulnerability.get("id")
                if not vulnerability_id:
                    continue
                finding = findings.setdefault(
                    vulnerability_id,
                    {
                        "id": vulnerability_id,
                        "observedPackages": [],
                        "osvAffectedRecords": [],
                    },
                )
                affected_sources = sorted(
                    {
                        (affected.get("package") or {}).get("name", "")
                        for affected in vulnerability.get("affected", [])
                        if (affected.get("package") or {}).get("ecosystem")
                        == "Debian:13"
                    }
                    - {""}
                )
                for affected in vulnerability.get("affected", []):
                    affected_package = affected.get("package") or {}
                    affected_record = {
                        "ecosystem": affected_package.get("ecosystem"),
                        "packageName": affected_package.get("name"),
                        "purl": affected_package.get("purl"),
                        "sourceUrl": (affected.get("database_specific") or {}).get(
                            "source"
                        ),
                        "versions": sorted(set(affected.get("versions", []))),
                        "ranges": [
                            {
                                "type": item.get("type"),
                                "events": item.get("events", []),
                            }
                            for item in affected.get("ranges", [])
                        ],
                        "urgency": (affected.get("ecosystem_specific") or {}).get(
                            "urgency"
                        ),
                    }
                    if affected_record not in finding["osvAffectedRecords"]:
                        finding["osvAffectedRecords"].append(affected_record)
                observed = {
                    "name": package.get("name"),
                    "ecosystem": package.get("ecosystem"),
                    "version": package.get("version"),
                    "purl": package.get("purl"),
                    "sourcePackages": affected_sources,
                    "severityVectors": sorted(
                        {
                            item.get("score", "")
                            for item in vulnerability.get("severity", [])
                            if item.get("score")
                        }
                    ),
                    "upstreamIds": sorted(set(vulnerability.get("upstream", []))),
                }
                if observed not in finding["observedPackages"]:
                    finding["observedPackages"].append(observed)
    return findings


def validate_scan_provenance(
    manifest: dict[str, Any], findings: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    scanner = manifest.get("scanner") or {}
    environment = manifest.get("environment") or {}
    commands = manifest.get("commands") or {}
    exit_codes = manifest.get("exitCodes") or {}
    xdg_cache_home = environment.get("XDG_CACHE_HOME")
    scanner_command = commands.get("scanner")
    if not isinstance(xdg_cache_home, str) or not xdg_cache_home:
        raise ValueError("OSV manifest has no explicit XDG_CACHE_HOME")
    if not isinstance(scanner_command, list) or not scanner_command:
        raise ValueError("OSV manifest has no recorded scanner command")
    if not scanner.get("version") or not scanner.get("binarySha256"):
        raise ValueError("OSV manifest has no scanner version or binary hash")
    required_arguments = [
        "scan",
        "image",
        "--archive",
        "--offline",
        "--offline-vulnerabilities",
        "--all-packages",
        "--all-vulns",
        "--format",
        "json",
        "--output-file",
    ]
    missing_arguments = [
        argument for argument in required_arguments if argument not in scanner_command
    ]
    if missing_arguments:
        raise ValueError(
            f"OSV scanner command is missing required options: {missing_arguments}"
        )
    if manifest.get("status") != "verified_with_findings":
        raise ValueError("OSV manifest is not a verified scan with findings")
    if exit_codes.get("auditWrapper") != 0 or exit_codes.get("dockerSave") != 0:
        raise ValueError("OSV audit wrapper or local image export did not succeed")
    if exit_codes.get("scanner") != 1:
        raise ValueError("OSV findings exist but scanner exit code is not 1")

    recorded_ids = set((manifest.get("findings") or {}).get("advisoryIds", []))
    if recorded_ids != set(findings):
        raise ValueError("OSV manifest advisory IDs do not match the scan JSON")

    databases = manifest.get("databases") or {}
    database_evidence = {}
    for name in ("Debian", "PyPI"):
        database = databases.get(name) or {}
        loaded = database.get("loaded") or {}
        expected_hash = database.get("expectedSha256")
        loaded_path = loaded.get("path")
        loaded_hash = loaded.get("sha256")
        if (
            loaded.get("status") != "verified"
            or not expected_hash
            or loaded_hash != expected_hash
            or database.get("preflightSha256") != expected_hash
            or not isinstance(loaded_path, str)
            or not Path(loaded_path).is_relative_to(Path(xdg_cache_home))
        ):
            raise ValueError(f"{name} OSV database provenance is not verified")
        database_evidence[name] = {
            "path": loaded_path,
            "sha256": loaded_hash,
            "status": loaded["status"],
        }

    return {
        "scannerVersion": scanner["version"],
        "scannerBinarySha256": scanner["binarySha256"],
        "scannerCommand": scanner_command,
        "scannerExitCode": exit_codes["scanner"],
        "auditWrapperExitCode": exit_codes["auditWrapper"],
        "dockerSaveExitCode": exit_codes["dockerSave"],
        "capturedAt": manifest.get("capturedAt"),
        "image": manifest.get("image"),
        "xdgCacheHome": xdg_cache_home,
        "networkPolicy": environment.get("networkPolicy"),
        "databases": database_evidence,
        "manifestStatus": manifest["status"],
    }


def build_review(
    scan_path: Path,
    manifest_path: Path,
    tracker_bundle_path: Path,
) -> dict[str, Any]:
    scan = json.loads(scan_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bundle = json.loads(tracker_bundle_path.read_text(encoding="utf-8"))
    if bundle.get("source") != "Official Debian Security Tracker individual CVE pages":
        raise ValueError("tracker source is not the expected official source")

    findings = scan_findings(scan)
    provenance = validate_scan_provenance(manifest, findings)
    pages = bundle.get("pages", [])
    page_by_id = {page.get("cve"): page for page in pages}
    expected_cves = {
        vulnerability_id.removeprefix("DEBIAN-")
        for vulnerability_id in findings
        if vulnerability_id.startswith("DEBIAN-CVE-")
    }
    if len(findings) != 81 or expected_cves != set(page_by_id):
        raise ValueError(
            "OSV findings and official tracker page set must match exactly "
            f"(findings={len(findings)}, pages={len(page_by_id)})"
        )

    records = []
    for vulnerability_id, finding in sorted(findings.items()):
        cve_number = vulnerability_id.removeprefix("DEBIAN-CVE-")
        cve = f"CVE-{cve_number}"
        page = page_by_id[cve]
        markdown = page.get("markdown", "")
        content_hash = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        if content_hash != page.get("extractedMarkdownSha256"):
            raise ValueError(f"tracker page hash mismatch for {cve}")
        official = parse_tracker_page(cve_number, markdown)
        tracker_source_packages = sorted(
            {
                row["sourcePackage"]
                for row in official["trixieRows"]
                if row["sourcePackage"]
            }
        )
        osv_source_packages = sorted(
            {
                source_package
                for package in finding["observedPackages"]
                for source_package in package["sourcePackages"]
            }
        )
        source_package_intersection = sorted(
            set(tracker_source_packages) & set(osv_source_packages)
        )
        source_package_status = (
            "matched"
            if source_package_intersection
            else "unmatched_review_required"
            if tracker_source_packages and osv_source_packages
            else "source_package_metadata_missing"
        )
        records.append(
            {
                "osvId": vulnerability_id,
                "upstreamCve": cve,
                "observedPackages": sorted(
                    finding["observedPackages"],
                    key=lambda item: (
                        item.get("name") or "",
                        item.get("version") or "",
                        item.get("purl") or "",
                    ),
                ),
                "osvAffectedRecords": sorted(
                    finding["osvAffectedRecords"],
                    key=lambda item: (
                        item.get("ecosystem") or "",
                        item.get("packageName") or "",
                        item.get("purl") or "",
                    ),
                ),
                "osvObservedVersionEvidence": [
                    {
                        "packageName": package.get("name"),
                        "version": package.get("version"),
                        "ecosystem": package.get("ecosystem"),
                        "exactVersionListedByOsv": any(
                            affected.get("ecosystem") == package.get("ecosystem")
                            and package.get("version") in affected.get("versions", [])
                            for affected in finding["osvAffectedRecords"]
                        ),
                    }
                    for package in sorted(
                        finding["observedPackages"],
                        key=lambda item: (
                            item.get("name") or "",
                            item.get("version") or "",
                            item.get("purl") or "",
                        ),
                    )
                ],
                "debianTracker": {
                    "url": page["url"],
                    "extractedMarkdownSha256": content_hash,
                    "trixieRows": official["trixieRows"],
                    "fixedVersionRows": official["fixedVersionRows"],
                    "trixieAssessment": official["trixieAssessment"],
                    "notes": official["notes"],
                },
                "sourcePackageCrosscheck": {
                    "status": source_package_status,
                    "trackerSourcePackages": tracker_source_packages,
                    "osvSourcePackages": osv_source_packages,
                    "matchedNames": source_package_intersection,
                },
                "exploitability": "not established by OSV matching or tracker status",
                "reachability": (
                    "See the static reachability table for the 26 critical/high IDs; "
                    "other IDs were not individually traced through worker call paths."
                ),
            }
        )

    assessments: dict[str, int] = {}
    source_crosschecks: dict[str, int] = {}
    for record in records:
        assessment = record["debianTracker"]["trixieAssessment"]
        assessments[assessment] = assessments.get(assessment, 0) + 1
        crosscheck = record["sourcePackageCrosscheck"]["status"]
        source_crosschecks[crosscheck] = source_crosschecks.get(crosscheck, 0) + 1

    return {
        "schemaVersion": 1,
        "retrievedDateUtc": bundle["retrievedDateUtc"],
        "source": {
            "name": bundle["source"],
            "captureMethod": bundle["captureMethod"],
            "trackerPages": len(pages),
            "trackerBundleSha256": sha256_file(tracker_bundle_path),
            "osvJsonSha256": sha256_file(scan_path),
            "osvManifestSha256": sha256_file(manifest_path),
            "osvScanProvenance": provenance,
            "exploitabilityCaveat": (
                "A scanner match is an inventory/advisory correlation, not proof "
                "of exploitability. Tracker status is suite/version metadata, not "
                "a worker call-path analysis."
            ),
        },
        "summary": {
            "osvAdvisoryIds": len(records),
            "debianTrackerPagesValidated": len(records),
            "debianTrixieAssessmentCounts": assessments,
            "sourcePackageCrosschecks": source_crosschecks,
            "criticalHighClassificationSource": (
                "OSV scan and the separately maintained 26-row static triage in "
                "DEPENDENCY_AUDIT.md; no CVSS score is inferred from tracker urgency."
            ),
        },
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-json", type=Path, required=True)
    parser.add_argument("--scan-manifest", type=Path, required=True)
    parser.add_argument("--tracker-pages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        review = build_review(args.scan_json, args.scan_manifest, args.tracker_pages)
    except (OSError, json.JSONDecodeError, ValueError, KeyError) as error:
        print(f"review_error: {error}")
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(review, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(review["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
