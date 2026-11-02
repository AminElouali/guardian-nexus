#!/usr/bin/env python3
"""Build a conservative, offline package-route triage for non-critical/high advisories."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


DEFAULT_REVIEW = Path(
    "generated-artifacts/guardian-ai-assessment-offline/"
    "debian-tracker-review-20261102.json"
)
DEFAULT_SUMMARY = Path(
    "generated-artifacts/guardian-ai-assessment-offline/"
    "osv-latest-db-20261102/summary-retry.json"
)
DEFAULT_AUDIT = Path("workers/guardian-ai-assessment/DEPENDENCY_AUDIT.md")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def critical_high_ids(audit_text: str) -> set[str]:
    ids: set[str] = set()
    for line in audit_text.splitlines():
        if not line.startswith("|") or not re.search(r"\b(?:critical|high)\b", line, re.I):
            continue
        match = re.search(r"\bDEBIAN-CVE-\d{4}-\d+\b", line)
        if match:
            ids.add(match.group(0))
    return ids


def critical_high_table_sha256(audit_text: str) -> str:
    rows = []
    for line in audit_text.splitlines():
        if (
            line.startswith("|")
            and "DEBIAN-CVE-" in line
            and re.search(r"\b(?:critical|high)\b", line, re.I)
        ):
            rows.append(line.rstrip())
    return hashlib.sha256(("\n".join(rows) + "\n").encode()).hexdigest()


def route_assessment(package_names: set[str]) -> dict[str, str]:
    normalized = {name.lower() for name in package_names}
    if normalized & {"glibc", "libc6", "libc-bin"}:
        return {
            "priority": "P1-runtime-library",
            "route": "La libc forma parte del proceso Python y de las extensiones nativas; el uso de la función concreta de cada aviso no se ha trazado.",
            "evidence": "Dockerfile.offline fija CPython 3.13 sobre Debian Trixie; el runtime nativo Qwen registra DT_NEEDED libc. Evidencia de linkage no demuestra llamada a la función vulnerable.",
        }
    if normalized & {"sqlite3", "libsqlite3-0"}:
        return {
            "priority": "P1-runtime-library",
            "route": "SQLite está disponible mediante el módulo sqlite3 de Python y existen consumidores en el conjunto de dependencias; no se ha demostrado que cada API afectada sea llamada en esta ejecución.",
            "evidence": "DEPENDENCY_AUDIT.md documenta la disponibilidad de _sqlite3 y los usos de Garak/NLTK. El ejecutable sqlite3 no está en la imagen. No se purga: apt simulado requiere retirar paquetes esenciales.",
        }
    if normalized & {"gcc-14", "libstdc++6", "libgcc-s1"}:
        return {
            "priority": "P1-native-runtime",
            "route": "El runtime local de Qwen incluye ELF de llama.cpp/ggml con dependencia dinámica de libstdc++/libgcc; la operación vulnerable específica no se ha identificado.",
            "evidence": "local-llm-build/native-runtime-inspection.json y la matriz estática del runtime nativo. La evidencia de linkage no prueba invocación de la función del aviso.",
        }
    if normalized & {"zlib", "bzip2", "ncurses", "libncursesw6"}:
        return {
            "priority": "P2-library-available",
            "route": "Biblioteca o soporte de formato está instalado y puede ser alcanzable por intérprete/extensiones; no se ha confirmado la API vulnerable concreta ni su entrada.",
            "evidence": "Inventario de paquetes de la imagen candidata y contrato de ejecución Python. No se realizaron pruebas de explotación.",
        }
    if normalized & {"apt", "coreutils", "tar", "util-linux", "dash", "perl", "shadow", "systemd", "pam", "diffutils", "acl", "attr"}:
        return {
            "priority": "P2-installed-command-or-service",
            "route": "El paquete está instalado, pero la revisión estática del camino del worker no encontró una invocación directa del ejecutable/operación afectada. Esto no prueba que toda ruta sea inalcanzable.",
            "evidence": "guardian_ai_assessment/__main__.py ejecuta Garak mediante sys.executable con argumentos fijos; Dockerfile.offline usa ENTRYPOINT JSON a Python. No se encontró shell=True ni invocación del comando afectado en el código revisado.",
        }
    return {
        "priority": "P3-route-unresolved",
        "route": "Paquete observado en el inventario; no se ha identificado una ruta concreta desde el camino fijo del worker.",
        "evidence": "OSV/Tracker prueban presencia y estado del paquete, no llamada a la función vulnerable. Requiere inspección específica del componente.",
    }


def build_triage(
    review: dict[str, Any],
    audit_text: str,
    scan_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    records = review.get("records")
    if not isinstance(records, list):
        raise ValueError("Debian Tracker review has no records list")
    high_ids = critical_high_ids(audit_text)
    if len(records) != 81 or len(high_ids) != 26:
        raise ValueError(
            f"Expected 81 reviewed IDs and 26 critical/high IDs; "
            f"got {len(records)} and {len(high_ids)}"
        )

    pending = [record for record in records if record.get("osvId") not in high_ids]
    if len(pending) != 55:
        raise ValueError(f"Expected 55 remaining IDs, got {len(pending)}")

    scan_severity = (
        ((scan_summary or {}).get("result") or {}).get("severityByUniqueId") or {}
    )
    if scan_summary is not None:
        result = scan_summary.get("result") or {}
        if (
            result.get("uniqueAdvisoryIds") != 81
            or sum(scan_severity.values()) + result.get("unscoredIds", 0) != 81
        ):
            raise ValueError("OSV severity summary must describe exactly 81 unique IDs")
        if scan_severity.get("critical") != 1 or scan_severity.get("high") != 25:
            raise ValueError("OSV summary does not agree with the 26 critical/high table")
        summary_image = scan_summary.get("image") or {}
        review_image = (
            ((review.get("source") or {}).get("osvScanProvenance") or {}).get("image")
            or {}
        )
        if summary_image.get("imageId") != review_image.get("imageId"):
            raise ValueError("OSV summary and Tracker review image IDs do not match")

    rows: list[dict[str, Any]] = []
    for record in sorted(pending, key=lambda item: item["osvId"]):
        packages = record.get("observedPackages") or []
        if not packages:
            raise ValueError(f"{record.get('osvId')} has no observed package")
        names = {str(package.get("name", "")) for package in packages}
        route = route_assessment(names)
        tracker = record.get("debianTracker") or {}
        tracker_rows = tracker.get("trixieRows") or []
        statuses = sorted({row.get("status", "unknown") for row in tracker_rows})
        package_versions = sorted(
            {
                (
                    package.get("name", ""),
                    package.get("version", ""),
                    package.get("purl", ""),
                )
                for package in packages
            }
        )
        vectors = sorted(
            {
                vector
                for package in packages
                for vector in package.get("severityVectors", [])
            }
        )
        has_tixie_fixed_status = any(status == "fixed" for status in statuses)
        rows.append(
            {
                "osvId": record["osvId"],
                "upstreamCve": record.get("upstreamCve"),
                "packageVersions": [
                    {"name": name, "version": version, "purl": purl}
                    for name, version, purl in package_versions
                ],
                "severityVectors": vectors,
                "perIdSeverity": (
                    "not-scored-in-this-triage"
                    if not vectors
                    else "source-vector-retained; numeric score not recomputed"
                ),
                "reviewPriority": route["priority"],
                "debianTrixieStatus": tracker.get("trixieAssessment", "unknown"),
                "debianTrixieRows": tracker_rows,
                "debianTrackerUrl": tracker.get("url"),
                "debianTrackerExtractSha256": tracker.get("extractedMarkdownSha256"),
                "debianTrackerNotes": tracker.get("notes", ""),
                "trackerFixedVersionRows": tracker.get("fixedVersionRows", []),
                "trixieFixedVersionInCapturedRows": has_tixie_fixed_status,
                "localFixStatus": (
                    "not demonstrated; no matching Trixie apt candidate in prior recorded simulations"
                ),
                "reachability": route["route"],
                "reachabilityEvidence": route["evidence"],
                "exploitability": "not demonstrated; no exploit test or advisory-specific reachable call was established",
                "mitigation": (
                    "Keep the worker non-root, read-only, capability-free, no-new-privileges, "
                    "resource-bounded and network=none; do not feed untrusted files to affected parsers. "
                    "These controls reduce preconditions but do not patch the package."
                ),
            }
        )

    summary = {
        "records": len(rows),
        "severityContextFromVerifiedFullScan": {
            "all81": {
                **scan_severity,
                "unscored": ((scan_summary or {}).get("result") or {}).get(
                    "unscoredIds", 3
                ),
            }
            if scan_summary
            else {
                "critical": 1,
                "high": 25,
                "moderate": 43,
                "low": 9,
                "unscored": 3,
            },
            "remaining55": "The 55 are the OSV result after excluding the 26 IDs in the separately maintained critical/high table. Per-ID CVSS category is not recomputed here; source vectors are retained.",
        },
        "trackerStatuses": {
            status: sum(row["debianTrixieStatus"] == status for row in rows)
            for status in sorted({row["debianTrixieStatus"] for row in rows})
        },
        "runtimePriorities": {
            priority: sum(row["reviewPriority"] == priority for row in rows)
            for priority in sorted({row["reviewPriority"] for row in rows})
        },
        "exploitability": "No exploitability claim; package match and Tracker status are not proof of an exploitable path.",
        "localFixes": "No Trixie package fix was verified in the recorded local apt simulations; do not infer fixes from other Debian suites.",
        "limitations": [
            "Static source search is not a complete dynamic call-graph or exploitability analysis.",
            "CVSS vectors are retained as supplied; this generator does not calculate numeric scores.",
            "The prior apt simulation was not rerun and is not proof that future repositories have no fixes.",
            "OSV/Tracker status is package-level and may differ for a particular binary build or code path.",
        ],
    }
    return {
        "schemaVersion": 1,
        "source": {
            "debianTrackerReviewSha256": review.get("source", {}).get("trackerBundleSha256"),
            "reviewFileSha256": None,
            "criticalHighTableSha256": critical_high_table_sha256(audit_text),
            "severitySource": "OSV scan summary plus the 26-row critical/high table in DEPENDENCY_AUDIT.md",
        },
        "summary": summary,
        "records": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--review", type=Path, default=DEFAULT_REVIEW)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    review = json.loads(args.review.read_text(encoding="utf-8"))
    scan_summary = json.loads(args.summary.read_text(encoding="utf-8"))
    audit_text = args.audit.read_text(encoding="utf-8")
    document = build_triage(review, audit_text, scan_summary)
    document["source"]["reviewFileSha256"] = sha256_file(args.review)
    document["source"]["scanSummarySha256"] = sha256_file(args.summary)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "generated",
                "records": document["summary"]["records"],
                "output": str(args.output),
                "outputSha256": sha256_file(args.output),
                "trackerStatuses": document["summary"]["trackerStatuses"],
                "runtimePriorities": document["summary"]["runtimePriorities"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
