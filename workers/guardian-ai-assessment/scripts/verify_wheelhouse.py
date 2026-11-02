#!/usr/bin/env python3
"""Verify an offline wheelhouse against hash-pinned requirements using stdlib only."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)==([^\s\\]+)\s*\\?\s*$"
)
_HASH = re.compile(r"^\s*--hash=sha256:([0-9a-fA-F]{64})\s*\\?\s*$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_lockfiles(paths: list[Path]) -> list[dict[str, str]]:
    locked: list[dict[str, str]] = []
    for lock_path in paths:
        current: dict[str, Any] | None = None

        def finish() -> None:
            if current is None:
                return
            hashes = current["hashes"]
            if len(hashes) != 1:
                raise ValueError(
                    f"{lock_path.name}: expected one pinned artifact hash for "
                    f"{current['name']}=={current['version']}, got {len(hashes)}"
                )
            locked.append(
                {
                    "name": current["name"],
                    "version": current["version"],
                    "sha256": hashes[0],
                    "lockfile": lock_path.name,
                }
            )

        for line_number, line in enumerate(
            lock_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            requirement = _REQUIREMENT.fullmatch(line)
            if requirement:
                finish()
                current = {
                    "name": requirement.group(1),
                    "version": requirement.group(2),
                    "hashes": [],
                }
                continue
            pinned_hash = _HASH.fullmatch(line)
            if pinned_hash and current is not None:
                current["hashes"].append(pinned_hash.group(1).lower())
                continue
            raise ValueError(
                f"{lock_path.name}:{line_number}: unsupported lock syntax"
            )
        finish()

    if not locked:
        raise ValueError("no hash-locked requirements found")
    return locked


def verify_wheelhouse(
    wheelhouse: Path, lockfiles: list[Path]
) -> dict[str, Any]:
    if not wheelhouse.is_dir():
        raise ValueError(f"wheelhouse not found: {wheelhouse}")
    locked = parse_lockfiles(lockfiles)
    artifacts = sorted(
        (item for item in wheelhouse.iterdir() if item.is_file()),
        key=lambda item: item.name,
    )
    hashes = {artifact: sha256_file(artifact) for artifact in artifacts}
    used: set[Path] = set()
    verified: list[dict[str, str | int]] = []

    for requirement in locked:
        matches = [
            artifact
            for artifact, digest in hashes.items()
            if digest == requirement["sha256"]
        ]
        if len(matches) != 1:
            raise ValueError(
                f"{requirement['name']}=={requirement['version']}: expected "
                f"exactly one artifact with pinned sha256, found {len(matches)}"
            )
        artifact = matches[0]
        if artifact in used:
            raise ValueError(f"artifact reused for multiple requirements: {artifact.name}")
        used.add(artifact)
        verified.append(
            {
                "name": requirement["name"],
                "version": requirement["version"],
                "lockfile": requirement["lockfile"],
                "filename": artifact.name,
                "sizeBytes": artifact.stat().st_size,
                "sha256": requirement["sha256"],
            }
        )

    unexpected = sorted(artifact.name for artifact in set(artifacts) - used)
    if unexpected:
        raise ValueError(f"unlocked files in wheelhouse: {', '.join(unexpected)}")

    return {
        "schemaVersion": 1,
        "verification": "local-sha256-lock-match",
        "networkUsed": False,
        "sourceProvenance": (
            "Artifacts are accepted only when their bytes match the pinned "
            "requirements hashes. Official PyPI release-metadata provenance is "
            "documented separately in DEPENDENCY_AUDIT.md; this verifier does "
            "not contact PyPI."
        ),
        "lockfiles": [
            {
                "filename": lockfile.name,
                "sha256": sha256_file(lockfile),
            }
            for lockfile in lockfiles
        ],
        "artifactCount": len(verified),
        "artifacts": sorted(
            verified, key=lambda item: (str(item["name"]).lower(), str(item["version"]))
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument(
        "--requirements",
        type=Path,
        action="append",
        required=True,
        help="Hash-locked requirements file; repeat for runtime and build locks.",
    )
    args = parser.parse_args()
    try:
        report = verify_wheelhouse(args.wheelhouse, args.requirements)
    except (OSError, ValueError) as exc:
        print(json.dumps({"verified": False, "error": str(exc)}), file=sys.stderr)
        return 1
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
