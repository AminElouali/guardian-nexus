#!/usr/bin/env python3
"""Verify the local development images run under Docker's active seccomp filter."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "profile-image-lock.json").read_text(encoding="utf-8"))


def check_source_hash(entry: dict[str, object]) -> None:
    source = ROOT / str(entry["sourceDockerfile"])
    actual = hashlib.sha256(source.read_bytes()).hexdigest()
    if actual != entry["sourceDockerfileSha256"]:
        raise SystemExit(f"source hash mismatch: {source.name}")


def main() -> None:
    if LOCK.get("provenance") != {
        "scope": "development",
        "method": "local_docker_inspect",
        "signedAttestation": False,
    }:
        raise SystemExit("image lock provenance metadata is invalid")

    security_options = subprocess.run(
        ["docker", "info", "--format", "{{json .SecurityOptions}}"],
        check=True,
        text=True,
        capture_output=True,
        timeout=10,
    ).stdout
    if "seccomp" not in security_options.lower():
        raise SystemExit("Docker daemon does not report seccomp support")

    for key, limits in (
        ("garak", ("0.5", "768m", "64m")),
        ("qwen", ("1", "1536m", "128m")),
    ):
        entry = LOCK["images"][key]
        check_source_hash(entry)
        inspected = json.loads(
            subprocess.run(
                [
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    str(entry["reference"]),
                ],
                check=True,
                text=True,
                capture_output=True,
                timeout=10,
            ).stdout
        )
        if inspected.get("Id") != entry["imageId"]:
            raise SystemExit(f"{key}: immutable image ID mismatch")
        labels = inspected.get("Config", {}).get("Labels") or {}
        if any(labels.get(k) != v for k, v in entry["labels"].items()):
            raise SystemExit(f"{key}: required OCI labels missing or changed")

        cpus, memory, tmpfs_size = limits
        tmpfs = f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={tmpfs_size}"
        if key == "qwen":
            tmpfs += ",mode=1777"
        args = [
            "docker",
            "run",
            "--rm",
            "--init",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--pids-limit=64",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65532:65532",
            f"--cpus={cpus}",
            f"--memory={memory}",
            f"--memory-swap={memory}",
            tmpfs,
        ]
        if key == "qwen":
            args.append(
                "--tmpfs=/opt/llm-runtime:rw,exec,nosuid,nodev,size=128m,mode=1777"
            )
        args.extend(
            [
                "--entrypoint=/bin/sh",
                str(entry["imageId"]),
                "-c",
                "grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status",
            ]
        )
        output = subprocess.run(
            args,
            check=True,
            text=True,
            capture_output=True,
            timeout=20,
        ).stdout.strip()
        fields = dict(line.split(":", 1) for line in output.splitlines())
        if fields.get("Seccomp", "").strip() != "2":
            raise SystemExit(f"{key}: seccomp filter is not active: {output}")
        if fields.get("NoNewPrivs", "").strip() != "1":
            raise SystemExit(f"{key}: no-new-privileges is not active: {output}")
        print(
            f"{key}: image_id={entry['imageId']} "
            f"Seccomp={fields['Seccomp'].strip()} "
            f"NoNewPrivs={fields['NoNewPrivs'].strip()} "
            "network=none"
        )


if __name__ == "__main__":
    main()
