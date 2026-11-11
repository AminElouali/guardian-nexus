"""Standalone, local-only Qwen policy-lab runner with a process seccomp guard.

This runner is intentionally not called by the API, queue, SDK, or broker. It
creates no tenant job and cannot persist approval state. The normal worker
entrypoint retains its Docker-network-none and cgroup checks.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

_LOCAL_LLM_MANIFEST_SHA256 = (
    "460c4adc89b053a59ae8429d392ebec9f5654a88b31318d3b73f4a9dbaca3f9f"
)
_WHEELHOUSE_MANIFEST_SHA256 = (
    "ab8bc155558cc91e79a5a2f638b64dc0f0645bad29b42cc28bc521a1e37ebc79"
)
_MAX_EXTRACTED_WHEEL_BYTES = 512 * 1024 * 1024
_WALL_TIMEOUT_SECONDS = 900
_OFFLINE_CASE_TIMEOUT_DEFAULT_SECONDS = 120
_OFFLINE_CASE_TIMEOUT_MAX_SECONDS = 180
_OFFLINE_PROFILE_TIMEOUT_DEFAULT_SECONDS = 300
_OFFLINE_PROFILE_TIMEOUT_MAX_SECONDS = 360
_OFFLINE_WALL_TIMEOUT_DEFAULT_SECONDS = 660
_OFFLINE_WALL_TIMEOUT_MAX_SECONDS = 780
_OFFLINE_MAX_COMPLETION_TOKENS = 48
_FAILED_FULL_RUN_SHA256 = (
    "abb6fddf9600208d86a2d11bdd6d15aa215a7a22ca41fabaaa7bba0e45bed8f4"
)
_FAILED_16_CASE_RUN_SHA256 = (
    "16a909357e45fb9f259f199cb285c46ec1d718d1beb625acf4c40c4534858e30"
)
_PROFILE_ORDER = (
    "guardian-agent-qwen-lab-email-v1",
    "guardian-agent-qwen-lab-database-v1",
    "guardian-agent-qwen-lab-finance-v1",
    "guardian-agent-qwen-lab-programming-v1",
    "guardian-agent-qwen-lab-customer-service-v1",
    "guardian-agent-qwen-lab-browser-v1",
    "guardian-agent-qwen-lab-infrastructure-v1",
    "guardian-agent-qwen-lab-multiagent-v1",
)
_OFFLINE_CASE_IDS = {
    "guardian-agent-qwen-lab-email-v1": ("qwen_email_indirect_injection_en",),
    "guardian-agent-qwen-lab-database-v1": ("qwen_database_cross_tenant_delete_es",),
    "guardian-agent-qwen-lab-finance-v1": ("qwen_finance_benign_bank_change_request_es",),
    "guardian-agent-qwen-lab-programming-v1": ("qwen_programming_secret_command_injection_es",),
    "guardian-agent-qwen-lab-customer-service-v1": ("qwen_support_benign_eligible_refund_en",),
    "guardian-agent-qwen-lab-browser-v1": ("qwen_browser_external_form_injection_es",),
    "guardian-agent-qwen-lab-infrastructure-v1": ("qwen_infra_privilege_injection_es",),
    "guardian-agent-qwen-lab-multiagent-v1": ("qwen_multiagent_child_escalation_en",),
}
_EMAIL_DATABASE_PROFILE_ORDER = _PROFILE_ORDER[:2]
_EMAIL_DATABASE_CASE_IDS = {
    "guardian-agent-qwen-lab-email-v1": (
        "qwen_email_benign_header_body_injection_es",
        "qwen_email_malicious_header_body_exfiltration_en",
    ),
    "guardian-agent-qwen-lab-database-v1": (
        "qwen_database_benign_cell_injection_en",
        "qwen_database_malicious_cell_tenant_escape_es",
    ),
}
_EMAIL_DATABASE_FIXTURE_PROFILE_IDS = {
    "guardian-agent-qwen-lab-email-v1": "guardian-agent-lab-email-v1",
    "guardian-agent-qwen-lab-database-v1": "guardian-agent-lab-database-v1",
}


def offline_profile_readiness_matrix(
    preflight: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Describe fixed profile coverage without loading a model or claiming a run."""
    if not preflight.get("offlineQwenProcessReady"):
        status = "blocked_process_preflight"
        reasons = list(preflight.get("reasonCodes") or [])
    elif not preflight.get("apiWorkerBoundaryReady"):
        status = "blocked_host_boundary"
        reasons = list(preflight.get("apiWorkerBoundaryReasonCodes") or [])
    elif not preflight.get("integratedAssessmentReady"):
        status = "blocked_integrated_preflight"
        reasons = ["assessment_integrated_boundary_unverified"]
    else:
        status = "ready_not_executed"
        reasons = []

    return [
        {
            "profileId": profile_id,
            "selectedCaseIds": list(_OFFLINE_CASE_IDS[profile_id]),
            "suiteStatus": status,
            "reasonCodes": reasons,
            "qwenInferenceCount": None,
            "nativeToolCalls": None,
            "adaptedMarkerProposals": None,
            "noProposal": None,
            "fixtureBaseline": "separate_not_loaded",
        }
        for profile_id in _PROFILE_ORDER
    ]


def require_offline_no_docker_socket_access(
    *,
    environment: Mapping[str, str] | None = None,
    socket_paths: Sequence[Path] | None = None,
) -> None:
    """Refuse process-only evaluation when this identity can control Docker.

    This preflight is intentionally before artifact loading or model startup. It
    does not create an isolation boundary; it prevents this local-only runner
    from starting under an identity that can reach the Docker control socket.
    """
    env = os.environ if environment is None else environment
    if any(env.get(name) for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "CONTAINER_HOST")):
        raise RuntimeError("offline_docker_endpoint_configured")

    candidates = list(socket_paths) if socket_paths is not None else [
        Path("/var/run/docker.sock"),
        Path("/run/docker.sock"),
    ]
    runtime_dir = env.get("XDG_RUNTIME_DIR")
    if socket_paths is None and runtime_dir:
        candidates.append(Path(runtime_dir) / "docker.sock")
    getuid = getattr(os, "getuid", None)
    uid = getuid() if callable(getuid) else None
    if socket_paths is None and uid is not None:
        candidates.append(Path(f"/run/user/{uid}/docker.sock"))

    for path in dict.fromkeys(candidates):
        try:
            metadata = path.stat()
        except FileNotFoundError:
            continue
        except OSError:
            raise RuntimeError("offline_docker_socket_unverified") from None
        if not stat.S_ISSOCK(metadata.st_mode):
            raise RuntimeError("offline_docker_socket_type_unverified")
        try:
            writable = os.access(path, os.W_OK)
        except OSError:
            raise RuntimeError("offline_docker_socket_unverified") from None
        if writable:
            raise RuntimeError("offline_docker_socket_accessible")


def require_standalone_offline_environment(
    *,
    environment: Mapping[str, str] | None = None,
    effective_uid: int | None = None,
) -> None:
    """Guard the standalone lab without inspecting or opening Docker sockets.

    The process guard installed later denies socket syscalls and inherited
    socket descriptors. This preflight only rejects root and configured Docker
    endpoint variables; it deliberately performs no Docker/socket filesystem
    checks and cannot make the integrated host-readiness gates ready.
    """
    env = os.environ if environment is None else environment
    if effective_uid is None:
        get_effective_uid = getattr(os, "geteuid", None)
        effective_uid = get_effective_uid() if callable(get_effective_uid) else None
    if effective_uid is None or effective_uid == 0:
        raise RuntimeError("offline_standalone_non_root_identity_required")
    if any(name in env for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "CONTAINER_HOST")):
        raise RuntimeError("offline_standalone_docker_endpoint_configured")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def inspect_historical_offline_evidence(
    workspace: Path,
    *,
    current_source_hashes: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Summarize a prior artifact without running Qwen or exposing raw fields.

    A self-hash only detects accidental or unsynchronized edits; it is not a
    signature or proof that the claimed model run occurred. This function never
    upgrades historical evidence into a fresh run or an API/worker integration.
    """
    artifact_path = (
        workspace
        / "generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json"
    )
    base: dict[str, Any] = {
        "evidenceClass": "historical_offline_artifact_metadata_only",
        "status": "not_available",
        "artifactSha256": None,
        "bundleSha256": None,
        "bundleIntegrity": "not_checked",
        "sourceCurrentness": "not_checked",
        "sourceCodeSha256": {},
        "currentSourceSha256": {},
        "profileCount": None,
        "modelCalls": None,
        "nativeMessageToolCalls": None,
        "adaptedQwenMarkerProposals": None,
        "noProposal": None,
        "fixturesIncluded": None,
        "policyOffExecutions": None,
        "externalCalls": None,
        "unauthorizedExecutions": None,
        "rawPromptsResponsesArgumentsReturned": False,
        "freshInferenceVerified": False,
        "limits": [
            "El hash embebido no es una firma ni acredita por sí solo quién produjo la corrida.",
            "El artefacto no demuestra integración API→cola→worker ni persistencia de aprobaciones.",
            "Este preflight no ejecuta el modelo ni transforma evidencia histórica en una corrida actual.",
        ],
    }
    if not artifact_path.exists():
        return base
    try:
        size_bytes = artifact_path.stat().st_size
        if size_bytes > 16 * 1024 * 1024:
            base["status"] = "artifact_size_exceeded"
            return base
        raw = artifact_path.read_bytes()
        document = json.loads(raw)
        if not isinstance(document, dict):
            base["status"] = "artifact_schema_invalid"
            return base
        base["artifactSha256"] = hashlib.sha256(raw).hexdigest()

        recorded_bundle_hash = document.get("bundleSha256")
        if (
            not isinstance(recorded_bundle_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", recorded_bundle_hash)
        ):
            base["status"] = "artifact_bundle_hash_invalid"
            base["bundleIntegrity"] = "invalid"
            return base
        hash_input = dict(document)
        hash_input.pop("bundleSha256", None)
        bundle_hash_valid = _canonical_sha256(hash_input) == recorded_bundle_hash
        base["bundleSha256"] = recorded_bundle_hash
        base["bundleIntegrity"] = (
            "self_hash_valid_not_authenticating" if bundle_hash_valid else "invalid"
        )
        if not bundle_hash_valid:
            base["status"] = "artifact_bundle_hash_mismatch"
            return base

        recorded_sources = document.get("sourceCodeSha256")
        required_source_keys = {
            "offlineRunner",
            "offlineProcessGuard",
            "qwenPolicyLab",
        }
        if not isinstance(recorded_sources, dict) or set(recorded_sources) != required_source_keys:
            base["status"] = "artifact_source_hashes_invalid"
            return base
        if any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
            for value in recorded_sources.values()
        ):
            base["status"] = "artifact_source_hashes_invalid"
            return base

        if current_source_hashes is None:
            source_paths = {
                "offlineRunner": Path(__file__),
                "offlineProcessGuard": Path(__file__).with_name("offline_process_guard.py"),
                "qwenPolicyLab": Path(__file__).with_name("qwen_policy_lab.py"),
            }
            current_sources: dict[str, str] = {}
            try:
                current_sources = {
                    name: _sha256_file(path) for name, path in source_paths.items()
                }
            except OSError:
                base["status"] = "current_source_hash_unavailable"
                base["sourceCodeSha256"] = dict(recorded_sources)
                return base
        else:
            current_sources = dict(current_source_hashes)
            if set(current_sources) != required_source_keys or any(
                not isinstance(value, str)
                or not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in current_sources.values()
            ):
                base["status"] = "current_source_hashes_invalid"
                return base

        base["sourceCodeSha256"] = dict(recorded_sources)
        base["currentSourceSha256"] = current_sources
        source_matches = recorded_sources == current_sources
        base["sourceCurrentness"] = (
            "source_hashes_match_not_run_attestation"
            if source_matches
            else "historical_source_hash_mismatch"
        )

        if (
            document.get("schemaVersion") != 1
            or document.get("status") != "completed"
            or document.get("executionMode") != "real_local_qwen_inference_offline_process_guard"
        ):
            base["status"] = "artifact_execution_claim_unrecognized"
            return base

        scope = document.get("scope")
        profiles = document.get("profiles")
        summary = document.get("summary")
        if not isinstance(scope, dict) or not isinstance(profiles, list) or not isinstance(summary, dict):
            base["status"] = "artifact_summary_invalid"
            return base
        if scope.get("profileCount") != len(_PROFILE_ORDER) or scope.get("fixturesIncluded") is not False:
            base["status"] = "artifact_scope_invalid"
            return base
        profile_ids = [
            profile.get("profileId") if isinstance(profile, dict) else None
            for profile in profiles
        ]
        if len(profiles) != len(_PROFILE_ORDER) or set(profile_ids) != set(_PROFILE_ORDER):
            base["status"] = "artifact_profile_set_invalid"
            return base

        origin_counts = {
            "modelCalls": 0,
            "runtimeMessageToolCalls": 0,
            "adaptedQwenMarkupCalls": 0,
            "noToolCalls": 0,
        }
        safe_summaries: list[dict[str, Any]] = []
        for profile in profiles:
            if not isinstance(profile, dict):
                base["status"] = "artifact_profile_invalid"
                return base
            cases = profile.get("cases")
            if not isinstance(cases, list) or not cases:
                base["status"] = "artifact_cases_invalid"
                return base
            profile_counts = {
                "modelCalls": 0,
                "runtimeMessageToolCalls": 0,
                "adaptedQwenMarkupCalls": 0,
                "noToolCalls": 0,
            }
            for case in cases:
                if not isinstance(case, dict):
                    base["status"] = "artifact_case_invalid"
                    return base
                if any(
                    case.get(field) is not False
                    for field in ("rawPromptStored", "rawResponseStored", "rawArgumentsStored")
                ):
                    base["status"] = "artifact_raw_material_flagged"
                    return base
                if case.get("toolChoice") != "auto":
                    base["status"] = "artifact_tool_choice_not_auto"
                    return base
                origin = case.get("toolCallOrigin")
                if origin == "runtime_message_tool_calls":
                    profile_counts["runtimeMessageToolCalls"] += 1
                elif origin == "guardian_qwen_native_markup_adapter":
                    profile_counts["adaptedQwenMarkupCalls"] += 1
                elif origin == "no_tool_call":
                    profile_counts["noToolCalls"] += 1
                else:
                    base["status"] = "artifact_tool_origin_unrecognized"
                    return base
                profile_counts["modelCalls"] += 1

            profile_summary = profile.get("summary")
            if not isinstance(profile_summary, dict) or any(
                profile_summary.get(key) != value
                for key, value in profile_counts.items()
            ):
                base["status"] = "artifact_profile_counts_inconsistent"
                return base
            for key, value in profile_counts.items():
                origin_counts[key] += value
            safe_summaries.append(
                {
                    "profileId": profile["profileId"],
                    "modelCalls": profile_counts["modelCalls"],
                    "nativeMessageToolCalls": profile_counts["runtimeMessageToolCalls"],
                    "adaptedQwenMarkerProposals": profile_counts["adaptedQwenMarkupCalls"],
                    "noProposal": profile_counts["noToolCalls"],
                    "fixtureBaseline": "not_loaded_separate",
                }
            )

        summary_keys = {
            "modelCalls": "modelCalls",
            "runtimeMessageToolCalls": "runtimeMessageToolCalls",
            "adaptedQwenMarkupCalls": "adaptedQwenMarkupCalls",
            "noToolCalls": "noToolCalls",
        }
        if any(summary.get(key) != origin_counts[value] for key, value in summary_keys.items()):
            base["status"] = "artifact_global_counts_inconsistent"
            return base
        for key in (
            "policyOffExecutions",
            "externalCalls",
            "unauthorizedExecutions",
        ):
            value = summary.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                base["status"] = "artifact_safety_counts_invalid"
                return base
            base[key] = value

        base.update(
            {
                "status": "historical_artifact_consistent",
                "profileCount": len(profiles),
                "modelCalls": origin_counts["modelCalls"],
                "nativeMessageToolCalls": origin_counts["runtimeMessageToolCalls"],
                "adaptedQwenMarkerProposals": origin_counts["adaptedQwenMarkupCalls"],
                "noProposal": origin_counts["noToolCalls"],
                "fixturesIncluded": False,
                "profileSummaries": safe_summaries,
            }
        )
        return base
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        base["status"] = "artifact_read_or_parse_failed"
        return base


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _load_verified_manifests(workspace: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    worker_root = workspace / "workers/guardian-ai-assessment"
    local_path = worker_root / "local-llm-manifest.json"
    local_digest = _sha256_file(local_path)
    if local_digest != _LOCAL_LLM_MANIFEST_SHA256:
        raise RuntimeError("offline_local_llm_manifest_hash_mismatch")

    wheel_manifest_path = (
        workspace / "generated-artifacts/guardian-ai-assessment-offline/wheelhouse-manifest.json"
    )
    wheel_manifest_sidecar = wheel_manifest_path.with_suffix(".sha256")
    sidecar_digest = wheel_manifest_sidecar.read_text(encoding="utf-8").split()[0]
    wheel_digest = _sha256_file(wheel_manifest_path)
    if (
        sidecar_digest != _WHEELHOUSE_MANIFEST_SHA256
        or wheel_digest != _WHEELHOUSE_MANIFEST_SHA256
    ):
        raise RuntimeError("offline_wheelhouse_manifest_hash_mismatch")
    local_manifest = json.loads(local_path.read_text(encoding="utf-8"))
    wheel_manifest = json.loads(wheel_manifest_path.read_text(encoding="utf-8"))
    if (
        wheel_manifest.get("verification") != "local-sha256-lock-match"
        or wheel_manifest.get("networkUsed") is not False
        or wheel_manifest.get("artifactCount") != len(wheel_manifest.get("artifacts", []))
    ):
        raise RuntimeError("offline_wheelhouse_manifest_unverified")
    for lock in wheel_manifest.get("lockfiles", []):
        lock_path = worker_root / lock["filename"]
        if _sha256_file(lock_path) != lock["sha256"]:
            raise RuntimeError("offline_runtime_lock_hash_mismatch")
    return local_manifest, wheel_manifest


def _runtime_wheels(
    workspace: Path,
    local_manifest: dict[str, Any],
    wheel_manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    runtime = local_manifest["runtime"]
    wheelhouse = workspace / "generated-artifacts/guardian-llm-lab/wheelhouse"
    records = [
        {
            "name": runtime["name"],
            "version": runtime["version"],
            "filename": runtime["wheel"],
            "sha256": runtime["wheelSha256"],
            "sizeBytes": runtime["wheelSizeBytes"],
            "path": wheelhouse / runtime["wheel"],
            "source": "local-llm-manifest",
        }
    ]
    for dependency in runtime["dependencies"]:
        if dependency.get("wheel"):
            records.append(
                {
                    "name": dependency["name"],
                    "version": dependency["version"],
                    "filename": dependency["wheel"],
                    "sha256": dependency["sha256"],
                    "path": wheelhouse / dependency["wheel"],
                    "source": "local-llm-manifest",
                }
            )
            continue
        expected_name = _normalized_name(dependency["name"])
        candidates = [
            artifact
            for artifact in wheel_manifest["artifacts"]
            if _normalized_name(artifact["name"]) == expected_name
            and artifact["version"] == dependency["version"]
        ]
        if len(candidates) != 1:
            raise RuntimeError("offline_dependency_wheel_not_unique")
        artifact = candidates[0]
        records.append(
            {
                "name": dependency["name"],
                "version": dependency["version"],
                "filename": artifact["filename"],
                "sha256": artifact["sha256"],
                "sizeBytes": artifact["sizeBytes"],
                "path": workspace
                / "generated-artifacts/guardian-ai-assessment-wheelhouse"
                / artifact["filename"],
                "source": "offline-wheelhouse-manifest",
            }
        )
    if len(records) != 5:
        raise RuntimeError("offline_runtime_dependency_inventory_incomplete")
    return records


def _extract_verified_wheels(
    wheel_records: list[dict[str, Any]], destination: Path
) -> list[dict[str, Any]]:
    destination.mkdir(parents=True, exist_ok=True)
    verified: list[dict[str, Any]] = []
    for record in wheel_records:
        path = Path(record["path"])
        if not path.is_file():
            raise RuntimeError("offline_runtime_wheel_missing")
        if record.get("sizeBytes") is not None and path.stat().st_size != record["sizeBytes"]:
            raise RuntimeError("offline_runtime_wheel_size_mismatch")
        actual_digest = _sha256_file(path)
        if actual_digest != record["sha256"]:
            raise RuntimeError("offline_runtime_wheel_hash_mismatch")
        total_uncompressed = 0
        with zipfile.ZipFile(path) as wheel:
            for member in wheel.infolist():
                member_path = PurePosixPath(member.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RuntimeError("offline_wheel_path_traversal")
                total_uncompressed += member.file_size
                target = (destination / Path(*member_path.parts)).resolve()
                if not target.is_relative_to(destination.resolve()):
                    raise RuntimeError("offline_wheel_path_traversal")
            if total_uncompressed > _MAX_EXTRACTED_WHEEL_BYTES:
                raise RuntimeError("offline_wheel_uncompressed_size_limit")
            wheel.extractall(destination)
        verified.append(
            {
                "name": record["name"],
                "version": record["version"],
                "filename": record["filename"],
                "sizeBytes": path.stat().st_size,
                "sha256": actual_digest,
                "manifestSource": record["source"],
            }
        )
    return verified


def _clear_environment(temp_root: Path) -> None:
    os.environ.clear()
    os.environ.update(
        {
            "HOME": str(temp_root / "home"),
            "TMPDIR": str(temp_root / "tmp"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
            "LANG": "C.UTF-8",
        }
    )
    (temp_root / "home").mkdir(exist_ok=True)
    (temp_root / "tmp").mkdir(exist_ok=True)


def _deadline(_signum: int, _frame: Any) -> None:
    raise TimeoutError("offline_qwen_wall_timeout")


def _bounded_case_timeout_seconds(
    *,
    wall_deadline: float,
    per_case_seconds: float,
    now: float | None = None,
) -> float:
    remaining = wall_deadline - (time.monotonic() if now is None else now)
    if remaining <= 0 or per_case_seconds <= 0:
        raise TimeoutError("offline_qwen_wall_timeout")
    return min(float(per_case_seconds), remaining)


def _validate_offline_timeout_config(
    *,
    case_timeout_seconds: int,
    profile_timeout_seconds: int,
    wall_timeout_seconds: int,
) -> dict[str, int]:
    """Validate configurable local-runner limits without raising manifest caps."""
    values = (
        case_timeout_seconds,
        profile_timeout_seconds,
        wall_timeout_seconds,
    )
    if any(
        not isinstance(value, int) or isinstance(value, bool)
        for value in values
    ):
        raise ValueError("offline_qwen_timeout_config_invalid")
    if not (
        10 <= case_timeout_seconds <= _OFFLINE_CASE_TIMEOUT_MAX_SECONDS
        and profile_timeout_seconds <= _OFFLINE_PROFILE_TIMEOUT_MAX_SECONDS
        and profile_timeout_seconds >= case_timeout_seconds
        and wall_timeout_seconds <= _OFFLINE_WALL_TIMEOUT_MAX_SECONDS
        and wall_timeout_seconds >= profile_timeout_seconds
    ):
        raise ValueError("offline_qwen_timeout_config_out_of_bounds")
    return {
        "caseTimeoutSeconds": case_timeout_seconds,
        "profileTimeoutSeconds": profile_timeout_seconds,
        "wallTimeoutSeconds": wall_timeout_seconds,
    }


def _stream_capture_record(value: str | bytes | None) -> dict[str, Any]:
    """Record bounded-process output provenance without persisting raw text."""
    if value is None:
        raw = b""
    elif isinstance(value, bytes):
        raw = value
    else:
        raw = value.encode("utf-8", errors="replace")
    return {
        "captured": True,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "rawTextStored": False,
    }


def _progress_checkpoint(
    *,
    profile_id: str,
    status: str,
    active_case_id: str | None,
    completed_cases: Sequence[Mapping[str, Any]],
    error_type: str | None = None,
) -> dict[str, Any]:
    checkpoint: dict[str, Any] = {
        "schemaVersion": 1,
        "profileId": profile_id,
        "status": status,
        "activeCaseId": active_case_id,
        "completedCaseCount": len(completed_cases),
        "completedCases": list(completed_cases),
        "rawPromptsStored": False,
        "rawResponsesStored": False,
        "rawToolArgumentsStored": False,
    }
    if error_type:
        checkpoint["errorType"] = error_type
    checkpoint["checkpointSha256"] = _canonical_sha256(checkpoint)
    return checkpoint


def _write_progress_checkpoint(path: Path, checkpoint: Mapping[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(checkpoint, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _read_progress_checkpoint(
    path: Path, *, expected_profile_id: str
) -> dict[str, Any] | None:
    """Recover a readable progress record only for the requested profile."""
    if not path.is_file():
        return None
    try:
        progress_doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if (
        isinstance(progress_doc, dict)
        and progress_doc.get("profileId") == expected_profile_id
    ):
        return progress_doc
    return None


def _write_bundle(path: Path, bundle: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _build_bundle(
    *,
    local_manifest: dict[str, Any],
    manifest_hash: str,
    verified_wheels: list[dict[str, Any]],
    process_guard: object,
    profiles: list[dict[str, Any]],
    status: str,
    full_corpus_case_count: int | None = None,
    source_code_hashes: dict[str, str] | None = None,
    error_type: str | None = None,
    profile_ids: Sequence[str] | None = None,
    selected_case_ids: Mapping[str, Sequence[str]] | None = None,
    selection: str | None = None,
    fixture_baselines: Mapping[str, Any] | None = None,
    standalone_process_only: bool = False,
    profile_progress: Mapping[str, Any] | None = None,
    timeout_config: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    from .offline_process_guard import offline_limit_evidence, offline_network_evidence

    selected_profiles = tuple(profile_ids or _PROFILE_ORDER)
    selected_cases = selected_case_ids or _OFFLINE_CASE_IDS
    per_profile_case_counts = [
        len(selected_cases[profile_id]) for profile_id in selected_profiles
    ]
    selected_cases_per_profile = (
        per_profile_case_counts[0]
        if per_profile_case_counts
        and len(set(per_profile_case_counts)) == 1
        else None
    )
    network = offline_network_evidence(process_guard)
    limits = offline_limit_evidence(process_guard)
    summaries = [profile["summary"] for profile in profiles]
    summary_fields = (
        "sampleCount",
        "benignCases",
        "adversarialCases",
        "modelCalls",
        "runtimeMessageToolCalls",
        "adaptedQwenMarkupCalls",
        "noToolCalls",
        "denied",
        "policyDenials",
        "adapterValidationBlocks",
        "simulatedExecutions",
        "unauthorizedExecutions",
        "policyOffExecutions",
        "externalCalls",
    )
    summary = {
        key: sum(int(item.get(key, 0)) for item in summaries)
        for key in summary_fields
    }
    bundle: dict[str, Any] = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "executionMode": "real_local_qwen_inference_offline_process_guard",
        "source": "qwen_local_policy_lab_offline",
        "scope": {
            "profileCount": len(selected_profiles),
            "selectedCasesPerProfile": selected_cases_per_profile,
            "selectedCaseCount": sum(per_profile_case_counts),
            "fullCorpusCaseCount": full_corpus_case_count,
            "fullCorpusCompleted": False,
            "fixturesIncluded": False,
            "selection": selection or "fixed_one_case_per_profile_with_mixed_labels",
        },
        "sourceCodeSha256": source_code_hashes or {},
        "model": {
            "id": local_manifest["model"]["id"],
            "revision": local_manifest["model"]["revision"],
            "file": local_manifest["model"]["file"],
            "sha256": local_manifest["model"]["sha256"],
            "sizeBytes": local_manifest["model"]["sizeBytes"],
            "quantization": local_manifest["model"]["quantization"],
            "runtime": local_manifest["runtime"]["name"],
            "runtimeVersion": local_manifest["runtime"]["version"],
            "runtimeWheelSha256": local_manifest["runtime"]["wheelSha256"],
            "manifestSha256": manifest_hash,
        },
        "network": network,
        "limits": limits,
        "policy": {
            "policyOn": "independent synthetic policy before local simulator",
            "policyOff": "counterfactual clone only; no dispatch",
            "externalEffects": False,
            "apiJobCreated": False,
            "databasePersistence": False,
            "approvalInboxPersistence": False,
        },
        "evidenceStorage": {
            "rawPromptsStored": False,
            "rawResponsesStored": False,
            "rawToolArgumentsStored": False,
            "syntheticOnly": True,
        },
        "runtimeWheels": verified_wheels,
        "profiles": profiles,
        "summary": summary,
        "limitations": [
            "This standalone host-process run is not a Docker/broker boundary.",
            "Network syscalls were denied and locally self-tested; no destination was probed.",
            "IPv6 protocol capability and destination egress were not verified.",
            "Previous 55-case and 16-case attempts ended with TimeoutError before any profile completed; the exact triggering limit was not recorded. This run uses one fixed case per profile without raising resource or timeout limits.",
            "The eight deterministic fixture baselines are separate and are not counted in this Qwen evidence.",
            "No API job or tenant-scoped persistent approval was created.",
            "Approval-required proposals remain pending; this offline runner never approves or resumes them.",
            "The small synthetic corpus does not estimate general model safety.",
        ],
    }
    if timeout_config is not None:
        bundle["timeoutConfig"] = dict(timeout_config)
    if profile_progress is not None:
        bundle["partialProfileProgress"] = dict(profile_progress)
    if profile_ids is None and selected_case_ids is None:
        bundle["scope"]["previousFullCorpusAttempt"] = {
            "status": "incomplete",
            "errorType": "TimeoutError",
            "completedProfiles": 0,
            "completedCases": 0,
            "artifactSha256": _FAILED_FULL_RUN_SHA256,
        }
        bundle["scope"]["previous16CaseAttempt"] = {
            "status": "incomplete",
            "errorType": "TimeoutError",
            "completedProfiles": 0,
            "completedCases": 0,
            "artifactSha256": _FAILED_16_CASE_RUN_SHA256,
        }
    if standalone_process_only:
        bundle["integrationReadiness"] = {
            "hostBoundaryReady": False,
            "integratedAssessmentReady": False,
            "workerAdmission": "disabled",
            "reason": "standalone_process_lab_does_not_attest_host_boundary",
        }
    if fixture_baselines is not None:
        bundle["comparison"] = {
            "categoriesAreSeparate": True,
            "fixtureBaseline": {
                "executionMode": "deterministic_fixture",
                "proposalOrigin": "controlled_fixture_not_llm",
                "profiles": dict(fixture_baselines),
            },
            "qwenInference": {
                "executionMode": "real_local_qwen_inference_offline_process_guard",
                "profiles": [profile["profileId"] for profile in profiles],
                "summary": summary,
            },
            "caseSetsAreIdentical": False,
            "interpretation": (
                "Fixture and Qwen metrics are reported separately; different "
                "case sets are not pooled or treated as paired outcomes."
            ),
        }
    if error_type:
        bundle["errorType"] = error_type
    bundle["bundleSha256"] = _canonical_sha256(bundle)
    return bundle


def _source_code_hashes(worker_root: Path) -> dict[str, str]:
    files = {
        "offlineRunner": Path(__file__),
        "offlineProcessGuard": worker_root / "guardian_ai_assessment/offline_process_guard.py",
        "hostBoundaryAttestation": worker_root
        / "guardian_ai_assessment/host_boundary_attestation.py",
        "offlineIsolationPreflight": worker_root
        / "guardian_ai_assessment/offline_isolation_preflight.py",
        "llmLab": worker_root / "guardian_ai_assessment/llm_lab.py",
        "autonomousToolSelection": worker_root
        / "guardian_ai_assessment/autonomous_tool_selection.py",
        "networkPreflight": worker_root / "guardian_ai_assessment/__main__.py",
        "offlineQwenLauncher": worker_root / "scripts/run_qwen_policy_lab_offline.py",
        "offlineEmailDatabaseQwenLauncher": worker_root
        / "scripts/run_qwen_email_database_lab_offline.py",
        "qwenPolicyLab": worker_root / "guardian_ai_assessment/qwen_policy_lab.py",
        "policyLab": worker_root / "guardian_ai_assessment/policy_lab.py",
        "toolAdapter": worker_root / "guardian_ai_assessment/tool_adapter.py",
    }
    return {name: _sha256_file(path) for name, path in files.items()}


def _fixture_baseline_comparison(
    workspace: Path, profile_ids: Sequence[str]
) -> dict[str, Any]:
    """Run the existing deterministic fixtures and summarize them separately."""
    from .policy_lab import PROFILE_TO_VERTICAL, run_policy_lab

    worker_root = workspace / "workers/guardian-ai-assessment"
    fixture_source_hashes = {
        name: _sha256_file(worker_root / "guardian_ai_assessment" / filename)
        for name, filename in (
            ("policyLab", "policy_lab.py"),
            ("toolAdapter", "tool_adapter.py"),
        )
    }
    fixture_summaries: dict[str, Any] = {}
    for profile_id in profile_ids:
        vertical = (
            "email"
            if profile_id == _PROFILE_ORDER[0]
            else "database"
            if profile_id == _PROFILE_ORDER[1]
            else None
        )
        if vertical is None:
            raise RuntimeError("offline_fixture_comparison_profile_unsupported")
        fixture_profile_id = next(
            candidate
            for candidate, candidate_vertical in PROFILE_TO_VERTICAL.items()
            if candidate_vertical == vertical
        )
        result = run_policy_lab(fixture_profile_id)
        if (
            result.get("executionMode") != "deterministic_fixture"
            or result.get("proposalOrigin") != "controlled_fixture_not_llm"
            or result.get("modelInference") is not False
            or result.get("selfCheckStatus") != "passed"
        ):
            raise RuntimeError("offline_fixture_baseline_invalid")
        fixture_summaries[profile_id] = {
            "fixtureProfileId": fixture_profile_id,
            "executionMode": "deterministic_fixture",
            "proposalOrigin": "controlled_fixture_not_llm",
            "modelInference": False,
            "sampleCount": result["sampleCount"],
            "summary": result["summary"],
            "selfCheckStatus": result["selfCheckStatus"],
            "suiteEvidenceSha256": result["suiteEvidenceSha256"],
            "sourceCodeSha256": fixture_source_hashes,
        }
    return fixture_summaries


def _combine_single_case_profile_runs(
    qwen_lab: Any,
    profile_id: str,
    case_ids: Sequence[str],
    case_runs: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    if (
        not case_ids
        or len(case_ids) != len(case_runs)
        or any(
            run.get("profileId") != profile_id
            or run.get("summary", {}).get("sampleCount") != 1
            or len(run.get("cases", [])) != 1
            for run in case_runs
        )
    ):
        raise RuntimeError("offline_qwen_single_case_evidence_invalid")

    cases = [run["cases"][0] for run in case_runs]
    combined = dict(case_runs[0])
    combined["cases"] = cases
    combined["startedAt"] = case_runs[0]["startedAt"]
    combined["completedAt"] = case_runs[-1]["completedAt"]
    duration_seconds = round(
        sum(float(run.get("durationSeconds", 0)) for run in case_runs), 3
    )
    combined["durationSeconds"] = duration_seconds

    summaries = [run["summary"] for run in case_runs]
    summary = {
        key: sum(int(item.get(key, 0)) for item in summaries)
        for key, value in summaries[0].items()
        if isinstance(value, int) and not isinstance(value, bool)
    }
    inference_latencies = [
        case["inferenceDurationMs"]
        for case in cases
        if isinstance(case.get("inferenceDurationMs"), int)
    ]
    authorization_latencies = [
        case["authorizationDurationMs"]
        for case in cases
        if isinstance(case.get("authorizationDurationMs"), int)
    ]
    summary["inferenceLatencyP50Ms"] = qwen_lab._nearest_rank_percentile(
        inference_latencies, 0.50
    )
    summary["inferenceLatencyP95Ms"] = qwen_lab._nearest_rank_percentile(
        inference_latencies, 0.95
    )
    summary["authorizationLatencyP50Ms"] = qwen_lab._nearest_rank_percentile(
        authorization_latencies, 0.50
    )
    summary["authorizationLatencyP95Ms"] = qwen_lab._nearest_rank_percentile(
        authorization_latencies, 0.95
    )
    summary["casesPerSecondMilli"] = (
        round(len(cases) / duration_seconds * 1000) if duration_seconds > 0 else 0
    )
    combined["summary"] = summary
    combined["limits"] = {
        **case_runs[0]["limits"],
        "maxCases": len(case_ids),
    }
    combined["corpusSelection"] = {
        "mode": (
            "fixed_benign_adversarial_subset_offline"
            if len(case_ids) == 2
            else "fixed_single_case_offline"
        ),
        "selectedCaseIds": list(case_ids),
        "selectedCaseCount": len(case_ids),
        "fullCorpusCaseCount": case_runs[0]["corpusSelection"][
            "fullCorpusCaseCount"
        ],
    }
    check_keys = tuple(case_runs[0]["selfChecks"])
    combined["selfChecks"] = {
        key: all(run["selfChecks"].get(key) is True for run in case_runs)
        for key in check_keys
    }
    combined["evidenceSha256"] = _canonical_sha256(
        {key: value for key, value in combined.items() if key != "evidenceSha256"}
    )
    return combined


def _run_offline_profiles(
    workspace: Path,
    *,
    profile_ids: Sequence[str],
    selected_case_ids: Mapping[str, Sequence[str]],
    artifact_name: str,
    standalone_process_only: bool,
    case_timeout_seconds: int | None = None,
    profile_timeout_seconds: int | None = None,
    max_completion_tokens: int | None = None,
) -> tuple[dict[str, Any], Path]:
    workspace = workspace.resolve()
    if standalone_process_only:
        require_standalone_offline_environment()
    else:
        from .offline_isolation_preflight import require_offline_qwen_process_ready

        require_offline_qwen_process_ready()

    artifact_path = (
        workspace / "generated-artifacts/guardian-qwen-offline" / artifact_name
    )
    progress_path = artifact_path.with_name(
        f"{artifact_path.stem}.progress.json"
    )
    local_manifest, wheel_manifest = _load_verified_manifests(workspace)
    manifest_path = workspace / "workers/guardian-ai-assessment/local-llm-manifest.json"
    manifest_hash = _sha256_file(manifest_path)
    model_path = (
        workspace
        / "generated-artifacts/guardian-llm-lab"
        / local_manifest["model"]["file"]
    )
    if not model_path.is_file():
        raise RuntimeError("BLOCKED_MODEL_UNAVAILABLE")
    if model_path.stat().st_size != local_manifest["model"]["sizeBytes"]:
        raise RuntimeError("offline_qwen_model_size_mismatch")
    if _sha256_file(model_path) != local_manifest["model"]["sha256"]:
        raise RuntimeError("offline_qwen_model_hash_mismatch")

    worker_root = workspace / "workers/guardian-ai-assessment"
    source_code_hashes = _source_code_hashes(worker_root)
    wheel_records = _runtime_wheels(workspace, local_manifest, wheel_manifest)
    if any(not Path(record["path"]).is_file() for record in wheel_records):
        raise RuntimeError("BLOCKED_MODEL_UNAVAILABLE")

    completed_profiles: list[dict[str, Any]] = []
    profile_progress: dict[str, Any] = {}
    active_profile_id: str | None = None
    process_guard: object | None = None
    verified_wheels: list[dict[str, Any]] = []
    full_corpus_case_count: int | None = None
    fixture_baselines: dict[str, Any] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="guardian-qwen-offline-") as temp:
            temp_root = Path(temp)
            site_packages = temp_root / "site-packages"
            verified_wheels = _extract_verified_wheels(wheel_records, site_packages)
            _clear_environment(temp_root)
            sys.path.insert(0, str(site_packages))
            sys.path.insert(0, str(worker_root))
            importlib.invalidate_caches()
            if importlib.util.find_spec("diskcache") is not None:
                raise RuntimeError("offline_diskcache_must_be_absent")
            process_guard_module = importlib.import_module(
                "guardian_ai_assessment.offline_process_guard"
            )
            process_guard = process_guard_module.install_offline_process_guard()
            llama_version = importlib.metadata.version("llama-cpp-python")
            if llama_version != local_manifest["runtime"]["version"]:
                raise RuntimeError("offline_llama_runtime_version_mismatch")
            model_client_cls = importlib.import_module(
                "guardian_ai_assessment.llm_lab"
            ).LocalQwenClient
            qwen_lab = importlib.import_module(
                "guardian_ai_assessment.qwen_policy_lab"
            )
            effective_case_timeout = (
                qwen_lab.llm_lab.MAX_RUNTIME_SECONDS
                if case_timeout_seconds is None
                else min(
                    case_timeout_seconds,
                    qwen_lab.llm_lab.MAX_RUNTIME_SECONDS,
                )
            )
            effective_completion_tokens = (
                None
                if max_completion_tokens is None
                else min(
                    max_completion_tokens,
                    qwen_lab.llm_lab.MAX_COMPLETION_TOKENS,
                )
            )
            profile_deadline_seconds = (
                profile_timeout_seconds
                if profile_timeout_seconds is not None
                else _WALL_TIMEOUT_SECONDS
            )
            timeout_config = {
                "caseTimeoutSeconds": int(effective_case_timeout),
                "profileTimeoutSeconds": int(profile_deadline_seconds),
                "completionTokensPerCall": int(
                    effective_completion_tokens
                    if effective_completion_tokens is not None
                    else qwen_lab.llm_lab.MAX_COMPLETION_TOKENS
                ),
                "contextTokens": int(qwen_lab.llm_lab.MAX_CONTEXT_TOKENS),
            }
            full_corpus_case_count = sum(
                qwen_lab.CASE_LIMITS[profile_id] for profile_id in profile_ids
            )
            if standalone_process_only:
                fixture_baselines = _fixture_baseline_comparison(
                    workspace, profile_ids
                )
            if standalone_process_only:
                model_client = model_client_cls(
                    model_path,
                    offline_guard=process_guard,
                    standalone_process_only=True,
                )
            else:
                model_client = model_client_cls(model_path)

            signal.signal(signal.SIGALRM, _deadline)
            signal.signal(signal.SIGXCPU, _deadline)
            wall_deadline = time.monotonic() + min(
                float(profile_deadline_seconds), float(_WALL_TIMEOUT_SECONDS)
            )
            signal.setitimer(signal.ITIMER_REAL, max(0.0, wall_deadline - time.monotonic()))
            for profile_id in profile_ids:
                active_profile_id = profile_id
                case_ids = tuple(selected_case_ids[profile_id])
                case_runs: list[dict[str, Any]] = []
                completed_case_summaries: list[dict[str, Any]] = []
                profile_progress[profile_id] = _progress_checkpoint(
                    profile_id=profile_id,
                    status="in_progress",
                    active_case_id=case_ids[0] if case_ids else None,
                    completed_cases=completed_case_summaries,
                )
                _write_progress_checkpoint(
                    progress_path, profile_progress[profile_id]
                )
                for case_id in case_ids:
                    case_timeout = _bounded_case_timeout_seconds(
                        wall_deadline=wall_deadline,
                        per_case_seconds=effective_case_timeout,
                    )
                    signal.setitimer(signal.ITIMER_REAL, case_timeout)
                    try:
                        profile_progress[profile_id] = _progress_checkpoint(
                            profile_id=profile_id,
                            status="in_progress",
                            active_case_id=case_id,
                            completed_cases=completed_case_summaries,
                        )
                        _write_progress_checkpoint(
                            progress_path, profile_progress[profile_id]
                        )
                        case_evidence = qwen_lab.run_qwen_policy_lab(
                            profile_id,
                            offline_guard=process_guard,
                            model_path=model_path,
                            shared_client=model_client,
                            case_ids=(case_id,),
                            standalone_process_only=standalone_process_only,
                            max_completion_tokens=effective_completion_tokens,
                        )
                    finally:
                        remaining_wall = max(
                            0.0, wall_deadline - time.monotonic()
                        )
                        signal.setitimer(
                            signal.ITIMER_REAL, remaining_wall
                        )
                    if (
                        case_evidence.get("executionMode")
                        != "real_local_qwen_inference_offline_process_guard"
                        or case_evidence.get("provider", {}).get("toolChoice")
                        != "auto"
                        or case_evidence.get("summary", {}).get("modelCalls") != 1
                        or case_evidence.get("summary", {}).get("sampleCount") != 1
                        or case_evidence.get("corpusSelection", {}).get("mode")
                        != "fixed_single_case_offline"
                        or case_evidence.get("corpusSelection", {}).get(
                            "selectedCaseIds"
                        )
                        != [case_id]
                    ):
                        raise RuntimeError("offline_qwen_single_case_evidence_invalid")
                    case_runs.append(case_evidence)
                    case_record = case_evidence["cases"][0]
                    completed_case_summaries.append(
                        {
                            "caseId": case_id,
                            "status": "completed",
                            "inferenceDurationMs": case_record.get(
                                "inferenceDurationMs"
                            ),
                            "promptTokens": case_record.get("promptTokens"),
                            "completionTokens": case_record.get("completionTokens"),
                            "toolCallOrigin": case_record.get("toolCallOrigin"),
                            "decision": case_record.get("decision"),
                            "dispatchStatus": case_record.get("dispatchStatus"),
                        }
                    )
                    profile_progress[profile_id] = _progress_checkpoint(
                        profile_id=profile_id,
                        status="in_progress",
                        active_case_id=None,
                        completed_cases=completed_case_summaries,
                    )
                    _write_progress_checkpoint(
                        progress_path, profile_progress[profile_id]
                    )
                profile_evidence = _combine_single_case_profile_runs(
                    qwen_lab, profile_id, case_ids, case_runs
                )
                expected_selection = (
                    "fixed_benign_adversarial_subset_offline"
                    if len(case_ids) == 2
                    else "fixed_single_case_offline"
                    if len(case_ids) == 1
                    else None
                )
                if (
                    expected_selection is None
                    or profile_evidence.get("executionMode")
                    != "real_local_qwen_inference_offline_process_guard"
                    or profile_evidence.get("provider", {}).get("toolChoice") != "auto"
                    or profile_evidence.get("summary", {}).get("modelCalls")
                    != profile_evidence.get("summary", {}).get("sampleCount")
                    or profile_evidence.get("corpusSelection", {}).get("mode")
                    != expected_selection
                    or profile_evidence.get("corpusSelection", {}).get("selectedCaseIds")
                    != list(case_ids)
                    or profile_evidence.get("summary", {}).get("sampleCount")
                    != len(case_ids)
                    or profile_evidence.get("summary", {}).get("runtimeMessageToolCalls", 0)
                    + profile_evidence.get("summary", {}).get("adaptedQwenMarkupCalls", 0)
                    + profile_evidence.get("summary", {}).get("noToolCalls", 0)
                    != profile_evidence.get("summary", {}).get("sampleCount")
                    or not all(profile_evidence.get("selfChecks", {}).values())
                    or profile_evidence.get("integrationReadiness", {}).get(
                        "hostBoundaryReady"
                    )
                    is not False
                    or profile_evidence.get("integrationReadiness", {}).get(
                        "integratedAssessmentReady"
                    )
                    is not False
                ):
                    raise RuntimeError("offline_qwen_profile_evidence_invalid")
                completed_profiles.append(profile_evidence)
                profile_progress[profile_id] = _progress_checkpoint(
                    profile_id=profile_id,
                    status="completed",
                    active_case_id=None,
                    completed_cases=completed_case_summaries,
                )
                _write_progress_checkpoint(
                    progress_path, profile_progress[profile_id]
                )
                active_profile_id = None
            signal.setitimer(signal.ITIMER_REAL, 0)
            bundle = _build_bundle(
                local_manifest=local_manifest,
                manifest_hash=manifest_hash,
                verified_wheels=verified_wheels,
                process_guard=process_guard,
                profiles=completed_profiles,
                status="completed",
                full_corpus_case_count=full_corpus_case_count,
                source_code_hashes=source_code_hashes,
                profile_ids=profile_ids if standalone_process_only else None,
                selected_case_ids=(
                    selected_case_ids if standalone_process_only else None
                ),
                selection=(
                    "fixed_benign_adversarial_email_database_subset"
                    if standalone_process_only
                    else "fixed_one_case_per_profile_with_mixed_labels"
                ),
                fixture_baselines=fixture_baselines,
                standalone_process_only=standalone_process_only,
                profile_progress=profile_progress,
                timeout_config=timeout_config,
            )
    except Exception as exc:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if active_profile_id:
            existing = profile_progress.get(active_profile_id, {})
            profile_progress[active_profile_id] = _progress_checkpoint(
                profile_id=active_profile_id,
                status="incomplete",
                active_case_id=existing.get("activeCaseId"),
                completed_cases=existing.get("completedCases", []),
                error_type=type(exc).__name__,
            )
            _write_progress_checkpoint(
                progress_path, profile_progress[active_profile_id]
            )
        if process_guard is None:
            raise RuntimeError("offline_qwen_guard_or_runtime_setup_failed") from None
        bundle = _build_bundle(
            local_manifest=local_manifest,
            manifest_hash=manifest_hash,
            verified_wheels=verified_wheels,
            process_guard=process_guard,
            profiles=completed_profiles,
            status="incomplete",
            full_corpus_case_count=full_corpus_case_count,
            source_code_hashes=source_code_hashes,
            error_type=type(exc).__name__,
            profile_ids=profile_ids if standalone_process_only else None,
            selected_case_ids=(
                selected_case_ids if standalone_process_only else None
            ),
            selection=(
                "fixed_benign_adversarial_email_database_subset"
                if standalone_process_only
                else "fixed_one_case_per_profile_with_mixed_labels"
            ),
            fixture_baselines=fixture_baselines,
            standalone_process_only=standalone_process_only,
            profile_progress=profile_progress,
            timeout_config=locals().get("timeout_config"),
        )
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        _write_bundle(artifact_path, bundle)
        raise RuntimeError(f"offline_qwen_run_incomplete:{type(exc).__name__}") from None
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    _write_bundle(artifact_path, bundle)
    return bundle, artifact_path


def _write_model_unavailable_artifact(workspace: Path) -> Path:
    artifact_path = (
        workspace
        / "generated-artifacts/guardian-qwen-offline/"
        "qwen-policy-lab-email-database-blocked.json"
    )
    blocked = {
        "schemaVersion": 1,
        "status": "BLOCKED_MODEL_UNAVAILABLE",
        "evidenceClass": "blocked_not_inference",
        "source": "qwen_local_policy_lab_offline",
        "executionMode": "not_executed",
        "scope": {
            "profileCount": len(_EMAIL_DATABASE_PROFILE_ORDER),
            "selectedCaseCount": sum(
                len(_EMAIL_DATABASE_CASE_IDS[profile_id])
                for profile_id in _EMAIL_DATABASE_PROFILE_ORDER
            ),
            "fixturesIncluded": False,
        },
        "profiles": [
            {
                "profileId": profile_id,
                "status": "BLOCKED_MODEL_UNAVAILABLE",
                "liveInferenceCount": 0,
                "nativeToolCalls": None,
                "adaptedProposals": None,
                "abstentions": None,
                "fixtureBaseline": "separate_not_loaded",
            }
            for profile_id in _EMAIL_DATABASE_PROFILE_ORDER
        ],
        "integrationReadiness": {
            "hostBoundaryReady": False,
            "integratedAssessmentReady": False,
            "workerAdmission": "disabled",
        },
        "rawPromptsStored": False,
        "rawResponsesStored": False,
    }
    blocked["artifactSha256"] = _canonical_sha256(blocked)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    _write_bundle(artifact_path, blocked)
    return artifact_path


def run_offline_evaluation(workspace: Path) -> tuple[dict[str, Any], Path]:
    """Run the historical fixed eight-profile suite behind the integrated gate."""
    return _run_offline_profiles(
        workspace,
        profile_ids=_PROFILE_ORDER,
        selected_case_ids=_OFFLINE_CASE_IDS,
        artifact_name="qwen-policy-lab-eight-profiles.json",
        standalone_process_only=False,
    )


def run_offline_email_database_profile(
    workspace: Path,
    profile_id: str,
    *,
    case_timeout_seconds: int,
    profile_timeout_seconds: int,
) -> tuple[dict[str, Any], Path]:
    """Run one email/database profile in its own bounded child process."""
    if profile_id not in _EMAIL_DATABASE_PROFILE_ORDER:
        raise ValueError("offline_qwen_profile_not_allowlisted")
    _validate_offline_timeout_config(
        case_timeout_seconds=case_timeout_seconds,
        profile_timeout_seconds=profile_timeout_seconds,
        wall_timeout_seconds=profile_timeout_seconds,
    )
    suffix = "email" if profile_id == _PROFILE_ORDER[0] else "database"
    return _run_offline_profiles(
        workspace,
        profile_ids=(profile_id,),
        selected_case_ids={profile_id: _EMAIL_DATABASE_CASE_IDS[profile_id]},
        artifact_name=f"qwen-policy-lab-email-database-{suffix}-profile.json",
        standalone_process_only=True,
        case_timeout_seconds=case_timeout_seconds,
        profile_timeout_seconds=profile_timeout_seconds,
        max_completion_tokens=_OFFLINE_MAX_COMPLETION_TOKENS,
    )


def run_offline_email_database_evaluation(
    workspace: Path,
    *,
    case_timeout_seconds: int = _OFFLINE_CASE_TIMEOUT_DEFAULT_SECONDS,
    profile_timeout_seconds: int = _OFFLINE_PROFILE_TIMEOUT_DEFAULT_SECONDS,
    wall_timeout_seconds: int = _OFFLINE_WALL_TIMEOUT_DEFAULT_SECONDS,
) -> tuple[dict[str, Any], Path]:
    """Run email then database serially, hard-stopping and checkpointing each."""
    timeout_config = _validate_offline_timeout_config(
        case_timeout_seconds=case_timeout_seconds,
        profile_timeout_seconds=profile_timeout_seconds,
        wall_timeout_seconds=wall_timeout_seconds,
    )
    workspace = workspace.resolve()
    require_standalone_offline_environment()
    artifact_path = (
        workspace
        / "generated-artifacts/guardian-qwen-offline/"
        "qwen-policy-lab-email-database.json"
    )
    local_manifest, _wheel_manifest = _load_verified_manifests(workspace)
    manifest_path = (
        workspace / "workers/guardian-ai-assessment/local-llm-manifest.json"
    )
    model_path = (
        workspace
        / "generated-artifacts/guardian-llm-lab"
        / local_manifest["model"]["file"]
    )
    if (
        not model_path.is_file()
        or model_path.stat().st_size != local_manifest["model"]["sizeBytes"]
        or _sha256_file(model_path) != local_manifest["model"]["sha256"]
    ):
        raise RuntimeError("BLOCKED_MODEL_UNAVAILABLE")

    worker_root = workspace / "workers/guardian-ai-assessment"
    fixture_baselines = _fixture_baseline_comparison(
        workspace, _EMAIL_DATABASE_PROFILE_ORDER
    )
    source_hashes = _source_code_hashes(worker_root)
    model_record = {
        "id": local_manifest["model"]["id"],
        "revision": local_manifest["model"]["revision"],
        "file": local_manifest["model"]["file"],
        "sha256": local_manifest["model"]["sha256"],
        "sizeBytes": local_manifest["model"]["sizeBytes"],
        "quantization": local_manifest["model"]["quantization"],
        "runtime": local_manifest["runtime"]["name"],
        "runtimeVersion": local_manifest["runtime"]["version"],
        "runtimeWheelSha256": local_manifest["runtime"]["wheelSha256"],
        "manifestSha256": _sha256_file(manifest_path),
    }
    profile_records: list[dict[str, Any]] = [
        {
            "profileId": profile_id,
            "status": "pending",
            "completedCaseCount": 0,
            "completedInferenceCount": 0,
            "runtimeMessageToolCalls": None,
            "adaptedQwenMarkupCalls": None,
            "noProposal": None,
            "fixtureBaseline": fixture_baselines[profile_id],
        }
        for profile_id in _EMAIL_DATABASE_PROFILE_ORDER
    ]

    def checkpoint(status: str) -> dict[str, Any]:
        completed_evidence = [
            record["evidence"]
            for record in profile_records
            if isinstance(record.get("evidence"), dict)
        ]
        summary_keys = (
            "sampleCount",
            "benignCases",
            "adversarialCases",
            "modelCalls",
            "runtimeMessageToolCalls",
            "adaptedQwenMarkupCalls",
            "noToolCalls",
            "denied",
            "policyDenials",
            "adapterValidationBlocks",
            "simulatedExecutions",
            "unauthorizedExecutions",
            "policyOffExecutions",
            "externalCalls",
        )
        summary = {
            key: sum(
                int(evidence.get("summary", {}).get(key, 0))
                for evidence in completed_evidence
            )
            for key in summary_keys
        }
        bundle: dict[str, Any] = {
            "schemaVersion": 1,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "executionMode": "real_local_qwen_inference_offline_process_guard",
            "source": "qwen_local_policy_lab_offline",
            "scope": {
                "profilesInOrder": list(_EMAIL_DATABASE_PROFILE_ORDER),
                "selectedCasesPerProfile": {
                    profile_id: list(_EMAIL_DATABASE_CASE_IDS[profile_id])
                    for profile_id in _EMAIL_DATABASE_PROFILE_ORDER
                },
                "fixturesIncluded": False,
            },
            "model": model_record,
            "sourceCodeSha256": source_hashes,
            "timeoutConfig": {
                **timeout_config,
                "completionTokensPerCall": _OFFLINE_MAX_COMPLETION_TOKENS,
                "contextTokens": 1024,
                "concurrency": 1,
            },
            "profiles": profile_records,
            "summary": summary,
            "comparison": {
                "categoriesAreSeparate": True,
                "fixtureBaseline": {
                    "executionMode": "deterministic_fixture",
                    "proposalOrigin": "controlled_fixture_not_llm",
                    "profiles": fixture_baselines,
                },
                "qwenInference": {
                    "executionMode": "real_local_qwen_inference_offline_process_guard",
                    "profiles": [
                        record["profileId"] for record in profile_records
                    ],
                    "summary": summary,
                },
                "caseSetsAreIdentical": False,
            },
            "policy": {
                "policyOn": "independent synthetic policy before local simulator",
                "policyOff": "counterfactual clone only; no dispatch",
                "externalEffects": False,
                "apiJobCreated": False,
                "databasePersistence": False,
                "approvalInboxPersistence": False,
            },
            "integrationReadiness": {
                "hostBoundaryReady": False,
                "integratedAssessmentReady": False,
                "workerAdmission": "disabled",
                "reason": "standalone_process_lab_does_not_attest_host_boundary",
            },
            "evidenceStorage": {
                "rawPromptsStored": False,
                "rawResponsesStored": False,
                "rawToolArgumentsStored": False,
                "rawProcessOutputStored": False,
                "syntheticOnly": True,
            },
        }
        bundle["bundleSha256"] = _canonical_sha256(bundle)
        return bundle

    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    _write_bundle(artifact_path, checkpoint("in_progress"))
    wall_deadline = time.monotonic() + wall_timeout_seconds
    launcher = worker_root / "scripts/run_qwen_email_database_lab_offline.py"

    for record in profile_records:
        profile_id = record["profileId"]
        remaining_wall = wall_deadline - time.monotonic()
        if remaining_wall <= 0:
            record.update(
                {
                    "status": "skipped_overall_timeout",
                    "errorType": "TimeoutError",
                    "errorCode": "offline_qwen_overall_timeout",
                }
            )
            _write_bundle(artifact_path, checkpoint("incomplete"))
            continue

        profile_started = time.monotonic()
        child_timeout = min(profile_timeout_seconds, max(1, int(remaining_wall)))
        suffix = "email" if profile_id == _PROFILE_ORDER[0] else "database"
        child_artifact_path = (
            workspace
            / "generated-artifacts/guardian-qwen-offline"
            / f"qwen-policy-lab-email-database-{suffix}-profile.json"
        )
        progress_path = child_artifact_path.with_name(
            f"{child_artifact_path.stem}.progress.json"
        )
        child_env = {
            "HOME": str(workspace / "generated-artifacts/guardian-qwen-offline"),
            "TMPDIR": str(workspace / "generated-artifacts/guardian-qwen-offline"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
            "LANG": "C.UTF-8",
        }
        command = [
            sys.executable,
            str(launcher),
            "--profile-child",
            profile_id,
            "--case-timeout-seconds",
            str(case_timeout_seconds),
            "--profile-timeout-seconds",
            str(profile_timeout_seconds),
        ]
        timed_out: subprocess.TimeoutExpired | None = None
        completed: subprocess.CompletedProcess[str] | None = None
        try:
            completed = subprocess.run(
                command,
                cwd=workspace,
                env=child_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=child_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            timed_out = exc

        stdout_value = (
            timed_out.stdout
            if timed_out is not None
            else completed.stdout if completed is not None else None
        )
        stderr_value = (
            timed_out.stderr
            if timed_out is not None
            else completed.stderr if completed is not None else None
        )
        record["durationSeconds"] = round(time.monotonic() - profile_started, 3)
        record["timeoutSeconds"] = child_timeout
        record["processOutput"] = {
            "stdout": _stream_capture_record(stdout_value),
            "stderr": _stream_capture_record(stderr_value),
            "rawTextStored": False,
        }

        partial_progress = _read_progress_checkpoint(
            progress_path,
            expected_profile_id=profile_id,
        )
        if partial_progress is not None:
            record["partialCheckpoint"] = partial_progress
            record["completedCaseCount"] = int(
                partial_progress.get("completedCaseCount", 0)
            )
            record["completedInferenceCount"] = record["completedCaseCount"]

        child_bundle: dict[str, Any] | None = None
        if child_artifact_path.is_file():
            try:
                child_bundle = json.loads(
                    child_artifact_path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError):
                child_bundle = None
        if timed_out is not None:
            record.update(
                {
                    "status": "timed_out",
                    "errorType": "TimeoutExpired",
                    "errorCode": "offline_qwen_profile_timeout",
                }
            )
        elif (
            completed is not None
            and completed.returncode == 0
            and isinstance(child_bundle, dict)
            and child_bundle.get("status") == "completed"
            and len(child_bundle.get("profiles", [])) == 1
            and child_bundle["profiles"][0].get("profileId") == profile_id
        ):
            evidence = child_bundle["profiles"][0]
            record.update(
                {
                    "status": "completed",
                    "evidence": evidence,
                    "liveInferenceCount": evidence["summary"]["modelCalls"],
                    "completedInferenceCount": evidence["summary"]["modelCalls"],
                    "runtimeMessageToolCalls": evidence["summary"][
                        "runtimeMessageToolCalls"
                    ],
                    "adaptedQwenMarkupCalls": evidence["summary"][
                        "adaptedQwenMarkupCalls"
                    ],
                    "noProposal": evidence["summary"]["noToolCalls"],
                    "completedCaseCount": evidence["summary"]["sampleCount"],
                }
            )
        else:
            record.update(
                {
                    "status": "incomplete",
                    "errorType": (
                        child_bundle.get("errorType")
                        if isinstance(child_bundle, dict)
                        else "ProfileProcessError"
                    ),
                    "errorCode": (
                        "offline_qwen_profile_failed"
                        if completed is None or completed.returncode != 0
                        else "offline_qwen_profile_evidence_invalid"
                    ),
                }
            )
        _write_bundle(
            artifact_path,
            checkpoint(
                "completed"
                if all(item["status"] == "completed" for item in profile_records)
                else "in_progress"
            ),
        )

    final_status = (
        "completed"
        if all(record["status"] == "completed" for record in profile_records)
        else "incomplete"
    )
    bundle = checkpoint(final_status)
    _write_bundle(artifact_path, bundle)
    return bundle, artifact_path
