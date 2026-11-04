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
import sys
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

_LOCAL_LLM_MANIFEST_SHA256 = (
    "460c4adc89b053a59ae8429d392ebec9f5654a88b31318d3b73f4a9dbaca3f9f"
)
_WHEELHOUSE_MANIFEST_SHA256 = (
    "ab8bc155558cc91e79a5a2f638b64dc0f0645bad29b42cc28bc521a1e37ebc79"
)
_MAX_EXTRACTED_WHEEL_BYTES = 512 * 1024 * 1024
_WALL_TIMEOUT_SECONDS = 900
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
) -> dict[str, Any]:
    from .offline_process_guard import offline_limit_evidence, offline_network_evidence

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
        "status": status,
        "executionMode": "real_local_qwen_inference_offline_process_guard",
        "source": "qwen_local_policy_lab_offline",
        "scope": {
            "profileCount": len(_PROFILE_ORDER),
            "selectedCasesPerProfile": len(next(iter(_OFFLINE_CASE_IDS.values()))),
            "selectedCaseCount": sum(
                len(case_ids) for case_ids in _OFFLINE_CASE_IDS.values()
            ),
            "fullCorpusCaseCount": full_corpus_case_count,
            "fullCorpusCompleted": False,
            "fixturesIncluded": False,
            "selection": "fixed_one_case_per_profile_with_mixed_labels",
            "previousFullCorpusAttempt": {
                "status": "incomplete",
                "errorType": "TimeoutError",
                "completedProfiles": 0,
                "completedCases": 0,
                "artifactSha256": _FAILED_FULL_RUN_SHA256,
            },
            "previous16CaseAttempt": {
                "status": "incomplete",
                "errorType": "TimeoutError",
                "completedProfiles": 0,
                "completedCases": 0,
                "artifactSha256": _FAILED_16_CASE_RUN_SHA256,
            },
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
    if error_type:
        bundle["errorType"] = error_type
    bundle["bundleSha256"] = _canonical_sha256(bundle)
    return bundle


def run_offline_evaluation(workspace: Path) -> tuple[dict[str, Any], Path]:
    """Verify local artifacts, install a syscall guard, then run all eight profiles."""
    workspace = workspace.resolve()
    artifact_path = workspace / (
        "generated-artifacts/guardian-qwen-offline/"
        "qwen-policy-lab-eight-profiles.json"
    )
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    local_manifest, wheel_manifest = _load_verified_manifests(workspace)
    manifest_path = workspace / "workers/guardian-ai-assessment/local-llm-manifest.json"
    manifest_hash = _sha256_file(manifest_path)
    model_path = (
        workspace
        / "generated-artifacts/guardian-llm-lab"
        / local_manifest["model"]["file"]
    )
    if not model_path.is_file():
        raise RuntimeError("offline_qwen_model_missing")
    if model_path.stat().st_size != local_manifest["model"]["sizeBytes"]:
        raise RuntimeError("offline_qwen_model_size_mismatch")
    if _sha256_file(model_path) != local_manifest["model"]["sha256"]:
        raise RuntimeError("offline_qwen_model_hash_mismatch")

    worker_root = workspace / "workers/guardian-ai-assessment"
    source_code_hashes = {
        "offlineRunner": _sha256_file(Path(__file__)),
        "offlineProcessGuard": _sha256_file(
            worker_root / "guardian_ai_assessment/offline_process_guard.py"
        ),
        "qwenPolicyLab": _sha256_file(
            worker_root / "guardian_ai_assessment/qwen_policy_lab.py"
        ),
    }
    wheel_records = _runtime_wheels(workspace, local_manifest, wheel_manifest)
    completed_profiles: list[dict[str, Any]] = []
    process_guard: object | None = None
    full_corpus_case_count: int | None = None
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
            full_corpus_case_count = sum(qwen_lab.CASE_LIMITS.values())
            model_client = model_client_cls(model_path)

            signal.signal(signal.SIGALRM, _deadline)
            signal.signal(signal.SIGXCPU, _deadline)
            signal.setitimer(signal.ITIMER_REAL, _WALL_TIMEOUT_SECONDS)
            for profile_id in _PROFILE_ORDER:
                profile_evidence = qwen_lab.run_qwen_policy_lab(
                    profile_id,
                    offline_guard=process_guard,
                    model_path=model_path,
                    shared_client=model_client,
                    case_ids=_OFFLINE_CASE_IDS[profile_id],
                )
                if (
                    profile_evidence.get("executionMode")
                    != "real_local_qwen_inference_offline_process_guard"
                    or profile_evidence.get("provider", {}).get("toolChoice") != "auto"
                    or profile_evidence.get("summary", {}).get("modelCalls")
                    != profile_evidence.get("summary", {}).get("sampleCount")
                    or profile_evidence.get("corpusSelection", {}).get("mode")
                    != "fixed_single_case_offline"
                    or profile_evidence.get("corpusSelection", {}).get("selectedCaseIds")
                    != list(_OFFLINE_CASE_IDS[profile_id])
                    or profile_evidence.get("summary", {}).get("sampleCount") != 1
                    or profile_evidence.get("summary", {}).get("runtimeMessageToolCalls", 0)
                    + profile_evidence.get("summary", {}).get("adaptedQwenMarkupCalls", 0)
                    + profile_evidence.get("summary", {}).get("noToolCalls", 0)
                    != profile_evidence.get("summary", {}).get("sampleCount")
                    or not all(profile_evidence.get("selfChecks", {}).values())
                ):
                    raise RuntimeError("offline_qwen_profile_evidence_invalid")
                completed_profiles.append(profile_evidence)
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
            )
    except Exception as exc:
        if process_guard is None:
            raise RuntimeError("offline_qwen_guard_or_runtime_setup_failed") from None
        bundle = _build_bundle(
            local_manifest=local_manifest,
            manifest_hash=manifest_hash,
            verified_wheels=verified_wheels if "verified_wheels" in locals() else [],
            process_guard=process_guard,
            profiles=completed_profiles,
            status="incomplete",
            full_corpus_case_count=full_corpus_case_count,
            source_code_hashes=source_code_hashes,
            error_type=type(exc).__name__,
        )
        _write_bundle(artifact_path, bundle)
        raise RuntimeError(f"offline_qwen_run_incomplete:{type(exc).__name__}") from None
    _write_bundle(artifact_path, bundle)
    return bundle, artifact_path
