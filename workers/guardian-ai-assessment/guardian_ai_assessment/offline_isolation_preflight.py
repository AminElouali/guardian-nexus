"""Read-only, fail-closed preflight for local Qwen process isolation.

This reports observable properties of the current process. It does not create a
security boundary, connect to Docker/PostgreSQL, inspect credential values, or
claim that an API/broker deployment is isolated.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

_DOCKER_ENDPOINT_KEYS = ("DOCKER_HOST", "DOCKER_CONTEXT", "CONTAINER_HOST")
_CREDENTIAL_ENV_KEYS = (
    "DATABASE_URL",
    "API_DATABASE_URL",
    "WORKER_DATABASE_URL",
    "BROKER_DATABASE_URL",
    "ASSESSMENT_BROKER_DATABASE_URL",
    "APP_RUNTIME_DB_PASSWORD",
    "SESSION_SECRET",
    "CLERK_SECRET_KEY",
)


def _current_identity() -> dict[str, Any]:
    if not all(hasattr(os, name) for name in ("geteuid", "getegid", "getgroups")):
        raise RuntimeError("offline_effective_identity_unavailable")
    return {
        "uid": int(os.geteuid()),
        "gid": int(os.getegid()),
        "groups": sorted({int(group) for group in os.getgroups()} | {int(os.getegid())}),
    }


def _validate_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    uid = identity.get("uid")
    gid = identity.get("gid")
    groups = identity.get("groups")
    if (
        not isinstance(uid, int)
        or isinstance(uid, bool)
        or uid < 0
        or not isinstance(gid, int)
        or isinstance(gid, bool)
        or gid < 0
        or not isinstance(groups, (list, tuple, set))
        or any(not isinstance(group, int) or isinstance(group, bool) or group < 0 for group in groups)
    ):
        raise RuntimeError("offline_effective_identity_unverified")
    return {"uid": uid, "gid": gid, "groups": sorted(set(groups) | {gid})}


def _known_docker_sockets(uid: int) -> tuple[Path, ...]:
    return (
        Path("/var/run/docker.sock"),
        Path("/run/docker.sock"),
        Path(f"/run/user/{uid}/docker.sock"),
    )


def _inspect_socket(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"path": str(path), "status": "absent"}
    except OSError:
        return {"path": str(path), "status": "unverified"}

    if not stat.S_ISSOCK(metadata.st_mode):
        return {"path": str(path), "status": "unverified"}
    if os.access not in os.supports_effective_ids:
        return {"path": str(path), "status": "unverified"}
    try:
        readable = os.access(path, os.R_OK, effective_ids=True, follow_symlinks=False)
        writable = os.access(path, os.W_OK, effective_ids=True, follow_symlinks=False)
    except (OSError, NotImplementedError, TypeError):
        return {"path": str(path), "status": "unverified"}
    return {
        "path": str(path),
        "status": "accessible" if readable or writable else "inaccessible",
        "readable": bool(readable),
        "writable": bool(writable),
        "checkedAs": "current_effective_uid_and_groups",
        "connected": False,
    }


def _inherited_socket_fds() -> dict[str, Any]:
    fd_directory = Path("/proc/self/fd")
    if not fd_directory.is_dir():
        return {"status": "unverified", "count": None}
    count = 0
    try:
        names = tuple(fd_directory.iterdir())
        for descriptor in names:
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            except OSError:
                return {"status": "unverified", "count": None}
            if target.startswith("socket:["):
                count += 1
    except OSError:
        return {"status": "unverified", "count": None}
    return {"status": "present" if count else "clear", "count": count}


def collect_offline_isolation_preflight(
    *,
    environment: Mapping[str, str] | None = None,
    socket_paths: Sequence[Path] | None = None,
    identity: Mapping[str, Any] | None = None,
    inherited_socket_fds: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect local metadata only; environment values are never read or returned."""
    env = os.environ if environment is None else environment
    try:
        effective_identity = _validate_identity(
            _current_identity() if identity is None else identity
        )
    except RuntimeError as exc:
        effective_identity = {"uid": None, "gid": None, "groups": []}
        identity_error = str(exc)
    else:
        identity_error = None

    # Membership checks inspect variable names only. Secret/config values are
    # deliberately not retrieved, compared, hashed, or printed.
    configured_endpoint = any(name in env for name in _DOCKER_ENDPOINT_KEYS)
    credential_names_present = sum(name in env for name in _CREDENTIAL_ENV_KEYS)
    candidate_sockets = (
        tuple(dict.fromkeys(socket_paths))
        if socket_paths is not None
        else _known_docker_sockets(effective_identity["uid"])
        if effective_identity["uid"] is not None
        else ()
    )
    socket_checks = [_inspect_socket(path) for path in candidate_sockets]
    inherited = (
        dict(inherited_socket_fds)
        if inherited_socket_fds is not None
        else _inherited_socket_fds()
    )

    reasons: list[str] = []
    if identity_error:
        reasons.append(identity_error)
    if effective_identity["uid"] == 0:
        reasons.append("offline_runner_root_identity")
    if configured_endpoint:
        reasons.append("offline_docker_endpoint_configured")
    if any(item["status"] == "accessible" for item in socket_checks):
        reasons.append("offline_docker_socket_accessible")
    if any(item["status"] == "unverified" for item in socket_checks):
        reasons.append("offline_docker_socket_unverified")
    if not candidate_sockets:
        reasons.append("offline_docker_socket_candidates_unavailable")
    if credential_names_present:
        reasons.append("offline_sensitive_environment_present")
    if inherited.get("status") == "present":
        reasons.append("offline_inherited_socket_fd_present")
    elif inherited.get("status") != "clear":
        reasons.append("offline_inherited_socket_fd_unverified")

    process_ready = not reasons
    host_boundary_reasons = [
        "assessment_broker_identity_unverified",
        "assessment_database_session_identity_unverified",
    ]
    # This process-only check cannot attest how the API, broker, or their live
    # PostgreSQL sessions are isolated. Keep that boundary unknown until a
    # host-level verifier is integrated; absence of an observation is not a pass.
    api_worker_boundary_ready = False
    return {
        "schemaVersion": 1,
        "mode": "read_only_local_metadata",
        "offlineQwenProcessReady": process_ready,
        "reasonCodes": reasons,
        "effectiveIdentity": effective_identity,
        "dockerEndpointConfigured": configured_endpoint,
        "dockerSocketChecks": socket_checks,
        "inheritedSocketFds": inherited,
        "databaseCredentialEnvironmentPresent": bool(credential_names_present),
        "databaseCredentialVariableCount": credential_names_present,
        "credentialValuesRead": False,
        "brokerIdentity": {
            "status": "unverified",
            "reasonCode": "assessment_broker_identity_not_attested",
        },
        "apiWorkerDatabaseIdentity": {
            "status": "unverified",
            "reasonCode": "assessment_database_session_identity_unverified",
            "databaseConnectionsMade": 0,
            "credentialValuesRead": False,
        },
        "apiWorkerBoundaryReasonCodes": host_boundary_reasons,
        "apiWorkerBoundaryReady": api_worker_boundary_ready,
        "integratedAssessmentReady": process_ready and api_worker_boundary_ready,
        "externalConnectionsMade": 0,
    }


def require_offline_qwen_process_ready(
    *,
    environment: Mapping[str, str] | None = None,
    socket_paths: Sequence[Path] | None = None,
) -> dict[str, Any]:
    """Block Qwen unless process isolation and host boundaries are attested."""
    report = collect_offline_isolation_preflight(
        environment=environment,
        socket_paths=socket_paths,
    )
    if not report["offlineQwenProcessReady"]:
        raise RuntimeError(report["reasonCodes"][0])
    from .host_boundary_attestation import (
        HostBoundaryAttestationError,
        require_host_boundary_attestation,
    )

    try:
        attestation = require_host_boundary_attestation()
    except HostBoundaryAttestationError as exc:
        raise RuntimeError(str(exc)) from None
    report["hostBoundaryReady"] = True
    report["apiWorkerBoundaryReady"] = True
    report["apiWorkerBoundaryReasonCodes"] = []
    report["integratedAssessmentReady"] = True
    report["hostBoundaryAttestation"] = attestation
    return report
