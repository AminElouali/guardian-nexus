"""Fail-closed, read-only host-preflight evaluator for the future isolated lab.

The evaluator accepts only metadata observations. It never reads secret values,
opens the Docker socket, connects to PostgreSQL, launches a model, or authorizes
tool actions. The live collector in Replit intentionally cannot establish the
external API/broker/database boundary and therefore remains blocked.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

SENSITIVE_ENV_KEYS = (
    "DATABASE_URL",
    "API_DATABASE_URL",
    "WORKER_DATABASE_URL",
    "BROKER_DATABASE_URL",
    "ASSESSMENT_BROKER_DATABASE_URL",
    "APP_RUNTIME_DB_PASSWORD",
    "SESSION_SECRET",
    "CLERK_SECRET_KEY",
)
ROLE_USERS = {
    "api": "guardian-api",
    "worker": "guardian-worker",
    "broker": "guardian-broker",
}
DOCKER_SOCKET_GROUP = "guardian-docker-broker"
EXPECTED_DB_ROLES = {
    "api": "guardian_api_login",
    "worker": "guardian_worker_login",
    "broker": "guardian_broker_login",
}
EXPECTED_DATABASE = "guardian_nexus"
PG_SERVICE_FILE = "/etc/guardian-nexus/pg_service.conf"
_ROLE_KEYS = {"api", "worker", "broker"}


def _sha256_json(value: Any) -> str:
    import hashlib

    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def evaluate_lab_host_observations(
    observations: Mapping[str, Any],
    *,
    observation_origin: str,
) -> dict[str, Any]:
    """Evaluate normalized host facts; only the live collector is live evidence.

    Mocked test facts can exercise the evaluator but can never open the
    executable gate. The function returns summary data only, not input values.
    """
    reasons: list[str] = []
    host = observations.get("host")
    if not isinstance(host, Mapping):
        host = {}
    if host.get("osId") != "ubuntu" or host.get("versionId") != "24.04":
        reasons.append("lab_host_not_ubuntu_2404")
    if host.get("systemd") is not True:
        reasons.append("lab_host_systemd_unverified")
    if host.get("container") is not False:
        reasons.append("lab_host_container_or_virtualization_unverified")

    identities = observations.get("identities")
    identity_summary: dict[str, Any] = {}
    if not isinstance(identities, Mapping) or set(identities) != _ROLE_KEYS:
        reasons.append("lab_service_identities_incomplete")
        identities = {}
    uid_values: list[int] = []
    gid_values: list[int] = []
    for role in sorted(_ROLE_KEYS):
        identity = identities.get(role)
        if not isinstance(identity, Mapping):
            reasons.append(f"lab_{role}_identity_unverified")
            identity_summary[role] = {"status": "unverified"}
            continue
        uid, gid, groups = identity.get("uid"), identity.get("gid"), identity.get("groups")
        if (
            not isinstance(uid, int)
            or isinstance(uid, bool)
            or uid <= 0
            or not isinstance(gid, int)
            or isinstance(gid, bool)
            or gid <= 0
            or not isinstance(groups, (list, tuple, set))
            or any(not isinstance(group, int) or isinstance(group, bool) or group < 0 for group in groups)
        ):
            reasons.append(f"lab_{role}_identity_invalid")
            identity_summary[role] = {"status": "invalid"}
            continue
        uid_values.append(uid)
        gid_values.append(gid)
        identity_summary[role] = {
            "status": "verified",
            "uid": uid,
            "gid": gid,
            "supplementaryGroupCount": len(set(groups) | {gid}),
        }
    if len(uid_values) == 3 and len(set(uid_values)) != 3:
        reasons.append("lab_service_uids_not_distinct")
    if len(gid_values) == 3 and len(set(gid_values)) != 3:
        reasons.append("lab_service_gids_not_distinct")

    socket = observations.get("dockerSocket")
    if not isinstance(socket, Mapping):
        socket = {}
    if (
        socket.get("status") != "verified"
        or socket.get("ownerUid") != 0
        or socket.get("groupName") != DOCKER_SOCKET_GROUP
        or socket.get("mode") != 0o660
        or socket.get("aclChecked") is not True
    ):
        reasons.append("lab_docker_socket_permissions_unverified")
    access = socket.get("accessByRole")
    if not isinstance(access, Mapping):
        access = {}
    for role in ("api", "worker"):
        role_access = access.get(role)
        if (
            not isinstance(role_access, Mapping)
            or role_access.get("read") is not False
            or role_access.get("write") is not False
        ):
            reasons.append(f"lab_docker_socket_access_not_denied_{role}")
    broker_access = access.get("broker")
    if (
        not isinstance(broker_access, Mapping)
        or broker_access.get("read") is not True
        or broker_access.get("write") is not True
    ):
        reasons.append("lab_docker_socket_broker_access_unverified")

    env_count = observations.get("sensitiveEnvironmentNameCount")
    if not isinstance(env_count, int) or isinstance(env_count, bool) or env_count < 0:
        reasons.append("lab_sensitive_environment_presence_unverified")
        env_count = None
    elif env_count:
        reasons.append("lab_sensitive_environment_present")

    database = observations.get("databaseSessions")
    database_ok = isinstance(database, Mapping) and set(database) == _ROLE_KEYS
    seen_db_roles: list[str] = []
    if not database_ok:
        reasons.append("lab_database_sessions_unverified")
        database = {}
    for role in sorted(_ROLE_KEYS):
        session = database.get(role)
        expected = EXPECTED_DB_ROLES[role]
        if not isinstance(session, Mapping):
            reasons.append(f"lab_{role}_database_session_unverified")
            continue
        if session.get("databaseName") != EXPECTED_DATABASE:
            reasons.append(f"lab_{role}_database_name_mismatch")
        current_user = session.get("currentUser")
        session_user = session.get("sessionUser")
        if session.get("status") != "verified" or current_user != expected or session_user != expected:
            reasons.append(f"lab_{role}_database_role_mismatch")
            continue
        if session.get("readOnly") is not True:
            reasons.append(f"lab_{role}_database_probe_not_read_only")
        if any(
            session.get(flag) is not False
            for flag in ("superuser", "bypassRls", "createRole", "createDatabase")
        ):
            reasons.append(f"lab_{role}_database_privilege_excess")
        seen_db_roles.append(str(current_user))
    if len(seen_db_roles) == 3 and len(set(seen_db_roles)) != 3:
        reasons.append("lab_database_roles_not_distinct")

    child = observations.get("qwenChildProbe")
    if not isinstance(child, Mapping):
        child = {}
    worker_identity = identities.get("worker") if isinstance(identities, Mapping) else None
    worker_uid = worker_identity.get("uid") if isinstance(worker_identity, Mapping) else None
    if (
        child.get("status") != "verified"
        or child.get("probeType") != "non_model_identity_probe"
        or child.get("uid") != worker_uid
        or child.get("dockerSocketAccessible") is not False
        or child.get("inheritedSocketFdCount") != 0
        or child.get("sensitiveEnvironmentNameCount") != 0
    ):
        reasons.append("lab_qwen_child_boundary_unverified")

    conditions_pass = not reasons
    is_live = observation_origin == "live_host_probe"
    sandbox = observations.get("qwenSandbox")
    qwen_sandbox_verified = isinstance(sandbox, Mapping) and all(
        sandbox.get(name) is True
        for name in (
            "networkNone",
            "readOnlyRoot",
            "capDropAll",
            "noNewPrivileges",
            "seccompVerified",
            "dockerSocketNotMounted",
            "imageIdPinned",
        )
    )
    socket_summary = (
        {
            key: socket.get(key)
            for key in (
                "status",
                "ownerUid",
                "groupName",
                "mode",
                "aclChecked",
                "currentProbeProcessAccess",
                "accessByRole",
            )
        }
        if isinstance((socket := observations.get("dockerSocket")), Mapping)
        else None
    )
    database_summary = {
        role: {
            key: session.get(key)
            for key in (
                "status",
                "databaseName",
                "sessionUser",
                "currentUser",
                "superuser",
                "bypassRls",
                "createRole",
                "createDatabase",
                "readOnly",
            )
        }
        for role, session in database.items()
        if isinstance(session, Mapping)
    }
    child_summary = (
        {
            key: child.get(key)
            for key in (
                "status",
                "probeType",
                "uid",
                "dockerSocketAccessible",
                "inheritedSocketFdCount",
                "sensitiveEnvironmentNameCount",
            )
        }
        if isinstance((child := observations.get("qwenChildProbe")), Mapping)
        else None
    )
    return {
        "schemaVersion": 1,
        "mode": "read_only_host_preflight",
        "observationOrigin": observation_origin,
        "evidenceClass": "live_metadata" if is_live else "synthetic_or_injected",
        "hostConditionsPassed": conditions_pass,
        "hostBoundaryReady": conditions_pass and is_live,
        "integratedAssessmentReady": conditions_pass and is_live and qwen_sandbox_verified,
        "runtimeQwenGuardStillRequired": True,
        "executionStarted": False,
        "qwenInferenceRun": False,
        "dockerCallsMade": 0,
        "databaseConnectionsMade": 0,
        "externalConnectionsMade": 0,
        "credentialValuesRead": False,
        "sensitiveEnvironmentNameCount": env_count,
        "identities": identity_summary,
        "dockerSocket": socket_summary,
        "currentProbeProcessSocketAccess": (
            socket_summary.get("currentProbeProcessAccess")
            if isinstance(socket_summary, Mapping)
            else None
        ),
        "dockerSocketAccessByRole": (
            socket_summary.get("accessByRole", {})
            if isinstance(socket_summary, Mapping)
            else {}
        ),
        "databaseRoleSeparationVerified": len(seen_db_roles) == 3 and len(set(seen_db_roles)) == 3,
        "databaseSessions": database_summary,
        "childIdentityProbeVerified": not any(
            reason == "lab_qwen_child_boundary_unverified" for reason in reasons
        ),
        "childIdentityProbe": child_summary,
        "qwenSandboxContractVerified": qwen_sandbox_verified,
        "runtimeGateReasonCodes": (
            [] if qwen_sandbox_verified else ["lab_qwen_sandbox_contract_unverified"]
        ),
        "reasonCodes": sorted(set(reasons)),
        "evidenceSha256": _sha256_json(
            {
                "observationOrigin": observation_origin,
                "hostConditionsPassed": conditions_pass,
                "reasonCodes": sorted(set(reasons)),
                "identities": identity_summary,
                "dockerSocket": socket_summary,
                "databaseSessions": database_summary,
                "childIdentityProbe": child_summary,
                "databaseRoleSeparationVerified": len(seen_db_roles) == 3
                and len(set(seen_db_roles)) == 3,
            }
        ),
        "interpretation": (
            "Este preflight solo mide condiciones de preparación. No crea una frontera, "
            "no ejecuta Qwen/Docker y no decide autorizaciones de herramientas. "
            "Una evaluación con observaciones sintéticas nunca abre el gate."
        ),
    }


def collect_local_read_only_observations() -> dict[str, Any]:
    """Collect current-process metadata without opening sockets or connecting to DB."""
    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"ID", "VERSION_ID"}:
                os_release[key] = value.strip().strip('"')
    except OSError:
        pass
    host = {
        "osId": os_release.get("ID"),
        "versionId": os_release.get("VERSION_ID"),
        "systemd": Path("/run/systemd/system").exists(),
        "container": Path("/run/systemd/container").exists(),
    }

    identities: dict[str, Any] = {}
    for role, username in ROLE_USERS.items():
        try:
            account = pwd.getpwnam(username)
            groups = sorted(set(os.getgrouplist(username, account.pw_gid)))
            identities[role] = {
                "uid": int(account.pw_uid),
                "gid": int(account.pw_gid),
                "groups": groups,
            }
        except (KeyError, OSError, OverflowError):
            identities[role] = None

    socket_candidates = (Path("/run/docker.sock"), Path("/var/run/docker.sock"))
    socket_observation: dict[str, Any] = {
        "status": "unverified",
        "aclChecked": False,
        "accessByRole": {},
        "currentProbeProcessAccess": None,
    }
    for path in dict.fromkeys(socket_candidates):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            break
        if not stat.S_ISSOCK(metadata.st_mode):
            break
        try:
            group_name = grp.getgrgid(metadata.st_gid).gr_name
        except KeyError:
            group_name = None
        socket_observation.update(
            {
                "status": "present",
                "ownerUid": int(metadata.st_uid),
                "groupName": group_name,
                "mode": stat.S_IMODE(metadata.st_mode),
                "path": str(path),
                "currentProbeProcessAccess": {
                    "read": os.access(str(path), os.R_OK, effective_ids=True),
                    "write": os.access(str(path), os.W_OK, effective_ids=True),
                },
            }
        )
        break

    sensitive_name_count = sum(name in os.environ for name in SENSITIVE_ENV_KEYS)
    return {
        "host": host,
        "identities": identities,
        "dockerSocket": socket_observation,
        "sensitiveEnvironmentNameCount": sensitive_name_count,
        "databaseSessions": None,
        "qwenChildProbe": None,
        # The container/runtime guard is checked separately by the existing
        # offline process guard; this host-only probe never starts a container.
        "qwenSandbox": None,
    }


def _run_identity_access_probe(username: str, socket_path: str) -> dict[str, bool] | None:
    """Run a tiny local `os.access` probe as a service account; never connects."""
    code = (
        "import json,os,sys; p=sys.argv[1]; "
        "print(json.dumps({'read':os.access(p,os.R_OK,effective_ids=True),"
        "'write':os.access(p,os.W_OK,effective_ids=True)}))"
    )
    try:
        completed = subprocess.run(
            [
                "runuser",
                "--user",
                username,
                "--",
                "env",
                "-i",
                "PATH=/usr/bin:/bin",
                sys.executable,
                "-I",
                "-S",
                "-c",
                code,
                socket_path,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            close_fds=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        result = json.loads(completed.stdout) if completed.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    if (
        not isinstance(result, dict)
        or set(result) != {"read", "write"}
        or not isinstance(result.get("read"), bool)
        or not isinstance(result.get("write"), bool)
    ):
        return None
    return result


def _probe_child_worker_identity(socket_path: str) -> dict[str, Any] | None:
    """Probe a worker-UID child with an empty environment; this is not Qwen."""
    code = r"""
import json, os, sys
paths = sys.argv[1:]
count = 0
try:
    for entry in os.scandir("/proc/self/fd"):
        try:
            if os.readlink(entry.path).startswith("socket:["):
                count += 1
        except OSError:
            pass
except OSError:
    count = -1
socket_accessible = any(
    os.access(path, os.R_OK, effective_ids=True)
    or os.access(path, os.W_OK, effective_ids=True)
    for path in paths
)
print(json.dumps({
    "uid": os.geteuid(),
    "gid": os.getegid(),
    "groups": sorted(set(os.getgroups()) | {os.getegid()}),
    "dockerSocketAccessible": socket_accessible,
    "inheritedSocketFdCount": count,
    "sensitiveEnvironmentNameCount": 0,
}))
"""
    try:
        completed = subprocess.run(
            [
                "runuser",
                "--user",
                ROLE_USERS["worker"],
                "--",
                "env",
                "-i",
                "PATH=/usr/bin:/bin",
                sys.executable,
                "-I",
                "-S",
                "-c",
                code,
                socket_path,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            close_fds=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        result = json.loads(completed.stdout) if completed.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    if not isinstance(result, dict):
        return None
    return {
        "status": "verified",
        "probeType": "non_model_identity_probe",
        "uid": result.get("uid"),
        "dockerSocketAccessible": result.get("dockerSocketAccessible"),
        "inheritedSocketFdCount": result.get("inheritedSocketFdCount"),
        "sensitiveEnvironmentNameCount": result.get("sensitiveEnvironmentNameCount"),
    }


def _probe_database_sessions() -> dict[str, dict[str, Any]] | None:
    """Open read-only peer-auth probes under each service UID; never print errors."""
    if shutil.which("psql") is None or shutil.which("runuser") is None:
        return None
    query = (
        "SELECT current_database(),session_user,current_user,"
        "CASE WHEN rolsuper THEN 't' ELSE 'f' END,"
        "CASE WHEN rolbypassrls THEN 't' ELSE 'f' END,"
        "CASE WHEN rolcreaterole THEN 't' ELSE 'f' END,"
        "CASE WHEN rolcreatedb THEN 't' ELSE 'f' END,"
        "current_setting('transaction_read_only') "
        "FROM pg_roles WHERE rolname=current_user"
    )
    results: dict[str, dict[str, Any]] = {}
    for role, username in ROLE_USERS.items():
        service_name = f"guardian_{role}"
        expected = EXPECTED_DB_ROLES[role]
        try:
            completed = subprocess.run(
                [
                    "runuser",
                    "--user",
                    username,
                    "--",
                    "env",
                    "-i",
                    "PATH=/usr/bin:/bin",
                    f"PGSERVICEFILE={PG_SERVICE_FILE}",
                    "PGOPTIONS=-c default_transaction_read_only=on",
                    "psql",
                    "-X",
                    "-A",
                    "-t",
                    "-F",
                    "|",
                    "-v",
                    "ON_ERROR_STOP=1",
                    f"service={service_name}",
                    "-c",
                    query,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                close_fds=True,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
            fields = completed.stdout.strip().split("|")
        except (OSError, subprocess.TimeoutExpired):
            results[role] = {"status": "unverified"}
            continue
        if completed.returncode != 0 or len(fields) != 8:
            results[role] = {"status": "unverified"}
            continue
        database_name, session_user, current_user, superuser, bypass_rls, create_role, create_db, read_only = fields
        results[role] = {
            "status": "verified" if session_user == expected and current_user == expected else "mismatch",
            "databaseName": database_name,
            "sessionUser": session_user,
            "currentUser": current_user,
            "superuser": superuser == "t",
            "bypassRls": bypass_rls == "t",
            "createRole": create_role == "t",
            "createDatabase": create_db == "t",
            "readOnly": read_only == "on",
        }
    return results


def _socket_acl_is_minimal(socket_path: str) -> bool:
    if shutil.which("getfacl") is None:
        return False
    try:
        completed = subprocess.run(
            ["getfacl", "--omit-header", "--absolute-names", socket_path],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
            close_fds=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if completed.returncode != 0:
        return False
    allowed_entries = {
        "user::rw-",
        "group::rw-",
        "mask::rw-",
        "other::---",
    }
    entries = {
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    return bool(entries) and entries.issubset(allowed_entries)


def collect_local_preflight_report(
    *,
    probe_database: bool = False,
    probe_worker_child: bool = False,
) -> dict[str, Any]:
    """Collect live metadata; optional probes are read-only and host-gated.

    `probe_database` is intentionally opt-in and uses only the three named
    libpq service profiles in the external lab. It is not run by default and
    must not be used on the Replit workspace. This function never prints or
    returns connection strings or password-file contents.
    """
    observations = collect_local_read_only_observations()
    host = observations["host"]
    safe_host = (
        host.get("osId") == "ubuntu"
        and host.get("versionId") == "24.04"
        and host.get("systemd") is True
        and host.get("container") is False
    )
    identities = observations["identities"]
    identities_present = all(
        isinstance(identities.get(role), Mapping) for role in _ROLE_KEYS
    )
    if (
        (probe_database or probe_worker_child)
        and safe_host
        and identities_present
        and os.geteuid() == 0
        and observations["sensitiveEnvironmentNameCount"] == 0
    ):
        socket = observations["dockerSocket"]
        if socket.get("status") == "present" and isinstance(socket.get("path"), str):
            access: dict[str, Any] = {}
            for role, username in ROLE_USERS.items():
                access[role] = _run_identity_access_probe(username, socket["path"])
            acl_checked = _socket_acl_is_minimal(socket["path"])
            socket.update(
                {
                    "status": (
                        "verified"
                        if all(isinstance(value, dict) for value in access.values())
                        and acl_checked
                        else "unverified"
                    ),
                    "aclChecked": acl_checked,
                    "accessByRole": access,
                }
            )
            if probe_worker_child and access.get("worker") == {"read": False, "write": False}:
                observations["qwenChildProbe"] = _probe_child_worker_identity(socket["path"])
        if probe_database:
            observations["databaseSessions"] = _probe_database_sessions()
    return evaluate_lab_host_observations(
        observations,
        observation_origin="live_host_probe",
    )
