"""Verify the independently issued host boundary before any Qwen inference.

The attestation is provisioned out-of-band by the lab host owner. Its Ed25519
signing key is trusted only from a root-owned, non-writable path; this module
never reads private keys, environment-variable values, sockets, or databases.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

DEFAULT_ATTESTATION_PATH = Path(
    "/run/guardian-nexus/host-boundary-attestation.json"
)
DEFAULT_PUBLIC_KEY_PATH = Path(
    "/etc/guardian-nexus/host-boundary-attestor-ed25519.pem"
)
MAX_ATTESTATION_BYTES = 32 * 1024
MAX_ATTESTATION_AGE = timedelta(hours=24)
MAX_FUTURE_SKEW = timedelta(minutes=5)
_HEX_SHA256 = set("0123456789abcdef")
_SOURCE_FILES = {
    "attestationVerifier": "guardian_ai_assessment/host_boundary_attestation.py",
    "autonomousToolSelection": "guardian_ai_assessment/autonomous_tool_selection.py",
    "llmLab": "guardian_ai_assessment/llm_lab.py",
    "networkPreflight": "guardian_ai_assessment/__main__.py",
    "offlineIsolationPreflight": "guardian_ai_assessment/offline_isolation_preflight.py",
    "offlineProcessGuard": "guardian_ai_assessment/offline_process_guard.py",
    "offlineQwenRunner": "guardian_ai_assessment/offline_qwen_runner.py",
    "offlineQwenLauncher": "scripts/run_qwen_policy_lab_offline.py",
    "qwenPolicyLab": "guardian_ai_assessment/qwen_policy_lab.py",
}
_SERVICE_NAMES = ("api", "broker", "worker")
_SANDBOX_REQUIREMENTS = (
    "networkNone",
    "readOnlyRoot",
    "capDropAll",
    "noNewPrivileges",
    "seccompVerified",
    "dockerSocketNotMounted",
    "imageIdPinned",
)


class HostBoundaryAttestationError(RuntimeError):
    """A stable, non-sensitive failure from host-attestation verification."""


def _raise(reason: str) -> None:
    raise HostBoundaryAttestationError(reason)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _raise("assessment_host_attestation_duplicate_key")
        result[key] = value
    return result


def _verify_root_owned_directory_chain(path: Path) -> None:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            _raise("assessment_host_attestation_directory_unavailable")
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            _raise("assessment_host_attestation_directory_untrusted")
        if current.parent == current:
            return
        current = current.parent


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _raise("assessment_host_attestation_payload_invalid")


def _read_root_owned_file(path: Path, *, max_bytes: int) -> bytes:
    try:
        before = path.lstat()
    except OSError:
        _raise("assessment_host_attestation_file_unavailable")
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_mode & 0o022
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > max_bytes
    ):
        _raise("assessment_host_attestation_file_untrusted")
    _verify_root_owned_directory_chain(path.parent)
    if not hasattr(os, "O_NOFOLLOW"):
        _raise("assessment_host_attestation_nofollow_unavailable")
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_uid != 0
                or opened.st_mode & 0o022
                or not stat.S_ISREG(opened.st_mode)
            ):
                _raise("assessment_host_attestation_file_changed")
            content = stream.read(max_bytes + 1)
    except HostBoundaryAttestationError:
        raise
    except OSError:
        _raise("assessment_host_attestation_file_unavailable")
    if len(content) > max_bytes:
        _raise("assessment_host_attestation_file_too_large")
    return content


def _source_hashes(worker_root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    try:
        for name, relative_path in _SOURCE_FILES.items():
            digest = hashlib.sha256(
                (worker_root / relative_path).read_bytes()
            ).hexdigest()
            hashes[name] = digest
    except OSError:
        _raise("assessment_host_attestation_source_unavailable")
    return hashes


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        _raise("assessment_host_attestation_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _raise("assessment_host_attestation_time_invalid")
    if parsed.tzinfo is None:
        _raise("assessment_host_attestation_time_invalid")
    return parsed.astimezone(timezone.utc)


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= _HEX_SHA256
    )


def _validate_payload(
    payload: Any,
    *,
    now: datetime,
    expected_source_hashes: Mapping[str, str],
) -> None:
    if not isinstance(payload, dict):
        _raise("assessment_host_attestation_payload_invalid")
    required = {
        "schemaVersion",
        "attestationId",
        "issuer",
        "independentVerifierId",
        "repository",
        "issuedAt",
        "expiresAt",
        "hostBoundaryReady",
        "integratedAssessmentReady",
        "sensitiveEnvironmentNameCount",
        "dockerSocketGroupGid",
        "serviceIdentities",
        "dockerSocketAccess",
        "databaseSessions",
        "qwenSandbox",
        "sourceCodeSha256",
    }
    if set(payload) != required or payload.get("schemaVersion") != 1:
        _raise("assessment_host_attestation_schema_invalid")
    for field in ("attestationId", "independentVerifierId"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 160:
            _raise("assessment_host_attestation_identity_invalid")
    if payload.get("issuer") != "guardian-nexus-independent-host-verifier":
        _raise("assessment_host_attestation_issuer_invalid")
    if payload.get("repository") != "guardian-nexus-lab":
        _raise("assessment_host_attestation_repository_mismatch")
    if (
        payload.get("hostBoundaryReady") is not True
        or payload.get("integratedAssessmentReady") is not True
        or payload.get("sensitiveEnvironmentNameCount") != 0
    ):
        _raise("assessment_host_boundary_not_ready")

    issued_at = _parse_timestamp(payload.get("issuedAt"))
    expires_at = _parse_timestamp(payload.get("expiresAt"))
    now = now.astimezone(timezone.utc)
    if (
        issued_at > now + MAX_FUTURE_SKEW
        or expires_at <= now
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_ATTESTATION_AGE
        or now - issued_at > MAX_ATTESTATION_AGE
    ):
        _raise("assessment_host_attestation_expired_or_stale")

    identities = payload.get("serviceIdentities")
    if not isinstance(identities, dict) or set(identities) != set(_SERVICE_NAMES):
        _raise("assessment_host_service_identities_invalid")
    socket_group_gid = payload.get("dockerSocketGroupGid")
    if (
        not isinstance(socket_group_gid, int)
        or isinstance(socket_group_gid, bool)
        or socket_group_gid <= 0
    ):
        _raise("assessment_host_socket_group_unverified")
    service_uids: set[int] = set()
    service_gids: set[int] = set()
    database_roles: set[str] = set()
    for name in _SERVICE_NAMES:
        identity = identities[name]
        if not isinstance(identity, dict) or set(identity) != {
            "uid",
            "gid",
            "groups",
            "databaseRole",
        }:
            _raise("assessment_host_service_identities_invalid")
        uid, gid, groups, role = (
            identity.get("uid"),
            identity.get("gid"),
            identity.get("groups"),
            identity.get("databaseRole"),
        )
        if (
            not isinstance(uid, int)
            or isinstance(uid, bool)
            or uid <= 0
            or not isinstance(gid, int)
            or isinstance(gid, bool)
            or gid <= 0
            or not isinstance(groups, list)
            or not groups
            or any(
                not isinstance(group, int)
                or isinstance(group, bool)
                or group <= 0
                for group in groups
            )
            or len(set(groups)) != len(groups)
            or gid not in groups
            or not isinstance(role, str)
            or not role
            or len(role) > 128
        ):
            _raise("assessment_host_service_identities_invalid")
        service_uids.add(uid)
        service_gids.add(gid)
        database_roles.add(role)
    if len(service_uids) != 3 or len(service_gids) != 3 or len(database_roles) != 3:
        _raise("assessment_host_identities_not_separate")
    if socket_group_gid in identities["api"]["groups"] or socket_group_gid in identities[
        "worker"
    ]["groups"]:
        _raise("assessment_host_socket_group_access_not_denied")
    if socket_group_gid not in identities["broker"]["groups"]:
        _raise("assessment_host_broker_socket_group_unverified")

    socket_access = payload.get("dockerSocketAccess")
    if not isinstance(socket_access, dict) or set(socket_access) != set(
        _SERVICE_NAMES
    ):
        _raise("assessment_host_socket_access_invalid")
    for name in ("api", "worker"):
        if socket_access.get(name) != {"read": False, "write": False}:
            _raise("assessment_host_socket_access_not_denied")
    if socket_access.get("broker") != {"read": True, "write": True}:
        _raise("assessment_host_broker_socket_authority_unverified")

    sessions = payload.get("databaseSessions")
    if not isinstance(sessions, dict) or set(sessions) != set(_SERVICE_NAMES):
        _raise("assessment_host_database_sessions_invalid")
    session_roles: set[str] = set()
    for name in _SERVICE_NAMES:
        session = sessions[name]
        if not isinstance(session, dict) or set(session) != {
            "databaseName",
            "role",
            "superuser",
            "bypassRls",
        }:
            _raise("assessment_host_database_sessions_invalid")
        role = session.get("role")
        if (
            not isinstance(role, str)
            or role != identities[name]["databaseRole"]
            or not isinstance(session.get("databaseName"), str)
            or not session["databaseName"].startswith("guardian_lab_")
            or session.get("superuser") is not False
            or session.get("bypassRls") is not False
        ):
            _raise("assessment_host_database_role_unverified")
        session_roles.add(role)
    if len(session_roles) != 3:
        _raise("assessment_host_database_roles_not_separate")

    sandbox = payload.get("qwenSandbox")
    if (
        not isinstance(sandbox, dict)
        or set(sandbox) != set(_SANDBOX_REQUIREMENTS)
        or any(sandbox.get(requirement) is not True for requirement in _SANDBOX_REQUIREMENTS)
    ):
        _raise("assessment_host_qwen_sandbox_unverified")

    source_hashes = payload.get("sourceCodeSha256")
    if (
        not isinstance(source_hashes, dict)
        or set(source_hashes) != set(expected_source_hashes)
        or any(not _is_sha256(value) for value in source_hashes.values())
        or dict(source_hashes) != dict(expected_source_hashes)
    ):
        _raise("assessment_host_attestation_source_mismatch")


def _verify_ed25519_signature(
    *, payload_bytes: bytes, signature: bytes, public_key_bytes: bytes
) -> None:
    openssl = shutil.which("openssl")
    if not openssl:
        _raise("assessment_host_signature_verifier_unavailable")
    try:
        executable = Path(openssl).resolve(strict=True)
        executable_stat = executable.stat()
    except OSError:
        _raise("assessment_host_signature_verifier_unavailable")
    if (
        not stat.S_ISREG(executable_stat.st_mode)
        or executable_stat.st_uid != 0
        or executable_stat.st_mode & 0o022
    ):
        _raise("assessment_host_signature_verifier_untrusted")
    _verify_root_owned_directory_chain(executable.parent)
    try:
        with tempfile.TemporaryDirectory(prefix="guardian-host-attest-") as root:
            root_path = Path(root)
            payload_path = root_path / "payload.json"
            key_path = root_path / "attestor.pem"
            signature_path = root_path / "signature.bin"
            payload_path.write_bytes(payload_bytes)
            key_path.write_bytes(public_key_bytes)
            signature_path.write_bytes(signature)
            result = subprocess.run(
                [
                    str(executable),
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-rawin",
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
                shell=False,
                env={"LC_ALL": "C", "LANG": "C", "OPENSSL_CONF": "/dev/null"},
            )
    except (OSError, subprocess.SubprocessError):
        _raise("assessment_host_signature_verification_failed")
    if result.returncode != 0:
        _raise("assessment_host_signature_invalid")


def verify_host_boundary_attestation(
    *,
    attestation_path: Path = DEFAULT_ATTESTATION_PATH,
    public_key_path: Path = DEFAULT_PUBLIC_KEY_PATH,
    now: datetime | None = None,
    expected_source_hashes: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify a fresh, root-installed, independently signed host attestation."""
    try:
        if os.geteuid() == 0:
            _raise("assessment_host_attestation_caller_must_not_be_root")
    except AttributeError:
        _raise("assessment_host_attestation_identity_unavailable")
    attestation_bytes = _read_root_owned_file(
        Path(attestation_path), max_bytes=MAX_ATTESTATION_BYTES
    )
    public_key_bytes = _read_root_owned_file(
        Path(public_key_path), max_bytes=16 * 1024
    )
    try:
        envelope = json.loads(
            attestation_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: _raise(
                "assessment_host_attestation_json_invalid"
            ),
        )
    except HostBoundaryAttestationError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        _raise("assessment_host_attestation_json_invalid")
    if not isinstance(envelope, dict) or set(envelope) != {
        "payload",
        "signatureAlgorithm",
        "signatureBase64",
    }:
        _raise("assessment_host_attestation_envelope_invalid")
    if envelope.get("signatureAlgorithm") != "Ed25519":
        _raise("assessment_host_attestation_signature_algorithm_invalid")
    encoded_signature = envelope.get("signatureBase64")
    if not isinstance(encoded_signature, str) or len(encoded_signature) > 256:
        _raise("assessment_host_attestation_signature_invalid")
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except (ValueError, binascii.Error):
        _raise("assessment_host_attestation_signature_invalid")
    if len(signature) != 64:
        _raise("assessment_host_attestation_signature_invalid")

    worker_root = Path(__file__).resolve().parents[1]
    source_hashes = (
        dict(expected_source_hashes)
        if expected_source_hashes is not None
        else _source_hashes(worker_root)
    )
    current_time = now or datetime.now(timezone.utc)
    payload = envelope["payload"]
    _validate_payload(
        payload,
        now=current_time,
        expected_source_hashes=source_hashes,
    )
    payload_bytes = _canonical_json(payload)
    _verify_ed25519_signature(
        payload_bytes=payload_bytes,
        signature=signature,
        public_key_bytes=public_key_bytes,
    )
    return {
        "status": "verified",
        "attestationId": payload["attestationId"],
        "independentVerifierId": payload["independentVerifierId"],
        "expiresAt": payload["expiresAt"],
        "sourceCodeSha256": source_hashes,
    }


def require_host_boundary_attestation() -> dict[str, Any]:
    """Raise a safe reason code unless the out-of-band attestation verifies."""
    return verify_host_boundary_attestation()
