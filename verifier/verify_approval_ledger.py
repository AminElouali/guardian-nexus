#!/usr/bin/env python3
"""Standalone v1 approval-ledger verifier; Python stdlib plus system OpenSSL."""

from __future__ import annotations

import base64
import binascii
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

EVENT_DOMAIN = b"guardian-nexus:approval-ledger-event:v1\n"
RECEIPT_DOMAIN = b"guardian-nexus:approval-receipt:v1\n"
CHECKPOINT_DOMAIN = b"guardian-nexus:approval-ledger-checkpoint:v1\n"
HASH_RE = re.compile(r"^[a-f0-9]{64}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_TRUST_BYTES = 256 * 1024
MAX_CHECKPOINT_BYTES = 256 * 1024
MAX_DEPTH = 64
MAX_NODES = 20_000
OPENSSL_EXECUTABLE: str | None = None
UNSUPPORTED_OPENSSL_MESSAGE = (
    "Unsupported OpenSSL: this verifier requires Ed25519 SPKI export and "
    "pkeyutl -verify -pubin -rawin support. Install OpenSSL 3.x, then pass "
    "--openssl /path/to/openssl or set LEDGER_OPENSSL."
)
PROBE_PUBLIC_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=\n"
    "-----END PUBLIC KEY-----\n"
)
# RFC 8032 Ed25519 test vector; the verifier needs only its public key,
# one-byte message, and public signature (never a private key).
PROBE_MESSAGE = bytes.fromhex("72")
PROBE_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540"
    "a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c"
    "387b2eaeb4302aeeb00d291612bb0c00"
)


class CanonicalizationError(ValueError):
    pass


def _reject_float(_: str) -> None:
    raise CanonicalizationError("canonical_integer_invalid")


def _parse_integer(token: str) -> int:
    if token == "-0":
        raise CanonicalizationError("canonical_integer_invalid")
    value = int(token)
    if not -(2**53 - 1) <= value <= 2**53 - 1:
        raise CanonicalizationError("canonical_integer_invalid")
    return value


def _reject_constant(_: str) -> None:
    raise CanonicalizationError("canonical_number_invalid")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError("canonical_duplicate_key")
        result[key] = value
    return result


def parse_json_strict(raw: bytes) -> Any:
    """Parse JSON while rejecting duplicate names, floats, -0, and unsafe ints."""
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except CanonicalizationError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise CanonicalizationError("canonical_json_invalid") from exc


def _validate_string(value: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
        value.encode("utf-16-be", errors="strict")
    except UnicodeError as exc:
        raise CanonicalizationError("canonical_string_invalid") from exc


def _sort_key_utf16(value: str) -> bytes:
    _validate_string(value)
    return value.encode("utf-16-be")


def canonicalize(value: Any) -> str:
    count = 0

    def visit(item: Any, depth: int) -> str:
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise CanonicalizationError("canonical_value_limit")
        if isinstance(item, bool):
            return "true" if item else "false"
        if isinstance(item, str):
            _validate_string(item)
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, int):
            if not -(2**53 - 1) <= item <= 2**53 - 1:
                raise CanonicalizationError("canonical_integer_invalid")
            return str(item)
        if isinstance(item, float):
            raise CanonicalizationError("canonical_integer_invalid")
        if isinstance(item, list):
            return "[" + ",".join(visit(element, depth + 1) for element in item) + "]"
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise CanonicalizationError("canonical_object_invalid")
            keys = sorted(item.keys(), key=_sort_key_utf16)
            fields = [
                f"{json.dumps(key, ensure_ascii=False, separators=(',', ':'))}:"
                f"{visit(item[key], depth + 1)}"
                for key in keys
            ]
            return "{" + ",".join(fields) + "}"
        raise CanonicalizationError("canonical_value_invalid")

    return visit(value, 0)


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    canonical = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return parsed.astimezone(timezone.utc) if canonical == value else None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_signature(value: Any) -> bytes | None:
    if not isinstance(value, str) or SIGNATURE_RE.fullmatch(value) is None:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        return None
    if (
        len(decoded) != 64
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
    ):
        return None
    return decoded


def _openssl_public_der(public_pem: str) -> bytes | None:
    if (
        not isinstance(public_pem, str)
        or len(public_pem) > 16_384
        or not public_pem.startswith("-----BEGIN PUBLIC KEY-----")
        or "PRIVATE KEY" in public_pem
    ):
        return None
    openssl = OPENSSL_EXECUTABLE
    if not openssl:
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="ledger-public-key-") as temp:
            key_path = Path(temp) / "trusted-public.pem"
            key_path.write_text(public_pem, encoding="ascii")
            result = subprocess.run(
                [
                    openssl,
                    "pkey",
                    "-pubin",
                    "-in",
                    str(key_path),
                    "-pubout",
                    "-outform",
                    "DER",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
                shell=False,
            )
            if result.returncode != 0:
                return None
            der = result.stdout
            if (
                len(der) != len(ED25519_SPKI_PREFIX) + 32
                or not der.startswith(ED25519_SPKI_PREFIX)
            ):
                return None
            return der
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return None


def _openssl_verify(public_pem: str, message: bytes, signature: bytes) -> bool:
    openssl = OPENSSL_EXECUTABLE
    if not openssl:
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="ledger-signature-verify-") as temp:
            root = Path(temp)
            key_path = root / "trusted-public.pem"
            message_path = root / "message.bin"
            signature_path = root / "signature.bin"
            key_path.write_text(public_pem, encoding="ascii")
            message_path.write_bytes(message)
            signature_path.write_bytes(signature)
            result = subprocess.run(
                [
                    openssl,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-rawin",
                    "-in",
                    str(message_path),
                    "-sigfile",
                    str(signature_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
                shell=False,
            )
            return result.returncode == 0
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return False


def parse_trusted_keys(document: Any) -> dict[str, dict[str, Any]] | None:
    if not isinstance(document, dict):
        return None
    dated = (
        len(document) == 2
        and type(document.get("version")) is int
        and document.get("version") == 1
        and isinstance(document.get("keys"), dict)
    )
    source = document["keys"] if dated else document
    if not source:
        return None
    result: dict[str, dict[str, Any]] = {}
    for key_id, config in source.items():
        if not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None:
            return None
        if not dated:
            if not isinstance(config, str):
                return None
            public_pem = config
            valid_from = None
            valid_until = None
            revoked_at = None
            status = "legacy"
        else:
            allowed = {"publicKeyPem", "validFrom", "status", "validUntil", "revokedAt"}
            if (
                not isinstance(config, dict)
                or set(config) - allowed
                or not {"publicKeyPem", "validFrom", "status"} <= set(config)
                or not isinstance(config.get("publicKeyPem"), str)
            ):
                return None
            public_pem = config["publicKeyPem"]
            valid_from = _timestamp(config.get("validFrom"))
            valid_until_value = config.get("validUntil")
            revoked_at_value = config.get("revokedAt")
            valid_until = (
                _timestamp(valid_until_value) if valid_until_value is not None else None
            )
            revoked_at = (
                _timestamp(revoked_at_value) if revoked_at_value is not None else None
            )
            status = config.get("status")
            if (
                valid_from is None
                or status not in ("active", "retired", "revoked")
                or (valid_until_value is not None and valid_until is None)
                or (revoked_at_value is not None and revoked_at is None)
                or (status == "retired" and valid_until is None)
                or (status == "revoked" and revoked_at is None)
                or (status != "revoked" and revoked_at is not None)
                or (valid_until is not None and valid_until <= valid_from)
                or (revoked_at is not None and revoked_at < valid_from)
            ):
                return None
        public_der = _openssl_public_der(public_pem)
        if public_der is None:
            return None
        result[key_id] = {
            "pem": public_pem,
            "der": public_der,
            "validFrom": valid_from,
            "validUntil": valid_until,
            "revokedAt": revoked_at,
            "status": status,
        }
    return result


def _resolve_key(
    key_id: Any, signed_at: Any, trusted_keys: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None:
        return None, "unknown_key"
    record = trusted_keys.get(key_id)
    if record is None:
        return None, "unknown_key"
    if record["status"] == "legacy":
        return record, None
    signed_time = _timestamp(signed_at)
    if signed_time is None:
        return None, "trusted_key_invalid"
    if signed_time < record["validFrom"] or (
        record["validUntil"] is not None and signed_time >= record["validUntil"]
    ):
        return None, "key_not_valid_at_signing_time"
    if record["status"] == "revoked" and signed_time >= record["revokedAt"]:
        return None, "key_revoked_at_signing_time"
    return record, None


def _verify_signed(
    domain: bytes,
    payload: Any,
    digest: Any,
    signature: Any,
    key_id: Any,
    trusted_keys: dict[str, dict[str, Any]],
    prefix: str,
    signed_at: Any,
) -> str:
    record, error = _resolve_key(key_id, signed_at, trusted_keys)
    if error:
        return error
    try:
        message = domain + canonicalize(payload).encode("utf-8")
    except CanonicalizationError:
        return "canonicalization_invalid"
    if not isinstance(digest, str) or HASH_RE.fullmatch(digest) is None:
        return f"{prefix}_hash_mismatch"
    if _sha256(message) != digest:
        return f"{prefix}_hash_mismatch"
    decoded = _decode_signature(signature)
    if decoded is None:
        return f"{prefix}_signature_invalid"
    return (
        "ok"
        if _openssl_verify(record["pem"], message, decoded)
        else f"{prefix}_signature_invalid"
    )


def _is_receipt_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    expected = {
        "version", "keyId", "receiptId", "workspaceId", "approvalId",
        "proposalBindingSha256", "actionSha256", "requestedBy", "approvedBy",
        "approvedByRole", "issuedAt", "expiresAt", "nonce",
    }
    issued = _timestamp(payload.get("issuedAt"))
    expires = _timestamp(payload.get("expiresAt"))
    return (
        set(payload) == expected
        and type(payload.get("version")) is int
        and payload.get("version") == 1
        and isinstance(payload.get("keyId"), str)
        and KEY_ID_RE.fullmatch(payload["keyId"]) is not None
        and all(
            isinstance(payload.get(key), str) and payload[key]
            for key in ("receiptId", "workspaceId", "approvalId", "requestedBy", "approvedBy")
        )
        and isinstance(payload.get("proposalBindingSha256"), str)
        and HASH_RE.fullmatch(payload["proposalBindingSha256"]) is not None
        and isinstance(payload.get("actionSha256"), str)
        and HASH_RE.fullmatch(payload["actionSha256"]) is not None
        and payload.get("requestedBy") != payload.get("approvedBy")
        and payload.get("approvedByRole") in ("owner", "admin")
        and issued is not None
        and expires is not None
        and issued < expires
        and isinstance(payload.get("nonce"), str)
        and NONCE_RE.fullmatch(payload["nonce"]) is not None
    )


def _is_signed_receipt(signed: Any) -> bool:
    return (
        isinstance(signed, dict)
        and set(signed) == {"payload", "payloadSha256", "signature"}
        and _is_receipt_payload(signed.get("payload"))
        and isinstance(signed.get("payloadSha256"), str)
        and HASH_RE.fullmatch(signed["payloadSha256"]) is not None
        and isinstance(signed.get("signature"), str)
    )


def _is_signed_event(signed: Any) -> bool:
    if (
        not isinstance(signed, dict)
        or set(signed) != {"event", "eventSha256", "signature"}
        or not isinstance(signed.get("event"), dict)
    ):
        return False
    event = signed["event"]
    event_keys = {
        "version", "keyId", "workspaceId", "sequence", "eventId", "eventType",
        "approvalId", "previousEventSha256", "occurredAt", "payload",
    }
    previous = event.get("previousEventSha256")
    return (
        set(event) == event_keys
        and type(event.get("version")) is int
        and event.get("version") == 1
        and isinstance(event.get("keyId"), str)
        and KEY_ID_RE.fullmatch(event["keyId"]) is not None
        and isinstance(event.get("workspaceId"), str)
        and bool(event["workspaceId"])
        and type(event.get("sequence")) is int
        and event["sequence"] > 0
        and isinstance(event.get("eventId"), str)
        and bool(event["eventId"])
        and event.get("eventType") in ("approval.approved", "approval.receipt_consumed")
        and isinstance(event.get("approvalId"), str)
        and bool(event["approvalId"])
        and (previous == "" or isinstance(previous, str) and HASH_RE.fullmatch(previous))
        and _timestamp(event.get("occurredAt")) is not None
        and isinstance(event.get("payload"), dict)
        and isinstance(signed.get("eventSha256"), str)
        and HASH_RE.fullmatch(signed["eventSha256"]) is not None
        and isinstance(signed.get("signature"), str)
    )


def verify_bundle(
    bundle: Any,
    trusted_keys: dict[str, dict[str, Any]],
    verification_time: datetime,
) -> str:
    if (
        not isinstance(bundle, dict)
        or set(bundle) != {"version", "events", "receipts"}
        or type(bundle.get("version")) is not int
        or bundle.get("version") != 1
        or not isinstance(bundle.get("events"), list)
        or not isinstance(bundle.get("receipts"), list)
        or verification_time.tzinfo is None
    ):
        return "invalid_bundle"

    receipts: dict[str, dict[str, Any]] = {}
    receipt_ids: set[str] = set()
    nonces: set[str] = set()
    for signed in bundle["receipts"]:
        if not _is_signed_receipt(signed):
            return "receipt_invalid"
        receipt = signed["payload"]
        receipt_id = receipt["receiptId"]
        nonce = receipt["nonce"]
        if receipt_id in receipt_ids or nonce in nonces:
            return "receipt_nonce_reused"
        receipt_ids.add(receipt_id)
        nonces.add(nonce)
        result = _verify_signed(
            RECEIPT_DOMAIN,
            receipt,
            signed["payloadSha256"],
            signed["signature"],
            receipt["keyId"],
            trusted_keys,
            "receipt",
            receipt["issuedAt"],
        )
        if result != "ok":
            return result
        receipts[receipt_id] = signed

    previous_hash = ""
    workspace_id: str | None = None
    issued: set[str] = set()
    consumed: set[str] = set()
    event_ids: set[str] = set()
    for index, signed in enumerate(bundle["events"]):
        if not _is_signed_event(signed):
            return "invalid_bundle"
        event = signed["event"]
        if (
            event["sequence"] != index + 1
            or event["previousEventSha256"] != previous_hash
            or (workspace_id is not None and event["workspaceId"] != workspace_id)
            or event["eventId"] in event_ids
        ):
            return "event_order_invalid"
        workspace_id = event["workspaceId"]
        event_ids.add(event["eventId"])
        result = _verify_signed(
            EVENT_DOMAIN,
            event,
            signed["eventSha256"],
            signed["signature"],
            event["keyId"],
            trusted_keys,
            "event",
            event["occurredAt"],
        )
        if result != "ok":
            return result
        previous_hash = signed["eventSha256"]

        payload = event["payload"]
        receipt_id = payload.get("receiptId")
        receipt_hash = payload.get("receiptSha256")
        if (
            not isinstance(receipt_id, str)
            or not receipt_id
            or not isinstance(receipt_hash, str)
            or HASH_RE.fullmatch(receipt_hash) is None
        ):
            return "receipt_reference_mismatch"
        receipt_signed = receipts.get(receipt_id)
        if not receipt_signed or receipt_signed["payloadSha256"] != receipt_hash:
            return "receipt_reference_mismatch"
        receipt = receipt_signed["payload"]
        if (
            receipt["workspaceId"] != event["workspaceId"]
            or receipt["approvalId"] != event["approvalId"]
        ):
            return "receipt_reference_mismatch"

        if event["eventType"] == "approval.approved":
            if set(payload) != {"receiptId", "receiptSha256"}:
                return "unsupported_event"
            if receipt["issuedAt"] != event["occurredAt"] or receipt_id in issued:
                return "receipt_reference_mismatch"
            issued.add(receipt_id)
            continue

        if set(payload) != {"receiptId", "receiptSha256", "nonce", "consumedAt"}:
            return "unsupported_event"
        if receipt_id not in issued:
            return "receipt_reference_mismatch"
        if receipt_id in consumed or payload.get("nonce") != receipt["nonce"]:
            return "receipt_replay"
        consumed_at = _timestamp(payload.get("consumedAt"))
        issued_at = _timestamp(receipt["issuedAt"])
        expires_at = _timestamp(receipt["expiresAt"])
        if (
            consumed_at is None
            or payload.get("consumedAt") != event["occurredAt"]
            or issued_at is None
            or expires_at is None
            or not (issued_at <= consumed_at < expires_at)
        ):
            return "receipt_expired"
        consumed.add(receipt_id)

    if issued != set(receipts):
        return "receipt_reference_mismatch"
    now = verification_time.astimezone(timezone.utc)
    for receipt_id, signed in receipts.items():
        if (
            receipt_id not in consumed
            and now >= _timestamp(signed["payload"]["expiresAt"])
        ):
            return "receipt_expired"
    return "ok"


def _public_der_from_record(record: dict[str, Any] | None) -> bytes | None:
    return record.get("der") if record else None


def verify_bundle_with_checkpoint(
    bundle: Any,
    ledger_keys: dict[str, dict[str, Any]],
    verification_time: datetime,
    signed_checkpoint: Any,
    checkpoint_keys: dict[str, dict[str, Any]],
) -> str:
    result = verify_bundle(bundle, ledger_keys, verification_time)
    if result != "ok":
        return result
    if (
        not isinstance(signed_checkpoint, dict)
        or set(signed_checkpoint) != {"checkpoint", "checkpointSha256", "signature"}
    ):
        return "checkpoint_invalid"
    checkpoint = signed_checkpoint["checkpoint"]
    checkpoint_fields = {
        "version", "keyId", "workspaceId", "sequence", "headEventSha256", "issuedAt"
    }
    if (
        not isinstance(checkpoint, dict)
        or set(checkpoint) != checkpoint_fields
        or type(checkpoint.get("version")) is not int
        or checkpoint.get("version") != 1
        or not isinstance(checkpoint.get("keyId"), str)
        or KEY_ID_RE.fullmatch(checkpoint["keyId"]) is None
        or not isinstance(checkpoint.get("workspaceId"), str)
        or not checkpoint["workspaceId"]
        or type(checkpoint.get("sequence")) is not int
        or checkpoint["sequence"] < 1
        or not isinstance(checkpoint.get("headEventSha256"), str)
        or HASH_RE.fullmatch(checkpoint["headEventSha256"]) is None
        or _timestamp(checkpoint.get("issuedAt")) is None
        or _timestamp(checkpoint["issuedAt"]) > verification_time
        or not isinstance(signed_checkpoint.get("checkpointSha256"), str)
        or HASH_RE.fullmatch(signed_checkpoint["checkpointSha256"]) is None
        or not isinstance(signed_checkpoint.get("signature"), str)
    ):
        return "checkpoint_invalid"
    result = _verify_signed(
        CHECKPOINT_DOMAIN,
        checkpoint,
        signed_checkpoint["checkpointSha256"],
        signed_checkpoint["signature"],
        checkpoint["keyId"],
        checkpoint_keys,
        "checkpoint",
        checkpoint["issuedAt"],
    )
    if result != "ok":
        return result

    checkpoint_record, error = _resolve_key(
        checkpoint["keyId"], checkpoint["issuedAt"], checkpoint_keys
    )
    if error or checkpoint_record is None:
        return error or "trusted_key_invalid"
    checkpoint_der = _public_der_from_record(checkpoint_record)
    if checkpoint_der is None:
        return "trusted_key_invalid"
    for record in ledger_keys.values():
        if _public_der_from_record(record) == checkpoint_der:
            return "checkpoint_key_not_independent"

    events = bundle["events"]
    if not events:
        return "checkpoint_head_mismatch"
    head = events[-1]
    if (
        len(events) != checkpoint["sequence"]
        or head["event"]["sequence"] != checkpoint["sequence"]
        or head["event"]["workspaceId"] != checkpoint["workspaceId"]
        or head["eventSha256"] != checkpoint["headEventSha256"]
        or checkpoint["issuedAt"] < head["event"]["occurredAt"]
    ):
        return "checkpoint_head_mismatch"
    return "ok"


def _parse_arguments(argv: list[str]) -> dict[str, str] | None:
    values: dict[str, str] = {}
    index = 0
    supported = {
        "--bundle", "--trusted-keys", "--checkpoint",
        "--checkpoint-trusted-keys", "--at", "--openssl",
    }
    while index < len(argv):
        flag = argv[index]
        value = argv[index + 1] if index + 1 < len(argv) else None
        if (
            flag not in supported
            or not value
            or value.startswith("--")
            or (flag != "--at" and flag in values)
        ):
            return None
        if flag == "--at":
            timestamp = _timestamp(value)
            if timestamp is None:
                return None
        values[flag] = value
        index += 2
    if "--bundle" not in values or "--trusted-keys" not in values:
        return None
    has_checkpoint = "--checkpoint" in values
    has_checkpoint_keys = "--checkpoint-trusted-keys" in values
    if has_checkpoint != has_checkpoint_keys:
        return None
    return values


def _resolve_openssl(args: dict[str, str]) -> str | None:
    requested = args.get("--openssl") or os.environ.get("LEDGER_OPENSSL") or "openssl"
    return shutil.which(requested)


def _probe_openssl(executable: str) -> bool:
    """Exercise the exact PEM conversion and raw Ed25519 verify operations."""
    try:
        version = subprocess.run(
            [executable, "version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
            shell=False,
        )
        if version.returncode != 0:
            return False
        with tempfile.TemporaryDirectory(prefix="ledger-openssl-probe-") as temp:
            root = Path(temp)
            key_path = root / "probe-public.pem"
            message_path = root / "probe-message.bin"
            signature_path = root / "probe-signature.bin"
            key_path.write_text(PROBE_PUBLIC_PEM, encoding="ascii")
            message_path.write_bytes(PROBE_MESSAGE)
            signature_path.write_bytes(PROBE_SIGNATURE)
            export_result = subprocess.run(
                [
                    executable,
                    "pkey",
                    "-pubin",
                    "-in",
                    str(key_path),
                    "-pubout",
                    "-outform",
                    "DER",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
                shell=False,
            )
            if (
                export_result.returncode != 0
                or len(export_result.stdout) != len(ED25519_SPKI_PREFIX) + 32
                or not export_result.stdout.startswith(ED25519_SPKI_PREFIX)
            ):
                return False
            verify_result = subprocess.run(
                [
                    executable,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-rawin",
                    "-in",
                    str(message_path),
                    "-sigfile",
                    str(signature_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
                shell=False,
            )
            return verify_result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _read_json_file(path: str, max_bytes: int) -> Any:
    raw = Path(path).read_bytes()
    if len(raw) > max_bytes:
        raise CanonicalizationError("canonical_json_invalid")
    return parse_json_strict(raw)


def verify_files(args: dict[str, str]) -> dict[str, Any]:
    try:
        bundle = _read_json_file(args["--bundle"], MAX_BUNDLE_BYTES)
        trust_document = _read_json_file(args["--trusted-keys"], MAX_TRUST_BYTES)
        ledger_keys = parse_trusted_keys(trust_document)
        if ledger_keys is None:
            return {"valid": False, "code": "trusted_key_invalid"}
        at_value = args.get("--at")
        verification_time = _timestamp(at_value) if at_value else datetime.now(timezone.utc)
        if verification_time is None:
            return {"valid": False, "code": "invalid_bundle"}
        if "--checkpoint" not in args:
            code = verify_bundle(bundle, ledger_keys, verification_time)
        else:
            checkpoint = _read_json_file(args["--checkpoint"], MAX_CHECKPOINT_BYTES)
            checkpoint_document = _read_json_file(
                args["--checkpoint-trusted-keys"], MAX_TRUST_BYTES
            )
            checkpoint_keys = parse_trusted_keys(checkpoint_document)
            if checkpoint_keys is None:
                return {"valid": False, "code": "trusted_key_invalid"}
            code = verify_bundle_with_checkpoint(
                bundle,
                ledger_keys,
                verification_time,
                checkpoint,
                checkpoint_keys,
            )
        return {"valid": code == "ok", "code": code}
    except Exception:
        # Keep parser, filesystem, and OpenSSL failures fixed and non-sensitive.
        return {"valid": False, "code": "invalid_bundle"}


def main(argv: list[str] | None = None) -> int:
    global OPENSSL_EXECUTABLE
    args = _parse_arguments(sys.argv[1:] if argv is None else argv)
    if args is None:
        result = {"valid": False, "code": "invalid_bundle"}
        exit_code = 1
    else:
        OPENSSL_EXECUTABLE = _resolve_openssl(args)
        if OPENSSL_EXECUTABLE is None or not _probe_openssl(OPENSSL_EXECUTABLE):
            print(UNSUPPORTED_OPENSSL_MESSAGE, file=sys.stderr)
            result = {"valid": False, "code": "unsupported_openssl"}
            exit_code = 2
        else:
            result = verify_files(args)
            exit_code = 0 if result["valid"] else 1
    print(json.dumps(result, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
