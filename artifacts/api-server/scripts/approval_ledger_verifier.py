#!/usr/bin/env python3
"""Offline v1 approval-ledger verifier; no API or database imports."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVENT_DOMAIN = b"guardian-nexus:approval-ledger-event:v1\n"
RECEIPT_DOMAIN = b"guardian-nexus:approval-receipt:v1\n"
HASH_RE = re.compile(r"^[a-f0-9]{64}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
MAX_DEPTH = 64
MAX_NODES = 20_000


class CanonicalizationError(ValueError):
    pass


def _reject_float(_: str) -> None:
    raise CanonicalizationError("canonical_integer_invalid")


def _reject_constant(_: str) -> None:
    raise CanonicalizationError("canonical_number_invalid")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError("canonical_duplicate_key")
        result[key] = value
    return result


def parse_json_strict(raw: str) -> Any:
    try:
        return json.loads(
            raw,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
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
            if not -(2**53 - 1) <= item <= (2**53 - 1):
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
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    canonical = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return parsed.astimezone(timezone.utc) if canonical == value else None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_signature(value: Any) -> bytes | None:
    if not isinstance(value, str) or not SIGNATURE_RE.fullmatch(value):
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error):
        return None
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        return None
    return decoded


def _openssl_verify(public_pem: str, message: bytes, signature: bytes) -> bool:
    openssl = shutil.which("openssl")
    if not openssl:
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="approval-ledger-verify-") as temp:
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
    except (OSError, TypeError, UnicodeError, subprocess.TimeoutExpired):
        return False


def _verify_signed(
    domain: bytes,
    payload: Any,
    digest: Any,
    signature: Any,
    key_id: Any,
    trusted_keys: dict[str, str],
    prefix: str,
) -> str:
    if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
        return "unknown_key"
    public_pem = trusted_keys.get(key_id)
    if not public_pem:
        return "unknown_key"
    if not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
        return f"{prefix}_hash_mismatch"
    decoded = _decode_signature(signature)
    if decoded is None:
        return f"{prefix}_signature_invalid"
    try:
        message = domain + canonicalize(payload).encode("utf-8")
    except CanonicalizationError:
        return "canonicalization_invalid"
    if _sha256(message) != digest:
        return f"{prefix}_hash_mismatch"
    return "ok" if _openssl_verify(public_pem, message, decoded) else f"{prefix}_signature_invalid"


def _is_receipt_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    expected = {
        "version",
        "keyId",
        "receiptId",
        "workspaceId",
        "approvalId",
        "proposalBindingSha256",
        "actionSha256",
        "requestedBy",
        "approvedBy",
        "approvedByRole",
        "issuedAt",
        "expiresAt",
        "nonce",
    }
    issued = _timestamp(payload.get("issuedAt"))
    expires = _timestamp(payload.get("expiresAt"))
    return (
        set(payload) == expected
        and type(payload.get("version")) is int
        and payload.get("version") == 1
        and isinstance(payload.get("keyId"), str)
        and KEY_ID_RE.fullmatch(payload["keyId"]) is not None
        and all(isinstance(payload.get(key), str) and payload[key] for key in (
            "receiptId", "workspaceId", "approvalId", "requestedBy", "approvedBy"
        ))
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


def verify_bundle(bundle: Any, trusted_keys: dict[str, str], verification_time: datetime) -> str:
    if (
        not isinstance(bundle, dict)
        or set(bundle) != {"version", "events", "receipts"}
        or bundle.get("version") != 1
        or not isinstance(bundle.get("events"), list)
        or not isinstance(bundle.get("receipts"), list)
        or verification_time.tzinfo is None
    ):
        return "invalid_bundle"

    receipts: dict[str, dict[str, Any]] = {}
    nonces: set[str] = set()
    for signed in bundle["receipts"]:
        if not isinstance(signed, dict) or set(signed) != {"payload", "payloadSha256", "signature"}:
            return "receipt_invalid"
        payload = signed["payload"]
        if not _is_receipt_payload(payload):
            return "receipt_invalid"
        receipt_id = payload["receiptId"]
        nonce = payload["nonce"]
        if receipt_id in receipts or nonce in nonces:
            return "receipt_nonce_reused"
        nonces.add(nonce)
        result = _verify_signed(
            RECEIPT_DOMAIN,
            payload,
            signed["payloadSha256"],
            signed["signature"],
            payload["keyId"],
            trusted_keys,
            "receipt",
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
        if not isinstance(signed, dict) or set(signed) != {"event", "eventSha256", "signature"}:
            return "invalid_bundle"
        event = signed["event"]
        event_keys = {
            "version", "keyId", "workspaceId", "sequence", "eventId", "eventType",
            "approvalId", "previousEventSha256", "occurredAt", "payload",
        }
        if not isinstance(event, dict) or set(event) != event_keys:
            return "invalid_bundle"
        if (
            event.get("version") != 1
            or not isinstance(event.get("keyId"), str)
            or not KEY_ID_RE.fullmatch(event["keyId"])
            or not isinstance(event.get("workspaceId"), str)
            or not event["workspaceId"]
            or type(event.get("sequence")) is not int
            or event["sequence"] < 1
            or not isinstance(event.get("eventId"), str)
            or not event["eventId"]
            or not isinstance(event.get("approvalId"), str)
            or not event["approvalId"]
            or _timestamp(event.get("occurredAt")) is None
            or not isinstance(event.get("payload"), dict)
        ):
            return "invalid_bundle"
        if (
            event["sequence"] != index + 1
            or event.get("previousEventSha256") != previous_hash
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
        )
        if result != "ok":
            return result
        previous_hash = signed["eventSha256"]

        payload = event["payload"]
        receipt_id = payload.get("receiptId")
        receipt_hash = payload.get("receiptSha256")
        if not isinstance(receipt_id, str) or not isinstance(receipt_hash, str):
            return "receipt_reference_mismatch"
        receipt_signed = receipts.get(receipt_id)
        if not receipt_signed or receipt_signed["payloadSha256"] != receipt_hash:
            return "receipt_reference_mismatch"
        receipt = receipt_signed["payload"]
        if receipt["workspaceId"] != event["workspaceId"] or receipt["approvalId"] != event["approvalId"]:
            return "receipt_reference_mismatch"

        if event["eventType"] == "approval.approved":
            if set(payload) != {"receiptId", "receiptSha256"} or receipt_id in issued:
                return "receipt_reference_mismatch"
            if receipt["issuedAt"] != event["occurredAt"]:
                return "receipt_reference_mismatch"
            issued.add(receipt_id)
        elif event["eventType"] == "approval.receipt_consumed":
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
                or consumed_at.isoformat(timespec="milliseconds").replace("+00:00", "Z")
                != event["occurredAt"]
                or issued_at is None
                or expires_at is None
                or not (issued_at <= consumed_at < expires_at)
            ):
                return "receipt_expired"
            consumed.add(receipt_id)
        else:
            return "unsupported_event"

    if issued != set(receipts):
        return "receipt_reference_mismatch"
    now = verification_time.astimezone(timezone.utc)
    for receipt_id, signed in receipts.items():
        if receipt_id not in consumed and now >= _timestamp(signed["payload"]["expiresAt"]):
            return "receipt_expired"
    return "ok"


def verify_vector_file(path: Path) -> tuple[int, int]:
    document = parse_json_strict(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("testOnly") is not True:
        return (0, 1)
    keys = document.get("trustedPublicKeys")
    if not isinstance(keys, dict):
        return (0, 1)
    now = _timestamp(document.get("verificationTime"))
    canonical_vector = document.get("canonicalizationVector")
    bundle = document.get("bundle")
    if (
        now is None
        or not isinstance(canonical_vector, dict)
        or set(canonical_vector) != {"value", "canonical"}
        or not isinstance(canonical_vector.get("canonical"), str)
        or not isinstance(bundle, dict)
    ):
        return (0, 1)
    try:
        canonical_ok = canonicalize(canonical_vector["value"]) == canonical_vector["canonical"]
    except CanonicalizationError:
        canonical_ok = False
    bundle_ok = verify_bundle(bundle, keys, now) == "ok"
    return int(canonical_ok) + int(bundle_ok), int(not canonical_ok) + int(not bundle_ok)


def main() -> int:
    default_vectors = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "lib"
        / "approval-ledger-v1.vectors.json"
    )
    parser = argparse.ArgumentParser(description="Verify TEST ONLY approval-ledger vectors")
    parser.add_argument("vectors", nargs="?", type=Path, default=default_vectors)
    args = parser.parse_args()
    try:
        passed, failed = verify_vector_file(args.vectors)
    except Exception:
        # Keep CLI failures fixed and non-sensitive, including parser/OpenSSL errors.
        passed, failed = 0, 1
    print(f"vectors: pass={passed} fail={failed}")
    return 0 if passed > 0 and failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
