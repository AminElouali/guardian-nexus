"""Offline tests for the standalone TEST ONLY vector verifier."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import approval_ledger_verifier as verifier

ROOT = Path(__file__).resolve().parents[1]
VECTORS_PATH = ROOT / "src" / "lib" / "approval-ledger-v1.vectors.json"
PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
# Public RFC 8032 vector seed. Test-only; never use for application signing.
TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
OTHER_TEST_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)


def sign_for_test(
    domain: bytes, payload: object, seed: bytes = TEST_SEED
) -> tuple[str, str]:
    message = domain + verifier.canonicalize(payload).encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="approval-ledger-test-sign-") as temp:
        root = Path(temp)
        key_path = root / "test-private.der"
        message_path = root / "message.bin"
        key_path.write_bytes(PKCS8_PREFIX + seed)
        message_path.write_bytes(message)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key_path),
                "-keyform",
                "DER",
                "-in",
                str(message_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
            shell=False,
        )
        if result.returncode != 0:
            raise AssertionError("test-only Ed25519 signing failed")
    return (
        hashlib.sha256(message).hexdigest(),
        base64.urlsafe_b64encode(result.stdout).decode("ascii").rstrip("="),
    )


class ApprovalLedgerVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = verifier.parse_json_strict(
            VECTORS_PATH.read_text(encoding="utf-8")
        )
        cls.now = verifier._timestamp(cls.document["verificationTime"])
        cls.keys = cls.document["trustedPublicKeys"]

    def test_shared_json_vectors_verify(self) -> None:
        passed, failed = verifier.verify_vector_file(VECTORS_PATH)
        self.assertEqual((passed, failed), (2, 0))

    def test_dated_key_registry_verifies_historical_signatures_after_rotation(self) -> None:
        registry = {
            "version": 1,
            "keys": {
                "fixture-key-1": {
                    "publicKeyPem": self.keys["fixture-key-1"],
                    "validFrom": "2026-11-16T09:00:00.000Z",
                    "validUntil": "2026-11-16T11:00:00.000Z",
                    "status": "retired",
                },
                "future-key": {
                    "publicKeyPem": self.document["untrustedPublicKeys"]["fixture-key-2"],
                    "validFrom": "2026-11-16T11:00:00.000Z",
                    "status": "active",
                },
            },
        }
        self.assertEqual(
            verifier.verify_bundle(self.document["bundle"], registry, self.now),
            "ok",
        )

    def test_dated_key_registry_rejects_out_of_window_and_revoked_signatures(self) -> None:
        for record, expected in (
            (
                {
                    "publicKeyPem": self.keys["fixture-key-1"],
                    "validFrom": "2026-11-16T10:00:01.000Z",
                    "status": "active",
                },
                "key_not_valid_at_signing_time",
            ),
            (
                {
                    "publicKeyPem": self.keys["fixture-key-1"],
                    "validFrom": "2026-11-16T09:00:00.000Z",
                    "status": "revoked",
                    "revokedAt": "2026-11-16T10:00:30.000Z",
                },
                "key_revoked_at_signing_time",
            ),
        ):
            registry = {"version": 1, "keys": {"fixture-key-1": record}}
            self.assertEqual(
                verifier.verify_bundle(self.document["bundle"], registry, self.now),
                expected,
            )

    def test_signed_checkpoint_detects_tail_truncation_with_separate_trust(self) -> None:
        bundle = copy.deepcopy(self.document["bundle"])
        head = bundle["events"][-1]
        checkpoint = {
            "version": 1,
            "keyId": "checkpoint-fixture-key",
            "workspaceId": head["event"]["workspaceId"],
            "sequence": head["event"]["sequence"],
            "headEventSha256": head["eventSha256"],
            "issuedAt": self.document["verificationTime"],
        }
        digest, signature = sign_for_test(
            verifier.CHECKPOINT_DOMAIN,
            checkpoint,
            OTHER_TEST_SEED,
        )
        signed_checkpoint = {
            "checkpoint": checkpoint,
            "checkpointSha256": digest,
            "signature": signature,
        }
        checkpoint_keys = {
            "checkpoint-fixture-key":
                self.document["untrustedPublicKeys"]["fixture-key-2"]
        }
        self.assertEqual(
            verifier.verify_bundle_with_checkpoint(
                bundle,
                self.keys,
                self.now,
                signed_checkpoint,
                checkpoint_keys,
            ),
            "ok",
        )

        bundle["events"].pop()
        self.assertEqual(
            verifier.verify_bundle_with_checkpoint(
                bundle,
                self.keys,
                self.now,
                signed_checkpoint,
                checkpoint_keys,
            ),
            "checkpoint_head_mismatch",
        )

    def test_checkpoint_signature_and_key_are_checked_separately(self) -> None:
        bundle = copy.deepcopy(self.document["bundle"])
        head = bundle["events"][-1]
        checkpoint = {
            "version": 1,
            "keyId": "checkpoint-fixture-key",
            "workspaceId": head["event"]["workspaceId"],
            "sequence": head["event"]["sequence"],
            "headEventSha256": head["eventSha256"],
            "issuedAt": self.document["verificationTime"],
        }
        digest, signature = sign_for_test(
            verifier.CHECKPOINT_DOMAIN, checkpoint, OTHER_TEST_SEED
        )
        signed_checkpoint = {
            "checkpoint": checkpoint,
            "checkpointSha256": digest,
            "signature": signature,
        }
        self.assertEqual(
            verifier.verify_bundle_with_checkpoint(
                bundle,
                self.keys,
                self.now,
                signed_checkpoint,
                self.keys,
            ),
            "unknown_key",
        )
        self.assertEqual(
            verifier.verify_bundle_with_checkpoint(
                bundle,
                self.keys,
                self.now,
                {**signed_checkpoint, "signature": "A" * 86},
                {
                    "checkpoint-fixture-key":
                        self.document["untrustedPublicKeys"]["fixture-key-2"]
                },
            ),
            "checkpoint_signature_invalid",
        )

    def test_python_canonicalization_matches_shared_vector(self) -> None:
        vector = self.document["canonicalizationVector"]
        self.assertEqual(
            verifier.canonicalize(vector["value"]),
            vector["canonical"],
        )

    def test_strict_json_parser_rejects_decimal_negative_zero_and_duplicates(self) -> None:
        for raw in ('{"n":1.0}', '{"n":-0}', '{"x":1,"x":2}'):
            with self.subTest(raw=raw):
                with self.assertRaises(verifier.CanonicalizationError):
                    verifier.parse_json_strict(raw)

    def test_edited_event_field_is_rejected(self) -> None:
        bundle = copy.deepcopy(self.document["bundle"])
        bundle["events"][0]["event"]["approvalId"] = "edited"
        self.assertEqual(
            verifier.verify_bundle(bundle, self.keys, self.now),
            "event_hash_mismatch",
        )

    def test_reordered_events_are_rejected(self) -> None:
        bundle = copy.deepcopy(self.document["bundle"])
        bundle["events"].reverse()
        self.assertEqual(
            verifier.verify_bundle(bundle, self.keys, self.now),
            "event_order_invalid",
        )

    def test_signature_from_another_key_is_rejected(self) -> None:
        bundle = copy.deepcopy(self.document["bundle"])
        event = bundle["events"][0]["event"]
        _, signature = sign_for_test(
            verifier.EVENT_DOMAIN,
            event,
            OTHER_TEST_SEED,
        )
        bundle["events"][0]["signature"] = signature
        self.assertEqual(
            verifier.verify_bundle(bundle, self.keys, self.now),
            "event_signature_invalid",
        )

    def test_wrong_signature_domain_is_rejected(self) -> None:
        bundle = copy.deepcopy(self.document["bundle"])
        event = bundle["events"][0]["event"]
        _, signature = sign_for_test(verifier.RECEIPT_DOMAIN, event)
        bundle["events"][0]["signature"] = signature
        self.assertEqual(
            verifier.verify_bundle(bundle, self.keys, self.now),
            "event_signature_invalid",
        )

    def test_expired_unconsumed_receipt_is_rejected(self) -> None:
        bundle = copy.deepcopy(self.document["bundle"])
        bundle["events"] = bundle["events"][:1]
        expired_time = verifier._timestamp("2026-11-16T10:06:00.000Z")
        self.assertEqual(
            verifier.verify_bundle(bundle, self.keys, expired_time),
            "receipt_expired",
        )

    def test_reused_nonce_is_rejected(self) -> None:
        bundle = copy.deepcopy(self.document["bundle"])
        payload = copy.deepcopy(bundle["receipts"][0]["payload"])
        payload["receiptId"] = "receipt-second-id"
        # It remains a distinct receipt but repeats the signed nonce.
        digest, signature = sign_for_test(verifier.RECEIPT_DOMAIN, payload)
        bundle["receipts"].append(
            {
                "payload": payload,
                "payloadSha256": digest,
                "signature": signature,
            }
        )
        self.assertEqual(
            verifier.verify_bundle(bundle, self.keys, self.now),
            "receipt_nonce_reused",
        )

    def test_second_consumption_of_one_receipt_is_rejected(self) -> None:
        bundle = copy.deepcopy(self.document["bundle"])
        signed_receipt = bundle["receipts"][0]
        previous = bundle["events"][-1]["eventSha256"]
        event = {
            "version": 1,
            "keyId": "fixture-key-1",
            "workspaceId": "workspace-test",
            "sequence": 3,
            "eventId": "event-replay",
            "eventType": "approval.receipt_consumed",
            "approvalId": "approval-001",
            "previousEventSha256": previous,
            "occurredAt": "2026-11-16T10:01:30.000Z",
            "payload": {
                "receiptId": "receipt-001",
                "receiptSha256": signed_receipt["payloadSha256"],
                "nonce": signed_receipt["payload"]["nonce"],
                "consumedAt": "2026-11-16T10:01:30.000Z",
            },
        }
        digest, signature = sign_for_test(verifier.EVENT_DOMAIN, event)
        bundle["events"].append(
            {"event": event, "eventSha256": digest, "signature": signature}
        )
        self.assertEqual(
            verifier.verify_bundle(bundle, self.keys, self.now),
            "receipt_replay",
        )


if __name__ == "__main__":
    unittest.main()
