from __future__ import annotations

import json
import unittest
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from guardian_nexus_sdk import (
    AGENT_ACTION_SCENARIOS,
    QWEN_AGENT_PROFILE_IDS,
    SYNTHETIC_REFUND_SCENARIO_ID,
    GuardianNexusClient,
    GuardianNexusSdkError,
)
from guardian_nexus_sdk.client import HttpResponse

WORKSPACE = "123e4567-e89b-42d3-a456-426614174000"
APPROVAL = "123e4567-e89b-42d3-a456-426614174001"
BINDING = "a" * 64


class FakeTransport:
    def __init__(self, responses: list[HttpResponse]):
        self.responses = deque(responses)
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def request(self, url, method, headers, body, timeout):
        self.calls.append((url, method, dict(headers), body))
        return self.responses.popleft()


def response(status: int, value: object, headers: dict[str, str] | None = None):
    return HttpResponse(
        status=status,
        headers=headers or {},
        body=json.dumps(value).encode("utf-8"),
    )


class GuardianNexusClientTests(unittest.TestCase):
    def client(self, transport: FakeTransport, **kwargs) -> GuardianNexusClient:
        return GuardianNexusClient(
            base_url="http://127.0.0.1:8080",
            workspace_id=WORKSPACE,
            get_access_token=lambda: "ephemeral-test-token",
            transport=transport,
            sleep=kwargs.pop("sleep", lambda _: None),
            **kwargs,
        )

    def test_rejects_insecure_remote_and_credential_bearing_urls(self) -> None:
        for base_url in (
            "http://example.test",
            "https://user:password@example.test",
            "https://example.test/api?token=x",
            "https://example.test/api#fragment",
        ):
            with self.subTest(base_url=base_url):
                with self.assertRaises(GuardianNexusSdkError):
                    GuardianNexusClient(
                        base_url=base_url,
                        workspace_id=WORKSPACE,
                        get_access_token=lambda: "not-used",
                        transport=FakeTransport([]),
                    )

    def test_intent_sends_only_fixed_scenario_and_idempotency(self) -> None:
        transport = FakeTransport(
            [
                response(
                    202,
                    {
                        "adapterVersion": "guardian-agent-intent-adapter-v1",
                        "source": "fixed_synthetic_scenario",
                        "decisionStatus": "pending_worker_evaluation",
                        "externalDispatch": False,
                        "actionIntent": {
                            "contractVersion": "guardian-action-intent-v1",
                            "workspaceId": WORKSPACE,
                            "scenarioId": "email.allowed_draft",
                            "intentSha256": "b" * 64,
                        },
                        "job": {
                            "id": APPROVAL,
                            "status": "queued",
                            "profileId": "guardian-agent-lab-email-v1",
                        },
                    },
                )
            ]
        )
        result = self.client(transport).submit_intent(
            scenario_id="email.allowed_draft",
            idempotency_key="client-request-000001",
        )
        self.assertFalse(result["externalDispatch"])
        url, method, headers, body = transport.calls[0]
        self.assertEqual(url, f"http://127.0.0.1:8080/api/workspaces/{WORKSPACE}/agent-action-adapter/intents")
        self.assertEqual(method, "POST")
        self.assertEqual(headers["Authorization"], "Bearer ephemeral-test-token")
        self.assertEqual(
            json.loads(body),
            {
                "contractVersion": "guardian-action-intent-v1",
                "scenarioId": "email.allowed_draft",
                "idempotencyKey": "client-request-000001",
            },
        )

    def test_qwen_profile_allowlist_covers_eight_profiles_and_keeps_pending_unverified(self) -> None:
        self.assertEqual(len(QWEN_AGENT_PROFILE_IDS), 8)
        transport = FakeTransport(
            [
                response(
                    202,
                    {
                        "id": APPROVAL,
                        "status": "queued",
                        "profileId": QWEN_AGENT_PROFILE_IDS[-1],
                        "workerVersion": "worker-test",
                        "createdAt": "2026-11-04T00:00:00.000Z",
                    },
                )
            ]
        )
        result = self.client(transport).submit_qwen_evaluation(
            profile_id=QWEN_AGENT_PROFILE_IDS[-1],
            idempotency_key="qwen-request-000001",
        )
        self.assertEqual(result["executionMode"], "not_yet_verified")
        self.assertFalse(result["externalDispatch"])
        with self.assertRaises(GuardianNexusSdkError):
            self.client(FakeTransport([])).submit_qwen_evaluation(
                profile_id="unapproved-profile",
                idempotency_key="qwen-request-000002",
            )

    def test_synthetic_refund_sdk_sends_only_fixed_scenario_and_idempotency(self) -> None:
        transport = FakeTransport(
            [
                response(
                    201,
                    {
                        "decision": "require_approval",
                        "reasonCode": "human_approval_required",
                        "approval": {
                            "id": APPROVAL,
                            "jobId": WORKSPACE,
                            "caseId": "support_trusted_refund_requires_approval",
                            "proposalBindingSha256": BINDING,
                            "status": "pending",
                            "expiresAt": "2026-11-14T12:15:00Z",
                            "syntheticActionRef": SYNTHETIC_REFUND_SCENARIO_ID,
                            "bindingVersion": 3,
                            "modelInference": False,
                            "executionMode": "deterministic_fixture",
                            "toolCallOrigin": "controlled_fixture_not_llm",
                            "requestedByRole": "owner",
                            "execution": "not_performed",
                            "simulatedAt": None,
                            "simulationResultCode": None,
                            "simulationResultSha256": None,
                            "replayBindingSha256": None,
                            "canCurrentUserDecide": False,
                        },
                        "execution": "not_performed",
                        "simulationResultCode": None,
                        "simulationResultSha256": None,
                        "idempotent": False,
                        "externalSideEffect": False,
                    },
                )
            ]
        )
        result = self.client(transport).propose_synthetic_refund(
            idempotency_key="refund-request-000001",
        )
        self.assertEqual(result["decision"], "require_approval")
        self.assertFalse(result["externalSideEffect"])
        url, method, headers, body = transport.calls[0]
        self.assertEqual(
            url,
            f"http://127.0.0.1:8080/api/workspaces/{WORKSPACE}/ai-security-assessments/synthetic-refund-proposals",
        )
        self.assertEqual(method, "POST")
        self.assertEqual(
            json.loads(body),
            {
                "scenarioId": SYNTHETIC_REFUND_SCENARIO_ID,
                "idempotencyKey": "refund-request-000001",
            },
        )

    def test_synthetic_refund_sdk_rejects_malformed_allow_response(self) -> None:
        transport = FakeTransport(
            [
                response(
                    200,
                    {
                        "decision": "allow",
                        "reasonCode": "synthetic_policy_allowed",
                        "approval": None,
                        "execution": "not_performed",
                        "simulationResultCode": "synthetic_refund_approved_in_clone",
                        "simulationResultSha256": "f" * 64,
                        "idempotent": False,
                        "externalSideEffect": False,
                    },
                )
            ]
        )
        with self.assertRaises(GuardianNexusSdkError) as error:
            self.client(transport).propose_synthetic_refund(
                idempotency_key="refund-request-000002",
            )
        self.assertEqual(error.exception.code, "invalid_synthetic_refund_response")

    def test_bounded_retry_reuses_same_idempotency_body_and_refreshes_token(self) -> None:
        transport = FakeTransport(
            [
                response(503, {"error": "not persisted"}, {"Retry-After": "9"}),
                response(
                    202,
                    {
                        "adapterVersion": "guardian-agent-intent-adapter-v1",
                        "source": "fixed_synthetic_scenario",
                        "decisionStatus": "pending_worker_evaluation",
                        "externalDispatch": False,
                        "actionIntent": {
                            "contractVersion": "guardian-action-intent-v1",
                            "workspaceId": WORKSPACE,
                            "scenarioId": "email.allowed_draft",
                            "intentSha256": "b" * 64,
                        },
                        "job": {
                            "id": APPROVAL,
                            "status": "queued",
                            "profileId": "guardian-agent-lab-email-v1",
                        },
                    },
                ),
            ]
        )
        sleeps: list[float] = []
        tokens = iter(("short-lived-1", "short-lived-2"))
        client = GuardianNexusClient(
            base_url="http://localhost:8080/api",
            workspace_id=WORKSPACE,
            get_access_token=lambda: next(tokens),
            transport=transport,
            sleep=sleeps.append,
        )
        client.submit_intent(
            scenario_id="email.allowed_draft",
            idempotency_key="retry-request-00001",
        )
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(transport.calls[0][3], transport.calls[1][3])
        self.assertEqual(transport.calls[0][2]["Authorization"], "Bearer short-lived-1")
        self.assertEqual(transport.calls[1][2]["Authorization"], "Bearer short-lived-2")
        self.assertEqual(sleeps, [1.0])

    def test_approval_decision_is_never_retried_and_binding_is_checked(self) -> None:
        transport = FakeTransport(
            [
                response(503, {"error": "temporary"}),
            ]
        )
        with self.assertRaises(GuardianNexusSdkError):
            self.client(transport).decide_approval(
                approval_id=APPROVAL,
                decision="approve",
                proposal_binding_sha256=BINDING,
            )
        self.assertEqual(len(transport.calls), 1)

        bad_binding = FakeTransport(
            [
                response(
                    200,
                    {
                        "execution": "not_performed",
                        "approval": {
                            "status": "approved",
                            "proposalBindingSha256": "c" * 64,
                        },
                    },
                )
            ]
        )
        with self.assertRaises(GuardianNexusSdkError):
            self.client(bad_binding).decide_approval(
                approval_id=APPROVAL,
                decision="approve",
                proposal_binding_sha256=BINDING,
            )

    def test_rejects_duplicate_json_keys_and_oversized_responses(self) -> None:
        duplicate = HttpResponse(
            status=200,
            headers={},
            body=b'{"approvals":[],"approvals":[{}]}',
        )
        with self.assertRaises(GuardianNexusSdkError):
            self.client(FakeTransport([duplicate])).list_approvals()
        with self.assertRaises(GuardianNexusSdkError) as error:
            self.client(FakeTransport([HttpResponse(200, {}, b" " * (2 * 1024 * 1024 + 1))])).list_approvals()
        self.assertEqual(error.exception.code, "response_body_too_large")

    def test_real_loopback_transport_refuses_redirects(self) -> None:
        requested_paths: list[str] = []

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                requested_paths.append(self.path)
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/redirect-target")
                self.end_headers()

            def log_message(self, _format, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = GuardianNexusClient(
                base_url=f"http://127.0.0.1:{server.server_port}",
                workspace_id=WORKSPACE,
                get_access_token=lambda: "loopback-test-token",
            )
            with self.assertRaises(GuardianNexusSdkError) as error:
                client.list_approvals()
            self.assertEqual(error.exception.status, 302)
            self.assertEqual(
                requested_paths,
                [f"/api/workspaces/{WORKSPACE}/ai-security-assessments/approvals"],
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_scenario_allowlist_is_fixed_and_not_user_policy(self) -> None:
        self.assertEqual(len(AGENT_ACTION_SCENARIOS), 4)
        for scenario in ("email.allowed_draft", "email.untrusted_send"):
            with self.subTest(scenario=scenario):
                with self.assertRaises(GuardianNexusSdkError):
                    self.client(FakeTransport([])).submit_intent(
                        scenario_id=f"{scenario}:admin",
                        idempotency_key="attempted-forgery-0001",
                    )


if __name__ == "__main__":
    unittest.main()
