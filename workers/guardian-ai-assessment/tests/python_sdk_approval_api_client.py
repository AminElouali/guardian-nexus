"""Test-only Python SDK consumer for the local synthetic approval API E2E."""

from __future__ import annotations

import os
import json

from guardian_nexus_sdk import GuardianNexusClient, GuardianNexusSdkError
from guardian_nexus_sdk.client import HttpResponse, UrllibTransport


class _SyntheticTestIdentityTransport:
    """Injects the E2E-only identity header; never used by the shipped SDK."""

    def __init__(self) -> None:
        self._transport = UrllibTransport()

    def request(self, url, method, headers, body, timeout) -> HttpResponse:
        return self._transport.request(
            url,
            method,
            {**headers, "x-guardian-test-user": os.environ["GUARDIAN_TEST_USER"]},
            body,
            timeout,
        )


def main() -> int:
    operation = os.environ.get("GUARDIAN_SDK_OPERATION", "approve")
    required = (
        "GUARDIAN_API_BASE_URL",
        "GUARDIAN_WORKSPACE_ID",
        "GUARDIAN_TEST_USER",
    )
    if any(not os.environ.get(name) for name in required):
        return 2

    client = GuardianNexusClient(
        base_url=os.environ["GUARDIAN_API_BASE_URL"],
        workspace_id=os.environ["GUARDIAN_WORKSPACE_ID"],
        # The local test auth middleware uses only GUARDIAN_TEST_USER. This
        # dummy bearer value is not a Clerk credential and never leaves loopback.
        get_access_token=lambda: "synthetic-approval-e2e-only",
        transport=_SyntheticTestIdentityTransport(),
        max_retries=0,
    )
    if operation == "propose_synthetic_refund":
        idempotency_key = os.environ.get("GUARDIAN_REFUND_IDEMPOTENCY_KEY")
        if not idempotency_key:
            return 2
        first = client.propose_synthetic_refund(idempotency_key=idempotency_key)
        replay = client.propose_synthetic_refund(idempotency_key=idempotency_key)
        first_approval = first["approval"]
        replay_approval = replay["approval"]
        if (
            first["decision"] != "require_approval"
            or first["execution"] != "not_performed"
            or first["externalSideEffect"] is not False
            or first_approval.get("status") != "pending"
            or first_approval.get("canCurrentUserDecide") is not False
            or replay.get("idempotent") is not True
            or replay_approval.get("id") != first_approval.get("id")
            or replay_approval.get("proposalBindingSha256")
            != first_approval.get("proposalBindingSha256")
        ):
            return 5
        print(
            json.dumps(
                {
                    "approvalId": first_approval["id"],
                    "jobId": first_approval["jobId"],
                    "proposalBindingSha256": first_approval[
                        "proposalBindingSha256"
                    ],
                    "idempotentReplay": replay["idempotent"],
                },
                separators=(",", ":"),
            )
        )
        return 0
    if operation != "approve" or any(
        not os.environ.get(name)
        for name in (
            "GUARDIAN_APPROVAL_ID",
            "GUARDIAN_PROPOSAL_BINDING_SHA256",
        )
    ):
        return 2

    pending = next(
        (
            item
            for item in client.list_approvals()
            if item.get("id") == os.environ["GUARDIAN_APPROVAL_ID"]
        ),
        None,
    )
    if (
        pending is None
        or pending.get("status") != "pending"
        or pending.get("proposalBindingSha256")
        != os.environ["GUARDIAN_PROPOSAL_BINDING_SHA256"]
    ):
        return 3
    outcome = client.decide_approval(
        approval_id=os.environ["GUARDIAN_APPROVAL_ID"],
        decision="approve",
        proposal_binding_sha256=os.environ["GUARDIAN_PROPOSAL_BINDING_SHA256"],
    )
    if (
        outcome.get("execution") != "synthetic_action_simulated_once"
        or outcome["approval"].get("status") != "approved"
    ):
        return 4
    print(
        "PYTHON_SDK_APPROVAL_E2E status=approved "
        "execution=synthetic_action_simulated_once"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GuardianNexusSdkError as error:
        print(
            "PYTHON_SDK_APPROVAL_E2E "
            f"error={error.code} status={error.status}"
        )
        raise SystemExit(10) from None
    except Exception:
        print("PYTHON_SDK_APPROVAL_E2E error=unexpected")
        raise SystemExit(11) from None
