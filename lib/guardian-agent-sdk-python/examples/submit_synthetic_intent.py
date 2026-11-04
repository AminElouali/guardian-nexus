"""Minimal local example. It never creates credentials or enables a worker."""

from __future__ import annotations

import os

from guardian_nexus_sdk import GuardianNexusClient


def main() -> int:
    base_url = os.environ.get("GUARDIAN_API_BASE_URL", "")
    workspace_id = os.environ.get("GUARDIAN_WORKSPACE_ID", "")
    # The host application should supply its existing short-lived Clerk token.
    # This sample reads an environment variable only when the user runs it;
    # it contains no embedded or default credential.
    token = os.environ.get("GUARDIAN_ACCESS_TOKEN")
    if not base_url or not workspace_id or not token:
        print(
            "Set GUARDIAN_API_BASE_URL, GUARDIAN_WORKSPACE_ID, and "
            "GUARDIAN_ACCESS_TOKEN in the local process environment."
        )
        return 2

    client = GuardianNexusClient(
        base_url=base_url,
        workspace_id=workspace_id,
        get_access_token=lambda: token,
    )
    result = client.submit_intent(
        scenario_id="email.allowed_draft",
        idempotency_key="python-sdk-demo-000001",
    )
    print(
        {
            "jobId": result["job"]["id"],
            "source": result["source"],
            "externalDispatch": result["externalDispatch"],
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
