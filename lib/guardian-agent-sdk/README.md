# Guardian Nexus Agent SDK

`@workspace/guardian-agent-sdk` is a typed client for the versioned Guardian
Nexus action-intent and laboratory approval API. Version `0.1.0` is a local
workspace package for development and integration testing; it has **not** been
published to a package registry.

The first adapter accepts a fixed synthetic scenario catalog only. It does not
accept caller-supplied tools, arguments, policy decisions, prompts, target
systems, or credentials. Guardian Nexus derives the actor, role, workspace,
resource and permissions from the authenticated server session. Denied and
approval-required actions are not dispatched. The approved bank-change example
replays once against an in-memory synthetic clone only.

## Build and test in this workspace

```sh
pnpm --filter @workspace/guardian-agent-sdk run build
pnpm --filter @workspace/guardian-agent-sdk run test
```

## Use from an application

Pass a callback that obtains a short-lived access token from the host
application's existing authentication session. The SDK does not store tokens,
log them, send cookies, follow redirects, or accept HTTP endpoints outside
loopback. Use HTTPS for any non-local API origin.

```ts
import {
  createIdempotencyKey,
  GuardianNexusClient,
} from "@workspace/guardian-agent-sdk";

const guardian = new GuardianNexusClient({
  baseUrl: "https://guardian.example",
  workspaceId: "123e4567-e89b-42d3-a456-426614174000",
  getAccessToken: () => hostAuthSession.getAccessToken(),
});

const submitted = await guardian.submitIntent({
  scenarioId: "finance.trusted_bank_change_approval",
  idempotencyKey: createIdempotencyKey(),
});
const job = await guardian.waitForJob(submitted.job.id);
if (job.status !== "succeeded") {
  throw new Error(`Evaluation ended with ${job.status}`);
}

const pending = (await guardian.listApprovals()).find(
  (approval) =>
    approval.jobId === job.id &&
    approval.caseId === "finance_trusted_bank_change_requires_approval",
);
if (pending?.status === "pending") {
  // Call only from a separately authorized reviewer session.
  const outcome = await reviewerGuardian.decideApproval({
    approvalId: pending.id,
    decision: "approve",
    proposalBindingSha256: pending.proposalBindingSha256,
  });
  // `synthetic_action_simulated_once` means only a local in-memory clone changed.
  console.log(outcome.execution);
}
```

`submitIntent` uses bounded retries and repeats the same caller-supplied
idempotency key. Approval decisions are one-shot and are not automatically
retried; on a conflict, fetch the approval state before taking any next step.
Polling has a fixed maximum attempt count and can be cancelled with an
`AbortSignal`. Errors expose only a status and a sanitized error code, never a
raw response body or bearer token.

## Current limits

- This is a lab SDK for the fixed synthetic scenarios, not a production
  integration to email, databases, banks, cloud, browsers, or customer systems.
- A local E2E auth harness is used in tests. A real Clerk browser session has
  not been exercised by this SDK test.
- No calls are made to external systems. `require_approval` is a durable,
  tenant-scoped approval; a successful approval can only replay the exact
  allowlisted synthetic action once in memory.
- Qwen/Garak evidence remains separate from this deterministic SDK scenario;
  this flow does not claim model inference.
