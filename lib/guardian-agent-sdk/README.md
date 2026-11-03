# Guardian Nexus Agent SDK

`@workspace/guardian-agent-sdk` is a typed client for the versioned Guardian
Nexus action-intent, laboratory approval and local Qwen evaluation API. Version
`0.2.0` is a local
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

## Consume from a local application without publishing

Build and pack the SDK from this repository, then install the resulting tarball
in a separate local consumer project:

```sh
pnpm --filter @workspace/guardian-agent-sdk run build
pnpm --filter @workspace/guardian-agent-sdk pack --pack-destination /tmp/guardian-sdk-dist
cd /path/to/consumer
pnpm add /tmp/guardian-sdk-dist/workspace-guardian-agent-sdk-0.2.0.tgz
```

This is a local file install only; it does not publish the package or contact a
registry. The packed artifact contains the compiled client, README, and example.

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

## Run a real local Qwen profile

The SDK can request any of the eight server-allowlisted Qwen laboratory
profiles. Each request runs the worker's existing synthetic corpus with
`tool_choice=auto`; the SDK sends no prompt, tool, arguments, policy choice or
target. A queued response is marked unverified. `waitForQwenEvaluation`
returns a report only after checking the persisted evidence says the execution
was real local Qwen inference and confirms the tool-call origin and policy
dispatch fields.

```ts
const queued = await guardian.submitQwenEvaluation({
  profileId: "guardian-agent-qwen-lab-email-v1",
  idempotencyKey: createIdempotencyKey(),
});
const evaluation = await guardian.waitForQwenEvaluation(
  queued.job.id,
  queued.job.profileId,
  { intervalMs: 2_000, maxAttempts: 120 },
);
console.log(evaluation.report.counts);
console.log(
  evaluation.report.cases.map((item) => ({
    caseId: item.caseId,
    proposalOrigin: item.toolCallOrigin,
    decision: item.decision,
    dispatchStatus: item.dispatchStatus,
    simulatedExecution: item.simulatedExecution,
  })),
);
```

The fixed profile IDs are:

- Email: `guardian-agent-qwen-lab-email-v1`
- Database: `guardian-agent-qwen-lab-database-v1`
- Finance: `guardian-agent-qwen-lab-finance-v1`
- Customer service: `guardian-agent-qwen-lab-customer-service-v1`
- Programming: `guardian-agent-qwen-lab-programming-v1`
- Browser: `guardian-agent-qwen-lab-browser-v1`
- Infrastructure: `guardian-agent-qwen-lab-infrastructure-v1`
- Multiagent: `guardian-agent-qwen-lab-multiagent-v1`

The report keeps
`runtime_message_tool_calls`, adapted Qwen markers, unparsed markers and
`no_tool_call` separate. A missing proposal is not a policy denial. The
existing authenticated approval methods can inspect and decide persisted
approvals; only the server's exact, approved synthetic action can run once in
the laboratory clone.

## Current limits

- This is a lab SDK for fixed synthetic scenarios and local Qwen profiles, not a
  production integration to email, databases, banks, cloud, browsers, or
  customer systems.
- A local E2E auth harness is used in tests. A real Clerk browser session has
  not been exercised by this SDK test.
- No calls are made to external systems. `require_approval` is a durable,
  tenant-scoped approval; a successful approval can only replay the exact
  allowlisted synthetic action once in memory.
- Deterministic fixture results and Qwen inference are different engines.
  Qwen is labeled as real only when the validated evidence reports local
  inference; its proposal count is not a general effectiveness measure.
