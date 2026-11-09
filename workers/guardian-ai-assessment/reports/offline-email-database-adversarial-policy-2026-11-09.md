# Offline adversarial proposal and Policy-order regression — 2026-11-09

## Safety gate

The checked-in host preflight is dated 2026-11-04 and reports
`hostBoundaryReady=false`. The API probe process has read/write access to the
Docker socket; API, broker, and worker identities and database sessions are
unverified; the Qwen sandbox contract is unverified. This is evidence that the
gate must remain closed, not evidence that isolation was established.

No Qwen inference, privileged worker, Docker/socket operation, database
connection, external service, or workflow was started for this increment.

## Offline regression

Added a unit regression using fixed synthetic responses, not model output. For
email and database adversarial corpus cases it checks both provenance paths:

- runtime `message.tool_calls`;
- a complete `<tool_call>…</tool_call>` marker normalized by the existing
  adapter.

For each path the test verifies `tool_choice=auto`, independent Policy returns
`deny` for the trusted-goal scope mismatch, no synthetic dispatch occurs, and
no approval action reference or action digest is produced. The database and
external-email proposals also fail the synthetic adapter's executable-argument
validation; the test preserves that distinct status instead of mislabeling it
as a Policy denial. No fixture is counted as inference.

Existing offline coverage remains in place for benign and adversarial cases
across all eight profiles, strict marker parsing, origin reconciliation,
cross-tenant rejection, Policy ON ordering, `NO_PROPOSAL` no-dispatch/no-
approval behavior, and Policy OFF counterfactual-only behavior.

## Approval/RLS status

The API's offline v3 contract suite checks provenance-bound finance/support
approval digests, tenant binding, expiry/replay/idempotency contract and RLS
source predicates. That suite inspects code/contracts and uses synthetic
evidence; it does **not** establish PostgreSQL persistence, live RLS
isolation, concurrency behavior, or a durable approval. No database was
connected because a disposable development database and isolated credentials
were not verified.

## Verification

Ran sequentially:

- `test_policy_lab.py`: 39/39 passed;
- `test_autonomous_tool_selection.py`: 11/11 passed;
- `test_qwen_evidence_reconciliation.py`: 6/6 passed;
- API `ai-assessment-qwen-evidence.test.ts`: 17/17 passed.

These are offline unit/contract tests. No live worker, PostgreSQL/RLS E2E,
Qwen inference, or UI build was run; UI code was not changed.

## Remaining gate

Before any Qwen or privileged-worker run, independently verify distinct
API/broker/worker identities, deny Docker-socket access to API and worker,
broker-only database credentials/sessions, and the sandbox boundary. Approval
persistence/RLS requires a disposable PostgreSQL environment with segregated
roles and runtime cross-tenant tests. Until both gates are met, keep model and
durable-approval claims limited to historical evidence and offline tests.
