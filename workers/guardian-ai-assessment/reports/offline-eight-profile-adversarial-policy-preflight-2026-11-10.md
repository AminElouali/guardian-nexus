# Offline eight-profile adversarial proposal and preflight check — 2026-11-10

## Starting state and safety

- Starting HEAD: `834e6760e224989ef091f67b68d48451f955281f`; branch `main`;
  clean tree and no matching Guardian/Qwen/test/dev-server process observed.
- Ran only the default read-only host metadata preflight. It does not connect
  to Docker/PostgreSQL or launch child identity/database probes.
- Fresh observation: `hostBoundaryReady=false`,
  `integratedAssessmentReady=false`, `qwenInferenceRun=false`,
  `dockerCallsMade=0`, `databaseConnectionsMade=0`,
  `externalConnectionsMade=0`, and `credentialValuesRead=false`.
  The Docker socket metadata reports present and readable/writable by this
  probe process; API/broker/worker identities, DB session separation, and the
  Qwen sandbox contract remain unverified. Four sensitive environment-variable
  names are present; their names and values were not output or read.
- Preflight evidence digest: `e1dbb18fed636bda22387b180714d28877e73998494d46dbd7a973811061eade`.
  No inference or worker-service execution was attempted. No disposable
  PostgreSQL with segregated roles was available for verification.

## Increment

Expanded the offline worker regression from email/database to all eight
verticals. Each mocked native-call and complete-marker-adapted response is
paired with a profile-specific adversarial synthetic case and sent through the
independent policy check. Tests require denial and no simulator dispatch;
provenance remains `runtime_message_tool_calls` or
`guardian_qwen_native_markup_adapter`, never a fixture or a live model result.
Cases cover untrusted email, cross-tenant database deletion, beneficiary
change, support refund injection, secret-command injection, external-form
injection, infrastructure privilege injection, and multiagent permission
laundering. The two non-executable proposal types retain their parser/adapter
block status. No-proposal and fixtures remain separate.

This tests deterministic mocked responses only. It does not create Qwen
inference evidence, enable a tool, or prove PostgreSQL persistence/RLS.

## Sequential offline tests

Run on 2026-11-10 after the test change:

- Worker `test_policy_lab.py`: **39/39 passed**.
- Worker `test_autonomous_tool_selection.py`: **11/11 passed**.
- Worker `test_qwen_evidence_reconciliation.py`: **6/6 passed**.
- Worker `test_offline_isolation_preflight.py`: **15/15 passed**.
- Worker `test_lab_host_preflight.py`: **6/6 passed**.
- Worker `test_cross_layer_qwen_contract.py`: **2/2 passed**.
- API `ai-assessment-qwen-evidence.test.ts`: **17/17 passed**.
- UI `AiEvaluationPage.integration.test.tsx`: **17/17 passed**.

These include unit/source-contract and component tests, not a live authenticated
preview or DB E2E. The DB-backed approval E2E was not run because no safe,
disposable PostgreSQL was verified. No workflows, Docker/socket operation,
Qwen, live worker, external service, or deployment was started.

## Historical evidence and blockers

- Worker test file SHA-256:
  `0200f0f38b5522a2fef40f01c8fc355a84726fa4f3f18e9899bfa58b8309ba0c`.
- The pinned Qwen artifact remains historical and unchanged:
  `generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`,
  SHA-256
  `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
  It records eight historical inferences: seven adapted proposals, zero native
  runtime `message.tool_calls`, and infrastructure `NO_PROPOSAL`. Eight fixture
  baselines remain separate. No Qwen inference was run in this iteration.
- Until host/broker/worker isolation is independently attested without API or
  worker Docker-socket access, and DB identities/sessions plus the sandbox
  boundary are verified, keep Qwen and live worker execution blocked.
- Durable tenant-safe approvals and RLS still need a disposable PostgreSQL
  instance with segregated roles and runtime cross-tenant/role/expiry/replay
  checks. Current coverage is contractual only.
