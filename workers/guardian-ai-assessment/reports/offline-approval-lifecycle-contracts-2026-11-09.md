# Guardian Nexus offline approval lifecycle contract check

Date: 2026-11-09

## Scope

Incremental offline validation from `11091221e4b7c55d461fb75c10ce5df4ab17dba3`.
No Qwen inference, real worker execution, Docker/socket access, live preflight,
PostgreSQL E2E, external service, deployment, or publication was performed.

This change factors the existing pending-and-unexpired approval predicate into
a pure helper used by the API route and tests the exact expiry boundary. It
also expands deterministic approval-contract tests for finance and support:
tenant/request/proposal/action/role/expiry binding, replay digest binding to
reviewer/role/time/result, and repeatable in-memory clone receipts. These are
contract and clone tests; they do not establish PostgreSQL persistence,
transactional audit durability, or a Qwen-originated approval.

The UI fixture result test now asserts `deterministic_fixture`,
`controlled_fixture_not_llm`, and `modelInference=false` and rejects copy that
would call that fixture a real Qwen inference.

## Offline evidence

- Worker policy corpus: `test_policy_lab.py`, 36/36 passed. Existing coverage
  verifies benign and adversarial synthetic cases in all eight profiles,
  untrusted injection denial before dispatch, and fixture provenance.
- Worker evidence reconciliation: `test_qwen_evidence_reconciliation.py`,
  6/6 passed. Existing coverage verifies the pinned historical eight-profile
  artifact, its seven adapted proposals, zero runtime-native calls, and
  infrastructure `NO_PROPOSAL` without dispatch.
- API evidence/approval contracts:
  `ai-assessment-qwen-evidence.test.ts`, 12/12 passed.
- Dashboard UI integration:
  `AiEvaluationPage.integration.test.tsx`, 15/15 passed.
- API and UI TypeScript checks passed; `git diff --check` passed.

The historical Qwen artifact remains unchanged at SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
Its evidence remains historical offline-process inference, not a new run or an
isolated API-to-worker execution. Its seven proposals were adapted markers;
native `message.tool_calls` count remains zero; infrastructure remains
`NO_PROPOSAL`. Deterministic fixtures are reported separately.

## Changed-file hashes

- `artifacts/api-server/src/lib/ai-assessment-approval-actions.ts`:
  `e1e9c627095551546fe7a5c829a8367d05e108834b0930bc7ac70b9ff47d379f`
- `artifacts/api-server/src/routes/ai-assessment-lab.ts`:
  `f9e8e32b928f519adc93c0590e688d5e0af7457678d2ebd3a4c1288321f2570f`
- `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`:
  `3e53fb0b41391cc0b4555a8dde8e95ee3000f0b553f9bb3ffd7e094e88f66777`
- `artifacts/eu-security-platform/src/components/AiEvaluationPage.integration.test.tsx`:
  `cd20dd300bb92b70ec703437964409086707be16330f6cbea0198a29d4feaab1`
- `workers/guardian-ai-assessment/tests/test_policy_lab.py`:
  `9a7db5aaaaffcff33b3ad1724925e156024325d9661ea02471fe1479d6e0d7c6`
- `workers/guardian-ai-assessment/tests/test_qwen_evidence_reconciliation.py`:
  `308e83a3c6abc69634ff2e1e962ecefe01a35fb78ef7c8c14f5f91625367ae8c`

## Limits and next gate

No claim is made that approvals are persisted or that the broker/worker is
isolated. The saved host-boundary state remains unverified/blocked. Before any
Qwen or real-worker run, an authorized isolated host must demonstrate distinct
API/worker/broker identities, Docker socket access restricted to the broker,
and separated database roles/sessions. After that, run the API-to-worker
synthetic path and a database-backed approval lifecycle test in that verified
environment. Until then, keep the live gate closed.
