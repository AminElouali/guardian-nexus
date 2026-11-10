# Offline adversarial NO_PROPOSAL regression — 2026-11-10

## Starting state and safety gate

- Starting HEAD: `5f6c6c4f0c2887c091f80d9da78479cdd262eaa6`; branch `main`;
  working tree clean. No matching Guardian, Qwen, test, or app-dev processes
  were present in the process snapshot.
- The saved read-only host preflight remains `hostBoundaryReady=false`.
  It reports Docker socket access by the probe process, unverified API/broker/
  worker identities and DB-session separation, and an unverified Qwen sandbox
  contract. No socket was inspected or contacted in this iteration, and no
  attempt was made to create an attestation from those observations.
- No safe, disposable PostgreSQL instance with segregated roles was verified.
  No credentials or secret values were read, and no DB connection was made.

## Increment

Strengthened the existing mocked `NO_PROPOSAL` contract test to select an
adversarial case for each of the eight verticals. For infrastructure it
specifically selects `qwen_infra_privilege_injection_es`. The mocked response
contains no tool-call marker. The test asserts `tool_choice=auto`, preserves
`no_tool_call` / `no_proposal` / `not_invoked`, and verifies that Policy, the
simulator, proposal/action hashes, and approval references are all absent.

This is deterministic test coverage, not a model response or new inference.
It leaves the eight fixture baselines and the historical evidence artifact
unchanged. Existing offline checks continue to keep runtime `message.tool_calls`,
complete-marker adapted proposals, malformed output, and fixtures distinct;
Policy ON precedes permitted simulation, and Policy OFF is counterfactual only.

## Sequential offline verification

- Worker unit suite `test_policy_lab.py`: **39/39 passed**.
- Worker unit suite `test_autonomous_tool_selection.py`: **11/11 passed**.
- Worker unit suite `test_qwen_evidence_reconciliation.py`: **6/6 passed**.
- API unit/contract suite `ai-assessment-qwen-evidence.test.ts`: **17/17 passed**.
- UI integration suite `AiEvaluationPage.integration.test.tsx`: **17/17 passed**.
- `git diff --check`: passed.

The first worker test invocation was issued from the repository root and failed
because `tests/` is not an importable directory there. Re-running the same
offline suite from `workers/guardian-ai-assessment` passed. No live worker,
Qwen, PostgreSQL, Docker/socket operation, workflow, external service, or
deployment was started.

The API tests verify source/contracts and synthetic approval invariants; they
do not prove PostgreSQL persistence, runtime RLS isolation, or concurrent
approval behavior. The UI tests are component integration tests, not a live
authenticated preview.

## Historical evidence and hashes

- Historical local-Qwen artifact SHA-256:
  `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
  It records eight prior inferences: seven adapted proposals, zero native
  runtime `message.tool_calls`, and infrastructure `NO_PROPOSAL`. It is not
  current inference evidence. The eight fixture baselines are separate.
- Saved preflight SHA-256:
  `3b85f5c1aab30012d27df96eec5aabeff7ac932198d45f1dd5536d55903d8445`.
- Updated worker test SHA-256:
  `7cb6076f51df889096078ec0c9cbd12357c77dfe36b5f99d49aa9f2e753db5f8`.

## Remaining blockers

Keep Qwen and privileged-worker execution blocked until host/broker/worker
separation is independently attested without granting API or worker Docker
socket access, the sandbox boundary is verified, and DB identities/sessions
are segregated. Durable approval/RLS validation additionally requires a
disposable PostgreSQL environment and runtime cross-tenant/role/expiry/replay
tests. Until then, report only offline contracts and historical model evidence.
