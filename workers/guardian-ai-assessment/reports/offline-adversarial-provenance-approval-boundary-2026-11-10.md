# Offline adversarial provenance and approval-boundary regression — 2026-11-10

## Starting state and gate

- Starting HEAD: `031244420dca74141f9543821d13a3c3d02b4ca6`; branch `main`;
  clean worktree. No matching Guardian, Qwen, test, or app-dev processes were
  visible before the change.
- The latest saved host preflight is still
  `hostBoundaryReady=false` (SHA-256
  `3b85f5c1aab30012d27df96eec5aabeff7ac932198d45f1dd5536d55903d8445`).
  No Qwen, live worker, Docker/socket operation, PostgreSQL connection, or
  workflow was started.
- No disposable PostgreSQL environment with segregated roles was verified.
  PostgreSQL persistence and runtime RLS therefore remain untested.

## Increment

Strengthened the existing offline all-profile provenance regression in
`tests/test_policy_lab.py`:

- Each vertical now uses an adversarial corpus case when the test supplies
  mocked native, complete-marker adapted, or no-marker responses.
- For `no_tool_call`, the test explicitly requires `no_proposal` /
  `not_invoked`, zero calls, no proposal or action digest, no synthetic
  approval reference, no trusted-scope binding, no tool events, and no Policy
  or simulator invocation.
- The test still verifies `tool_choice=auto` and that a simulated dispatch can
  occur only after the independent Policy ON check in its controlled mock.

This is contract coverage using deterministic mocked outputs, not an LLM
response or new Qwen inference. The pinned eight-fixture baseline and
historical Qwen artifact were not changed. Adapted markers, runtime
`message.tool_calls`, no-proposal, and fixtures remain separate categories.

## Sequential verification

All successful checks below were run in sequence on 2026-11-10:

1. Worker `test_policy_lab.py`: **39/39 passed**.
2. Worker `test_autonomous_tool_selection.py`: **11/11 passed**.
3. Worker `test_qwen_evidence_reconciliation.py`: **6/6 passed**.
4. API `ai-assessment-qwen-evidence.test.ts`: **17/17 passed**.
5. UI `AiEvaluationPage.integration.test.tsx`: **17/17 passed**.

The first worker-test discovery attempt from the repository root failed because
`tests/` is not importable there; direct execution without the worker package
path also failed to import `guardian_ai_assessment`. The correct invocation,
`PYTHONPATH=. python tests/test_policy_lab.py` from the worker directory,
passed. No package or dependency changes were made.

The API and UI checks are offline unit/component tests. They do not prove a
live authenticated preview, database persistence, PostgreSQL RLS, or
concurrent approval behavior.

## Evidence and limits

- Historical Qwen evidence remains unchanged:
  `generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`,
  SHA-256
  `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
  It records 8 historical local inferences: 7 adapted proposals, 0 native
  runtime `message.tool_calls`, and infrastructure `NO_PROPOSAL`. It is not
  current inference evidence.
- Updated worker regression SHA-256:
  `298b7f5124fc491e3f6f685937bd76bf9eff82a8fb845cfdeaa12977d522ee5d`.
- Keep Qwen and privileged-worker execution blocked until host/broker/worker
  isolation is independently attested without API/worker Docker-socket access,
  the sandbox boundary is verified, and DB identities/sessions are segregated.
- Durable approval validation remains blocked pending a safe disposable
  PostgreSQL instance with segregated roles.
