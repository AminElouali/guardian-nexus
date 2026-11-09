# Offline proposal provenance, Policy order, and API outage UX — 2026-11-09

## Scope and changes

Starting point: HEAD `c92d42aeeb46748a9f6327aecb99d3ce1b3b05e1`, clean tree,
with no Guardian Nexus, Qwen, or test process active.

- Added a worker regression using fixed test doubles for all eight profiles.
  It verifies that `runtime_message_tool_calls`, complete adapted Qwen markers,
  and `no_tool_call` remain distinct. Both proposal origins require an
  independent Policy ON decision before the synthetic dispatcher; a missing
  proposal invokes neither Policy nor the dispatcher. This test is not model
  inference and does not alter the eight deterministic fixtures.
- Clarified the client-facing gateway error (`502/503/504`) as API
  unavailability. The retry path remains available, internal details remain
  hidden, and UI coverage asserts that an outage cannot render a success claim.
- Existing offline coverage remains responsible for injection cases, finance
  and support approval-binding contracts, expiry/replay and fixture-vs-model
  provenance. Those contracts do not establish PostgreSQL persistence or live
  RLS.

## Verification, run sequentially

1. Worker `test_policy_lab.py`: **38/38 passed**.
2. Worker `test_autonomous_tool_selection.py`: **11/11 passed**.
3. Worker `test_qwen_evidence_reconciliation.py`: **6/6 passed**.
4. API `ai-assessment-qwen-evidence.test.ts`: **17/17 passed**.
5. UI `AiEvaluationPage.integration.test.tsx`: **17/17 passed**.
6. UI `workspace-load-errors.test.ts`: **4/4 passed**.
7. API and web TypeScript checks: passed.
8. Web build: passed with `PORT=5173 BASE_PATH=/eu-security-platform`.
   An initial build without the required `PORT` failed during Vite config
   loading, before compilation; it was rerun successfully with required values.
9. API build: passed. `git diff --check`: passed.

The web build retains existing warnings about the tooltip sourcemap and a
minified chunk exceeding 500 kB.

## Limits

No Qwen inference, live worker, PostgreSQL, Docker/socket, external service,
workflow, or deployment was started. The saved host preflight from 2026-11-04
still reports `hostBoundaryReady=false` and was not refreshed. Thus the new
worker tests are deterministic test-double coverage only.

The last Qwen evidence remains historical: eight calls, seven adapted
proposals, zero runtime-native `message.tool_calls`, and one infrastructure
`NO_PROPOSAL`. The eight baseline fixtures remain separate. Approval v3,
tenant RLS, persistence, concurrency and replay have only offline contract
coverage; no PostgreSQL-backed behavior is claimed.

The `/ai-evaluations` UI code now explains gateway errors as API unavailability
and avoids claiming success. This turn did not start the configured web/API
workflows or verify the live authenticated preview. When the API workflow is
stopped, the proxy may still return `502`; restoring the workflow is an
operational prerequisite, not evidence that data loaded.

## SHA-256 evidence

- `tests/test_policy_lab.py`:
  `b258e6885a4557a746f727a8bead3fa024465cdc5c8bf54515651c67b7640b66`
- `artifacts/eu-security-platform/src/lib/workspace-load-errors.ts`:
  `46730a997832a6c4a8c87caed4ce0a737a58b522e58adb0a0678620815e45652`
- `artifacts/eu-security-platform/src/components/AiEvaluationPage.integration.test.tsx`:
  `23b4fce10f3fbc17e828692f8db12a3548b570c953c07cafab96aaa284fc460a`
- Historical Qwen artifact:
  `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`
- Saved preflight (2026-11-04):
  `3b85f5c1aab30012d27df96eec5aabeff7ac932198d45f1dd5536d55903d8445`

Next safe gates: verify the separately isolated host/broker boundary before
Qwen or a live worker, and obtain an explicitly disposable PostgreSQL database
with separated roles before approval/RLS E2E. Restart the configured API and
web workflows before claiming current preview availability.
