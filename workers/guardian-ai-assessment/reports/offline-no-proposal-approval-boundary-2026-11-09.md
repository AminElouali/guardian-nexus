# Offline NO_PROPOSAL and approval-boundary regression — 2026-11-09

## Scope

Starting point: HEAD `0e1aac3edc79d462da1ed638cafcd31603a58a63`, clean tree,
and no Guardian Nexus, Qwen, or test process active.

The existing explicit-no-marker regression already covered all eight verticals,
but did not assert that the independent Policy Engine was never called or that
the result had no approval/action binding. The test now checks both boundaries
for every profile: no proposal hash, synthetic action reference, or action hash;
Policy evaluation and synthetic dispatch are not called; the result remains
`no_tool_call` / `no_proposal` / `not_invoked`. This also protects the
historical infrastructure `NO_PROPOSAL` case from being turned into a proposed
or approval-eligible action.

The test uses a fixed fake client with `tool_choice=auto`. It is an offline
contract regression, not a Qwen inference, worker run, or live approval test.
No fixtures or historical evidence were changed.

## Verification, executed sequentially

1. `tests.test_policy_lab`: **37/37 passed**.
2. `tests.test_autonomous_tool_selection`: **11/11 passed**.
3. `tests.test_qwen_evidence_reconciliation`: **6/6 passed**.
4. API `ai-assessment-qwen-evidence.test.ts`: **17/17 passed**.
5. `git diff --check`: passed.

The API suite checks provenance and approval contracts offline. No UI code was
changed, so the UI suite was not rerun. No PostgreSQL E2E was run and no live
RLS or durable approval persistence is claimed.

## Gate and evidence limits

The saved host preflight is dated 2026-11-04 and reports
`hostBoundaryReady=false`; it was not refreshed in this increment. API, broker,
and worker identities/database sessions remain unverified in that record. No
Qwen, privileged worker, Docker/socket, PostgreSQL connection, external service,
workflow, or deployment was started.

The pinned Qwen artifact remains historical: eight model calls, seven adapted
Qwen markup proposals, zero runtime-native `message.tool_calls`, and one
Infrastructure `NO_PROPOSAL`. The eight deterministic fixtures remain separate.
No new inference or API-to-isolated-worker run is evidenced. Finance/support
approval persistence, live PostgreSQL RLS, concurrent replay, and durable
audit remain unverified.

## Evidence hashes and next gate

- Updated worker test: `tests/test_policy_lab.py` — SHA-256 recorded in
  `MVP_CHECKPOINT.md`.
- Historical Qwen artifact:
  `generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`
  — `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
- Saved host preflight:
  `reports/lab-host-preflight-2026-11-04.json` —
  `3b85f5c1aab30012d27df96eec5aabeff7ac932198d45f1dd5536d55903d8445`.

Next gate: independently verify segregated host/broker/worker identities and
provide an explicitly disposable PostgreSQL target with separated roles before
attempting Qwen, privileged worker execution, or approval/RLS E2E.
