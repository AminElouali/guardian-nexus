# Email/database API v2 adapter-provenance contract — 2026-11-11

## Change

- Added one parametrized API unit regression for email and database synthetic
  marker responses in
  `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`.
- Each fixed `<tool_call>...</tool_call>` response is passed to the existing
  Python `adapt_qwen_native_tool_markup` implementation. The test then carries
  the adapter-derived provenance and call count into a hash-consistent
  API-evidence envelope.
- For both profiles, the test confirms the runtime supplied no native
  `message.tool_calls`, the adapter produced one adapted proposal, and API v2
  rejects `real_local_qwen_inference_offline_process_guard` as live inference.
  The approval-provenance resolver also refuses to promote this offline
  synthetic result to live inference.
- These are fixed test inputs, not model output. This does not demonstrate a
  new Qwen inference, a live API/worker integration, or a completed agent
  profile.
- No production code, Policy Engine behavior, worker gate, queue, or baseline
  fixtures changed. Existing `NO_PROPOSAL`, fixture, adapted-proposal, native
  runtime-call, and live-inference categories remain separate.

## Verification performed in this increment

Executed serially:

1. `pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern='email and database marker-adapter output stays offline and is rejected as live API v2 evidence' src/lib/ai-assessment-qwen-evidence.test.ts`
   — **1/1 passed**. The test invokes a constrained `python3` subprocess only
   to import and call the marker adapter with fixed JSON. The environment is
   allowlisted; no model client is constructed.
2. `pnpm --filter @workspace/api-server run typecheck`
   — **passed**.
3. `git diff --check`
   — **passed**.

Not run: Qwen/model loading, workers, broker, Docker/socket, PostgreSQL,
migrations, API services, E2E/UI services, network calls, or deployment. Policy
ordering and simulator behavior were not re-executed in this increment; their
production code was not changed.

## SHA-256 and limits

- Test file:
  `29cca2c299ff7ea9e6170c95b57ae777fba07f16f6cf60fd3e9e509bd3ac23f1`
- This report's SHA-256 is recorded in `MVP_CHECKPOINT.md`.
- Base HEAD: `1eafc66d20cd22dc58e9bcad30036de090aaa354`.
- `hostBoundaryReady` remains unverified/false per the latest recorded
  attestation status. No new live inference evidence was produced.

## Next increment

Keep Qwen and worker execution blocked until an independent host/broker
attestation passes. After that, wire the existing email/database runner
evidence into the API v2 queue path behind the current gate and verify it in
the authorized synthetic lab. Until then, only offline contract tests are
supported.
