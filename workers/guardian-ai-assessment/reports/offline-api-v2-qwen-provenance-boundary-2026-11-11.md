# API v2 offline Qwen evidence provenance boundary — 2026-11-11

## Change and result

- Added one focused synthetic regression in
  `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`.
- No production code, queue/broker gates, or baseline fixtures changed.
- The test passes a hash-consistent artifact labeled
  `real_local_qwen_inference_offline_process_guard` to the API v2 live-evidence
  validator and confirms rejection with
  `identity_provider_network_or_limits`.
- The same test separately checks adapted marker proposals, native runtime
  `message.tool_calls`, deterministic fixtures, and `NO_PROPOSAL`. This is
  provenance-contract coverage using `makeEvidence()` and fixed synthetic
  inputs; it is not new Qwen inference and does not count test data as a live
  model result.
- The existing broker identity gate and disabled local assessment enqueue
  behavior remain unchanged while host readiness is not independently
  attested.

## Tests run in this increment

Executed serially, without starting services:

1. `pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern='API v2 rejects offline process-guard evidence as live and preserves provenance classes' src/lib/ai-assessment-qwen-evidence.test.ts`
   — **1/1 passed**.
2. `pnpm --filter @workspace/api-server run typecheck`
   — **passed**.
3. `git diff --check`
   — **passed** after adding the test; will be checked again after this report
   and checkpoint update.

Not run: Qwen, workers, Docker/socket, PostgreSQL/migrations, API/E2E/UI
services, external services, or deployment. No inference, database persistence,
RLS runtime, or live dispatch is established by this change.

## SHA-256

- Test file:
  `58c89ccfda5aed488e6d1a4d26ca2eb54efdf6f33e423816fc182d3a3f769e53`

Next operational gate remains an independent host/broker/worker attestation
bound to the current relevant source hashes. Only after that gate is verified
should the authorized disposable-lab path be considered.
