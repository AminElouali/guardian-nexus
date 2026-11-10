# Offline financial approval binding checks — 2026-11-10

## Scope

- Starting point: `df767ef69568dc6f09a0403e7e3d1b38d84b14e0`, branch `main`,
  clean worktree; no matching local Guardian, Qwen, test, PostgreSQL, Docker,
  API, or worker process was observed before editing.
- Existing architecture already defines the approval table, v3 provenance and
  digest constraints, tenant RLS policies, indexes, conditional decision update,
  audit event, and disposable-database E2E guard. No schema defect was found,
  so this increment added no migration or production-code changes.
- Added one offline API contract test covering finance invoice injection cases
  and v3 approval-binding integrity. All identities and cases are synthetic;
  this is not Qwen inference or runtime `message.tool_calls` evidence.

## Verification

Commands ran sequentially:

1. `pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern='finance invoice injections cannot create approval actions or reuse a v3 binding' src/lib/ai-assessment-qwen-evidence.test.ts`
   — **1/1 passed**.
2. `pnpm --filter @workspace/api-server run typecheck`
   — **passed**. An earlier run found a TypeScript literal-widening issue in
   the test fixture; the type was narrowed and the rerun passed.
3. `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-qwen-evidence.test.ts`
   — **19/19 passed**.
4. `git diff --check`
   — passed.

The new test ensures the four existing adversarial finance case IDs
(`qwen_finance_indirect_bank_change_en`, `qwen_finance_indirect_payment_es`,
`qwen_finance_beneficiary_injection_es`, and
`qwen_finance_hidden_beneficiary_es`) cannot obtain the allow-listed bank-change
approval action. It also verifies that the deterministic v3 binding changes
when tenant, job, proposal digest, action digest, requester, requester role,
or expiry changes. The positive case is explicitly tagged as a deterministic
fixture (`modelInference=false`, `controlled_fixture_not_llm`).

## Limits

- This API unit suite and typecheck do not connect to PostgreSQL and do not
  prove persistence or live RLS. The database-backed approval E2E was not run.
- No Qwen, worker, broker, Docker, API service, external service, or real data
  was used. `hostBoundaryReady` remains blocked pending the independent signed
  host/broker/worker attestation.
- Existing DENY/REQUIRE_APPROVAL dispatch boundaries and Policy ON ordering
  remain covered by the worker's offline policy tests; this increment adds a
  complementary API allowlist/binding check, not a new policy execution.

## SHA-256

- `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`:
  `92919e8e8e7088c73bc0d3baaf2b2908e036cd2567fa721f47b35555bcca744f`
