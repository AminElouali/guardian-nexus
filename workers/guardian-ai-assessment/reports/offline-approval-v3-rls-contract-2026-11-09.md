# Offline approval binding v3 and tenant RLS contract

Date: 2026-11-09

## Finding and change

The worker persists approval candidates with `bindingVersion: 3` and includes
model provenance in the proposal binding. The approval INSERT RLS policy in
both the canonical SQL and the Drizzle schema admitted only binding versions 1
and 2. Under `app_runtime`, that policy rejected the worker's v3 INSERT even
though the table constraint and worker supported v3.

Updated both policy definitions to admit v3 while retaining the existing
workspace/user scope, owner/admin membership, pending-only state, completed-job
requirement, and v3 provenance/hash constraints. Added an offline source
contract test that checks the SQL and Drizzle policy stay aligned with the
worker's v3 insert, `ENABLE/FORCE ROW LEVEL SECURITY`, tenant-scoped membership,
the unique workspace/job/case index, and the adapted/native provenance allowlist.
It also asserts that `no_tool_call` cannot be promoted into an approval origin.

This is a code/source-level fix, not proof that a database has received the
updated policy. The static test reads repository sources; it does not connect to
PostgreSQL or execute the SQL.

## Verification actually run

Sequentially:

- Targeted API Qwen evidence/approval contract test:
  `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-qwen-evidence.test.ts`
  — **16/16 passed**.
- API offline test suite:
  `pnpm --filter @workspace/api-server run test` — **85/85 passed**.
- API TypeScript check:
  `pnpm --filter @workspace/api-server run typecheck` — passed.
- `git diff --check` — passed.

The first targeted run exposed an incorrect relative path in the new static
test; that path was corrected, after which the targeted and full suites passed.

## Not verified / gates kept closed

- No PostgreSQL connection, migration/application of the policy, live RLS,
  `app_runtime` insert, concurrent database decisions, or durable audit was
  tested. The database-backed approval E2E was not run; no database target or
  credentials were inspected.
- No Qwen inference, live worker, Docker/socket, service workflow, or deploy
  was started. The last saved preflight (2026-11-04) says
  `hostBoundaryReady=false`; it was not repeated. Keep Qwen/worker closed.
- Current model evidence remains historical only: eight calls, seven adapted
  proposals, zero native `message.tool_calls`, and infrastructure
  `NO_PROPOSAL`. Fixtures remain distinct from those model calls.

## Next verification

On an authorized, disposable development PostgreSQL target, apply the reviewed
RLS SQL and verify that `app_runtime` can create a v3 approval from a pinned
synthetic adapted proposal, while cross-tenant, non-reviewer, expired, altered
binding, replay, and concurrent-decision cases remain denied or idempotent.
This database test does not require Qwen and must not be described as fresh
model inference.
