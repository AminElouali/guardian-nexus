# Offline Qwen provenance and approval-contract verification

Date: 2026-11-09

## Scope

Starting HEAD: `5f9d4178db96dc0b0a1250a7b29dd3e64423b4e4` (clean).
No PostgreSQL server process or local listener on ports 5432/5433 was visible.
`psql` is installed, but that does not establish a safe disposable database.
No database environment value or credential was read, and no connection was
attempted.

The existing offline API contract was tightened to pin the historical model
artifact metadata, assert that its eight samples exclude fixtures, and assert
that the artifact itself claims no API job or approval/database persistence.
Infrastructure `NO_PROPOSAL` must have zero tool calls, no proposal/action
hashes, no tool events, `no_tool_call` reason, and no approval provenance.
Fixture provenance remains `controlled_fixture_not_llm`; historical adapted
proposals remain `guardian_qwen_native_markup_adapter`; native runtime calls
remain separately identified as `runtime_message_tool_calls`.

## Historical Qwen evidence only

The pinned artifact is
`generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`,
SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
It records eight historical Qwen3 local model calls: seven adapted marker
proposals, zero native `message.tool_calls`, and one infrastructure
`NO_PROPOSAL`. The artifact says fixtures were excluded, no API job was created,
and approval inbox/database persistence was not performed. No inference was
run in this iteration.

## Verification run, sequentially

- Worker offline policy-lab tests:
  `PYTHONDONTWRITEBYTECODE=1 python -m unittest tests.test_policy_lab`
  — **36/36 passed**.
- Worker historical evidence reconciliation:
  `python -m unittest tests.test_qwen_evidence_reconciliation`
  — **6/6 passed**.
- Targeted API Qwen/approval contracts:
  `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-qwen-evidence.test.ts`
  — **16/16 passed**.
- Full offline API suite:
  `pnpm --filter @workspace/api-server run test` — **85/85 passed**.
- API typecheck — passed.
- Dashboard integration:
  `pnpm --filter @workspace/eu-security-platform exec tsx --test src/components/AiEvaluationPage.integration.test.tsx`
  — **15/15 passed**.
- Dashboard typecheck — passed.

Two initial targeted assertions were overly strict about extra fields in the
pinned JSON metadata, and an initial typecheck found a missing field in the
test's local type. The test was adjusted to assert the required contract fields;
the final targeted test, full API suite, and typechecks passed.

## PostgreSQL/E2E and safety limits

The PostgreSQL-backed synthetic approval E2E was not run. Its test requires
`DATABASE_URL`, calls the RLS readiness check, and writes fixture job/approval
rows. No independently verified disposable database was available from the
read-only local process/listener check, so running it would risk using an
unknown target. This does not verify persisted v3 approvals, live RLS, tenant
isolation, transaction concurrency, replay, idempotency, or durable audit.

The last saved isolation preflight is dated 2026-11-04 and reports
`hostBoundaryReady=false`, including Docker-socket accessibility and sensitive
environment presence; broker and database-session identities are unverified.
It was not rerun. No Qwen inference, live worker, Docker/socket, PostgreSQL,
external service, or deployment was started.

## Next safe step

Provision an explicitly authorized disposable development PostgreSQL instance
with separate runtime/reviewer roles, apply the reviewed RLS policy, then run
the existing synthetic approval E2E against that confirmed target. Verify
cross-tenant denial, role checks, expiry, proposal binding, replay,
concurrency, and idempotency. This database validation does not require Qwen.
Keep the Qwen/worker gate closed until an authorized isolated host passes the
broker, identity, socket, and database-session preflight.
