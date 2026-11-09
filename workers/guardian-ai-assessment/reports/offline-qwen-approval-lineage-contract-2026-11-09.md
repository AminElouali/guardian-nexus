# Offline Qwen proposal-to-approval lineage contract

Date: 2026-11-09

## Scope and result

From base HEAD `219879218614f091ee82cba3a262d64b5c572c28`, added one API-side
offline regression that composes the pinned historical eight-profile artifact
with the existing evidence validator, Policy ordering assertions, approval
allowlist, provenance-aware proposal binding, expiry check, reviewer replay
digest, and deterministic in-memory simulation receipt.

The test begins with the benign email and database cases and confirms their
adapted proposal origins, `tool_choice=auto`, `ALLOW`, Policy authorization
before the synthetic dispatch, and no Policy-OFF execution. It then follows the
historical adapted finance and support cases through `REQUIRE_APPROVAL`, no
dispatch, exact allowlisted proposal/action hashes, tenant-bound proposal
binding, expiry, reviewer-role-bound replay digest, and a fixed synthetic clone
receipt. Infrastructure remains `NO_PROPOSAL` and cannot be promoted into an
approval request.

The test is contract-level and read-only with respect to the historical
artifact. The approval receipt operates on a fixed in-memory clone. It does not
create or persist approval rows, execute a live worker, call Qwen, or prove
PostgreSQL/RLS behavior. Fixtures remain separate from model evidence.

## Serial verification

- Worker policy lab:
  `PYTHONDONTWRITEBYTECODE=1 python -m unittest tests.test_policy_lab` —
  **36/36 passed**.
- Worker historical-evidence reconciliation:
  `PYTHONDONTWRITEBYTECODE=1 python -m unittest tests.test_qwen_evidence_reconciliation`
  — **6/6 passed**.
- API Qwen evidence and approval contracts:
  `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-qwen-evidence.test.ts`
  — **15/15 passed**.
- API TypeScript check:
  `pnpm --filter @workspace/api-server run typecheck` — passed.
- Dashboard integration:
  `pnpm --filter @workspace/eu-security-platform exec tsx --test src/components/AiEvaluationPage.integration.test.tsx`
  — **15/15 passed**.
- Dashboard TypeScript check:
  `pnpm --filter @workspace/eu-security-platform run typecheck` — passed.
- `git diff --check` — passed.

The first targeted run exposed an incorrect expected support case ID in the new
test. The expectation was corrected to the ID in the pinned artifact, and the
complete serial sequence above then passed.

## Explicitly not verified

- No fresh Qwen inference, worker execution, Docker/socket access, service
  workflow, PostgreSQL connection, or deployment was started.
- PostgreSQL-backed approval persistence, live RLS, transaction concurrency,
  and durable audit remain unverified. The PostgreSQL E2E was not run because
  no independently verified disposable database target was provided; no
  credentials or database environment values were read.
- The last saved host preflight is dated 2026-11-04 and reports
  `hostBoundaryReady=false`; it was not repeated in this offline cycle. Keep
  the Qwen/worker gate closed.
- The historical artifact is pinned at SHA-256
  `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`. It
  records eight historical model calls, seven adapted proposals, zero native
  `message.tool_calls`, and one infrastructure `NO_PROPOSAL`; it is not a new
  run or API-to-worker isolation evidence.

## Changed-file hash

- `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`:
  `a6b3466f6bfddcf401c3c5a8d3b94cf237f08e410b4bc21f8f4a065d8dcfe44b`.

## Next safe gate

On an authorized isolated host, prove distinct API, worker, and broker
identities, broker-only Docker socket access, and independent PostgreSQL
roles/sessions. Then run the existing synthetic approval API E2E against a
confirmed disposable development database. Only after the isolation gate
passes should fresh Qwen-to-API/worker runs be attempted and separately
classified as native calls, adapted proposals, or no proposal.
