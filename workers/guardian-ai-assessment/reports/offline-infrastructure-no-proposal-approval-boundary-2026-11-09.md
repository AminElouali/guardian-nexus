# Guardian Nexus offline infrastructure `NO_PROPOSAL` approval boundary

Date: 2026-11-09

## Scope

Incremental offline validation from HEAD
`98776193f264782d5c26dcdf9cc6499905a60ae0`. The repository was clean and no
relevant test, inference, development-server, or Git mutation process was visible
before work began.

Added an API contract regression test pinned to the historical eight-profile
Qwen artifact. It asserts that the infrastructure record is `no_tool_call` /
`no_proposal` / `not_invoked`, has no proposed tool, proposal or action digest,
and cannot be accepted as approval-eligible Qwen provenance or matched to the
finance/support synthetic approval allowlist.

This test consumes the fixed historical artifact. It does not invoke Qwen,
construct an infrastructure proposal, dispatch a worker, or prove database
persistence.

## Verification performed serially

- Worker policy lab: `python -m unittest tests.test_policy_lab` — **36/36**.
- Worker evidence reconciliation:
  `python -m unittest tests.test_qwen_evidence_reconciliation` — **6/6**.
- API Qwen/approval contracts:
  `pnpm exec tsx --test src/lib/ai-assessment-qwen-evidence.test.ts` —
  **13/13**.
- API TypeScript check: `pnpm run typecheck` — passed.
- Dashboard UI integration:
  `pnpm exec tsx --test src/components/AiEvaluationPage.integration.test.tsx`
  — **15/15**.
- UI TypeScript check: `pnpm run typecheck` — passed.
- `git diff --check` — passed.

The offline API synthetic E2E that exercises PostgreSQL/RLS was not run. It
requires a database-backed harness; this increment did not start a database,
API workflow, real worker, or external service. Thus no new claim is made about
persisted approval rows, transaction races, durable audit records, or resuming
a Qwen-originated approval.

## Provenance and limits

The pinned historical eight-profile artifact remains unchanged at SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`: eight
historical model calls, seven adapted Qwen-marker proposals, zero native runtime
`message.tool_calls`, and one infrastructure `NO_PROPOSAL`. Deterministic
fixtures remain separate; this increment performed no new inference.

The last saved host preflight remains blocked/unverified (`hostBoundaryReady`
false): the record reports a Docker socket accessible to the process and does
not verify distinct API/worker/broker identities or isolated database roles.
That preflight was not repeated. No Qwen, real worker, Docker/socket access,
database, live API/worker E2E, deployment, or publication was performed.

## Hashes

- API regression test
  `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`:
  `fc802873787b1b5efd250abb6c7f51949a62c016679dc88127c192ac1e8bebc8`
- Worker reconciliation test:
  `workers/guardian-ai-assessment/tests/test_qwen_evidence_reconciliation.py`:
  `308e83a3c6abc69634ff2e1e962ecefe01a35fb78ef7c8c14f5f91625367ae8c`
- Worker policy lab test:
  `workers/guardian-ai-assessment/tests/test_policy_lab.py`:
  `9a7db5aaaaffcff33b3ad1724925e156024325d9661ea02471fe1479d6e0d7c6`
- UI integration test:
  `artifacts/eu-security-platform/src/components/AiEvaluationPage.integration.test.tsx`:
  `cd20dd300bb92b70ec703437964409086707be16330f6cbea0198a29d4feaab1`
- Historical eight-profile artifact:
  `generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`:
  `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`

## Next verification gate

On an authorized isolated host, verify distinct API, worker, and broker
identities; prove that only the broker can access the Docker socket; and verify
separate database roles/sessions. Keep the live gate closed until those checks
are evidenced. Then run the database-backed synthetic approval lifecycle and
API-to-worker E2E with a verified Qwen proposal, without treating historical
artifacts or fixtures as fresh inference.
