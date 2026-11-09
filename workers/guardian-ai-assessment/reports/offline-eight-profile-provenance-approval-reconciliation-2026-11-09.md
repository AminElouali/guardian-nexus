# Guardian Nexus offline eight-profile provenance and approval reconciliation

Date: 2026-11-09

## Scope

Offline-only incremental verification from HEAD `52c0d270971c8399e4719c4affbc7d8b0f6cb6af`.
Added an API-side cross-layer regression over the pinned historical worker
artifact. It reconciles all eight profile origins and Policy ON dispatch states,
keeps adapted Qwen markup distinct from native runtime calls and no-proposal,
checks that only the exact finance/support cases resolve to their synthetic
approval allowlist entries, and verifies authorization precedes the two
synthetic dispatches.

The regression does not invoke Qwen or a worker, write PostgreSQL, start a
workflow, access the Docker socket, or change policy. Its input is historical
evidence, not a new inference. Existing deterministic fixture approval tests
remain explicitly fixture-only.

## Verification run serially

- Worker policy lab: `PYTHONDONTWRITEBYTECODE=1 python -m unittest tests.test_policy_lab` — **36/36**.
- Worker evidence reconciliation: `PYTHONDONTWRITEBYTECODE=1 python -m unittest tests.test_qwen_evidence_reconciliation` — **6/6**.
- API evidence/approval suite: `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-qwen-evidence.test.ts` — **14/14**.
- API TypeScript check: `pnpm --filter @workspace/api-server run typecheck` — passed.
- Dashboard integration: `pnpm --filter @workspace/eu-security-platform exec tsx --test src/components/AiEvaluationPage.integration.test.tsx` — **15/15**.
- Dashboard TypeScript check: `pnpm --filter @workspace/eu-security-platform run typecheck` — passed.
- `git diff --check` — passed.

The first API test attempt and first typecheck exposed errors in the newly
written test assertions; they were corrected, then the complete listed sequence
passed. No application or database workflow was started.

## Approval and isolation limits

Approval expiry, tenant/proposal/action/identity binding, replay digest fields,
and repeatable in-memory clone receipts are covered by offline contract tests.
These tests do **not** prove PostgreSQL persistence, live RLS, transaction
concurrency, durable audit, or a human decision on a Qwen-originated proposal.
The PostgreSQL-backed synthetic approval E2E was not run: no database-backed
test target was independently verified safe and available, and this change did
not read credentials or open a database connection.

The saved host preflight remains blocked/unverified
(`hostBoundaryReady=false`); it was not repeated. No Qwen inference, real
worker, Docker/socket, database, external service, deployment, or publication
was performed. Keep the live gate closed.

The pinned historical artifact remains SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`: eight
historical local model calls, seven adapted proposals, zero native
`message.tool_calls`, and one infrastructure `NO_PROPOSAL`. It is not evidence
of a fresh run or of API-to-worker isolation.

## Changed-file hashes

- API cross-layer regression test:
  `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`
  SHA-256: `1567a4627f29befe3bebbd843df4e9bf41278655a46f679412b9a4425b495182`.
- This report SHA-256:
  `e4d40330d8df0442d6b1f4e99d9ba9de5c60777b132ad1baf2aab7559251a386`.
- Historical Qwen artifact SHA-256:
  `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.

## Next safe gate

On an authorized isolated host, verify distinct API/worker/broker identities,
broker-only Docker socket access, and independent PostgreSQL roles/sessions.
Then run the database-backed synthetic approval lifecycle against a confirmed
disposable development database, followed by API-to-worker Qwen tests with a
verified proposal. Do not use this historical artifact or fixtures as fresh
inference.
