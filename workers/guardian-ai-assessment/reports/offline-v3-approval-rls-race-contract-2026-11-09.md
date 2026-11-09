# Offline approval v3 RLS and replay-boundary verification

Date: 2026-11-09

## Starting state and database safety

Starting HEAD: `b9d5323d4a9443daf72892d90434ede8dd46b764`; Git was clean.
The read-only host check found no PostgreSQL/postmaster process, no listener on
ports 5432/5433, and no active local PostgreSQL service. No database environment
values or credentials were read, and no database connection was attempted.
The managed development database was not assumed to be disposable. Therefore,
the PostgreSQL-backed approval E2E was not run.

The saved host preflight remains the 2026-11-04 record with
`hostBoundaryReady=false`. It was not rerun; the Docker socket was not accessed.
Qwen inference, a live worker, external services, and deployment were not
started.

## Offline regression coverage added

`artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts` now:

- rejects an internally rehashed synthetic evidence case that attempts to
  relabel a no-proposal result as an adapted proposal;
- checks the SQL and Drizzle approval policies for tenant-scoped reads and
  writes, membership roles, pending-only decisions, expiry, non-self-approval,
  reviewer identity, and column-scoped update grants;
- checks that the API decision update is a conditional compare-and-set over
  tenant, pending status, proposal binding, expiry, and unused simulation
  receipt, and that a losing concurrent request is rejected;
- checks that replay remains an in-memory synthetic clone and that the
  PostgreSQL E2E source retains cross-tenant, one-winner concurrency, and replay
  rejection cases.

The historical infrastructure profile remains `NO_PROPOSAL`: zero calls,
proposal/action hashes, tool events, dispatch, or approval provenance. The
eight-profile artifact is unchanged and remains historical evidence, not a new
inference or an API-to-worker integration run.

These source-contract tests do **not** prove that the reviewed SQL is applied
to a live PostgreSQL database, that the runtime role is configured correctly,
or that RLS predicates work under real sessions.

## Verification performed serially

1. Worker offline policy lab: `tests.test_policy_lab` — **36/36 passed**.
2. Worker evidence reconciliation: `tests.test_qwen_evidence_reconciliation`
   — **6/6 passed**.
3. Targeted API evidence/approval contracts — **17/17 passed**.
4. Full offline API suite — **86/86 passed**.
5. API TypeScript typecheck — passed.
6. Dashboard integration — **15/15 passed**.
7. Dashboard TypeScript typecheck — passed.
8. `git diff --check` — passed.

No PostgreSQL approval E2E or live RLS check was run. Persisted Qwen-derived
approval, actual tenant isolation, database concurrency behavior, and durable
audit remain unverified.

## Evidence classification and next gate

The pinned Qwen artifact
`generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`
has SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`. It
records eight historical local model calls: seven adapted proposals, zero
native `message.tool_calls`, and one infrastructure `NO_PROPOSAL`. Fixtures
remain distinct. No Qwen-origin approval was persisted or tested.

The next persistence check requires an explicitly authorized disposable
development PostgreSQL target, with separate non-privileged runtime and
reviewer roles. Apply the reviewed RLS policy, then run the existing synthetic
approval E2E and verify cross-tenant denial, role and expiry checks, proposal
binding, one-winner concurrency, replay rejection, idempotency, and audit rows.
Keep Qwen and the worker blocked until the host/broker/identity isolation
preflight is independently satisfied.
