# Offline parser, infrastructure no-proposal, and approval v3 contracts

Date: 2026-11-09

## Safety and target availability

Starting HEAD: `c297ca1e58a92a91279a5e6d0cb6e80085a85f6c`, clean.
Read-only process and listener checks found no PostgreSQL/postmaster process,
no local listener on ports 5432/5433, and no active local PostgreSQL service.
No database environment values or credentials were read, and no database
connection was attempted. The managed development database was not presumed
disposable.

The saved host preflight from 2026-11-04 still has
`hostBoundaryReady=false`; it was not rerun. No Qwen inference, live worker,
PostgreSQL E2E, Docker/socket access, external services, or deployment occurred.

## Offline regression changes

- The Qwen marker parser tests now include a complete marker followed by prose
  and an orphan closing marker. Both must remain unparsed, without partial
  `tool_calls`.
- An infrastructure privilege-injection case now passes malformed marker
  output from the real parser adapter into the offline Qwen policy boundary.
  It must use `tool_choice=auto`, return `unparsed_qwen_native_markup` /
  `deny` / `blocked_by_parser`, emit no tool events, and never call the
  synthetic dispatcher. This is a scripted test double, not model inference.
- Existing offline tests continue to cover all eight fixture profiles'
  benign/adversarial inputs, Policy ON ordering, cross-tenant denials, v3
  binding/expiry/replay, and provenance separation.

These tests do not apply or exercise live PostgreSQL RLS. The historical
Infrastructure Qwen evidence remains `NO_PROPOSAL`, with no proposed tool,
proposal/action hashes, dispatch, or approval provenance.

## Verification, serially

1. Worker offline modules for autonomous selection/parser, policy lab,
   historical evidence reconciliation, and synthetic tool adapter:
   **59/59 passed**.
2. Targeted API evidence/approval contract suite: **17/17 passed**.
3. Full offline API suite: **86/86 passed**.
4. API TypeScript typecheck: passed.
5. Dashboard integration: **15/15 passed**.
6. Dashboard TypeScript typecheck: passed.
7. `git diff --check`: passed.

The PostgreSQL approval E2E was intentionally not run: no independently
verified disposable target was available. Persisted Qwen-derived approvals,
live RLS predicates, real cross-tenant isolation, transaction concurrency, and
durable audit remain unverified.

## Evidence classification and next gate

Pinned historical artifact
`generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`
has SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`. It records
eight historical Qwen calls: seven adapted proposals, zero native
`message.tool_calls`, and one Infrastructure `NO_PROPOSAL`. Fixtures are
separate; no inference was performed in this increment.

Next, use an explicitly authorized disposable PostgreSQL target with separate
runtime and reviewer roles. Apply and verify the RLS policies, then run the
synthetic approval E2E for tenant boundaries, roles, expiry, binding,
concurrency, replay, idempotency, and audit. Keep Qwen and the live worker
blocked until the isolated host/broker preflight is independently satisfied.
