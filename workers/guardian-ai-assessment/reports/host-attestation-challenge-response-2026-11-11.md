# Host attestation challenge-response protocol — 2026-11-11

## Scope

Added a minimal signed host-attestation challenge/response path without
connecting it to worker admission. This is a code and offline-test milestone,
not a host-isolation verification or a Qwen inference.

## Implementation

- API issues a 256-bit URL-safe nonce with a two-minute expiry only when the
  fixed external trust anchor, current Git commit/runtime digest, effective
  non-root API identity, and durable challenge repository are available.
- The trust anchor is fixed at
  `/etc/guardian-nexus/host-boundary-attestor-ed25519.pem`. The loader accepts
  only a root-owned, non-writable Ed25519 public-key PEM; it has no environment
  variable or worker-controlled key override.
- The response is Ed25519-signed over domain-separated canonical JSON and is
  bound to the workspace, challenge, nonce digest, current commit, current
  runtime-entry/source digest, API identity, distinct API/broker/worker
  identities and database roles, namespace IDs, privilege/seccomp claims,
  Docker-socket claims, empty inherited-descriptor lists, and synthetic
  database-name restrictions.
- Nonce digests and final response status are stored in a workspace-scoped
  PostgreSQL table. The API locks a challenge row for update, then records a
  single terminal status and audit event in the same tenant transaction.
  RLS allows only workspace owners/admins to read, issue, and consume a
  challenge. The API login is not granted direct table access; the runtime role
  receives no DELETE privilege.
- API/OpenAPI response fields explicitly return
  `hostBoundaryReady: false`, `integratedAssessmentReady: false`, and
  `workerAdmission: "disabled"`, including after a synthetically valid
  signature. The existing broker gate remains unchanged and closed.

## Offline verification performed

Date: 2026-11-11.

- `pnpm --filter @workspace/api-spec run codegen` — passed; generated API
  clients and ran the workspace library typecheck.
- `pnpm --filter @workspace/api-server run typecheck` — passed.
- `pnpm --filter @workspace/api-server exec tsx --test src/lib/host-attestation-protocol.test.ts`
  — 17 passed, 0 failed. All signatures and repositories in this suite are
  explicitly TEST ONLY and in-memory. Coverage includes valid signature with
  readiness still false, altered signature, replay, expiry, stale commit and
  digest, shared/mismatched identities, absent trust anchor, incomplete
  claims, unsupported socket/privilege claims, nonce shape/TTL, and the
  permanently closed worker gate.
- `pnpm --filter @workspace/api-server exec tsx --test --test-name-pattern="oversized host attestation response" src/middlewares/ai-assessment-json.test.ts`
  — 1 passed, 0 failed. This direct handler test did not start an HTTP server.
- `git diff --check` — passed.

An initial test invocation exposed an unavailable direct `zod` dependency in
the API package. The strict payload schema was moved to the existing shared
`@workspace/api-zod` package; the focused suite was rerun successfully. An
initial API typecheck also found project-reference and type issues; after
refreshing library typechecks and correcting them, the API typecheck passed.

## Not verified / remains blocked

- No external supervisor, independently provisioned public key, signed host
  response, or real API/broker/worker process attestation was used or verified.
- No attempt was made to inspect or open Docker sockets. Docker, workers, Qwen,
  PostgreSQL, network services, and deployment were not run.
- The challenge table and RLS SQL are source changes only. PostgreSQL schema
  application, role provisioning, RLS behavior, durable replay under
  concurrency, and approval persistence were not tested. API readiness checks
  will fail closed until the table and required RLS policies/grants exist.
- The existing environment's host isolation and broker identity remain
  unverified. This change does not provide evidence that `hostBoundaryReady`
  or `integratedAssessmentReady` is true.
- No new Qwen inference was run. Historical inference evidence, adapted
  proposals, native runtime `message.tool_calls`, and deterministic fixtures
  were not changed or recounted.

## Next external prerequisites

1. An independent host supervisor must be provisioned outside the API/worker
   trust domain, with the pinned public key installed at the fixed root-owned
   path and a real fresh challenge response available.
2. A disposable PostgreSQL lab must apply the challenge table, grants, and RLS
   policies, including the required broker DB role, before persistence and
   cross-tenant replay behavior can be tested.
3. Only after those checks are independently verified should a separate
   change consider wiring attestation evidence into worker admission. This
   protocol itself never opens the gate.
