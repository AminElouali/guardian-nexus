# Approval E2E loopback diagnostic — 2026-11-10

## Scope and safety

- Starting HEAD: `c256af421d2955104cb9a71e6995babaf8e279d6`, branch `main`,
  clean. No matching Guardian, Qwen, test, PostgreSQL or Git process was
  observed before editing.
- No database URL, password, secret, Docker socket, external service, Qwen
  inference, worker container, or deployment was accessed or started.
- Read-only availability checks:
  - `ss -ltn` showed no loopback listeners.
  - `pg_isready -h 127.0.0.1 -p 5432 -t 1` returned
    `127.0.0.1:5432 - no response` (exit 2).
  - `psql` and `pg_isready` binaries are installed, but no local PostgreSQL
    service was found. This does not establish that any database is disposable.
- The latest recorded host-boundary preflight remains `hostBoundaryReady=false`;
  it was not rerun and no privileged socket was inspected.

## Change

The approval E2E target guard now accepts only explicit loopback IP literals
(`127.0.0.1` or IPv6 `::1`), rather than the hostname `localhost`, whose
destination depends on name resolution. It still requires development mode,
no deployment, explicit disposable-DB opt-in, a dedicated
`guardian_approval_lab_*` database name matching the URL path, and no
`host`/`hostaddr` override.

An offline regression rejects a `localhost` URL in addition to the existing
missing opt-in, production, remote host, host override, mismatched name and
malformed URL cases. This hardens test target selection; it does not prove a
database is disposable or prove PostgreSQL persistence/RLS.

## Verification, run sequentially

| Area | Result |
|---|---:|
| Worker isolation preflight | 16/16 |
| Worker Policy/provenance lab | 39/39 |
| Worker historical evidence reconciliation | 6/6 |
| API tests | 87/87 |
| API typecheck | passed |
| Approval PostgreSQL E2E | skipped 1 before DB connection; no opt-in or DB URL supplied |
| AI evaluation UI integration | 17/17 |
| `git diff --check` | passed |

The tests were offline/synthetic. No fresh Qwen inference, native runtime
`message.tool_calls`, live worker execution, PostgreSQL persistence, or RLS
runtime verification was produced. Historical Qwen evidence and deterministic
fixtures remain distinct.

## Next gates

1. Provide an owned disposable loopback PostgreSQL database with segregated
   roles, then run the explicitly guarded approval E2E and inspect live RLS
   predicates/role attributes. Do not substitute a managed or production DB.
2. Obtain independent host/broker/worker isolation attestation. Until then,
   keep Qwen and live worker execution blocked.

## Source SHA-256

- `artifacts/api-server/src/lib/approval-e2e-db-guard.ts`:
  `96887232eb12bb6885a11125f94b1a83df1cccf6903c7d88d90b6d06a0298808`
- `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`:
  `65131a82f4579b74358243aad6d0fcaf38ada71d781df15ff9b9ed1864045be8`
