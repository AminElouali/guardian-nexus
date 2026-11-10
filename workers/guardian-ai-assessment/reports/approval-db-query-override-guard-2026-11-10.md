# Approval database target guard — 2026-11-10

## Scope and safety

- Starting HEAD: `4262f2fbd9eb3e5f0f263d7c15538b8dfc5c4e6c`, branch `main`,
  clean. No matching Guardian, Qwen, PostgreSQL, or test process was observed.
- No Qwen inference, live worker, database connection, Docker socket, secret,
  external service, or deployment was used.
- The last recorded host boundary state remains `hostBoundaryReady=false`;
  privileged isolation checks were not repeated.

## Change

The disposable approval DB URL guard rejects all query parameters and URL
fragments. A loopback hostname alone is insufficient if a driver service file
or connection option can alter the effective target/configuration. The guard
continues to require development mode, no deployment, explicit opt-in,
literal loopback IP, and an exact `guardian_approval_lab_*` database-name
match. This validates URL shape only; it cannot prove that a database is
disposable.

Offline regression cases cover `service`, `servicefile`, `options`,
`host`/`hostaddr`, and URL fragments. Existing synthetic approval checks cover
tenant/proposal/role/expiry binding, role and expiry rejection, one-time replay
and idempotent receipts. Existing source-contract checks inspect RLS SQL and
schema declarations; they are not runtime PostgreSQL/RLS verification.

## Verification, run sequentially

| Command / area | Result |
|---|---:|
| API Qwen evidence/approval contract test | 18/18 |
| Worker policy lab | 39/39 |
| Worker Qwen evidence reconciliation | 6/6 |
| API typecheck | passed |
| PostgreSQL approval E2E, with DB URL and opt-in explicitly unset | skipped 1 before connection |
| `git diff --check` | passed before checkpoint/report were added |

The first worker test invocation omitted `PYTHONPATH` and failed during test
module import. Re-running with
`PYTHONPATH=workers/guardian-ai-assessment` passed. No case from that first
attempt ran.

## Evidence SHA-256

- `artifacts/api-server/src/lib/approval-e2e-db-guard.ts`:
  `f2623a25e1b8ce5c909fb48cb8cf35f4043b21f53347b44b8dd962a8f1b0047e`
- `artifacts/api-server/src/lib/ai-assessment-qwen-evidence.test.ts`:
  `4d33c5fb72b484cd680fdc939bb04c7173dfc3eadad91e09e88d5493225e3d60`

## Limits and next gates

PostgreSQL persistence and live RLS remain unverified because no safe
disposable DB was provided; the guarded E2E skipped before opening a
connection. Qwen and live worker execution remain blocked until an independent
host/broker/worker isolation attestation is available. Keep the gate closed;
do not substitute offline contracts for those runtime checks.
