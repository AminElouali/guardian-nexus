# Approval E2E disposable database gate — 2026-11-10

## Scope and safety

- Starting HEAD: `4c5edf2a9f571a6098f57b01f59d0490d1d8fc8e`, branch `main`,
  clean; no matching Guardian, Qwen, test, or PostgreSQL process was observed.
- The last recorded host preflight remains `hostBoundaryReady=false`. It was not
  rerun here; no Docker socket was inspected or accessed.
- No disposable PostgreSQL target was verified. The persistent-approval E2E was
  run with its database URL and opt-in variables removed; it skipped before
  constructing a pool or making a connection.
- No Qwen inference, live assessment worker, external service, or deployment
  was started.

## Change

The DB-backed synthetic approval E2E now fails closed unless the process is in
development, not deployed, and explicitly opts in with
`GUARDIAN_APPROVAL_E2E_DISPOSABLE=1`. The connection URL must use PostgreSQL,
resolve to loopback, contain no `host` or `hostaddr` query override (case
insensitive), and identify the same dedicated `guardian_approval_lab_*`
database name supplied through `GUARDIAN_APPROVAL_E2E_DATABASE_NAME`.

A pure offline contract test covers the valid local disposable shape and
rejects missing opt-in, production/deployment mode, remote host, host overrides,
database-name mismatch, non-dedicated names, and malformed URLs. The predicate
returns only a boolean; neither the test nor the guard prints connection data.

This change does not prove a database is disposable by itself: the operator must
create and own the isolated loopback database and explicitly set the opt-in
variables. Existing approval tests still cover synthetic tenant, role,
proposal/action digest, expiry, idempotency, concurrency and audit contracts.

## Verification run sequentially

| Area | Command | Result |
|---|---|---:|
| Worker isolation preflight | `cd workers/guardian-ai-assessment && PYTHONPATH=. python -m unittest discover -s tests -p 'test_offline_isolation_preflight.py' -v` | 16/16 |
| Worker Policy/provenance | `cd workers/guardian-ai-assessment && PYTHONPATH=. python -m unittest discover -s tests -p 'test_policy_lab.py' -v` | 39/39 |
| Worker evidence reconciliation | `cd workers/guardian-ai-assessment && PYTHONPATH=. python -m unittest discover -s tests -p 'test_qwen_evidence_reconciliation.py' -v` | 6/6 |
| API suite | `pnpm --filter @workspace/api-server run test` | 87/87 |
| API typecheck | `pnpm --filter @workspace/api-server run typecheck` | passed |
| Persistent approval DB E2E | `env -u DATABASE_URL -u GUARDIAN_APPROVAL_E2E_DISPOSABLE -u GUARDIAN_APPROVAL_E2E_DATABASE_NAME pnpm --filter @workspace/api-server run test:ai-assessment-synthetic-e2e` | skipped before DB connection (1 skipped) |
| UI evaluation component | `pnpm --filter @workspace/eu-security-platform exec tsx --test src/components/AiEvaluationPage.integration.test.tsx` | 17/17 |

An initial worker test invocation from the repository root failed because the
relative `tests` directory was not importable; rerunning from the worker
directory passed. No test command invoked Qwen or Docker. `git diff --check`
passed after the changes.

## Limits and next gate

- PostgreSQL persistence, live RLS predicates, role segregation, and DB-backed
  approval replay remain unverified. The DB E2E is skipped until an operator
  supplies a dedicated loopback lab database and the explicit opt-in.
- Qwen and the live worker remain blocked because host/broker/worker isolation
  has not been independently attested. Historical inference and deterministic
  fixtures remain separate; this change creates no new inference evidence.
- Next: provision a disposable loopback PostgreSQL database with segregated
  owner/runtime roles, run the guarded E2E, inspect live RLS predicates and
  role attributes, and retain sanitized evidence. Separately obtain the
  host-owner and independent broker-boundary attestation without touching the
  privileged socket.

## Source SHA-256

- `src/lib/approval-e2e-db-guard.ts`:
  `33480f6b8b10f93b160f6533b55d4379df1afb5e9276847b6a48569a47bd2cc5`
- `src/lib/ai-assessment-qwen-evidence.test.ts`:
  `a0f8f632e3c86fdbce48d702e6cfff7c890e839a97dd88ec2af534be005d917b`
- `src/ai-assessment-synthetic-approval-e2e.test.ts`:
  `d24daee861ed9426598d72885cb97b62f926dc7c73b3e94b70f68df657709b0e`
