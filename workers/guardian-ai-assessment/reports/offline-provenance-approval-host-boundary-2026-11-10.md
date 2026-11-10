# Offline provenance, approval, and host-boundary verification — 2026-11-10

## Scope and starting state

- Starting commit: `43c702aa911590ad47dd0688241863e7a279a4b9`, `main`, clean.
- No matching Guardian, Qwen, test, or server process was running when inspected.
- The latest recorded live preflight remains `hostBoundaryReady=false`.
  This turn did not rerun a host preflight or inspect/connect to the real
  Docker socket. No Qwen, worker service, PostgreSQL, external service, or
  deployment was started.
- The added preflight regression supplies only a synthetic absent socket path,
  an empty key-only environment, and a synthetic process identity. It verifies
  that process-only readiness is insufficient to authorize the integrated
  Qwen gate.

## Offline evidence executed in this turn

Commands were run sequentially:

| Area | Command | Result |
|---|---|---:|
| Worker preflight | `PYTHONPATH=. python -m unittest discover -s tests -p 'test_offline_isolation_preflight.py' -v` | 16/16 |
| Worker policy/provenance | `PYTHONPATH=. python -m unittest discover -s tests -p 'test_policy_lab.py' -v` | 39/39 |
| Worker evidence reconciliation | `PYTHONPATH=. python -m unittest discover -s tests -p 'test_qwen_evidence_reconciliation.py' -v` | 6/6 |
| API evidence/approval contract | `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-qwen-evidence.test.ts` | 17/17 |
| UI evaluation component | `pnpm --filter @workspace/eu-security-platform exec tsx --test src/components/AiEvaluationPage.integration.test.tsx` | 17/17 |

The suites exercise synthetic or mocked inputs. The eight-profile tests keep
`runtime_message_tool_calls`, complete-marker adapter proposals,
`NO_PROPOSAL`, and deterministic fixtures distinct; require `tool_choice=auto`;
check parser rejection and cross-tenant/prompt-injection denial before
simulator dispatch; and keep Policy OFF counterfactual-only.

Finance/support approval tests verify synthetic binding to tenant, proposal,
action, requester, role and expiry; exact expiry rejection; replay digest
idempotency; and allowlist/clone-only behavior. API tests also inspect the RLS
and database transaction contracts. These are offline unit/source-contract
checks, **not** proof that PostgreSQL persisted a row or enforced RLS at
runtime. The database-backed approval E2E was not run; no disposable PostgreSQL
with segregated roles was verified.

## Qwen provenance: historical evidence only

The pinned historical artifact
`generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`
has SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
It records eight prior inference cases: seven adapted proposals, zero native
runtime `message.tool_calls`, and infrastructure `NO_PROPOSAL`. The eight
fixture baselines are a separate dataset. No model inference was performed in
this turn, and mocked native-origin tests are not new native Qwen calls.

## Safe host/broker/worker separation evidence plan

Do not use Docker CLI/API, open or connect to the privileged socket, or read
process environment values. Do not infer the API or worker identity from the
current agent process. A future host owner can assemble a redacted,
read-only attestation using:

1. The service supervisor's API, broker, and worker definitions, recording
   configured UIDs/GIDs/groups, namespace/mount policy, and declared socket
   mounts; redact command arguments and environment values.
2. For the exact service PIDs, `/proc/<pid>/status` identity fields,
   `/proc/<pid>/mountinfo`, cgroup/namespace identifiers, and symlink targets
   under `/proc/<pid>/fd`. Do not open the socket or `/proc/<pid>/environ`.
3. Evidence that API and worker have distinct identities from the broker,
   no socket mount in their namespaces, and no inherited socket descriptor.
   The broker's exclusive authority must be visible in supervisor policy and
   independently reviewed. A missing observation or shared identity is a
   failure, not a pass.
4. A separately authorized disposable-PostgreSQL run for database session
   roles and RLS. Never substitute production or a credential-bearing
   development database.
5. A host-owner attestation and an independent verifier result bound to the
   inspected service/config revision. Do not set `hostBoundaryReady=true`
   from process-local metadata alone.

This plan is not an attestation and does not change the gate. Current blocker:
the API/broker/worker separation and database session identities remain
unverified, so live Qwen and worker execution must remain disabled.

## Limits

- SHA-256 of the added metadata-only regression:
  `d639ecd47ba3cb5536ae3ed2f14aa1ce7e4034505e688903df207aa94283f033`.
- No real Qwen inference, no PostgreSQL connection or RLS runtime proof.
- No live worker, Docker operation, authenticated preview, or external
  integration was run.
- Existing tests establish offline contracts only; do not count them, fixtures,
  or the seven historical adapted proposals as eight real, independently
  authorized agents.
