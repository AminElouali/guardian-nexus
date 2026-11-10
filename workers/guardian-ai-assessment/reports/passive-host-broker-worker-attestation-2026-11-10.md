# Passive host/broker/worker attestation — 2026-11-10

## Scope

This is a live, read-only metadata observation, not an isolation certification.
The command was run with no opt-in flags:

```sh
python3 workers/guardian-ai-assessment/scripts/run_lab_host_preflight.py
```

The collector checked local OS/account metadata, socket path metadata with
`lstat`, and effective access bits with `os.access`. It did **not** open or
connect to a socket, run a child as another identity, invoke Docker, connect to
PostgreSQL, read credential values, start a worker, or run Qwen. Exit code `2`
is the expected fail-closed result.

## Observed result

- `hostBoundaryReady=false`; `integratedAssessmentReady=false`.
- The current probe identity had read and write access according to the
  metadata access check for a present Docker socket (`root:runner`, mode
  `0660`). This permission check is not a socket connection.
- API, broker, and worker identities were unverified; no segregated database
  sessions, worker child-identity probe, or sandbox contract were verified.
- Four sensitive environment-variable names were present. Their names and
  values were not included in the report; no values were read.
- Report counters: Docker calls `0`, database connections `0`, external
  connections `0`, Qwen inference `false`, credential values read `false`.
- The result does not establish a host/broker boundary. Keep Qwen and the live
  worker blocked.

The machine-readable redacted result is
`passive-host-broker-worker-attestation-2026-11-10.json`. Its source collector
stdout SHA-256 is
`d50daf0b68f504b285ccf5975c129269316ebfe2e77268046c305bd4754d581e`; the
canonical summary SHA-256 is
`0d73dcfa44f4ea3d1879ec6e555429afd6230a7fc0ca1c7ebffb00538e46170d`.

## Offline regression coverage

- A collector test asserts that default attestation does not invoke the
  optional identity, worker-child, ACL, or database probes.
- Synthetic email and database marker responses are classified as
  `guardian_qwen_native_markup_adapter`, then evaluated by the independent
  Policy ON function before the in-memory synthetic simulator. They are
  deterministic test responses, not Qwen output or inference evidence.
- Existing tests continue to distinguish runtime `message.tool_calls`,
  adapted markers, and no proposal; deny malformed/adversarial proposals
  before dispatch; and keep Policy OFF counterfactual-only.

## Verification

Run sequentially:

| Suite | Result |
|---|---:|
| Worker `test_lab_host_preflight.py` | 7/7 |
| Worker `test_offline_isolation_preflight.py` | 16/16 |
| Worker `test_autonomous_tool_selection.py` | 12/12 |
| Worker `test_policy_lab.py` | 40/40 |
| Worker `test_qwen_evidence_reconciliation.py` | 6/6 |
| API Qwen evidence/approval contract | 18/18 |
| Persistent-approval PostgreSQL E2E | SKIP 1 before connection; explicit DB URL/opt-in absent |

The offline-isolation unit suite uses a temporary test-only Unix socket fixture;
it never opens the host Docker socket. No UI suite or build was run because
neither UI nor production code changed.

## Remaining gates

1. An independently administered lab must attest distinct API/broker/worker
   identities and prove the API/worker cannot access the broker-only Docker
   socket or broker database role.
2. Only then consider local Qwen inference behind that verified boundary.
3. Approval persistence/RLS still requires an explicitly authorized,
   disposable loopback PostgreSQL instance with segregated roles. No database
   was available or used in this iteration.
