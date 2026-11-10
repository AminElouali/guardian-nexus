# Fail-closed signed host-boundary gate for local Qwen — 2026-11-10

## Scope and result

This change wires an independent host-boundary requirement in front of every
local Qwen model entry point. It is an offline code/test increment only. No
Qwen model, live worker, Docker daemon/socket, PostgreSQL instance, API service,
or external service was started or contacted. The last recorded live host
preflight remains `hostBoundaryReady=false`; it was not rerun in this change.
Therefore the new gate remains closed and no new inference evidence exists.

## Attestation contract

The runtime accepts no environment-variable override for the trust paths:

- Signed report: `/run/guardian-nexus/host-boundary-attestation.json`
- Ed25519 public key: `/etc/guardian-nexus/host-boundary-attestor-ed25519.pem`

Both files and every parent directory must be root-owned, regular/non-symlink,
and not group/world writable; the caller must be non-root. The detached Ed25519
signature covers canonical UTF-8 JSON for the exact `payload` object. Verification
uses a root-owned, non-writable OpenSSL executable; no private key is read by the
project. The private signing key must remain outside the Replit workspace, with
the public trust key and signed report installed out-of-band by the lab host
owner after independent review.

The strict payload is fresh for at most 24 hours and is bound to SHA-256 hashes
of the verifier, process guard, isolation/network preflights, offline launcher,
local Qwen runner, Qwen policy lab, shared LLM runner, and autonomous
tool-selection runner. Future inference evidence bundles also record those
entrypoint and gate hashes. It requires:

- distinct non-root API, broker, and worker UIDs/GIDs and distinct database
  roles/session roles;
- API and worker denied Docker socket read/write and excluded from its group;
  broker alone has socket authority;
- database sessions target the same `guardian_lab_*` database and are neither
  superuser nor `BYPASSRLS`;
- zero sensitive-environment names and a pinned, networkless Qwen sandbox with
  read-only root, dropped capabilities, no-new-privileges, verified seccomp,
  no Docker socket mount, and pinned image identity.

The verifier fails closed for missing, stale, malformed, tampered, untrusted,
or source-mismatched evidence. Local process metadata must also pass. All live
entry points and `LocalQwenClient` check the gate before model verification,
runtime lookup, or model construction; the offline launcher checks before
artifact extraction or output-directory creation.

## Offline behavior and provenance

Email and database tests retain benign read, prompt-injection, and cross-tenant
cases. The parser accepts only complete recognized markers; unparsed or partial
markup is denied before policy/dispatch. Explicit abstention remains
`no_tool_call`/`NO_PROPOSAL` and never calls Policy or a simulator. Test doubles
use `tool_choice=auto`; they are not model outputs. Policy ON is checked before
the in-memory synthetic simulator, while Policy OFF remains clone-only.

The eight deterministic fixtures remain a separate baseline. Runtime native
`message.tool_calls`, adapted marker proposals, no-proposal, and fixtures remain
separate evidence classes. This change did not execute Qwen or modify fixtures.

## Tests actually executed

Commands ran serially from the workspace root with
`PYTHONPATH=workers/guardian-ai-assessment`; no test starts Qwen, a worker
service, Docker, PostgreSQL, or the API:

| Suite | Result |
|---|---:|
| `test_host_boundary_attestation.py` | 12/12 |
| `test_offline_isolation_preflight.py` | 17/17 |
| `test_policy_lab.py` | 42/42 |
| `test_autonomous_tool_selection.py` | 12/12 |
| `test_lab_host_preflight.py` | 7/7 |
| `test_qwen_evidence_reconciliation.py` | 6/6 |
| `git diff --check` | passed |

Total: 96 offline unit tests passed. The isolation-preflight suite creates one
temporary Unix-domain socket fixture solely to test metadata detection; it does
not open or touch the host Docker socket. Attestation signature verification
was mocked in unit tests; no keypair, signature, OpenSSL verification process,
or host attestation was generated or used. UI, API, DB E2E, build, and live
preflight were not run because the change is worker-side and their required
services/gates are unavailable or explicitly prohibited for this iteration.

One early targeted attestation-test run had a test-fixture aliasing failure;
the mutable test mapping was copied and the final suite passed 12/12. No
product-code test failure remains.

### SHA-256 of changed source and test files

| File | SHA-256 |
|---|---|
| `guardian_ai_assessment/host_boundary_attestation.py` | `c0f1740924be8f786db18eaee39be91856bbcab3bc268956c487273d51e739bc` |
| `guardian_ai_assessment/offline_isolation_preflight.py` | `7f9a08ff571a1ebf53f4a85dbc749f6c6815143c96b29f6355fceb4865d9c052` |
| `guardian_ai_assessment/qwen_policy_lab.py` | `a8b75093c2bf9660326c8ad3deb6a7a6b34e642d10fa9483b9e0cdebf7c8097d` |
| `guardian_ai_assessment/llm_lab.py` | `903501f63b97dc390bca3b6d078a718c87a1368077879b6b47c47caf388681cf` |
| `guardian_ai_assessment/autonomous_tool_selection.py` | `35adf3ae09d8419dc4f2bae195fb4ef513be6b890eeb2df064b8a31163cdde86` |
| `guardian_ai_assessment/offline_qwen_runner.py` | `c99b93e0dead61210210f71160795c46792807d713935a2e1a84352c07b282fe` |
| `tests/test_host_boundary_attestation.py` | `38a11d6cba5df28bc9aa5f130f528551b7644f8023aa2d579d42f8b14f486cdf` |
| `tests/test_offline_isolation_preflight.py` | `41d5bea7fcf4f939d8ef425019311c6a7605ae8f0f0d1b74c313d60de2787b78` |
| `tests/test_policy_lab.py` | `3b8523fcf2b5b08dee417ff1cea214413bf496ceda46d53ddba43b1e60abf09c` |

## Limitations and next gate

- This is not a host isolation certification and does not set
  `hostBoundaryReady=true`.
- No new Qwen inference, authorization derived from Qwen, worker execution,
  PostgreSQL persistence, or runtime RLS proof is claimed.
- The standalone local Qwen runner is still not an API v2 queue/worker
  integration and does not persist approvals. This change only makes every
  existing model entry point fail closed behind the attestation.
- The next operational step is for an independently authorized lab host owner
  to provision the public trust key and signed report at the fixed paths, bound
  to the exact source hashes, after proving service identities, socket ACLs,
  segregated DB roles, and sandbox properties. Then run only the authorized
  disposable lab flow, starting with synthetic email and database cases. Do not
  run Qwen while the attestation is absent or rejected.
