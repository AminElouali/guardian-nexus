# Offline proposal provenance checks — email and database — 2026-11-10

## Scope and safety

- Starting HEAD: `6d7caeaff0cfdfd42fe188379a1f90c86de74c14`, branch `main`,
  clean. No matching Guardian, Qwen, PostgreSQL, or test process was observed.
- No Qwen inference, live worker, Docker socket, database, secret, external
  service, or deployment was used.
- Last recorded host isolation state remains `hostBoundaryReady=false`; no
  privileged isolation check was attempted.

## Change

Added an offline parser regression for complete Qwen-style markers in the
email and database domains. It checks exact synthetic arguments and labels
the outputs as `qwen_native_markup_adapter`, not native runtime
`message.tool_calls`. Inputs are deterministic test completions, not model
outputs or inference evidence.

The existing test suites continue to exercise `tool_choice=auto`, synthetic
prompt-injection cases across all eight profiles, fail-closed parser behavior,
Policy ON before simulated dispatch, Policy OFF as counterfactual clone only,
and approval binding/expiry/replay contracts. These tests do not establish
that a live model autonomously selected a tool.

## Verification, run sequentially

| Area | Result |
|---|---:|
| Worker autonomous tool-selection/parser suite | 12/12 |
| Worker synthetic Policy lab | 39/39 |
| Worker evidence reconciliation | 6/6 |
| API evidence/approval contract | 18/18 |
| API persistent approval E2E | skipped 1 before connection; DB URL and opt-in unset |
| AI Evaluation UI integration | 17/17 |
| `git diff --check` | passed |

The API E2E did not connect to PostgreSQL. No PostgreSQL persistence or runtime
RLS result is being claimed.

## SHA-256

- `workers/guardian-ai-assessment/tests/test_autonomous_tool_selection.py`:
  `87f37f29077623820c5d77161d8fa0b16afcaa9063dfc04df50851eb06947b09`

## Limits and next gates

The latest documented `hostBoundaryReady` remains false, so Qwen and live
worker runs remain prohibited. No disposable PostgreSQL instance with
segregated roles is available/verified; persistence and RLS remain pending.
Next safe step is independent host/broker/worker isolation attestation, then
live Qwen only inside that verified boundary. PostgreSQL/RLS validation
requires a separately verified disposable loopback lab and isolated roles.
