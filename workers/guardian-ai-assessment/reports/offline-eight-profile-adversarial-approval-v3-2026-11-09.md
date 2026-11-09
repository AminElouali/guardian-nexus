# Offline adversarial profile matrix and approval binding

Date: 2026-11-09

## Boundary

Starting HEAD: `a26a613fab1a8698f93800c4e5c5b6c32962bc62`, clean.
No active Qwen, Guardian worker/broker, or PostgreSQL process was visible in
the read-only process check; no local PostgreSQL listener/service was found.
The saved host preflight remains `hostBoundaryReady=false`. It was not rerun,
and the Docker socket was not accessed. No database values or credentials
were read and no DB connection was attempted.

## Offline test changes

- The worker Qwen corpus test now pins the expected adversarial scenario IDs
  across all eight verticals: email, database, finance, support, programming,
  browser, infrastructure, and multiagent. This detects accidental loss of
  attack coverage while retaining the synthetic fixture baseline.
- The approval binding test now tries every adversarial finance and support
  case with the exact allowlisted action shape and also attempts to bind an
  approval to infrastructure's adversarial NO_PROPOSAL case. None may produce
  an approval action reference or action hash.
- Existing offline tests still distinguish native runtime `tool_calls`,
  adapter-parsed Qwen markers, fixtures and `NO_PROPOSAL`; exercise the strict
  parser; assert Policy ON decisions precede synthetic dispatch; and cover
  tenant/role/hash/expiry/replay boundaries.

These checks use deterministic fixtures and test doubles only. They do not
constitute new Qwen inference, PostgreSQL persistence, live RLS, or persistent
approval replay validation.

## Verification, in order

1. Worker offline modules (policy lab, autonomous/parser, reconciliation,
   synthetic adapter): **59/59 passed**.
2. Targeted API Qwen/approval tests: **17/17 passed**.
3. Full offline API suite: **86/86 passed**; API typecheck passed.
4. UI integration suite: **15/15 passed**; UI typecheck passed.
5. `git diff --check`: passed.

The PostgreSQL-backed approval E2E was not run because no explicitly
disposable database target was verified. The saved 2026-11-04 preflight is
still blocked. No Qwen inference, live worker, Docker control, external
connection, or deployment occurred.

Historical evidence remains separate: the pinned Qwen artifact has SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9` and records
eight historical calls: seven adapted proposals, zero native
`message.tool_calls`, and one infrastructure `NO_PROPOSAL`. No new inference
was run in this increment.

## Next safe step

First, independently verify a segregated broker/worker host. Separately obtain
an authorized disposable PostgreSQL database with distinct runtime and
reviewer roles. Then run the approval v3/RLS E2E for tenant isolation, roles,
expiry, proposal binding, one-winner concurrency, replay rejection,
idempotency, and audit. Do not enable Qwen or the live worker until the
host-boundary preflight passes.
