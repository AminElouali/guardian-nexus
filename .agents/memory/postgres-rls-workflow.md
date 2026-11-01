---
name: PostgreSQL RLS workflow
description: Non-obvious behavior to verify when changing or publishing tenant RLS.
---

**Rule:** Do not assume schema push applied PostgreSQL policy predicates. In this workspace, policies appeared in `pg_policies` with empty predicates after schema push; apply the explicit policy SQL and verify live predicates, role attributes, and cross-tenant tests. Provision the runtime role separately and verify it has no superuser, login, bypass-RLS, or role-creation privileges.

**Why:** An unqualified RLS policy can permit every row, while a privileged runtime login can bypass RLS entirely.

**Additional workflow constraint:** In this workspace, Replit Secrets are available to managed artifact workflows but not to one-off agent shell commands. For secret-backed development role provisioning, run the guarded command through the managed development workflow, restore its normal command afterward, and confirm no secret appears in logs.

**Why:** Isolated shell and CodeExecution commands did not receive the Replit secret, while the managed development workflow did.

**How to apply:** After every development schema push, run the guarded development policy/grant steps and the API’s RLS readiness check. Before production publication, provide an equivalent reviewed migration and a non-superuser runtime database connection. If provisioning needs a Replit Secret, use the managed development workflow rather than attempting to extract or print it in an agent shell.

**Additional rule:** For a queue role using `UPDATE ... RETURNING`, its narrow SELECT policy must admit every resulting state that the role is permitted to write, including terminal `failed`; keep result/evidence columns outside its grants.

**Why:** Row-level visibility can hide an allowed state transition when the updated row no longer satisfies the role's SELECT policy, even if the UPDATE check itself permits the new state.

**How to apply:** Test queued-to-running, running-to-failed, expired-lease recovery, and terminal visibility with the actual worker role after applying RLS policies.

**Additional rule:** Do not assume `drizzle-kit push` widened an existing PostgreSQL `CHECK` constraint just because it reports that changes were applied; verify the live definition and keep an idempotent guarded SQL update.

**Why:** During the local LLM job-profile change, push reported success while the live profile constraint still rejected the new profile.

**How to apply:** After changing allowed queue/profile values, inspect `pg_constraint` in development, apply the guarded SQL if stale, then verify the actual worker can claim and persist that job before considering the migration complete.
