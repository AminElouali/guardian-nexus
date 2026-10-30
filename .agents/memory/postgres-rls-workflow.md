---
name: PostgreSQL RLS workflow
description: Non-obvious behavior to verify when changing or publishing tenant RLS.
---

**Rule:** Do not assume schema push applied PostgreSQL policy predicates. In this workspace, policies appeared in `pg_policies` with empty predicates after schema push; apply the explicit policy SQL and verify live predicates, role attributes, and cross-tenant tests. Provision the runtime role separately and verify it has no superuser, login, bypass-RLS, or role-creation privileges.

**Why:** An unqualified RLS policy can permit every row, while a privileged runtime login can bypass RLS entirely.

**How to apply:** After every development schema push, run the guarded development policy/grant steps and the API’s RLS readiness check. Before production publication, provide an equivalent reviewed migration and a non-superuser runtime database connection.
