---
name: Retrying read-only query mistakes
description: The user’s standing rule for recovering from agent-authored read-only SQL and verification mistakes.
---

If a read-only query or verification fails because of an agent-authored mistake (such as invalid SQL syntax or a wrong column or table name), correct it and retry up to three times instead of stopping immediately. Stop for the user only if an operation writes, migrates, deletes, affects production, changes dependencies or workflow, or a correctly formed verification shows an unexpected result.

**Why:** the user explicitly asked for autonomous recovery from read-only query mistakes while preserving all other project safety rules.

**How to apply:** this permits retries only for read-only queries/checks; it never authorizes additional writes, migrations, main commits, or RLS/OIDC/test changes.
