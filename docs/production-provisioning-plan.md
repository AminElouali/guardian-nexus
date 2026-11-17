# Guardian Nexus: production provisioning plan

This is a design document only. It does not provision roles, apply schema, change grants or policies, access production, or rotate keys.

## Why publishing failed

The reported publication failure was `role app_runtime does not exist` while copying database objects to production. The application schema declares policies that reference runtime roles, while the required roles and grants are provisioned by project-specific scripts rather than by a plain schema copy. A destination without those roles cannot safely satisfy that schema contract. The provisioning order must therefore create and verify the required roles before applying schema objects and policies, and must complete before the first application process connects.

This diagnosis is based on the reported failure and repository design; it does not establish whether the failed platform copy made any partial production changes. Check deployment/database logs and the production catalog read-only before any retry.

## Proposed order and stop conditions

1. **Prepare recovery first.** Create a production backup, verify it can be listed/read, and rehearse restoration into a disposable PostgreSQL instance. Do not proceed with real data until restoration has been demonstrated.
2. **Confirm the target.** Use the production provisioning identity only after an explicit environment/target check. Never reuse a development URL or infer the destination from an application URL.
3. **Provision roles.** Run reviewed, idempotent role/bootstrap SQL for `app_runtime`, `app_runtime_login`, and `app_ai_assessment_worker`. Do not set or rotate a login password as a side effect; configure credentials through the approved secret-management process as a separate controlled step.
4. **Apply the schema contract.** Review the exact SQL/DDL preview first. Stop on drops, truncation, deletion, unexpected cascade behavior, or any object outside the approved change. Do not trust a schema tool's exit status alone.
5. **Apply RLS policies.** Apply the checked-in policy SQL only after referenced roles and tables exist. Confirm RLS and FORCE RLS flags, policy command/role/USING/WITH CHECK content, and the unchanged expected policy count.
6. **Apply least-privilege grants and runtime login configuration.** Use the dedicated scripts only after review. Stop if a step requests credential rotation, broadens privileges, or reports a mismatch.
7. **Verify independently before app startup.** Run the read-only catalog auditor and runtime-role verifier. The expected catalog is **13 tables, 149 columns, 37 indexes, 54 constraints, 36 policies, and 3 roles**, with no violations or unexpected objects. Confirm the append-only ledger matrix separately: `app_runtime` has SELECT and INSERT, and not UPDATE, DELETE, TRUNCATE, REFERENCES, or TRIGGER (including applicable column privileges). Also inspect membership/inheritance and effective privileges rather than relying only on explicit GRANT statements.
8. **Start the application only after a clean audit.** Run health and authenticated runtime checks; stop on failed preflight, authentication, or catalog drift. Do not “fix” a failed audit by weakening RLS or skipping checks.

At every stage, keep a record of the reviewed change, sanitized result, operator, and recovery point. If an expected count, object definition, role, policy, or privilege differs, stop and investigate; do not continue to later steps.

## Signing keys and checkpoints

The current ledger signing key was shown during its creation and must be treated as exposed. Do not use it to protect real production records. Generate a new Ed25519 key in a controlled process, store its private half only in the approved secret store or a separately isolated signing service, and publish only the public key. Assign a new stable, versioned `keyId`; add it to a versioned trust registry with `validFrom`, status, and where appropriate `validUntil` or `revokedAt`. Preserve old public keys for historical verification according to the documented signing-time validity rules. Revocation is evaluated at the signature's signing time; do not claim that it retroactively invalidates or preserves signatures beyond that policy.

Prefer a signer isolated from the API/database host. A private key stored as an application secret does not protect against a compromised application host. Checkpoints should be signed by a distinct key and distributed on a channel independent of the bundle and database writer. Define an owner, publication cadence, retention, and recovery process; consumers must obtain the latest checkpoint from that trusted channel. A checkpoint only attests to its recorded workspace and sequence, and does not prove recency if an attacker can supply an older checkpoint.

## Backups and limits

Before production data is accepted, retain a verified backup under the approved retention policy and test restoration into a disposable environment. Rehearse both recovery and key-registry recovery. A Replit checkpoint is useful for workspace state but is not a substitute for a verified database backup, a tested data restore, or an independently held signing key/checkpoint.

## Implemented vs. projected

**Implemented in the project:** v1 receipt/event signing and verification, an append-only ledger with RLS/least-privilege contract, catalog/runtime preflight checks, offline bundle verification, and signed-checkpoint verification.

**Projected / not established by this plan:** production role/schema provisioning, production catalog conformance, tested production restore, rotation away from the exposed key, isolated signing service, and independent checkpoint publication. This document performs none of those operations and does not certify production readiness.
