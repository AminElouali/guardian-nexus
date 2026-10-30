---
name: Guardian Nexus safety commitments
description: Product boundaries for security integrations, claims, and production actions.
---

**Rule:** Guardian Nexus must use explicitly authorized, minimum-permission, read-only integrations; never request passwords or permanent credentials; never run unauthorized scans or automatic production remediation; clearly distinguish real capabilities and evidence from planned work; and never claim automatic compliance or certification.

**Why:** The user explicitly requires tenant consent, verifiable evidence, supervised actions, and accurate preparation-versus-certification claims.

**How to apply:** Apply these boundaries to connector setup, security scans, AI features, remediation, compliance copy, and public marketing before enabling or describing them.

**Rule:** A locally saved provider setup is not a live connection. Mark a connector connected only after validating the tenant's OAuth grant or successful AWS STS role assumption; local cancellation must never be presented as provider-side revocation.

**Why:** Microsoft consent and AWS trust are external authorization steps, and setup metadata alone does not prove access or revoke a grant.

**How to apply:** Keep readiness, preparation, consent, validated connection, and external revocation as distinct states in API responses, UI copy, evidence, and tests.
