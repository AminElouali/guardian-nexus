---
name: Approval replay boundary
description: Safety requirements for persistent human approvals and any later laboratory-only replay.
---

Human approval records a decision only. Do not re-dispatch an action unless the exact normalized synthetic action can be reconstructed from an allow-listed representation and its immutable binding is revalidated atomically at replay. Replays must remain simulation-only; never connect approval to external tools or real tenant systems.

**Why:** An approval endpoint can become a second action-execution path. Persisting or accepting mutable raw arguments creates replay, alteration, and data-exposure risks.

**How to apply:** Keep API/UI wording explicit that approval does not execute or resume. If a future lab replay is added, bind tenant, job, case, action digest, actor and policy version; enforce one-time expiry and idempotency before invoking only the synthetic simulator. If exact reconstruction is unavailable, leave the decision as audit state and report resumption as pending.
