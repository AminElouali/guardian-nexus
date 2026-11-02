---
name: AI assessment queue test ordering
description: Avoid races between real evaluation jobs and lease-recovery tests.
---

**Rule:** Run real API/worker E2E jobs serially with API tests that claim or recover rows in the shared PostgreSQL assessment queue.

**Why:** The development queue is shared across test processes; a concurrent E2E worker can legitimately claim the row a lease-recovery test expects to claim.

**How to apply:** Let all E2E jobs reach terminal states and clean up before running the API security suite. Typecheck and builds can run independently.
