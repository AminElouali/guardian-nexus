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

**Rule:** Never describe deterministic fixtures as a garak evaluation. Run garak only in a dedicated isolated worker with deny-by-default egress, explicit loopback allowlisting, and enforceable resource/concurrency limits.

**Why:** garak's REST generator accepts configurable targets, so process-level assumptions or a localhost-looking UI do not prevent network access or bound tenant cost.

**How to apply:** If an isolated worker and verified egress boundary are unavailable, expose only a clearly labeled mock simulation and keep real garak execution disabled.

**Rule:** In this Replit host, `unshare --net` is denied but Docker `--network=none` is available; an inactive `sit0` tunnel interface may still appear.

**Why:** Interface names alone are not proof of egress, and an unavailable namespace tool should not be bypassed with weaker isolation.

**How to apply:** Test the actual Docker runtime, reject default routes and active non-loopback links, and verify IPv4, IPv6, DNS, and loopback behavior before claiming an offline worker.

**Rule:** A network probe reported as `unavailable` because the host kernel lacks IPv6 is not evidence that IPv6 egress is blocked; treat it as incomplete and do not activate a remote worker until a dual-stack-capable environment verifies it.

**Why:** The current development host cannot create an IPv6 socket, so the public IPv6 connection attempt cannot prove deny behavior.

**How to apply:** Report each address family as blocked, reachable, or unavailable. Require blocked IPv4, IPv6, and DNS results before remote evaluation jobs are enabled.

**Rule:** Define AI security evaluation labels by task. Keep instruction execution separate from literal or encoded canary propagation; a literal-trigger detector must not be presented as a semantic execution classifier.

**Why:** Static local fixtures showed that quoting can be a positive for propagation but a false positive for execution, while Base64 propagation can be missed by a detector that only searches for the raw trigger.

**How to apply:** Report separate confusion matrices with denominators for each task and split. When using Garak, require the expected probe/detector `eval` record and verify its `fails` count against the attempt scores; describe static fixtures as detector tests, not model evaluations.

**Rule:** Persist only bounded per-case objective masks and evidence digests plus aggregate tool counters; do not persist raw prompts, responses, or tool traces.

**Why:** Raw content can expose sensitive material, while retaining every trace can exceed the worker-to-API evidence limit.

**How to apply:** Keep raw fixture content in worker memory only, validate hashes and aggregate denominators at API ingestion, and store compact evidence inside the tenant-scoped job result.

**Rule:** Autonomous Qwen results must separate expected task outcomes from observed tool events; small calibration/holdout splits are bookkeeping, not statistical validation.

**Why:** Scenario labels describe intended cases, not detector findings, and a model may produce no native tool calls even when a task explicitly requests one.

**How to apply:** Report native calls, proposal/attempt/authorization/execution, task outcomes, inconclusives, and denominators separately. Do not generalize small samples or claim an LLM policy denial unless a real unauthorized proposal was observed.

**Rule:** Policy-off counterfactuals must never call tool adapters; evaluate only a cloned synthetic state and report hypothetical effects without persistent or external actions.

**Why:** A paired comparison must show the value of enforcement without actually disabling the safety boundary.

**How to apply:** Reuse the same hashed proposals, seed, initial-state digest, and deterministic oracles for both arms; assert zero real executions, persistent changes, external calls, and raw payload storage.

**Rule:** A timed-out development E2E command does not prove its separately managed queue worker stopped. Check job status and lease before retrying; let owned lab work reach a terminal state instead of deleting queue rows manually.

**Why:** A long local-model job continued under the managed API worker after its initiating test command exceeded the shell timeout, leaving a live lease that correctly blocked the next E2E setup.

**How to apply:** Run expensive local-model cases by test-name pattern, inspect only development job metadata after a timeout, wait for completion or recovery, then rerun the targeted test.
