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

**Rule:** Audit mounted model wheels and weights separately from the worker image; an image SBOM does not establish their provenance or risk.

**Why:** A local model wheelhouse can be outside the image inventory, and a matching version/hash in a project manifest alone does not prove the binary came from an official release. A separate scan can also find advisories omitted from the image scan.

**How to apply:** Before enabling a worker for customers, keep a separate hash, license, provenance, and advisory inventory for every mounted runtime artifact; require an official release match or a reproducible source build.

**Rule:** An OSV fixed-version event does not prove a patch is available in the pinned distribution; refresh and hash the advisory database, then check package-manager candidates separately.

**Why:** Updated Debian OSV data changed the image count from 177 matches / 81 IDs to 186 / 84 and listed fixed events for some advisories, while the pinned Trixie repository still offered no candidate updates for the matched packages.

**How to apply:** Report package-match counts separately from unique advisory IDs, distinguish CVSS severity from distro urgency, record the database hash, and simulate upgrades against the exact pinned distro before claiming remediation.

**Rule:** Keep untrusted or tenant-controlled content out of pickle-backed inference caches; when caching has no product need, omit it and fail closed if it is unexpectedly enabled.

**Why:** A cache can turn attacker-controlled writes into unsafe deserialization, and merely not using an optional cache path is weaker than removing its package and preventing activation.

**How to apply:** Review the model runtime's optional cache dependencies and serialization format whenever changing inference runtimes; preserve tests for absence, disabled configuration, and fail-closed construction.

**Rule:** Compare OSV scans only when the advisory database and scanner flags match; record the scanner process exit code separately from any shell or log-wrapper exit code.

**Why:** The same refreshed local database produced a filtered 18-ID result and a full 81-ID result with `--all-vulns`; an earlier comparison wrongly attributed the difference to database content. A logging wrapper can also fail after the scanner has already saved its result.

**How to apply:** Save exact argv, database hashes, scanner version/binary hash, JSON hash, scanner exit status, and wrapper status. Treat a failed database load as invalid—not a zero-finding scan—and never infer a fix from absence across different filtering modes or database snapshots.

**Rule:** In this Replit environment, OSV Scanner honors the inherited `XDG_CACHE_HOME` before a custom `HOME`; setting only `HOME` can silently select the wrong local advisory database.

**Why:** A Trixie scan intended to use the refreshed database instead loaded the workspace default cache, so its result counts were valid but the recorded database provenance was wrong. A later isolated cache path used symlinks to shared local archives, so the scanner-reported canonical file path differed from the configured XDG path despite matching content hashes.

**How to apply:** Set `XDG_CACHE_HOME` explicitly and record the configured database path, scanner-reported path, resolved symlink target, archive hashes, and loaded `stderr` lines. Validate hashes and target identity before comparing results; preserve prior logs and add correction records rather than rewriting evidence.

**Rule:** A scanner exit code indicating findings is not an execution failure when valid output and database provenance are verified; record scanner and wrapper exit codes separately.

**Why:** OSV Scanner returns a nonzero status for vulnerability matches, while cache, version, archive, or JSON failures make the result untrustworthy for a different reason.

**How to apply:** Require a parseable scanner version, exact loaded DB paths and hashes, valid JSON, and internally consistent finding counts. Classify mismatched provenance separately from process failures and findings.

**Rule:** A proposal held at `approval_required_before_dispatch` is neither an explicit policy DENY nor an execution. In paired-evidence v2, report pending approvals separately from denials while retaining strict validation and reading legacy v1 evidence compatibly.

**Why:** Counting a valid approval hold as DENY made worker/API/UI metrics disagree and obscured the action state, even though dispatch correctly never occurred.

**How to apply:** Derive approval state from the verified trace result code, require matching pair and summary fields in v2, and ensure the hold remains unauthorized and unexecuted. Do not change policy outcomes merely to fit the report.

**Rule:** The laboratory SDK may submit only versioned, server-allowlisted scenario IDs; tenant, actor, role, tool, resource, policy decision, and action binding are derived or verified server-side. Never accept caller-selected policy outcomes or arbitrary tool dispatch.

**Why:** SDK callers are untrusted inputs; accepting their identity or policy claims would bypass the independent policy engine and tenant boundary.

**How to apply:** Keep the lab adapter fixed and synthetic. Any future general action SDK must bind authenticated identity to workspace membership and pass server-side policy before dispatch; DENY and approval-required actions never dispatch directly.

**Rule:** Verify evidence digests against the exact canonical wire representation and the versioned engine convention; do not normalize timestamp strings before validation.

**Why:** Deterministic policy-lab cases omit the digest field when hashing, while Qwen evidence hashes an empty-field sentinel. Zod date coercion also rewrites timestamp precision/offsets, which changes signed bytes without changing the represented instant.

**How to apply:** Keep engine-specific digest conventions explicit, preserve raw timestamp strings through verification, and test both valid evidence and altered-digest rejection.
