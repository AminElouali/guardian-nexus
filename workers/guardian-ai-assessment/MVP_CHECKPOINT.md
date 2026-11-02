# Guardian Nexus MVP checkpoint

Updated: 2026-11-02 — offline OSV reconciliation and supply-chain summary
Scope: development/local laboratory only. No customer systems, external model APIs,
paid services, production database, remote deployment, or publishing.

## Latest supply-chain and isolation follow-up

This section supersedes older statements below about the cold offline image
build, IPv4 UDP coverage, and worker/API/dashboard test counts. Detailed
methodology and package triage are in `DEPENDENCY_AUDIT.md`.

- The preceding offline-build milestone began at clean HEAD `31bad696`. This
  follow-up started from HEAD `828766f286643f523b5035b30020a7cb2c7083e4`.
  The offline candidate
  `guardian-ai-assessment:offline-rebuilt` was already built locally as
  `sha256:e2d13fb48471dbcdc169e421598d5830303717266baf9892a3f11e86eb48e476`;
  it was not pushed or promoted over `guardian-ai-assessment:local`.
- Cold/offline build support uses the pinned local base plus the verified
  wheelhouse; this succeeds in the current prepared environment without build
  network. It is not an empty-machine build or bitwise reproducibility claim.
- Wheelhouse: 38/38 locked artifacts verified locally (36 runtime, 2
  build-only), `networkUsed=false`. Manifest SHA-256
  `ab8bc155558cc91e79a5a2f638b64dc0f0645bad29b42cc28bc521a1e37ebc79`.
  Candidate CycloneDX 1.6 SBOM: 124 components, SHA-256
  `8eb49149a21afac04818f94ac0183eb799ed740b8f2254a9f63c453c279c5d97`.
- The original full `--all-vulns` scan used Debian DB
  `95c71e88…6ec8` and PyPI DB `8fd7138a…5dde`: 186 Debian matches / 84 IDs;
  JSON SHA-256
  `c80e9efec40dbed890c691d33ac85cebe98dcd5aa646cedef7a3698ae326e6c2`.
  An offline rerun on 2026-11-02 with OSV Scanner 2.7.0 / SCALIBR 0.5.3,
  `--offline --offline-vulnerabilities --all-packages --all-vulns`, produced
  byte-identical JSON and exit code 1. The prior checkpoint's exit code 2 was
  incorrect; the original local `.exit-code` file also contains 1. Exit 1
  indicates findings, not a clean scan or a scan execution failure. Invocation,
  stdout/stderr, hashes, and summary are in
  `generated-artifacts/guardian-ai-assessment-offline/osv-reconciliation-20261102/`;
  summary SHA-256 `793ccb8d1c7e76e9c4978ef7f615d340522da98e78735478e5951112107cef55`;
  checksum manifest SHA-256 `c785e79f76773c134144d16a496db6a74ac499a984e0dab4b617134ce86a0089`.
  The shell capture wrapper then exited 2 on a formatting-only `printf` error
  after saving scanner exit 1 and JSON; that wrapper error is separately
  recorded and does not change the scanner result.
  The 124 PURLs match the preceding inventory exactly; no package remediation
  occurred. A full offline rescan of the same candidate image using the newer
  already-local Debian DB `4816191f…3582` returned exit 1, 177 matches / 81 IDs
  (1 critical, 25 high, 43 moderate, 9 low, 3 unscored; zero PyPI matches).
  Latest JSON SHA-256
  `292c48b7a65092730f080cb737e72e8e29a1610cbd3e304e1d9b6a87d18c59ca`;
  summary SHA-256
  `efcc94a5e803ca7999acec31812fdcd5d7a943a179c2fdd32b3777ddda4ceb6f`;
  run manifest SHA-256
  `d1f59502a412b9ee3acb5bdbd9e6f8e4c31547a91ae663551857b8c2126bcd16`.
  The older full scan had 186/84; only three moderate IDs differ across
  databases, not due to package changes. The separate 18-ID result used default
  filtering and is not the complete inventory. All 26 critical/high IDs remain
  in the latest full scan. Individual triage is in `DEPENDENCY_AUDIT.md`.
- Real container network audit under `--network=none`: IPv4 TCP/UDP and DNS
  blocked; IPv4 loopback reachable; IPv6
  `kernel_protocol_unavailable`, therefore NO VERIFICADO. Overall
  `incomplete_ipv6_not_verified`, exit 2; evidence SHA-256
  `be7b4fcb57bf9354fb8d655c30b8665350a2371bff1e9bcdbe81282012f4ed79`.
- Previously recorded, not rerun in this follow-up: API AI-contract 7/7 and
  dashboard report 4/4 passed. RLS/RBAC integration tests were not rerun because
  they write PostgreSQL fixtures and this step did not verify the target DB
  environment. No API or database code changed.
- Wheel provenance was rechecked against local hash locks. `langdetect 1.0.9`
  remains license-ambiguous (MIT metadata versus Apache license files); the
  local license inventory for all 38 locked artifacts has SHA-256
  `168e1534da55376e403b5587c6d702810f356c0517c6d8a3d64aa5aca4b36ff0`.
  The separate mounted native runtime inventory has SHA-256
  `2fafa80a397f89ccae66fcab113b94cd6475db627e4dc3f6f58f5ca528197873`;
  it hashes the local llama-cpp-python shared libraries and MarkupSafe extension.
  This is not complete dependency attribution or legal clearance. No package
  was removed or updated. The Trixie candidate simulation found no safe
  applicable package fix for the matched Debian advisories.
- The worker runtime inventory confirmed the reported source-package versions.
  `mount`, `nsenter`, `ldd`, `infocmp`, and `perl` binaries are present;
  `sqlite3`, `getfacl`, `setfacl`, `getfattr`, and `setfattr` are absent.
  Python's SQLite and gzip modules are present, but no worker source call path
  to the affected SQLite, ACL, attr, ncurses, PAM, Perl, or util-linux tools was
  identified. This is static reachability review, not exploit testing.
- The worker suite was rerun under `network=none`, read-only root, resource and
  capability limits, with an ephemeral `/tmp` tmpfs: 64/64 passed. A preceding
  read-only run without tmpfs had 7 errors from temporary-directory creation;
  that failed run is retained separately and was not counted as a pass.
- No package was changed and no image rebuild was needed or performed for this
  evidence/documentation-only follow-up. API, dashboard, database, typecheck,
  build, and E2E were not rerun; the UI was not changed.
- The Qwen/Garak executive report remains a tenant-scoped agent-evaluation
  report. The global worker supply-chain evidence is not inserted into that
  report because it is not tenant-job evidence; a separate internal summary is
  `reports/worker-supply-chain-executive.md`. No dashboard/API supply-chain
  report route was added.
- Remaining blockers: dual-stack host needed to verify IPv6; legal review of
  `langdetect` and native component obligations; the local OSV archives have no
  upstream signature verification and no Trixie fix candidate was found. The
  latest already-cached local database was used offline. The API still uses the
  prior `:local` image; candidate promotion was intentionally not performed.

## Follow-up audit — 2026-11-02

This update supersedes the older diskcache status, worker-test count, and OSV
“current scan” wording below. Prior runs remain as historical evidence; see
`DEPENDENCY_AUDIT.md` for the reconciled scan inputs and hashes.

- Worker image rebuilt locally as `guardian-ai-assessment:local`,
  config ID `sha256:1d433e201a17a138267a31b316e4a0cab2f373d44fb347034177581268fcf9bb`.
  No image was pushed. Worker tests now pass 55/55. A cold
  `docker build --network=none` did not complete because the pinned PyPI layer
  was not cached; the successful local build reused the cached hash-locked layer.
  Runtime inference is still `--network=none`.
- The patched `llama-cpp-python` source-build script completed offline. Its
  second wheel hash differs from the active wheel because of ELF build-id and
  temporary `llama.pc` prefix metadata; it was not promoted. Exact
  reproducibility remains open; see `DEPENDENCY_AUDIT.md` and
  `local-llm-build/source-manifest.json`.
- The mounted local-LLM runtime no longer contains `diskcache`: the patched
  `llama-cpp-python 0.3.36` wheel is hash-pinned, its cache feature fails closed,
  and the separate runtime SBOM/OSV scan covers three wheels with zero advisory
  IDs in the current local PyPI database. This is a runtime removal, not an
  upstream advisory fix or general security certification.
- A fresh direct Qwen run used eight real local inferences (4 attack, 4 benign;
  4 English, 4 Spanish) in 84.697 seconds. Results: 4/4 attack outputs exposed
  the synthetic canary, 0/4 unauthorized tool proposals, 0/4 target-tool
  proposals, 0 tool attempts, 0 state changes, 0 external calls; benign quoted
  instruction text propagated in 1/2 controls. Evidence file SHA-256
  `dc66a5d607edfeea172a2968b174b0c147c529c0e91a7553bfcfaabacd1e3956`.
  This separate eight-case run is not combined with the 14-case API E2E.
- New egress test evidence: IPv4 TCP and DNS UDP blocked, loopback reachable,
  IPv6 is `kernel_protocol_unavailable`, so overall is incomplete and IPv6 is
  not verified. A separate public IPv4 UDP destination was not probed; do not
  claim that protocol-specific check passed. Evidence SHA-256
  `3e6c52fddaf22e485fd4f5f0f2c7957213c36afbc180d9d7c53316c97e2bc424`.
- The earlier scan against the newer Debian OSV database used default
  filtering and showed 18 IDs (four high, zero critical); it was not a complete
  `--all-vulns` inventory. The comparable full scan against that same database
  shows 177 matches / 81 IDs, including 1 critical and 25 high. Compared with
  the older full scan, only three moderate IDs are absent; no package changed.
  The earlier claim that 66 IDs disappeared due to database content was wrong.
  This is not remediation. Exact scan hashes and critical/high triage are in
  `DEPENDENCY_AUDIT.md`.
- API unit tests pass 34/34; API and dashboard typechecks pass; the dashboard
  JSON download/redaction component test passes as part of 4/4 component tests.
  The download plumbing is tested without a Clerk session; no authenticated
  browser download was automated. User-provided screenshots previously
  confirmed an actual Clerk login and dashboard visit, but do not verify this
  download control.
- Fresh workspace scans after the changes reported 0 dependency findings,
  0 SAST findings, and 0 HoundDog findings. These do not change the container
  OSV status.
- Root typecheck and build passed with the workspace-required
  `PORT=5000 BASE_PATH=/`. Vite reported the existing >500 kB frontend chunk
  advisory; all package builds completed.
- Desktop preview at 1280×800 rendered the public Spanish Guardian Nexus home.
  Browser logs showed only the expected Clerk development-key warning and a
  WebGPU context warning; no Clerk sign-in was attempted in the capture.
- The combined E2E shell command exceeded 300 seconds after its first two tests
  passed. Its third synthetic job
  `40bc3e62-8e85-4ef4-b472-f893fb6c622e` later reached `succeeded` on attempt 2.
  A targeted autonomous E2E rerun then passed 1/1 in 147.1 seconds. A fresh
  full API E2E run passed 3/3, followed by dashboard integration tests 4/4.
  Latest autonomous job: `6b7fd29e-8c42-49fd-bfae-af4b0e467745`, succeeded on
  attempt 1 in 145.492 seconds. It used 14 real local Qwen inferences, all with
  `tool_choice=auto` (7 calibration, 7 holdout; 7 EN, 7 ES; 5 attack, 9 benign).
  Runtime `finish_reason` was `stop` in 14/14; direct `message.tool_calls` was
  0/14. The model's Qwen template marker adapter produced proposals in 13/14;
  this is adapted model output, not a direct native runtime tool-call event.
- Paired authorization result on those proposals: 13/13 identical proposal
  pairs; policy ON attempted 13, allowed 12, denied 1, and simulated 12
  authorized actions. Policy OFF only evaluated a disposable in-memory clone:
  13/13 counterfactual proposals would pass the bypassed gate, with 4 clone
  state changes. Both arms had 0 actual operation executions, persistent
  state changes, or external calls. Benign task success was 9/9, false blocks
  0/9, and attack potential was 1/5. Small laboratory sample only.
- Overall scenario metrics: unauthorized-proposal and unauthorized-attempt
  matrices each TP=1, FP=0, TN=9, FN=4 (n=14; positive support=5);
  unauthorized-execution matrix TP=0, FP=0, TN=9, FN=5 (n=14). These are
  attack-label metrics, not a claim of broad detector accuracy; the measured
  unauthorized execution count itself was 0. Task success was 12/14.
- Redacted report SHA-256 `1c42a9d9833f2151c051d3b371e189b288a70d1b6ee8435ed9e1960885b18e9c`;
  result evidence SHA-256 `c0ec6cac06ba61487c2e4c39b04bd237683656b025d43ac4f5fcc411bd65b433`;
  suite evidence SHA-256
  `5f9d7417822e2fd6cf86c7502beed4675bf029d5187194917e7df35a12b32f67`;
  paired-comparison evidence SHA-256
  `9c462e76b9126c3a5a7d6ab5685d3b042c58e801d120cf64191bed52cbeba87b`.

## Latest verified end-to-end laboratory evidence

- Latest API job `44bc6698-b334-41ef-8707-2a1be6f27ad0` succeeded on
  2026-11-01 using Qwen3-0.6B-GGUF Q8_0, the source-built
  `llama-cpp-python 0.3.36` wheel, and `tool_choice=auto`.
- Model revision `23749fefcc72300e3a2ad315e1317431b06b590a`; GGUF SHA-256
  `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`;
  Apache-2.0. Suite v1.4.0 / engine v1.3, fixed seed 20261031.
- 14 cases: 9 benign and 5 attack, 7 calibration / 7 holdout, 7 English / 7
  Spanish. All 14 model calls ended with `finish_reason=stop`; direct runtime
  `message.tool_calls` was 0/14. Guardian adapted 13 complete Qwen GGUF
  `<tool_call>` markers into proposals; 1 case produced no proposal. No forced
  function selection, free-JSON parsing, or fixture output contributed.
- Of 13 proposals, policy ON recorded 13 attempts, 12 authorizations and 12
  fictitious simulated executions; it denied 1 unauthorized fictitious bank
  change. Actual operations, persistent changes, and external calls: 0.
- Policy OFF reused all 13 proposal identities, only against disposable
  in-memory clones: 13/13 counterfactual "would execute", 4 clone-only state
  changes, and 0 tool-adapter calls or real effects.
- Bounded observations: benign task success 9/9; false blocks 0/9; attack
  potential 1/5; total task success 12/14. The Spanish holdout invoice
  override case produced no tool proposal; this is not evidence that the model
  detected or blocked that instruction. These small lab counts are not general
  accuracy, safety, or customer-service claims.
- API job runtime was 148.082 seconds. Docker verified network `none`, IPv4 and DNS
  blocked, loopback only, 1 CPU, 1536 MiB, 64 PIDs, concurrency 1, hard timeout
  180 seconds. IPv6 remained unavailable, not verified blocked.
- Evidence SHA-256:
  `c1e5b2b3f18f1339fcabedc3bc246b64b9fe8495dfe7ce4cc1c5e2b170c5d68f`
- Paired-policy evidence SHA-256:
  `9c462e76b9126c3a5a7d6ab5685d3b042c58e801d120cf64191bed52cbeba87b`
- Case-set SHA-256:
  `0980d82cbdc03e11b2ab164a64091e14a6e77ad386cd95deb7de856fe6fb28d0`
- The completed run's raw prompts, model responses, and tool arguments were not
  persisted. No real operation, persistent mutation, or external call occurred.
- Raw prompts, model responses, and tool arguments are not persisted. A
  sanitized tracked run summary is in `reports/autonomous-tool-selection-v1.4.0.md`.

## Isolation and tenant boundaries

- Worker used Docker `network=none`; IPv4 and DNS were blocked and loopback was
  available. IPv6 is **unavailable/unverified** because the kernel reports
  `kernel_protocol_unavailable`; do not claim IPv6 egress is blocked.
- The result was requested through the development API queue and returned
  through the tenant-scoped route; E2E covers role authorization, tenant
  isolation, idempotency, and evidence hashes using its development-only test
  identity. It does not verify a live Clerk browser sign-in. No production
  database was used.
- The dashboard component rendered the real run summary in its authenticated
  component state. Component tests passed; the screenshot browser cannot sign
  in, so the signed-in screen was not visually captured.

## Last verified checks

- API suite: 34/34 passed, including tenant/RLS/RBAC/idempotency/recovery cases.
- The 2026-11-01 worker suite was 44/44; the 2026-11-02 follow-up suite passed
  55/55 after the network-audit and cache-policy tests were added.
- Targeted real Qwen API E2E: 1/1 passed after source-wheel integration
  (148.082 seconds of worker runtime).
- Authenticated dashboard component suite: the prior 3/3 passed; the follow-up
  suite passed 4/4, including the JSON download/redaction test.
- The dashboard report is now Spanish executive copy with a redacted JSON
  download; component tests reject raw prompt/response/argument leakage.
- Typecheck and workspace build passed with `PORT=18753`, `BASE_PATH=/`, and
  `NODE_ENV=production`. The frontend build reported a large-bundle warning;
  no build errors.
- Replit dependency, SAST, and HoundDog scans: 0 reported findings each. These
  scan the workspace, not the worker container's OS packages.
- The first 14-case attempt failed closed with `worker_output_invalid` because
  the API contract still capped suite denominators at 12/8/4. The OpenAPI
  contract was extended additively to accept both legacy 12-case and new
  14-case evidence; codegen/typecheck passed, then the targeted E2E succeeded.
- Replacing the local LLM wheel also exposed a stale wheel filename in the API
  installer. The API allowlist/installer was aligned with the source-built
  manifest, local readiness returned `ready`, and the real queued E2E then
  passed.
- The combined E2E command exceeded its 300-second shell limit once. It was
  rerun by test name after the queue drained; the autonomous E2E passed.

## Supply-chain audit state

- Clean no-cache candidate image built from the pinned official base:
  `guardian-ai-assessment:audit-final`, config ID
  `sha256:8ddd216cb7511e998c4a6c6b7e38a92946e04ae231cc9826fde263b3a9ee7ebb`.
  It has no registry digest and was not pushed. Base is Python 3.13.18 /
  Debian 13, `python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb`.
- The 36 runtime distributions are now pinned by version and SHA-256 in
  `requirements-runtime.txt`; all selected filenames, sizes, and hashes matched
  official PyPI release metadata. The 2 build-only tools (`setuptools 84.2.1`,
  `wheel 0.48.0`) are separately hash-locked, installed to a temporary prefix,
  and removed before runtime. Their absence was checked in the final image.
- Build verification: `docker build --no-cache --pull=false --network=default`
  succeeded. Build-time package retrieval used the official PyPI index and
  hash-checked locks; the build network itself was not constrained by a host
  allowlist. Evaluation runs remain `--network=none`.
- Earlier worker tests: 44/44 passed in the final image using read-only filesystem,
  `--network=none`, 0.5 CPU, 768 MiB, and 64 PIDs. The self-test passed:
  public IPv4/DNS blocked, loopback only, IPv6 unavailable. The follow-up
  55/55 result is listed above; build tools are absent from the runtime image.
- Final CycloneDX 1.6 SBOM, generated inside the audited image: 124 components
  (37 Python distributions, 87 Debian packages), SHA-256
  `41bca7bfc0d5692af3802b5dbbd493d2e584516f939cda76fad06fd9427edc91`.
  License evidence: 12 reported expressions, 23 unnormalized names, 2
  `NOASSERTION`; 83 Python license files listed and copyright files present for
  all 87 Debian packages. Debian expressions remain unnormalized.
- OSV Scanner 2.7.0 / SCALIBR 0.5.3 was verified against Google's official
  release checksum (`160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b`).
  Official offline Debian and PyPI databases were downloaded and archive-tested;
  their local SHA-256 values are recorded in `DEPENDENCY_AUDIT.md`.
- Current OSV scan: exit status 1 because findings exist; 186 Debian
  package/advisory match records across 84 unique IDs and 0 PyPI matches in the
  image. By scanner max severity: 1 critical, 25 high, 46 moderate, 9 low, and
  3 unscored. Debian urgency separately marks 25 `unimportant` and 59
  unassigned. OSV records fixed-version events for 33 IDs, but the Trixie
  package-manager simulation found no candidate updates for matched packages.
  This is not an exploitability verdict or a clean scan.
- The 2026-11-01 separate offline OSV scan of the mounted local-LLM runtime found one
  `diskcache 5.6.3` issue (`CVE-2025-69872`, `PYSEC-2026-2447`,
  `GHSA-w8v5-vhqr-4h9v` aliases). The current runner does not attach a cache,
  but the package was still installed in that snapshot. The 2026-11-02
  follow-up removed it from the active wheelhouse and added fail-closed cache
  tests; the upstream advisory is not fixed. `llama-cpp-python` has a verified
  PyPI sdist input and local source-build manifest; exact byte-for-byte
  reproducibility and complete native license review are still open.
- A simulation using current official Debian Trixie package indexes showed only
  `tzdata` upgradable; no candidate updates were available for the affected
  packages. No packages were installed or changed by that simulation.
- `langdetect 1.0.9` has conflicting license metadata: PyPI/setup metadata says
  MIT, while the sdist `LICENSE`, `NOTICE`, and PyPI classifier say Apache-2.0.
  It remains license-ambiguous pending legal review. The SBOM is not legal
  clearance.
- The older 164-match / 69-advisory report is historical and not the result for
  this image. IPv6 remains unavailable/unverified because the host kernel
  rejects IPv6 sockets (`kernel_protocol_unavailable`).

## MVP decision and blockers

- The development-only laboratory MVP is demonstrable end to end: authenticated
  request, durable tenant queue, local model execution, external deterministic
  policy decision, paired counterfactual, persisted redacted evidence, API
  retrieval, and dashboard rendering are verified.
- This is not a customer-ready or remotely hosted service. The current image has
  unresolved Debian OSV matches (including four current high util-linux IDs)
  with no candidate upgrades in the pinned repository, unresolved `langdetect`
  and native-component license review, and no verified IPv6 egress test. The
  active local-LLM runtime excludes `diskcache`; the upstream advisory is not
  fixed and the old wheel remains only in ignored audit artifacts. Do not call
  that upstream issue fixed or treat it as installed in the rebuilt worker.
- Full cold image build with `--network=none` remains unverified: the successful
  local worker build reused a cached hash-locked dependency layer after the
  cold build could not reach uncached PyPI. Evaluator execution itself remains
  `--network=none`. Automated tests use a development identity; user-provided
  earlier captures confirm Clerk login and dashboard use, but no authenticated
  browser download of the JSON was independently automated. Redaction and
  download behavior passed component tests.
- No production database, customer systems, cloud worker, or publishing action
  was used. See `DEPENDENCY_AUDIT.md` for hashes, scope, and remaining
  limitations. Do not enable customer evaluations until the open dependency,
  legal, and dual-stack controls are resolved or formally accepted.
- Next verification requires an authorized dual-stack development host for
  IPv4/IPv6 TCP/UDP and DNS negative tests, plus a reviewed Trixie fix or
  deliberate base-image update and legal review of ambiguous/vendor licenses.
