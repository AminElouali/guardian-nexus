# Guardian Nexus MVP checkpoint

Updated: 2026-11-01
Scope: development/local laboratory only. No customer systems, external model APIs,
paid services, production database, remote deployment, or publishing.

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
- Worker suite is now 44/44 passed in the clean rebuilt image.
- Targeted real Qwen API E2E: 1/1 passed after source-wheel integration
  (148.082 seconds of worker runtime).
- Authenticated dashboard component suite: 3/3 passed.
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
- Worker tests: 44/44 passed in the final image using read-only filesystem,
  `--network=none`, 0.5 CPU, 768 MiB, and 64 PIDs. The self-test passed:
  public IPv4/DNS blocked, loopback only, IPv6 unavailable. Build tools are
  absent from the runtime image.
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
- A separate offline OSV scan of the mounted local-LLM runtime found one
  `diskcache 5.6.3` issue (`CVE-2025-69872`, `PYSEC-2026-2447`,
  `GHSA-w8v5-vhqr-4h9v` aliases). The current runner does not attach a cache,
  but the package remains installed and has no fixed version in the refreshed
  OSV record. `llama-cpp-python` now has a verified PyPI sdist input and local
  source-build manifest; exact byte-for-byte reproducibility and complete
  native license review are still open.
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
  unresolved Debian OSV matches with no candidate upgrades in the pinned
  repository, a separate `diskcache` advisory in the local-LLM wheelhouse,
  unresolved `langdetect` and native-component license review, and no verified
  IPv6 egress test. A live Clerk browser sign-in and signed-in screenshot remain
  unverified; E2E uses a development-only identity and the dashboard component
  tests render authenticated state.
- No production database, customer systems, cloud worker, or publishing action
  was used. See `DEPENDENCY_AUDIT.md` for hashes, scope, and remaining
  limitations. Do not enable customer evaluations until the open dependency,
  legal, and dual-stack controls are resolved or formally accepted.
