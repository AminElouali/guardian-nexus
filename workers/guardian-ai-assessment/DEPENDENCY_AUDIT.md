# Guardian Nexus worker dependency audit

**Date:** 2026-11-01  
**Scope:** local development worker image only; no production, customers, cloud
workers, or published image. This is an inventory and advisory triage, not a
penetration test or legal opinion.

## Rebuild and provenance

- Final image tag: `guardian-ai-assessment:audit-final`.
- Local image config SHA-256:  
  `8ddd216cb7511e998c4a6c6b7e38a92946e04ae231cc9826fde263b3a9ee7ebb`
- Registry digest: none; the image was not pushed.
- Base: official Python `3.13.18-slim-trixie`, Debian 13, pinned as
  `python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb`.
  Docker Hub's current amd64 manifest matched that digest (image metadata dated
  2026-10-28).
- A clean `--no-cache --pull=false` build completed. The Docker build had network
  access for package retrieval; the Dockerfile pins `https://pypi.org/simple`
  and `pip --require-hashes`. The builder network was not enforced by an
  external hostname allowlist. No dependency installation happens at worker
  execution time.
- The separately mounted `llama-cpp-python 0.3.36` runtime was rebuilt from the
  official PyPI sdist (76,589,250 bytes; SHA-256
  `832db0699007f1be95a7e41ef12e88926b02ba836461e36a36372db2760c1a2e`) using
  the isolated build recipe in `local-llm-build/`. The resulting wheel is
  24,139,061 bytes, SHA-256
  `a71a5a2e4b27e25b0fd783bdd5deb5a612ad950e2b0e92a0b500dee24ccb7981`;
  its source URL, hashes, build inputs, license, and limitations are in
  `local-llm-build/source-manifest.json`. The wheel was built outside the
  evaluator and exercised under `--network=none`. This records provenance but
  does not claim bit-for-bit reproducible output.
- The source manifest pins the vendored `llama.cpp` commit
  `0c1e57098bba43ac29e6e3b677cdceebdd22334f` and records its MIT license.
  License obligations for every native vendored component are not yet fully
  normalized; see the residual license notes below.
- Dockerfile SHA-256:
  `5617c3a1e05d4287dbeda9740bdac6b7c04c6c55d67745b71366dcc02fe21972`.
- All 36 selected runtime artifacts were downloaded into the ignored
  `generated-artifacts/guardian-ai-assessment-wheelhouse/` directory outside
  the evaluation runtime. Their filename, size, and SHA-256 matched the
  corresponding official PyPI release JSON. This set contains 35 wheels and
  the `langdetect` source archive. The two build-only wheels were verified
  against their PyPI release hashes as well.
- Runtime packages are locked in `requirements-runtime.txt`; build tools are
  locked in `requirements-build.txt`. The build-only `setuptools 84.2.1` and
  `wheel 0.48.0` were installed under `/tmp/guardian-build-tools`, used to build
  the source package, then removed. The final image has neither module
  installed.
- Lock-file hashes: `requirements-runtime.txt`
  `75bcda09cdcaaa9d1528936ea2406965a497c0d91803f3b3e4b3c9fed74352a5`;
  `requirements-build.txt`
  `d19fd247e275104d426c23297aa0cead3c7c70626306cb5b3d5a0ae0edadbac1`.
- PyPI artifact verification manifest SHA-256:
  `b5d9638196673dce41934c9709fd234eef616b09a3a58926cf92fd1f75eea8c4`.
- `garak==0.17.1` and its existing attribution/license notice are preserved.

## SBOM and license review

- CycloneDX 1.6, generated from inside the audited image:
  `generated-artifacts/guardian-ai-assessment-audit-final.sbom.cdx.json`
- SBOM SHA-256:
  `41bca7bfc0d5692af3802b5dbbd493d2e584516f939cda76fad06fd9427edc91`
- Inventory: 124 components — 37 Python distributions and 87 Debian packages.
- Python license metadata: 12 SPDX-like expressions reported by package
  metadata, 23 unnormalized license names, and 2 `NOASSERTION`; 83 license,
  copying, or notice files were listed. All 87 Debian packages have a copyright
  file, but Debian license expressions were not normalized.
- `langdetect 1.0.9` is unresolved: PyPI's `info.license` and its `setup.py`
  state MIT, while the sdist's `LICENSE` and `NOTICE` and the PyPI classifier
  state Apache-2.0. Neither claim is silently preferred. Legal review is needed
  before customer distribution.
- Build-only `setuptools` and `wheel` report `MIT` in their wheel metadata and
  are not present in the final runtime SBOM. Other package license fields are
  preserved as reported; this audit does not grant legal clearance.

## Vulnerability scan

- Scanner: official Google OSV Scanner 2.7.0 / SCALIBR 0.5.3,
  commit `bfe2f84abd2f09fe0b83ba7f6dad40d296762f40`.
- Linux amd64 scanner binary SHA-256
  `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b`
  matched `osv-scanner_SHA256SUMS` from the v2.7.0 official GitHub release;
  that checksum file SHA-256 is
  `95d69019bcfe0586eb8f07aad4c56e2f734ee969e8e3e209591f259a1bfde88c`.
- OSV Scanner loaded the local offline database archives:
  - Debian `all.zip`: SHA-256
    `95c71e88a626f4ba428196019dae1658358862d45e2c769ad85b8a5e74ee6ec8`
  - PyPI `all.zip`: SHA-256
    `8fd7138ad08c733316d229a05ac5a8a9fdcba4f6439d80cdab97fe4e18445dde`
  The database hashes identify the exact local scan inputs; no separate
  upstream signature verification of the database archives was performed.
- The rebuilt image was scanned with the official offline vulnerability
  databases and `--all-packages --all-vulns`. JSON:
  `generated-artifacts/guardian-ai-assessment-osv-audit-rebuilt.json`
- Scan output SHA-256:
  `8bfd4528ff1c503fc485e5b8bfdc1f5a85a8ac65e5326e4d1a3832216951d803`
- Results: 186 Debian package/advisory match records across 84 unique advisory
  IDs and 20 unique matched package/version pairs; 0 PyPI matches in the worker
  image. The scanner exited 1 because findings were present, not because the
  scan command failed. The earlier 177/81 count is from the prior database
  snapshot, not this scan.
- By the scanner's maximum severity score per unique ID: 1 critical, 25 high,
  46 moderate, 9 low, and 3 without a numeric score. Debian urgency metadata
  separately marks 25 IDs `unimportant` and leaves 59 unassigned; these
  classifications can differ and are not exploitability determinations.
- The updated OSV data contains a fixed-version event for 33 IDs and none for
  51. A fixed event somewhere in the advisory history does not prove that a
  fix is available in the pinned Debian 13 repository. The separate official
  Trixie package-manager simulation found only `tzdata` upgradable and no
  candidate updates for the matched packages.
- Findings include core package families such as `glibc`, `zlib1g`,
  `libsqlite3-0`, and `util-linux`, as well as command-line packages. The raw
  report retains the full advisory list. A package/version match is not proof
  that a vulnerable code path is reachable.

## Separate local-LLM wheelhouse

The Qwen runtime is mounted into the worker from
`generated-artifacts/guardian-llm-lab/wheelhouse`; it is not installed in the
image. Therefore it is not covered by the image SBOM or image scan above.

- The local GGUF file is 639,446,688 bytes and its SHA-256 matches the pinned
  manifest: `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`.
- PyPI filename, size, and digest matched for the `diskcache 5.6.3`, `Jinja2
  3.1.6`, and `MarkupSafe 3.0.4` wheel artifacts. `numpy 2.3.4` and
  `typing-extensions 4.16.0` are inherited from the image and are in its
  hash-locked runtime inventory.
- `llama-cpp-python 0.3.36` now uses the locally built wheel whose digest and
  source archive are recorded above and in `local-llm-manifest.json`. The source
  wheel build and local Qwen run succeeded. This closes the earlier unknown
  binary-provenance gap for this wheel, but does not establish byte-identical
  rebuilds or complete licensing of every bundled native component.
- The offline OSV scan of the six pinned local-LLM Python packages found one
  unique issue in `diskcache 5.6.3`, represented by
  `CVE-2025-69872`, `PYSEC-2026-2447`, and `GHSA-w8v5-vhqr-4h9v`. OSV describes
  unsafe pickle deserialization and arbitrary code execution if an attacker
  can write to the cache directory. Its affected range ends at 5.6.3; PyPI's
  recorded affected range includes 5.6.3 and has no fixed-version event. The
  refreshed scan reports two alias records for one underlying issue. Other
  packages in this six-package scan had no OSV match in the downloaded database.
- In the current runner, `LocalQwenClient` creates `Llama` without a cache
  argument and does not attach a `LlamaCache`; the library initializes
  `self.cache` as `None`. This makes the vulnerable cache path unexercised in
  the observed code path, but does not remove the vulnerable dependency or
  establish safety for future cache use. The issue remains a customer-readiness
  blocker until a fixed release or an approved, tested removal is available.
- The PyPI metadata verification artifact is
  `generated-artifacts/guardian-ai-assessment-llm-pypi-verification.json`
  (SHA-256
  `a37bca5df8b10def24fae2388a326797656c2856f85f7a19b272625a93e84b4c`);
  the separate OSV result is
  `generated-artifacts/guardian-ai-assessment-llm-runtime-osv-rebuilt.json`
  (SHA-256
  `ee20fa979f42f968ed40147dbdb64468b5948bd0f21b12b9a74760f336446911`).
  The scanned package list is
  `generated-artifacts/guardian-ai-assessment-llm-runtime-requirements.txt`
  (SHA-256
  `8626ee2073b0a99a593d61291248143620de8269365e65d672b1471dc983ecf6`).

## Patch availability and runtime controls

- A simulation against current official Debian Trixie package indexes, using
  the image's installed package status, showed only `tzdata` upgradable.
  No packages were installed or changed. No candidate update was available for
  the OSV-matched packages at the time of this check. Simulation output:
  `generated-artifacts/guardian-ai-assessment-apt-upgrade-simulation.txt`
  (SHA-256
  `bd5676eadf4f51483e50c744c9cf460425349a22270c6ed4b0b95db1c4bfcc59`).
- Worker suite: 44/44 passed in the final image under Docker `--network=none`,
  read-only root, 0.5 CPU, 768 MiB memory, 64 PIDs, dropped capabilities, and
  non-root UID. The worker self-test passed: public IPv4 and DNS blocked,
  loopback only.
- IPv6 remains **unavailable/unverified**, not blocked: the host reports
  `kernel_protocol_unavailable`. No dual-stack claim is made.
- No Debian packages were force-removed, no alternative base was substituted,
  and no OSV finding was suppressed. Unresolved OS advisories, the separate
  `diskcache` advisory, the `langdetect` license ambiguity, incomplete native
  license review, and missing dual-stack verification remain blockers for
  customer use.

## Workspace security scans

- Replit dependency audit: 0 findings; SAST: 0 findings; HoundDog: 0 findings.
  These are workspace-level scans and do not supersede the OSV results for the
  container image or separately mounted LLM artifacts.

All raw images, scanner databases, package artifacts, SBOM, scan output, and
simulation output are in ignored `generated-artifacts/`; no secrets were read.
