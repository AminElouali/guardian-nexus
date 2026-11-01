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
  blocker in this 2026-11-01 snapshot. The 2026-11-02 addendum below records
  its tested removal from the active runtime wheelhouse and patched optional
  dependency behavior.
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
- Earlier worker suite: 44/44 passed in the final image under Docker `--network=none`,
  read-only root, 0.5 CPU, 768 MiB memory, 64 PIDs, dropped capabilities, and
  non-root UID. This count is superseded by the 55/55 follow-up suite below.
- IPv6 remains **unavailable/unverified**, not blocked: the host reports
  `kernel_protocol_unavailable`. No dual-stack claim is made.
- No Debian packages were force-removed, no alternative base was substituted,
  and no OSV finding was suppressed. This 2026-11-01 snapshot still had the
  `diskcache` advisory in its mounted runtime; the 2026-11-02 addendum below
  records the tested removal. OS advisories, `langdetect` license ambiguity,
  incomplete native license review, and missing dual-stack verification remain
  blockers for customer use.

## Workspace security scans

- Replit dependency audit: 0 findings; SAST: 0 findings; HoundDog: 0 findings.
  These are workspace-level scans and do not supersede the OSV results for the
  container image or separately mounted LLM artifacts.

All raw images, scanner databases, package artifacts, SBOM, scan output, and
simulation output are in ignored `generated-artifacts/`; no secrets were read.

## Follow-up addendum — 2026-11-02

This is a development-only follow-up; it supersedes earlier “current” statements
about the mounted diskcache package and the worker test count. It does not claim
that the container is vulnerability-free or ready for customer workloads.

### Rebuilt image, SBOM, and current OSV snapshot

- The local image `guardian-ai-assessment:local` was rebuilt with the pinned
  Python 3.13.18 / Debian 13 base. Its local image ID is
  `sha256:1d433e201a17a138267a31b316e4a0cab2f373d44fb347034177581268fcf9bb`.
  It was not pushed. The full Docker build with `--network=none` could not
  resolve an uncached PyPI build layer. The subsequent development build used
  the configured official PyPI index and reused the locally cached, hash-locked
  dependency layer. The evaluator itself remains `--network=none`; this is not
  evidence that a cold full image build is network-independent.
- CycloneDX 1.6 inventory from the rebuilt image:
  `generated-artifacts/guardian-ai-assessment-worker-followup.sbom.cdx.json`,
  SHA-256
  `ba34bd7da9ef7759f69ffaeb16a0e7d39888fd64b4c1b2c68d3f66a699a14533`.
  It contains 124 installed-package components (37 Python distributions and
  87 Debian packages). Its 124 package PURLs are identical to the prior image
  inventory: no OS package was removed or upgraded. The inventory explicitly
  says vulnerability scanning is separate.
- The current local Debian OSV archive is SHA-256
  `4816191fe3b9edc162646d56b0f26ee417c26bacdd02d1c39a5bcfa957c53582`;
  the PyPI archive is unchanged at
  `8fd7138ad08c733316d229a05ac5a8a9fdcba4f6439d80cdab97fe4e18445dde`.
  OSV Scanner 2.7.0 loaded both offline. The Debian archive hash differs from
  the prior scan input (`95c71e88…`); neither archive has an upstream signature
  verification in this project.
- Current offline scan:
  `generated-artifacts/guardian-ai-assessment-worker-followup-osv.json`,
  SHA-256
  `9b8f43b7482d5a36239eef4e5325940065a57dec6e0741c7602d01bbe31a87e6`.
  The scanner exited 1 because findings were present. Of 124 inventoried
  packages, six have current advisory groups across 18 unique IDs: 4 high, 6
  moderate, 7 low, and 1 unscored; there are 0 critical IDs in this refreshed
  local dataset. The four current high IDs are all in installed
  `util-linux 2.41.5-0+deb13u1`: `DEBIAN-CVE-2026-76642` (8.5),
  `DEBIAN-CVE-2026-78408` (7.9), `DEBIAN-CVE-2026-78410` (7.8), and
  `DEBIAN-CVE-2026-78409` (7.0).
- The other 14 current IDs in that JSON are low/moderate/unscored: apt
  `2011-3374`; coreutils `2017-18018`, `2025-5278`, `2026-56391`, `2026-56392`;
  dash `2026-102473`, `2026-102474`; diffutils `2026-53910`; tar
  `2005-2541`, `2026-18477`, `2026-18508`, `2026-5704`; util-linux
  `2022-0563`, `2026-3184`. No current match was suppressed.
- The previous scan JSON still records 186 match records / 84 IDs, including
  one critical and 25 high, against the older Debian database hash. The new
  scan finds only 18 of those IDs (66 are absent from the newer local
  dataset). The installed-package PURLs are identical, so this is a scanner
  database-content difference, not a patch or remediation. Do not mark the
  66 as fixed based on absence from the refreshed scan. The preserved old JSON
  is the evidence for its historical result; the old database archive is no
  longer available in the workspace.

### Actionable historical critical/high triage

| Priority and package | Historical IDs and affected surface | Reachability and mitigation | Fix/status |
| --- | --- | --- | --- |
| Critical, `libc6 2.41-12+deb13u4` (`glibc`) | `DEBIAN-CVE-2019-1010022`, score 9.8 in the prior snapshot | Core libc is present and used. Debian urgency was `unimportant`; upstream describes the issue as a mitigation bypass that requires a separate stack overflow, not an independently reachable remote flaw. No exploit test was run. | Absent from the refreshed local OSV archive, but this is not a package fix. Debian tracker: https://security-tracker.debian.org/tracker/CVE-2019-1010022 . No Trixie candidate was available in the recorded apt simulation. |
| High, `libc6` (`glibc`) | `2019-1010023` (8.8), `2018-20796` (7.5), `2019-9192` (7.5), `2026-19499` (7.7), `2026-5435` (7.3), `2026-84243` (7.0) | Core library paths are present; applicability depends on the specific allocator, resolver, and process state described by each advisory. No public exploit was attempted. | These high IDs were in the prior result and absent from the refreshed local OSV snapshot. No installed package changed. Recorded newer-suite events include glibc 2.43-5/2.43-7; no matching Trixie package candidate. |
| High, `libsqlite3-0 3.46.1-7+deb13u2` (`sqlite3`) | `2026-119374` (8.5), `2026-119379` (8.5), `2026-119586` (8.5), `2026-119373` (7.8), `2025-70873` (7.5) | SQLite library is installed. The `.recover` CLI finding is not reachable through the worker because the `sqlite3` CLI is absent; FTS5, session/changeset, and zipfile paths require callers to exercise those APIs/extensions. | Historical-only in the refreshed local archive; no package update. No Trixie candidate recorded. Do not infer the library findings are fixed from the missing match. |
| High, `util-linux 2.41.5-0+deb13u1` | Current: `2026-76642` (8.5), `2026-78408` (7.9), `2026-78410` (7.8), `2026-78409` (7.0) | `mount` and `nsenter` are present. The evaluator runs non-root, read-only, with all capabilities dropped and `no-new-privileges`; these reduce privileged mount/cgroup paths but do not fix the installed code. | Current local OSV hits and official Debian tracker still require follow-up: https://security-tracker.debian.org/tracker/source-package/util-linux . No Trixie candidate; newer-suite event `2.42.4-1` is not a Trixie fix. |
| High, `libacl1 2.3.2-2+b1` | `2026-54369` (8.4), `2026-54370` (7.2) | Library is installed; symlink/TOCTOU conditions depend on attacker-controlled filesystem paths. Worker inputs are fixed and mounts are read-only, reducing but not eliminating applicability. | Historical-only in refreshed local OSV data. Newer-suite event `acl 2.4.0-1`; no Trixie candidate. |
| High, `libattr1 1:2.5.2-3` | `2026-54371` (8.4) | Library is installed; `getfattr`/`setfattr` tools are absent. | Historical-only in refreshed local OSV data. Newer-suite event `attr 1:2.6.0-1`; no Trixie candidate. |
| High, `zlib1g 1:1.3.dfsg+really1.3.1-1+b1` | `2026-85091` (8.3) | Runtime library is present. Advisory concerns specific `gz_*` write behavior; no such input-controlled write path was identified in the evaluator. | Historical-only in refreshed local OSV data; no Trixie candidate or verified patch for the pinned suite. |
| High, `ncurses-bin 6.5+20250216-2` | `2025-69720` (7.8) | `infocmp` is present, but the worker does not invoke it on untrusted terminal databases. | Historical-only in refreshed local OSV data. Newer-suite event `ncurses 6.6+20251231-1`; no Trixie candidate. |
| High, `libpam0g`, `libpam-modules`, `libpam-modules-bin`, `libpam-runtime` 1.7.0-5 | `2025-8941` (7.8) | PAM namespace path is installed; the worker is not an interactive login service and does not invoke `pam_namespace` in its job flow. | Prior Debian status was undetermined; historical-only in refreshed local OSV data. No Trixie candidate. |
| High, `perl-base 5.40.1-6+deb13u1` | `2026-82560` (7.5), `2026-9538` (7.5) | Perl is installed but not invoked by the worker. The reports concern Pod::Text and Archive::Tar parsing/availability. | Historical-only in refreshed local OSV data. Newer-suite event `perl 5.42.3-1`; no Trixie candidate. |
| High, `libstdc++6 14.2.0-19` | `2026-95619` (7.7), `2026-102010` (7.0) | The C++ runtime is needed by the native llama runtime. Removing it would break inference; no exploit path was demonstrated. | Historical-only in refreshed local OSV data. Newer-suite GCC event `14.4.0-3`; no Trixie candidate. |

The exact Debian-source mapping and all 186 historical match records remain in
the preserved OSV JSON. The table distinguishes package presence and plausible
attack surface from proof of exploitability; no findings were suppressed.
Debian tracker source pages for the affected families:
https://security-tracker.debian.org/tracker/source-package/glibc ,
https://security-tracker.debian.org/tracker/source-package/sqlite3 ,
https://security-tracker.debian.org/tracker/source-package/acl ,
https://security-tracker.debian.org/tracker/source-package/attr ,
https://security-tracker.debian.org/tracker/source-package/zlib ,
https://security-tracker.debian.org/tracker/source-package/ncurses ,
https://security-tracker.debian.org/tracker/source-package/pam ,
https://security-tracker.debian.org/tracker/source-package/perl ,
https://security-tracker.debian.org/tracker/source-package/gcc-14 .

### Runtime, egress, and unresolved review

- The separately mounted runtime now contains only `llama-cpp-python 0.3.36`,
  `Jinja2 3.1.6`, and `MarkupSafe 3.0.4` (three wheel packages). Its
  CycloneDX 1.6 inventory from the pinned package list is
  `generated-artifacts/guardian-ai-assessment-llm-runtime-followup.sbom.cdx.json`,
  SHA-256
  `5ee47581e269eb2456a88e828cef79092ff50f18b00fd52c34f5942179e0a1f5`.
  The offline PyPI OSV scan found 3 packages, 0 advisory IDs:
  `generated-artifacts/guardian-ai-assessment-llm-runtime-osv-followup.json`,
  SHA-256
  `8b2a6f1a5c9381a396e99ac111d6d820834eae21d4fee30f79d296d72f2de0f6`.
  The inherited `numpy` and `typing-extensions` remain covered by the worker
  image scan, not by this separate wheelhouse SBOM.
- The local `llama-cpp-python` wheel was rebuilt from the hash-verified official
  sdist with `--network=none`; its size is 24,140,277 bytes and SHA-256 is
  `5e50c8f09c0ed78512bfb16adb32be9e0c65b8ced7c1efcfc200c38782141e96`.
  `local-llm-build/build-wheel.sh` records the source hash and offline build
  steps. Only one build was run, so bit-for-bit reproducibility is not claimed.
- The wheel patch makes `diskcache` optional and lazy-loaded. It is absent from
  the active wheelhouse; `cache=None` is explicit; runtime startup fails closed
  if `diskcache` is importable or caching is requested. Five cache-policy tests,
  an isolated wheel smoke, and a fresh eight-case real-Qwen run passed. This
  removes the vulnerable package from this local runtime; it does not remediate
  the package's own advisory or certify the modified upstream component.
- `scripts/verify-egress-isolation.sh` ran with Docker `--network=none` and
  returned its documented incomplete status (exit 2): IPv4 TCP and DNS UDP
  were blocked; IPv4 loopback worked; IPv6 socket creation returned
  `kernel_protocol_unavailable`, so IPv6 TCP/DNS and IPv6 loopback are
  **unverified**, not blocked. Evidence JSON SHA-256:
  `3e6c52fddaf22e485fd4f5f0f2c7957213c36afbc180d9d7c53316c97e2bc424`.
  A dual-stack host is still required to validate the IPv6 branches.
- The 87-versus-78 Debian package comparison did not justify a new base or
  forced package removal. The Python image's additional libraries support
  Python, TLS/certificates, FFI, and the native runtime; the two obvious
  candidates (`adduser`, `netbase`) offer small reduction without removing the
  high-risk core families. No alternative image was built, so no reduced-image
  scan is claimed. `langdetect 1.0.9` license conflict and complete native
  vendor license review remain unresolved and require legal/source evidence.
- Fresh workspace scans after these changes: Replit dependency audit reported
  0 findings at every severity, SAST reported 0 results, and HoundDog reported
  0 vulnerabilities. These results do not cover or override the Debian OSV
  findings above.
- A second local build of the patched `llama-cpp-python 0.3.36` wheel completed
  offline from the verified sdist and patch, using builder image ID
  `sha256:1190b243b1ebdd29c6547a1959531a58c474e3c6cb953333fc9bf20b866bf2d6`.
  It produced SHA-256
  `7bd646f48c830457b85fe4801f2f6992065299f3fea253dea03c247683397ad1`, not the
  active wheel's `5e50c8f09c0ed78512bfb16adb32be9e0c65b8ced7c1efcfc200c38782141e96`.
  Comparing the 92 zip entries found only ELF build-id bytes, the temporary
  `llama.pc` prefix, and the derived `RECORD` hashes differed. This is evidence
  of a successful offline source rebuild, not bit-for-bit reproducibility; the
  rebuilt artifact was not installed or promoted.
