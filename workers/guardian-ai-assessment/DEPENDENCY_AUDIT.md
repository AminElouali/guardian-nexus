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
- Earlier default-filter offline scan:
  `generated-artifacts/guardian-ai-assessment-worker-followup-osv.json`,
  SHA-256
  `9b8f43b7482d5a36239eef4e5325940065a57dec6e0741c7602d01bbe31a87e6`.
  It returned 18 IDs (4 high, 6 moderate, 7 low, 1 unscored) because it used
  the default filtering and did not pass `--all-vulns`; its 0 critical count
  must not be treated as a full-inventory result.
- Comparable full scan of `guardian-ai-assessment:offline-rebuilt` against the
  newer local Debian DB `4816191fe3b9edc162646d56b0f26ee417c26bacdd02d1c39a5bcfa957c53582`
  used `--offline --offline-vulnerabilities --all-packages --all-vulns`.
  Output:
  `generated-artifacts/guardian-ai-assessment-offline/osv-latest-db-20261102/osv-retry.json`,
  SHA-256
  `292c48b7a65092730f080cb737e72e8e29a1610cbd3e304e1d9b6a87d18c59ca`.
  It exited 1 with valid JSON: 177 match records, 81 IDs, 20 matched
  package/version pairs, 93 ID/package/version tuples; severity is 1 critical,
  25 high, 43 moderate, 9 low and 3 unscored. It found 0 PyPI matches.
- The 26 critical/high IDs listed in the full scan below are still present in
  the newer DB result. Compared with the older `95c71e88…` full scan
  (186 records/84 IDs), three moderate IDs are absent:
  `DEBIAN-CVE-2026-114690` (score 6.2),
  `DEBIAN-CVE-2026-114691` (5.9), and
  `DEBIAN-CVE-2026-115455` (6.5). No advisory IDs were added. Both candidate
  SBOMs have 124/124 identical PURLs, so these differences are due to the local
  database contents, not a package patch. Do not call an absent advisory fixed.
- The other 14 IDs visible in the earlier default-filter scan are low/moderate/unscored: apt
  `2011-3374`; coreutils `2017-18018`, `2025-5278`, `2026-56391`, `2026-56392`;
  dash `2026-102473`, `2026-102474`; diffutils `2026-53910`; tar
  `2005-2541`, `2026-18477`, `2026-18508`, `2026-5704`; util-linux
  `2022-0563`, `2026-3184`. No current match was suppressed.

### Earlier grouped triage (superseded)

The individual 26-row table under **Offline OSV exit-code reconciliation and
current critical/high review** below is authoritative for the full scan with
`--all-vulns`. The earlier grouped table conflated the default-filter scan with
the full inventory and is removed. The full scan is still scanner evidence,
not proof of exploitability; no finding has been suppressed or marked fixed.
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

## Offline OSV exit-code reconciliation and current critical/high review — 2026-11-02

### Reproducible offline scan and discrepancy

- Starting HEAD: `828766f286643f523b5035b30020a7cb2c7083e4`; image
  `guardian-ai-assessment:offline-rebuilt`, image ID
  `sha256:e2d13fb48471dbcdc169e421598d5830303717266baf9892a3f11e86eb48e476`.
- Scanner was local OSV Scanner 2.7.0 / SCALIBR 0.5.3. Exact argv:

  ```sh
  /nix/store/fqrzh6k64f06wa536i8blmh45cm3sy12-replit-runtime-path/bin/osv-scanner \
    scan image --offline --offline-vulnerabilities --all-packages --all-vulns \
    --format json \
    --output-file generated-artifacts/guardian-ai-assessment-offline/osv-reconciliation-20261102/osv.json \
    guardian-ai-assessment:offline-rebuilt
  ```

- Run timestamp: `2026-11-02T05:06:09Z`. `--offline` disables features
  requiring network access; the image was already local. Scanner stderr confirms
  that it loaded local databases:
  - Executable resolved to
    `/nix/store/12zjcq0r4lxw73kc3c1h5yyfdqmcq5cq-osv-scanner-2.7.0/bin/osv-scanner`,
    SHA-256
    `73cc8c323f04d4dbc39a861033819624524f3a7908be730f92d3f076fda0f087`.
    The binary version is verified locally; this run did not independently
    verify that Nix-store binary against an upstream release signature.
  - Debian archive SHA-256
    `95c71e88a626f4ba428196019dae1658358862d45e2c769ad85b8a5e74ee6ec8`
  - PyPI archive SHA-256
    `8fd7138ad08c733316d229a05ac5a8a9fdcba4f6439d80cdab97fe4e18445dde`
  - CycloneDX 1.6 SBOM SHA-256
    `8eb49149a21afac04818f94ac0183eb799ed740b8f2254a9f63c453c279c5d97`
- New output JSON SHA-256:
  `c80e9efec40dbed890c691d33ac85cebe98dcd5aa646cedef7a3698ae326e6c2`.
  It is byte-identical to the earlier local JSON with that same hash. Both the
  earlier `osv.exit-code` file and the offline rerun recorded **1**. The previous
  checkpoint's **2** was a documentation error. The rerun returned 1 with valid
  JSON and local DB load messages; this is the findings exit status, not a
  successful-clean result. Stdout was empty.
- Older-database scan counts: 186 Debian package/advisory match records; 84
  unique advisory IDs; 20 unique package/version pairs (96 ID/package/version
  tuples); zero PyPI matches. Severity by unique ID: 1 critical, 25 high,
  46 moderate, 9 low, 3 unscored. These are matches, not demonstrated exploits.
- Captured evidence under
  `generated-artifacts/guardian-ai-assessment-offline/osv-reconciliation-20261102/`:
  `command.txt`, `context.txt`, `osv.json`, `stdout.log`, `stderr.log`,
  `exit-code.txt`, and `summary.json`; the summary SHA-256 is
  `793ccb8d1c7e76e9c4978ef7f615d340522da98e78735478e5951112107cef55`.
  `SHA256SUMS.txt` covers the run files and has SHA-256
  `c785e79f76773c134144d16a496db6a74ac499a984e0dab4b617134ce86a0089`.
  The scanner itself exited 1; the enclosing display wrapper exited 2 only
  after capture, because Bash `printf` treated a separator beginning with `-`
  as an option under `set -e`. The scanner JSON and exit-code file were already
  written and hashed; this wrapper error does not change scan status.
- A second full offline scan used the newer already-local Debian DB
  `4816191fe3b9edc162646d56b0f26ee417c26bacdd02d1c39a5bcfa957c53582` and the
  same PyPI DB `8fd7138a…5dde`, same image ID and same `--all-packages
  --all-vulns` options. It returned 1 with valid JSON:
  `generated-artifacts/guardian-ai-assessment-offline/osv-latest-db-20261102/osv-retry.json`,
  SHA-256
  `292c48b7a65092730f080cb737e72e8e29a1610cbd3e304e1d9b6a87d18c59ca`.
  Results: 177 match records, 81 IDs, 20 matched package/version pairs, 93
  ID/package/version tuples; 1 critical, 25 high, 43 moderate, 9 low, 3
  unscored; zero PyPI matches. The summary SHA-256 is
  `efcc94a5e803ca7999acec31812fdcd5d7a943a179c2fdd32b3777ddda4ceb6f`;
  `SHA256SUMS.txt` SHA-256 is
  `d1f59502a412b9ee3acb5bdbd9e6f8e4c31547a91ae663551857b8c2126bcd16`.
  The successful cache setup and environment are in `retry-context.txt` and
  `env-retry.txt`.
- The first attempt with `XDG_CACHE_HOME` pointed at the local archive exited
  127 because OSV Scanner could not find an offline DB version; its emitted
  zero-match JSON is invalid/incomplete and is expressly not treated as a clean
  scan. Re-running with the archive linked under `HOME/.cache/osv-scalibr`
  loaded both local DBs, as confirmed by stderr.
- The previous 18-ID result used default filtering, so it is not comparable to
  either all-vulnerabilities scan. Comparing the two full scans, older DB
  `95c71e88…` returned 186 records/84 IDs and newer DB `4816191f…` returned
  177/81; only three moderate IDs disappeared:
  `DEBIAN-CVE-2026-114690` (6.2), `DEBIAN-CVE-2026-114691` (5.9), and
  `DEBIAN-CVE-2026-115455` (6.5). No IDs were added. All 26 critical/high IDs
  remain in the newer full scan. Both SBOMs have identical 124 PURLs; no
  packages changed, so the reduction is due to database content, not
  remediation. The current local database archives have no upstream signature
  verification recorded.
- No package changed. The local Trixie package simulation previously recorded
  no candidate upgrades for the matched packages. No OSV finding is claimed
  remediated without a package update, image rebuild, and rescan.

### Critical/high advisory-by-advisory triage

The latest `4816…` full scan's source-package/version mappings and advisory
descriptions were read from the local JSON. The same 26 critical/high IDs also
appear in the older `95c…` full scan. The 18-ID default-filter result does not
include every unimportant/uncalled advisory and is not used for this table.
Runtime presence and executable availability were checked
inside the candidate image using a read-only, non-root container with
`--network=none`. Static source review found no worker invocation of the
affected command/API paths listed below. This does not prove every path
unreachable, especially for libraries loaded by Python or the native runtime.
No exploit test was performed. Neither local Debian archive supplied a Debian
13 fixed event for these 26 IDs and the recorded apt simulation found no
candidate update; therefore each remains installed/unfixed in this image.

| Severity / score | Advisory | Installed package/version | Affected operation and runtime reachability | Local fix, mitigation, residual |
| --- | --- | --- | --- | --- |
| Critical 9.8 | `DEBIAN-CVE-2019-1010022` | `libc6 2.41-12+deb13u4` | glibc stack-guard bypass; advisory requires a separate stack-buffer-overflow exploit. libc is used; the prerequisite flaw is not established. | No Trixie fix candidate. Non-root, dropped capabilities, read-only root and network isolation reduce impact, but do not fix libc or eliminate memory-safety risk. |
| High 8.8 | `DEBIAN-CVE-2019-1010023` | `libc6 2.41-12+deb13u4` | Malicious ELF execution through `ldd`; `/usr/bin/ldd` exists, but no worker call on untrusted ELF was found. | No local fix candidate. Do not run `ldd` on untrusted binaries; residual if a future path does so. |
| High 7.5 | `DEBIAN-CVE-2018-20796` | `libc6 2.41-12+deb13u4` | Recursive regex behavior in glibc `regexec`; exploit requires a crafted pattern reaching that API. No such worker call was found. | No local fix candidate. Bound/avoid untrusted regex input; residual library exposure is not disproven. |
| High 7.5 | `DEBIAN-CVE-2019-9192` | `libc6 2.41-12+deb13u4` | Related crafted-pattern recursion in `regexec`; no worker call to this libc API was found. | No local fix candidate. Same residual as above; not marked false positive. |
| High 7.7 | `DEBIAN-CVE-2026-19499` | `libc6 2.41-12+deb13u4` | `strfmon`/`strfmon_l` buffer overrun with a particular right-justified width and undersized destination; caller path unknown. | No local fix candidate. Do not treat package controls as a patch; no reachable caller confirmed. |
| High 7.3 | `DEBIAN-CVE-2026-5435` | `libc6 2.41-12+deb13u4` | Deprecated DNS TSIG printing functions can write past caller buffer; worker use not identified. | No local fix candidate. Keep call-path status unknown; no exploit test. |
| High 7.0 | `DEBIAN-CVE-2026-84243` | `libc6 2.41-12+deb13u4` | `gettext` may load a catalog selected by attacker-controlled `LANGUAGE`; worker environment is not tenant-controlled in this lab, but future environment control is not independently audited. | No local fix candidate. Keep environment fixed and do not expose catalog paths; residual remains. |
| High 8.5 | `DEBIAN-CVE-2026-119374` | `libsqlite3-0 3.46.1-7+deb13u2` | FTS5 secure-delete overflow with a crafted FTS5 database. Python `sqlite3` is available; no worker SQLite usage or tenant database-file input was found. | No local fix candidate. No uploaded DB path in the reviewed worker flow; library remains installed and path not universally disproved. |
| High 7.8 | `DEBIAN-CVE-2026-119373` | `libsqlite3-0 3.46.1-7+deb13u2` | FTS5 merge overflow requires a crafted table and prefix query; no worker SQLite call path found. | No local fix candidate. Do not ingest untrusted SQLite files; residual library remains. |
| High 8.5 | `DEBIAN-CVE-2026-119379` | `libsqlite3-0 3.46.1-7+deb13u2` | Session/changeset API overflow; no worker use of session/changeset APIs found. | No local fix candidate. No demonstrated caller; not treated as fixed. |
| High 8.5 | `DEBIAN-CVE-2026-119586` | `libsqlite3-0 3.46.1-7+deb13u2` | `.recover` shell-command injection; the `sqlite3` CLI is absent in the candidate image. | CLI-specific route is not currently available; library advisory remains in OSV output and no package fix is available locally. |
| High 7.5 | `DEBIAN-CVE-2025-70873` | `libsqlite3-0 3.46.1-7+deb13u2` | SQLite zipfile extension disclosure with a crafted ZIP/database; no SQLite file or extension use found in worker source. | No local fix candidate. Avoid untrusted SQLite databases; library-level reachability remains unproven. |
| High 8.5 | `DEBIAN-CVE-2026-76642` | `util-linux 2.41.5-0+deb13u1` | `mount` helper hooks after a failed helper; `/usr/bin/mount` exists. Worker runs UID 65532 with all capabilities dropped, read-only root and `no-new-privileges`; no mount flow found. | No local fix candidate. Runtime confinement blocks the privileged preconditions in this job, but does not patch the binary. |
| High 7.9 | `DEBIAN-CVE-2026-78408` | `util-linux 2.41.5-0+deb13u1` | `nsenter --join-cgroup` can retain root cgroup authority; `nsenter` exists, but no invocation or privileged target exists in the worker flow. | No local fix candidate. Non-root/no capabilities and no worker invocation reduce reachability; residual package remains. |
| High 7.0 | `DEBIAN-CVE-2026-78409` | `util-linux 2.41.5-0+deb13u1` | `mount` `X-mount.subdir` requires an fstab-authorized entry and applicable kernel behavior; no worker mount/fstab path identified. | No local fix candidate. No mount privileges or configured flow in this image; still an unfixed scanner match. |
| High 7.8 | `DEBIAN-CVE-2026-78410` | `util-linux 2.41.5-0+deb13u1` | Restricted bind mount race requires privileged `mount`, an authorized fstab source, and attacker replacement of a path; no worker use found. | No local fix candidate. No capabilities, non-root user and read-only filesystem mitigate this execution context only. |
| High 8.4 | `DEBIAN-CVE-2026-54369` | `libacl1 2.3.2-2+b1` | Path-based ACL operations vulnerable to symlink traversal; `getfacl`/`setfacl` are absent and no worker library call or privileged path was found. | No local fix candidate. Tools absent and no privileged caller; library package remains and call-path analysis is not exhaustive. |
| High 7.2 | `DEBIAN-CVE-2026-54370` | `libacl1 2.3.2-2+b1` | ACL TOCTOU behavior requires an attacker-controlled pathname and privileged caller; ACL utilities are absent. | No local fix candidate. Same confinement; not claimed remediated. |
| High 8.4 | `DEBIAN-CVE-2026-54371` | `libattr1 1:2.5.2-3` | `getfattr`/`setfattr` path traversal; both utilities are absent and no worker call path found. | No local fix candidate. Utilities absent; package remains in the image. |
| High 8.3 | `DEBIAN-CVE-2026-85091` | `zlib1g 1:1.3.dfsg+really1.3.1-1+b1` | Non-blocking `gzwrite`/`gzprintf` stale-buffer overflow. Python `gzip` module exists, but no direct vulnerable C API caller was found. | No local fix candidate. Avoid untrusted compressed writes through the affected API; library exposure remains. |
| High 7.8 | `DEBIAN-CVE-2025-69720` | `ncurses-bin 6.5+20250216-2` | `infocmp` is present; flaw requires crafted terminal database input. Worker does not invoke `infocmp` on supplied terminfo. | No local fix candidate. No current worker input path identified; not marked fixed. |
| High 7.8 | `DEBIAN-CVE-2025-8941` | `libpam0g`, `libpam-modules`, `libpam-modules-bin`, `libpam-runtime 1.7.0-5` | `pam_namespace` symlink/race privilege path; worker is not an interactive login service and does not invoke PAM in its job flow. | No local fix candidate. Non-root execution reduces relevant privilege context, but packages remain installed. |
| High 7.5 | `DEBIAN-CVE-2026-82560` | `perl-base 5.40.1-6+deb13u1` | `Pod::Text` can loop and exhaust resources on crafted POD; Perl binary exists, but worker source has no Perl subprocess invocation. | No local fix candidate. Do not parse untrusted POD using Perl; residual if future subprocess paths are added. |
| High 7.5 | `DEBIAN-CVE-2026-9538` | `perl-base 5.40.1-6+deb13u1` | `Archive::Tar` can allocate based on attacker-controlled tar size; Perl is present, no worker Perl invocation found. | No local fix candidate. No current call path identified; no tar parser invocation established. |
| High 7.7 | `DEBIAN-CVE-2026-95619` | `libstdc++6 14.2.0-19` (Debian source `gcc-14`) | Aligned `operator new` integer-overflow condition; the native LLM runtime needs the C++ runtime, but use of this specific operation is unknown. | No local fix candidate. Removing `libstdc++` risks breaking native inference; keep it, retain isolation and require a fixed Debian package/rebuild before claiming resolution. |
| High 7.0 | `DEBIAN-CVE-2026-102010` | `libstdc++6 14.2.0-19` (Debian source `gcc-14`) | `erase_if` on binary-heap `priority_queue`; no call path confirmed in worker or local inference harness. | No local fix candidate. Required runtime library remains; package-level residual is open. |

For all rows above, the candidate runs as UID 65532, with no Linux capabilities,
`no-new-privileges`, a read-only root filesystem, `network=none`, and bounded
CPU/memory/PIDs. Those are defense-in-depth controls, not advisory fixes.
The local Debian database did not provide a Debian 13 fixed event for these
entries; the prior local apt simulation found no candidate updates. The
follow-up check of the official Debian Security Tracker below also found no
fixed package version for Trixie at its 2026-11-02 capture time. Fix status
must be reevaluated when Debian publishes a Trixie update and only closed after
applying it, rebuilding, and rescanning.

### Official Debian Security Tracker review — 2026-11-02

The official Debian Security Tracker was checked for each of the 26 CVEs and
for the affected source packages. At capture time, **no row had a fixed package
version available in Debian 13/Trixie**: 25 tracker rows say `vulnerable`; the
PAM row is `undetermined`. Some fixes are listed for unstable, forky, or sid;
those are not Trixie packages and were not copied into this Debian 13 image.
The existing installed binary versions and call-path assessment are in the
preceding 26-row matrix; this table adds Debian's current suite status and any
version listed outside Trixie.

| CVE | Debian source / Trixie source version | Trixie status | Version listed fixed outside Trixie / official note |
| --- | --- | --- | --- |
| [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022) | glibc `2.41-12+deb13u4` | vulnerable | unstable: unfixed; tracker urgency `unimportant` |
| [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023) | glibc `2.41-12+deb13u4` | vulnerable | unstable: unfixed; tracker urgency `unimportant` |
| [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796) | glibc `2.41-12+deb13u4` | vulnerable | eglibc/glibc unstable: unfixed; tracker urgency `unimportant` |
| [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192) | glibc `2.41-12+deb13u4` | vulnerable | eglibc/glibc unstable: unfixed; tracker urgency `unimportant` |
| [CVE-2026-19499](https://security-tracker.debian.org/tracker/CVE-2026-19499) | glibc `2.41-12+deb13u4` | vulnerable | unstable fixed version `2.43-5`; Trixie marked no-DSA/minor |
| [CVE-2026-5435](https://security-tracker.debian.org/tracker/CVE-2026-5435) | glibc `2.41-12+deb13u4` | vulnerable | unstable fixed version `2.43-3`; Trixie marked no-DSA/minor |
| [CVE-2026-84243](https://security-tracker.debian.org/tracker/CVE-2026-84243) | glibc `2.41-12+deb13u4` | vulnerable | unstable: unfixed |
| [CVE-2026-119374](https://security-tracker.debian.org/tracker/CVE-2026-119374) | sqlite3 `3.46.1-7+deb13u2` | vulnerable | Debian unstable: unfixed; upstream fix is SQLite `3.54.0`, not a Trixie package |
| [CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373) | sqlite3 `3.46.1-7+deb13u2` | vulnerable | Debian unstable: unfixed; upstream fix is SQLite `3.54.0`, not a Trixie package |
| [CVE-2026-119379](https://security-tracker.debian.org/tracker/CVE-2026-119379) | sqlite3 `3.46.1-7+deb13u2` | vulnerable | Debian unstable: unfixed; upstream fix is SQLite `3.54.0`, not a Trixie package |
| [CVE-2026-119586](https://security-tracker.debian.org/tracker/CVE-2026-119586) | sqlite3 `3.46.1-7+deb13u2` | undetermined | no fixed version listed; affected CLI is absent in this worker |
| [CVE-2025-70873](https://security-tracker.debian.org/tracker/CVE-2025-70873) | sqlite3 `3.46.1-7+deb13u2` | vulnerable | Debian tracker says the zipfile extension is not built for its binary packages; local image reports `ENABLE_ZIPFILE=False` (see runtime probe below) |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | util-linux `2.41.5-0+deb13u1` | vulnerable | unstable fixed version `2.42.3-1`; Trixie marked no-DSA/minor |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | util-linux `2.41.5-0+deb13u1` | vulnerable | unstable fixed version `2.42.4-1`; Trixie marked no-DSA/minor |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | util-linux `2.41.5-0+deb13u1` | vulnerable | unstable fixed version `2.42.3-1`; Trixie marked no-DSA/minor |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | util-linux `2.41.5-0+deb13u1` | vulnerable | unstable fixed version `2.42.3-1`; Trixie marked no-DSA/minor |
| [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | acl `2.3.2-2` | vulnerable | unstable fixed version `2.4.0-1`; Debian says fix will go through unstable then a point release, not individual backports |
| [CVE-2026-54370](https://security-tracker.debian.org/tracker/CVE-2026-54370) | acl `2.3.2-2` | vulnerable | unstable fixed version `2.4.0-1`; Debian says fix will go through unstable then a point release, not individual backports |
| [CVE-2026-54371](https://security-tracker.debian.org/tracker/CVE-2026-54371) | attr `1:2.5.2-3` | vulnerable | unstable fixed version `1:2.6.0-1`; Debian says fix will go through unstable then a point release, not individual backports |
| [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091) | zlib `1:1.3.dfsg+really1.3.1-1` | vulnerable | sid fixed version `1:1.3.dfsg+really1.3.2-4`; not a Trixie package |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | ncurses `6.5+20250216-2` | vulnerable | unstable fixed threshold `6.6+20251231-1`; current forky/sid version shown as `6.6+20260608-2` |
| [CVE-2025-8941](https://security-tracker.debian.org/tracker/CVE-2025-8941) | pam `1.7.0-5` | undetermined | no fixed version listed |
| [CVE-2026-82560](https://security-tracker.debian.org/tracker/CVE-2026-82560) | perl `5.40.1-6+deb13u1` | vulnerable | Debian perl/podlators: unfixed; upstream podlators has release `6.1.1`; Trixie marked no-DSA/minor |
| [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | perl `5.40.1-6+deb13u1` | vulnerable | unstable fixed version `5.42.3-1`; Trixie fix postponed |
| [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) | gcc-14 `14.2.0-19` | vulnerable | forky/sid fixed version `14.4.0-3`; no Trixie fix listed |
| [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010) | gcc-14 `14.2.0-19` | vulnerable | forky/sid fixed version `14.4.0-3`; no Trixie fix listed |

The tracker labels (for example, `unimportant`, `no-DSA`, or `undetermined`)
are Debian triage, not replacements for the OSV/CVSS scores in the scan. They do
not erase the OSV matches. Conversely, a fixed version in unstable/forky/sid is
not a safe Trixie patch. No package update was applied, so the candidate image,
SBOM, and 177/81 scan remain unchanged.

Evidence files saved under
`generated-artifacts/guardian-ai-assessment-offline/`:

- Individual CVE page excerpts, 26 rows: `debian-cve-tracker-status-20261102.json`,
  SHA-256 `b7ec922e37a5951387f2986cfbf3632f09727f2b5db92f98e6a53f8e4696f7ec`.
- Source-package page excerpts: `debian-source-package-status-20261102.json`,
  SHA-256 `10d28ad109a83f9d7022a8491e2da875a754f3f40a59b144039fb1e3d176609f`.
- Candidate-only SQLite compile-option probe and invocation:
  `debian-official-review-20261102/`, with a SHA-256 manifest
  `24a258a49d2bd21e1756ceef796a3f9d3203ae7ab4eb1d704782fc7762410a8c`.
  It ran with `--network=none`, read-only root, UID 65532, dropped capabilities
  and resource limits. The exact image ID was unchanged; SQLite reports
  `ENABLE_ZIPFILE=False`, and `sqlite3` CLI is absent. This makes the specific
  zipfile-extension route not applicable to the tested binary, but the OSV
  record remains visible and was not suppressed.

### Local wheel and native-component license evidence

- A standard-library inspection of all local locked archives emitted
  `generated-artifacts/guardian-ai-assessment-offline/wheel-license-inventory.json`,
  SHA-256
  `168e1534da55376e403b5587c6d702810f356c0517c6d8a3d64aa5aca4b36ff0`.
  It lists 38/38 archive SHA matches, package license metadata and paths/hashes
  for included license/notice files. This is local archive evidence, not a legal
  license interpretation. A separate read of the official PyPI JSON API
  confirmed the local SHA-256 for all 38 artifacts matches the published
  release digest. The captured metadata has no PyPI attestations for these
  artifacts; a digest match is not independent publisher/build provenance.
  Evidence file:
  `generated-artifacts/guardian-ai-assessment-offline/official-pypi-provenance-20261102.json`,
  SHA-256 `0765397da2d2c663d16fa69f6cf8798fec5f364bc17c9f8a58301d157ddf665f`.
- `langdetect 1.0.9` sdist hash is
  `cbc1fef89f8d062739774bd51eda3da3274006b3661d199c2655f6b3f6d605a0`.
  `setup.py`/`PKG-INFO` say MIT, while the classifier and `LICENSE`/`NOTICE`
  indicate Apache-2.0. This exact artifact hash matches PyPI's published
  digest; the local LICENSE and setup.py file hashes also match the fetched
  upstream `master` files. The `v1.0.9` raw tag URL returned 404, so that branch
  match is not a pinned release-tag attestation. No definitive license is
  selected; legal review remains.
- Local LLM source manifest SHA-256
  `8fb7551d2fee1d4e8bb81e2d5e1eaabc4ba6dc776c92662ac61bc0e0132a529b`;
  it records `llama-cpp-python 0.3.36` sdist SHA-256
  `832db0699007f1be95a7e41ef12e88926b02ba836461e36a36372db2760c1a2e`,
  active local wheel SHA-256
  `5e50c8f09c0ed78512bfb16adb32be9e0c65b8ced7c1efcfc200c38782141e96`,
  and vendored `llama.cpp` commit
  `0c1e57098bba43ac29e6e3b677cdceebdd22334f` with the listed MIT notice.
  The source archive hash matches the official PyPI JSON digest; the upstream
  `v0.3.36` `LICENSE.md` file hash
  `c479fb11a66a85fed2004a17dd1b3e44a1858c564b167aecb20ff66cb422ed75`
  matches the local source archive. The vendored llama.cpp MIT license file
  hash at that exact commit is
  `94f29bbed6a22c35b992c5c6ebf0e7c92f13b836b90f36f461c9cf2f0f1d010d`.
  The active wheel is locally built, not a PyPI release artifact; source hash
  equality does not prove the local build was reproducible or attested.
  The separate native wheel is outside the worker SBOM. Its complete native
  linkage/notice obligations and legal clearance remain unresolved.
- The local mounted-runtime inventory is
  `generated-artifacts/guardian-ai-assessment-offline/native-runtime-license-inventory.json`,
  SHA-256
  `2fafa80a397f89ccae66fcab113b94cd6475db627e4dc3f6f58f5ca528197873`.
  It records the exact Jinja2, MarkupSafe, and llama-cpp-python wheel hashes,
  embedded native `.so` hashes, available license-file hashes, and the source
  manifest relationship. MarkupSafe's extension is BSD-3-Clause metadata;
  llama-cpp-python declares MIT and vendors `llama.cpp` under the MIT notice
  identified above. The source manifest also shows NumPy and
  typing-extensions inherited from the worker image, not separate runtime
  wheelhouse archives. This inventory is not a complete native transitive
  dependency or legal clearance.

### Validation and report boundary

- The candidate runtime inventory command and output are stored beside the scan;
  output SHA-256
  `f559d9eda94e856480f7f214ff8c2d84e41e3e9fe106202eb1f8cad47211dbf7`.
- Worker suite with ephemeral `/tmp` under `network=none`, read-only root,
  0.5 CPU, 768 MiB, 64 PIDs, dropped capabilities, non-root and
  `no-new-privileges`: 64/64 passed. Log SHA-256
  `8751c989537b89cda8068fc9cf1898af4e5d16380c0a12dc5cf2541f5416b450`.
  The first attempt without tmpfs ran 62 tests and had 7 temp-directory errors;
  it is retained as a failed attempt, not a pass.
- No image rebuild was performed: the image inventory and installed package
  versions did not change, and no remediations were applied. API/dashboard
  tests, database RLS/RBAC fixtures, typecheck, build, and E2E were not rerun
  because application/database code was unchanged; the report is a separate
  internal document, not a UI/API feature.
- Prior API/dashboard unit tests, database RLS/RBAC fixtures, typecheck, build
  and E2E results remain historical, not fresh results from this scan.
- The Qwen executive report describes tenant-scoped agent-evaluation evidence.
  It is not a supply-chain audit. To avoid mixing a global worker image finding
  into tenant job evidence, a separate internal business summary is in
  `reports/worker-supply-chain-executive.md`; the tenant dashboard was not
  changed.

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

## Offline worker rebuild and traceability follow-up — 2026-11-02

This addendum reconciles commit `31bad696` and the local evidence generated
after the preceding checkpoint. It supersedes earlier statements that IPv4 UDP
was untested and that an offline worker image could not be built. It does not
replace `guardian-ai-assessment:local`, which remains the API's existing image.

### Rebuild, inventory, and scan evidence

- The cold build had previously stopped at a missing PyPI layer. The new
  `Dockerfile.offline` and `build-offline-image.sh` consume an already-present,
  digest-pinned Python base and the local hash-locked wheelhouse. The
  dependencies stage uses `--no-index`, and the candidate build uses
  `--no-cache --pull=false --network=none`. The script fails if the pinned base
  is not already local; it does not fetch dependencies or promote the result.
- Candidate image: `guardian-ai-assessment:offline-rebuilt`, image ID
  `sha256:e2d13fb48471dbcdc169e421598d5830303717266baf9892a3f11e86eb48e476`.
  It was built locally and not pushed. This verifies an offline build with the
  currently cached base and prepared wheelhouse, not a build from an empty
  machine or bit-for-bit reproducibility.
- Wheelhouse verification used the standard-library verifier against both
  lockfiles: 38/38 artifacts matched one exact pinned SHA-256 each (36 runtime,
  2 build-only); no network was used. Runtime lock SHA-256
  `75bcda09cdcaaa9d1528936ea2406965a497c0d91803f3b3e4b3c9fed74352a5`;
  build lock SHA-256
  `d19fd247e275104d426c23297aa0cead3c7c70626306cb5b3d5a0ae0edadbac1`.
  The verification JSON is
  `generated-artifacts/guardian-ai-assessment-offline/wheelhouse-verification.json`,
  SHA-256
  `ab8bc155558cc91e79a5a2f638b64dc0f0645bad29b42cc28bc521a1e37ebc79`.
  The verifier checks local bytes against locks; official PyPI release metadata
  provenance remains the separate evidence described above.
- Candidate CycloneDX 1.6 SBOM:
  `generated-artifacts/guardian-ai-assessment-offline/sbom.cdx.json`,
  124 components, SHA-256
  `8eb49149a21afac04818f94ac0183eb799ed740b8f2254a9f63c453c279c5d97`.
  Its 124 PURLs exactly match the preceding worker-follow-up SBOM; no package
  version changed in this build. The offline OSV JSON is
  `generated-artifacts/guardian-ai-assessment-offline/osv.json`, SHA-256
  `c80e9efec40dbed890c691d33ac85cebe98dcd5aa646cedef7a3698ae326e6c2`.
- That candidate scan used local Debian database SHA-256
  `95c71e88a626f4ba428196019dae1658358862d45e2c769ad85b8a5e74ee6ec8` and
  PyPI database SHA-256
  `8fd7138ad08c733316d229a05ac5a8a9fdcba4f6439d80cdab97fe4e18445dde`.
  It reports 186 Debian package/advisory matches, 84 unique IDs, 20
  package/version pairs, and zero PyPI matches. Its recorded process exit code
  is 2; the JSON is present and contains findings. A prior scan against the
  same two database hashes has identical advisory-ID and package/version/ID
  sets, with the documented severity distribution: 1 critical, 25 high, 46
  moderate, 9 low, and 3 unscored. The nonzero code is preserved as observed;
  it is not interpreted as a clean scan.
- A separate, previously refreshed Debian database
  (`4816191fe3b9edc162646d56b0f26ee417c26bacdd02d1c39a5bcfa957c53582`)
  produced 18 IDs, including four high util-linux findings. That refreshed
  report is from the prior local image, not a new scan of this candidate.
  Because the candidate and prior SBOMs have identical PURLs, the installed
  package inventory is unchanged; database changes explain the count
  difference, not remediation. The four high IDs remain
  `DEBIAN-CVE-2026-76642` (8.5), `DEBIAN-CVE-2026-78408` (7.9),
  `DEBIAN-CVE-2026-78410` (7.8), and `DEBIAN-CVE-2026-78409` (7.0) in
  installed `util-linux 2.41.5-0+deb13u1`.
- No OS package was upgraded or removed, no advisory was suppressed, and no
  finding was confirmed as a false positive. No exploitability test was run.
  Existing per-package critical/high reachability notes and fixed-version
  events remain in “Actionable historical critical/high triage” above. The
  recorded Trixie package simulation had no candidate update for matched
  packages; an OSV fixed event elsewhere is not a Trixie patch. Lower-severity
  matches have not each received a separate code-path exploitability review.
  Package presence and OSV severity are not proof of exploitability.

### Network, tests, and licensing

- The candidate egress audit ran inside Docker `--network=none` and produced
  `ipv4PublicTcp=blocked`, `ipv4PublicUdp=blocked`, `ipv4DnsUdp=blocked`,
  `loopbackIpv4=reachable`, no active non-loopback interface, and
  `ipv6Capability=kernel_protocol_unavailable`. IPv6 TCP/UDP/DNS and IPv6
  loopback are unavailable, not verified blocked. Overall
  `incomplete_ipv6_not_verified`, exit code 2. JSON SHA-256
  `be7b4fcb57bf9354fb8d655c30b8665350a2371bff1e9bcdbe81282012f4ed79`.
  Reproduction instructions invoke the checked-in mode-100644 scripts through
  `bash`/`sh`; direct execution is not supported by their file mode.
- Repeated local verification, with logs in ignored
  `generated-artifacts/guardian-ai-assessment-offline/`:
  - Worker suite: 64/64 passed, exit 0; log SHA-256
    `30ecb3d22976e558d337406a6efe5fdba1e0152bb93141792627b57128893f1b`.
  - API AI-contract suite: 7/7 passed, exit 0; log SHA-256
    `82ff454b02486aac8b08aba51e2c220ff34e4225e09db4e08e33071b17b4d63f`.
  - Dashboard report component suite: 4/4 passed, exit 0; log SHA-256
    `b2ac12b5079db6f0cb4a91f165e8f44b6459e1deb5eaf5315da96ea4270cad23`.
  - Egress audit: exit 2 solely as an incomplete result with IPv6 unavailable;
    the IPv4 UDP/TCP and DNS outcomes above are recorded. The first direct
    script invocation was denied by file permissions; running it through `sh`
    completed the probe.
- The wheelhouse verifier rechecked all locked bytes without network. In
  particular, `langdetect-1.0.9.tar.gz` is 981,474 bytes,
  SHA-256 `cbc1fef89f8d062739774bd51eda3da3274006b3661d199c2655f6b3f6d605a0`.
  Its `setup.py` and PyPI `PKG-INFO` say MIT, but the package classifier,
  `LICENSE`, and `NOTICE` indicate Apache-2.0. The archived `LICENSE` hash is
  `9c539fdc47fa4e195b88efaa6495f11463de271f59c8de96feb8bc9c8abab1ab`;
  `NOTICE` hash is
  `bc22bad5907339e12834d91f7809ec35c3c44fa4b812f274ebfefa38de080869`.
  This is still ambiguous and requires legal review; no license is selected as
  definitive.
- The separate local-LLM runtime remains outside the worker image SBOM. Its
  source manifest pins the official `llama-cpp-python 0.3.36` sdist SHA-256
  `832db0699007f1be95a7e41ef12e88926b02ba836461e36a36372db2760c1a2e`, the
  locally built wheel SHA-256
  `5e50c8f09c0ed78512bfb16adb32be9e0c65b8ced7c1efcfc200c38782141e96`, and
  vendored llama.cpp commit `0c1e57098bba43ac29e6e3b677cdceebdd22334f`
  (MIT). The component notices are inventoried, but complete native linkage
  and legal review remain open; a later offline wheel rebuild differed in ELF
  build-id and temporary prefix metadata.
- No remediation was justified by available local package candidates, so none
  was applied. `diskcache` remains absent from the active LLM wheelhouse with
  fail-closed cache tests; this does not fix its upstream advisory.
- Database-backed RLS/RBAC tests were not rerun: their fixture setup writes
  tenants and requires `DATABASE_URL`, and this step did not inspect or use
  connection credentials to establish the database environment. The pure API
  contract and dashboard report tests above do not replace those DB tests.
  No API/database code changed. No production data, customers, credentials,
  external services, or paid infrastructure were used.

## Inspección estática de runtime nativo local — 2026-11-02

Esta comprobación reconcilia artefactos locales sin volver a construir la imagen
worker ni repetir OSV. Los binarios ELF se inspeccionaron con `readelf -d`; no se
ejecutó ningún `.so` ni se usó egress. El inventario máquina-legible está en
`local-llm-build/native-runtime-inspection.json`, SHA-256
`5dfe95f9cc8e1a7876e43a3aee6a8d8e305a53508b19f23540b14d9fdea968f2`.
The local verifier checked 23 wheel, manifest, ELF and license-file hashes;
its successful output SHA-256 is
`facb336673e2b843f71c59fc07a330dd2d76c282400367afedf9d4676c872846`.
The first verifier attempt failed because its expected archive path for
`libllama-common.so` was wrong; that log is retained separately
(`e01cd3427a44073e1ad534b7f85775acc6ac202376024bee6fa365a7611044f5`).
The archive path was corrected to `lib/libllama-common.so`, then all 23 checks
passed. The failure was in the inventory verifier, not in the wheel or runtime.

- **Wheel que valida el runner configurado:** el script
  `scripts/run-local-llm.sh` verifica y monta
  `generated-artifacts/guardian-llm-lab/wheelhouse/llama_cpp_python-0.3.36-py3-none-linux_x86_64.whl`.
  El archivo local mide 24,140,277 bytes y su SHA-256
  `5e50c8f09c0ed78512bfb16adb32be9e0c65b8ced7c1efcfc200c38782141e96`
  coincide con el wheel fijado por `local-llm-manifest.json` y el
  `source-manifest.json`. El wheel declara MIT y requiere
  `typing-extensions`, `numpy` y `jinja2`; no declara `diskcache`. Jinja2 3.1.6
  y MarkupSafe 3.0.4 completan el wheelhouse montado. NumPy 2.3.4 y
  typing-extensions 4.16.0 proceden de la imagen worker existente.
- **Artefactos que no deben confundirse con el wheel activo:**
  `llama-source-built-wheel` SHA `a71a5a2e…` tiene un manifiesto vecino cuya
  metadata declara `diskcache 5.6.3`; no es la ruta configurada por el runner.
  El build offline posterior SHA `7bd646f4…` tampoco se promovió ni lo monta el
  runner. La rueda precompilada PyPI SHA `c8a3e980…` es una descarga oficial
  verificada en el análisis previo, no la rueda activa, y declara diskcache como
  dependencia. Las tres permanecen como artefactos de auditoría separados.
- **Fuente y build:** la sdist oficial `llama-cpp-python 0.3.36` tiene hash
  `832db069…`; el commit vendorizado de `llama.cpp` es
  `0c1e57098bba43ac29e6e3b677cdceebdd22334f`. El constructor local fue
  `sha256:1190b243…`, con base Python 3.13/Trixie fijada por digest y snapshot
  Debian `20261027T000000Z`. Dentro de ese constructor se verificaron GCC/G++
  `14.2.0-19`, CMake `3.31.6` y Ninja `1.11.1.4`; CMake y Ninja proceden de
  wheels fijadas, no de paquetes Debian instalados. El build usa
  `--network=none`, usuario `65532`, límites del manifiesto y los argumentos
  CMake allí registrados (AVX/AVX2/FMA sí; AVX512/OpenMP desactivados).
- Los artefactos de build son scikit-build-core 0.11.6 (Apache), pathspec
  0.12.1 (MPL-2.0), packaging 25.0 (Apache/BSD), CMake 3.31.6 (Apache/BSD) y
  Ninja 1.11.1.4 (clasificadores Apache/BSD). Sus hashes de wheel y los hashes
  locales de los textos de licencia se incluyen en el JSON de inspección y en
  `build-inputs.json` (SHA-256 `dd10ed8b…`). Los metadatos y ficheros disponibles
  sirven para trazabilidad; no equivalen a revisión legal de las licencias
  anidadas de CMake/Ninja.
- Se identificaron seis objetos ELF `llama.cpp/ggml` en el wheel activo,
  incluidos hashes individuales y `DT_NEEDED` en el JSON. Sus dependencias
  dinámicas incluyen las bibliotecas internas `libggml*`/`libllama*` y SONAMEs
  del sistema `libc`, `libm`, `libstdc++`, `libgcc_s` y el cargador ELF.
  MarkupSafe incluye además `_speedups` nativo BSD-3-Clause. Los componentes
  `libc6 2.41-12+deb13u4`, `libgcc-s1 14.2.0-19` y `libstdc++6 14.2.0-19`
  aparecen en el SBOM candidato de 124 componentes; este paso no consultó
  propiedad de archivos dentro de la imagen ni creó una SBOM completa para el
  runtime LLM montado.
- La rueda activa corresponde a la salida fijada; una reconstrucción offline
  posterior difirió en build-id ELF, prefijo temporal de `llama.pc` y hashes
  `RECORD`. Por tanto, la trazabilidad de entradas está ampliada, pero la
  reproducibilidad bit a bit y una atestación firmada **no están demostradas**.
  Los hashes no prueban por sí solos una firma del publicador. Los componentes
  nativos comparten la licencia declarada MIT del código vendorizado, pero la
  revisión de obligaciones transitivas sigue abierta. No se declara aprobación
  legal; la discrepancia de `langdetect` continúa pendiente.
- No se generó un nuevo SBOM ni OSV scan porque la imagen y sus paquetes no
  cambiaron. La SBOM del worker no sustituye al inventario nativo local adjunto.
  Las condiciones de compatibilidad fuera del hardware x86_64 configurado
  tampoco se probaron.
