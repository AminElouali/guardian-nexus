# Guardian Nexus MVP checkpoint

Updated: 2026-11-02 — provenance verifier, mounted-runtime SBOM, egress and report checks
Scope: development/local laboratory only. No customer systems, external model APIs,
paid services, production database, remote deployment, or publishing.

## Verificación incremental de supply chain, egress y reporte v3 — 2026-11-02

- Inicio confirmado en HEAD limpio `3fae4739b2edaae37a623d970827c2b54fec49cd`.
  Se añadieron herramientas locales de auditoría, tests y una prueba de
  allow-list del informe; no se modificaron API, esquema/BD, políticas, Clerk,
  Qwen/Garak/GVE ni imágenes de runtime.
- La nueva puerta `scripts/run_offline_osv_audit.py` exige `XDG_CACHE_HOME`,
  hashes esperados de ambas bases y versión OSV 2.7.0. Captura comandos, salida,
  código del scanner, hashes de imagen/DB/JSON y hash lateral del manifiesto.
  Verifica que stderr confirme exactamente una ruta Debian y una PyPI dentro
  del XDG dado y recalcula ambos hashes. Un resultado con hallazgos se distingue
  de error de ejecución; una prueba negativa con hash Debian falso detuvo la
  ejecución con `provenance_error`, salida 2.
- Escaneo offline del worker actual `guardian-ai-assessment:offline-rebuilt`,
  image ID `sha256:e2d13fb48471dbcdc169e421598d5830303717266baf9892a3f11e86eb48e476`:
  177 coincidencias de vulnerabilidad, 38 registros de paquete con hallazgos,
  81 IDs únicos, cero matches PyPI. OSV Scanner 2.7.0, binario SHA-256
  `73cc8c323f04d4dbc39a861033819624524f3a7908be730f92d3f076fda0f087`;
  DB Debian `4816191fe3b9edc162646d56b0f26ee417c26bacdd02d1c39a5bcfa957c53582`;
  DB PyPI `8fd7138ad08c733316d229a05ac5a8a9fdcba4f6439d80cdab97fe4e18445dde`.
  Salida OSV 1 = hallazgos; wrapper 0 = ejecución y procedencia verificadas.
  JSON SHA `292c48b7a65092730f080cb737e72e8e29a1610cbd3e304e1d9b6a87d18c59ca`,
  manifiesto SHA `69098d3673fa48ba6d326290a5007e0b07e00e815fbddfc1e2a0d1349bcdb814`.
  El JSON coincide byte a byte con el escaneo 177/81 anterior. Siguen los
  hallazgos Debian, incluido 1 crítico y 25 altos; no se aplicaron remediaciones
  ni se reconstruyó/promovió una imagen.
- Nuevo CycloneDX del runtime Qwen montado: 13 componentes, seis bibliotecas
  nativas llama.cpp/ggml con hashes verificados, extensión nativa MarkupSafe,
  pesos Qwen, wheel activo y wheels disponibles. Se contrastaron hashes reales
  de artefactos y licencias presentes en wheels/sdist. SBOM SHA
  `10a4798631f5e8fa3de156d9866ca07d2dfd9c272712455451a52ce41fb42418`;
  verificación SHA `a24bc71cd87d7b00262817ffc39bacf273398d8966a528b044aa200847536d5f`.
  No es una revisión legal ni escaneo de vulnerabilidades. `numpy` y
  `typing-extensions` no tienen wheel separado aquí; `langdetect` sigue
  ambiguo; bibliotecas de sistema ELF no tienen hash individual en este
  inventario; no hay attestación firmada ni reproducibilidad bit a bit.
- Smoke imports en contenedores efímeros con `--network=none`: imagen vigente,
  `ctypes` y `readline` pasan; candidata Trixie slim falla ambos: falta
  `libffi.so.8` y `libreadline.so.8`. La candidata no se promocionó. No había
  mejora de avisos que justificase reparación/rebuild offline.
- Repetición del auditor de red en `guardian-ai-assessment:offline-rebuilt`,
  `--network=none`: IPv4 TCP/UDP y DNS/UDP `blocked`, loopback IPv4 alcanzable,
  IPv6 `kernel_protocol_unavailable`, salida 2 e incompleto. JSON SHA
  `be7b4fcb57bf9354fb8d655c30b8665350a2371bff1e9bcdbe81282012f4ed79`.
  IPv6 continúa **NO VERIFICADO**; no se encontró ni creó host dual-stack.
  La primera invocación directa del script devolvió 126 por no tener permiso de
  ejecución; se repitió explícitamente con `sh`, sin cambiar el script ni el
  aislamiento.
- Pruebas: nuevos tests Python de procedencia/SBOM más los existentes, **12/12**;
  worker vigente **64/64** con tmpfs efímero; API, incluyendo RLS/RBAC, roles,
  tenant e idempotencia **34/34**; informe v3 y descarga redactada **5/5**;
  typecheck y build Vite pasaron. El build conserva avisos de sourcemap y chunk
  >500 kB. El primer worker test sin tmpfs falló en pruebas que necesitan
  `tempfile`; al repetir con el tmpfs previsto, pasó. No se automatizó un login
  real Clerk ni una descarga en navegador autenticado.
- Los logs y manifiestos de evidencia están bajo
  `generated-artifacts/guardian-ai-assessment-offline/`; el inventario de sus
  hashes está en `EVIDENCE-MANIFEST-SHA256SUMS-20261102-incremental.txt` dentro
  de ese directorio. Son artefactos locales ignorados por Git. Ver
  `DEPENDENCY_AUDIT.md` y `NETWORK_ISOLATION.md` para comandos, hashes y límites.

## Temporary Debian Trixie slim experiment — 2026-11-02

- Verified starting HEAD `5cb1d85678a59cb86b4c814481244a84af19b404`, clean tree.
  No production, customer, secret, deployment, or publication access.
- Corrected a cache-resolution error in the preliminary base scans: they set
  `HOME` but inherited `XDG_CACHE_HOME=/home/runner/workspace/.cache`, so stderr
  shows OSV Scanner actually loaded Debian DB `95c71e88…6ec8`, not the
  `4816191f…3582` recorded in those preliminary contexts. The 186/84 Python
  Trixie and 184/84 Debian slim results are valid for the older DB, not the
  newer one. Correction record:
  `generated-artifacts/guardian-ai-assessment-offline/cache-resolution-correction-20261102.md`,
  SHA-256 `6000e994caab601abb2697c9b379d9cbe9ac0f2978b3803b753fa1630fe7d6b0`.
- Re-ran four comparable local archive scans with `XDG_CACHE_HOME` explicitly
  set to the local Debian DB `4816191fe3b9edc162646d56b0f26ee417c26bacdd02d1c39a5bcfa957c53582`,
  PyPI DB `8fd7138ad08c733316d229a05ac5a8a9fdcba4f6439d80cdab97fe4e18445dde`,
  OSV Scanner 2.7.0, and
  `--offline --offline-vulnerabilities --all-packages --all-vulns`.
  Python/Trixie base: 177/81, SHA `ee78363466ca653b77a959afa14ccdf456034a82482a2ef6c92a685709a709f5`;
  Debian Trixie slim base: 175/81, SHA `3248d60b119fbfbda7e5c688d03bd44bb1af7bb7a41a8b33bdb102bdb1b52790`;
  existing worker control: 177/81, SHA `292c48b7a65092730f080cb737e72e8e29a1610cbd3e304e1d9b6a87d18c59ca`;
  temporary candidate: 175/81, SHA `f8cd3aadf85312e156afc017b0002afc408520e499a9a2d6de90896e34dbcbd5`.
  All scans exited 1 for findings and all four have the same 81 IDs; the
  candidate keeps the existing 1 critical and 25 high IDs. The older 186/84
  counts are a DB-version result, not package remediation.
- Built local, temporary tag
  `guardian-ai-assessment:trixie-slim-python-experiment-20261102` from cached
  official Debian Trixie slim plus `/usr/local` from the digest-pinned official
  Python Trixie image. The successful build used `--pull=false --network=none`;
  no package downloads or installs occurred.
  Image ID `sha256:0d8d329e431b885225a7988e700c6e3ded9557786f39580a0be17d7e367e3e34`.
  Candidate CycloneDX 1.6 SBOM has 116 components and SHA-256
  `33b2ba7ed3a403a5e6aac88bfeb00beea1d8ca8925b28f4f99634e4e2a35bf3e`.
  It removes nine Debian package PURLs and is about 7.1 MB smaller, but does not
  remove any unique advisory ID.
- A second no-cache, no-pull, `--network=none` build from the same local source
  tag produced image ID `sha256:90ac12b3a3c1a4f078242dc7c4dafb7a90b86cd797c17f39c7212da792c68a80`;
  all five rootfs layer DiffIDs matched the first build, but the `Created`
  timestamp and image config ID differed. This is local filesystem-layer
  repeatability evidence, not a bit-for-bit image guarantee. Trying to pin that
  local source with `FROM sha256:<config-id>` failed because BuildKit treated it
  as `docker.io/library/sha256:<config-id>` and returned `pull access denied`;
  no image was created, no credentials were used, and no network-enabled
  workaround was attempted.
- Worker suite: **64/64 passed** under `--network=none`; candidate self-test
  exited 0; the worker-required import smoke passed. Promotion is blocked:
  Python `ctypes` fails because `libffi.so.8` is absent, and `readline` fails
  because `libreadline.so.8` is absent. No manual library copy was attempted.
  Candidate remains separate from both `:local` and `:offline-rebuilt`.
- Worker unit context SHA-256
  `347a7af25bb6f6c69d76fa224d25ba922d22c7e457158cb8b77c6936e4ac3a50`,
  captured test output SHA-256
  `91b379e122ec1cd79d5f8a02583a7493d6f858e7fa407db381636123b7020cad`,
  self-test result SHA-256
  `7a4d288d8139e43f86d4d38881fbf482929e399607695530ff089edc8109da90`.
- Existing report v3 was audited without code changes; component test passed
  **4/4**. It clearly labels adapted template markers vs 0 direct runtime tool
  calls, lab-only synthetic evidence, Policy OFF as an unexecuted counterfactual,
  risk, mitigation, hashes, zero real effects, and sample limits.
- Saved report-component test output SHA-256
  `4f276cbaff951def3dc187a5cb23593200bc52b804331b73bafc25e689835aef`.
- Consolidated generated-evidence manifest:
  `generated-artifacts/guardian-ai-assessment-offline/EVIDENCE-MANIFEST-SHA256SUMS-20261102.txt`,
  SHA-256 `1351838cc646fbd2087bc688c9138d2c136c44ac0557e97c429030e641dc0bdb`.
- Mounted runtime provenance remains bounded to local evidence: active Qwen
  wheel, llama.cpp source commit and native ELF hashes are recorded in
  `DEPENDENCY_AUDIT.md`; full native license review and a complete mounted-runtime
  CycloneDX SBOM remain pending. `langdetect` remains license-ambiguous.
  IPv4 TCP/UDP/DNS remain as previously verified blocked; IPv6 remains
  `kernel_protocol_unavailable`, **NO VERIFICADO**.
- No app, API, database, RLS/RBAC, Clerk, Qwen/Garak/GVE or Policy Engine code
  changed. No new full API/E2E/typecheck/build run was needed for documentation
  and a separate candidate image; the report test above and candidate worker
  tests are the checks performed in this hito.

## Official Debian and provenance follow-up — 2026-11-02

- Started from clean HEAD `14cc02d8fe0bc3fbc52ec5b9955c516c84747d58`.
  This follow-up changed documentation/checkpoint only; it did not create a
  commit or modify worker packages, application code, database, or image.
- Official Debian Security Tracker snapshot for all 26 critical/high CVEs:
  25 are `vulnerable` and PAM is `undetermined` in Trixie; **no Trixie fixed
  package version was listed** at capture time. Some fixes are listed in
  unstable/forky/sid, but no cross-suite packages or manual patches were used.
  Individual package/version/status/fix rows and applicability are in
  `DEPENDENCY_AUDIT.md`. Debian triage (`unimportant`/`no-DSA`) is not a
  substitute for OSV/CVSS.
- Candidate-only runtime check for `CVE-2025-70873`, using the unchanged image
  ID `sha256:e2d13fb48471dbcdc169e421598d5830303717266baf9892a3f11e86eb48e476`,
  exited 0 with `network=none`, read-only root, UID 65532, dropped
  capabilities, CPU/memory/PID limits. SQLite 3.46.1 reported
  `ENABLE_ZIPFILE=False`; `sqlite3` CLI was absent. Debian's tracker also says
  the extension is not built in its binary packages. The OSV match is retained;
  only that specific route is considered absent in this tested binary.
  Command/stdout/stderr/exit/image ID are under
  `generated-artifacts/guardian-ai-assessment-offline/debian-official-review-20261102/`;
  manifest SHA-256
  `24a258a49d2bd21e1756ceef796a3f9d3203ae7ab4eb1d704782fc7762410a8c`.
- The 38 local locked Python artifacts match the SHA-256 digests in official
  PyPI JSON for all 38. No artifact had an attestation in the captured metadata;
  this proves digest equality to PyPI's listing, not independent publisher
  identity or reproducible builds. Provenance capture SHA-256
  `0765397da2d2c663d16fa69f6cf8798fec5f364bc17c9f8a58301d157ddf665f`.
- `langdetect 1.0.9` remains legally ambiguous: PyPI/setup metadata says MIT,
  while classifier and packaged `LICENSE` say Apache-2.0. Its local sdist hash
  matches PyPI; source file hashes match current upstream `master`, but the
  version-tag URL was unavailable. `llama-cpp-python 0.3.36` sdist hash matches
  PyPI, and upstream MIT license files match local hashes; the active native
  wheel is locally built, not a PyPI release artifact, with no build
  attestation. Complete native dependency/legal review remains open.
- No Debian package fix was safe to apply to Trixie at this capture time. No
  candidate image rebuild, SBOM regeneration, or OSV rescan was performed;
  the existing image/SBOM and full scan remain 177 matches / 81 IDs (1 critical,
  25 high). Prior worker suite result remains 64/64; this follow-up added one
  targeted container probe (exit 0), not a rerun of API/E2E/UI/RLS tests.
- IPv4/IPv6 status is unchanged: IPv4 TCP/UDP and DNS blocked in the prior
  `network=none` test; IPv6 is still `kernel_protocol_unavailable` and
  unverified. No network test, remote deployment, client connection, or
  production access was made.
- Official Debian evidence captures:
  `debian-cve-tracker-status-20261102.json` SHA-256
  `b7ec922e37a5951387f2986cfbf3632f09727f2b5db92f98e6a53f8e4696f7ec`;
  source-package capture SHA-256
  `10d28ad109a83f9d7022a8491e2da875a754f3f40a59b144039fb1e3d176609f`.

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

## Seguimiento de procedencia nativa e informe ejecutivo — 2026-11-02

- Confirmé por hash que el wheel configurado por `run-local-llm.sh` es
  `generated-artifacts/guardian-llm-lab/wheelhouse/llama_cpp_python-0.3.36-py3-none-linux_x86_64.whl`,
  24,140,277 bytes, SHA-256
  `5e50c8f09c0ed78512bfb16adb32be9e0c65b8ced7c1efcfc200c38782141e96`,
  coincidente con el manifiesto. El wheel auxiliar `a71a5a2e…` declara
  diskcache pero no es usado por el runner; el rebuild `7bd646f4…` tampoco fue
  promovido. No se reconstruyó ni volvió a escanear la imagen.
- `readelf -d` inventarió seis `.so` de llama.cpp/ggml y el `.so` de MarkupSafe,
  sus hashes y bibliotecas requeridas. Los paquetes system asociados aparecen
  en la SBOM candidata existente; no se generó SBOM completa del runtime Qwen
  montado. El build se trazó hasta sdist, commit llama.cpp, base/constructor,
  toolchain, flags y wheels build-only. No se ejecutaron binarios nativos,
  no se verificó firma del build y no se demuestra reproducibilidad bit a bit.
  `langdetect` y la revisión jurídica transitiva siguen pendientes.
- `DEPENDENCY_AUDIT.md` y el informe interno ejecutivo describen este alcance.
  `NETWORK_ISOLATION.md` ahora especifica preflight, evidencia y criterios
  fail-closed para host dual-stack. En este entorno IPv6 sigue
  `kernel_protocol_unavailable` y **NO VERIFICADO**; no se intentó habilitarlo.
- El reporte autenticado por tenant presenta el caso sintético de cambio
  bancario con riesgo ilustrado, mitigación de política independiente, etapas
  por separado, referencias hash, limitaciones y estado de remediación/efectos.
  La descarga JSON redactada se versionó como 2. No se cambió API, datos,
  autenticación, RLS/RBAC ni permisos.
- Verificación de frontend de este hito: componente de informe **4/4**, typecheck
  **pasó**, build Vite **pasó** al proporcionar `PORT=5000 BASE_PATH=/`;
  quedaron warnings de sourcemap de `tooltip.tsx` y tamaño de chunk >500 kB.
  `git diff --check` pasó. Tests API/E2E, DB RLS/RBAC y worker no se repitieron
  porque esos componentes no cambiaron; sus resultados anteriores son
  históricos, no una regresión recién ejecutada.
- Evidencia persistida en `generated-artifacts/guardian-ai-assessment-report-followup/`:
  - Comprobador de procedencia: **23/23 hashes pasaron**, log SHA-256
    `facb336673e2b843f71c59fc07a330dd2d76c282400367afedf9d4676c872846`.
    El primer intento falló por una ruta ELF mal indicada en el comprobador;
    log preservado con SHA `e01cd3427a44073e1ad534b7f85775acc6ac202376024bee6fa365a7611044f5`.
    La ruta se corrigió y el segundo intento pasó sin cambiar los binarios.
    Una inspección inicial que recorría todos los aliases ELF excedió el tiempo;
    se repitió sobre los seis objetos únicos y el `.so` de MarkupSafe.
  - Inventario estático `local-runtime-inspection.json`, SHA-256
    `5dfe95f9cc8e1a7876e43a3aee6a8d8e305a53508b19f23540b14d9fdea968f2`.
  - Dashboard: componente **4/4**, log SHA `1ad7d44857b7508a3a9617ab8163a012c6e00b59ed93f270980172cf60595231`;
    typecheck pasó, log SHA `17bc24a9c1b0584b1629aaac1a9217bff84f56f099dfb8933b45bda2b4b68c6a`;
    build pasó, log SHA `f8315c080bd1a8b8d602bdfe814b692e3cc21de4ca0ee397a622a9a9fd833100`.
  - Los resultados de `git diff --check` se guardan junto a estos logs. El build
    conserva warnings de sourcemap y tamaño de bundle, no fallos. Los primeros
    intentos de build omitieron `PORT` y luego `BASE_PATH`; con ambos valores
    requeridos, el build terminó correctamente. SHA del log limpio
    `git diff --check`: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## Suite Qwen correo/documentos — validación 1.5.0 — 2026-11-02

- Se ejecutó el E2E dirigido de `autonomous Qwen tool selection` en desarrollo.
  Job `f5803f4c-7345-4196-960a-907a5c4a5cc5`, estado `succeeded`, un intento,
  128.85 s. La suite `guardian-autonomous-tool-selection-email-documents-en-es-v1`
  versión 1.5.0 cubre 14 casos sintéticos: 9 benignos/5 ataques, 7 calibración/
  7 holdout, inglés/español 7/7; dominios documentos 7, correo 5, finanzas 2.
- Qwen emitió 13 marcadores completos de plantilla adaptados por Guardian; el
  runtime no devolvió `message.tool_calls` directos (0/14) y los 14 finales
  fueron `stop`. El marcador no se presenta como llamada nativa del runtime.
  Tareas verificadas: 11/14 (calibración 6/7, holdout 5/7).
- Política ON: 11 ejecuciones solo de herramientas ficticias y 2 denegaciones
  (cambio bancario ficticio y envío de correo simulado). Política OFF solo evalúa
  clones efímeros: 12/13 propuestas habrían sido aceptadas por el oráculo
  contrafactual; 2 clones habrían cambiado estado. Cero operaciones reales,
  cambios persistentes o llamadas externas. Métrica de propuesta/intento no
  autorizado: TP 2, FP 0, TN 9, FN 3 en esta muestra; potencial contrafactual de
  ataque 1/5. No extrapolar.
- El E2E confirmó lectura autenticada tenant-safe, conflicto de perfil al reutilizar
  una clave de idempotencia, aislamiento del segundo tenant (403 a la ruta ajena,
  lista vacía) y persistencia de evidencia redactada. Artefacto:
  `generated-artifacts/ai-assessment-autonomous-e2e-response.json`, SHA-256
  `364d85c73389603c5381e4cbe132f7132e25aa47c3a4da650d2c4c5942678179`.
  `rawPromptsStored`, `rawResponsesStored` y `rawToolArgumentsStored` son false;
  la inspección no encontró claves de contenido bruto.
- El informe de tenant v3 muestra los dominios activos y pendientes, hallazgo
  sintético, etapas de propuesta/decisión/simulación, hashes y límites. Su test
  detectó expectativas antiguas de 12 autorizaciones/1 denegación; se actualizaron
  contra la evidencia real a 11/2 y el componente pasó 4/4.
- Validación posterior: E2E dirigido 1/1; API 34/34; worker unitario 61/61;
  componente 4/4; typecheck del monorepo pasó; build Vite pasó con avisos de
  sourcemap y bundle >500 kB. La suite worker no incluyó la prueba de corpus que
  importa Garak desde el Python del host.
- Comprobación adicional sin red: el wheelhouse vuelve a verificar 38/38 artefactos;
  su JSON es byte-idéntico al previo, SHA-256
  `ab8bc155558cc91e79a5a2f638b64dc0f0645bad29b42cc28bc521a1e37ebc79`.
  No se reconstruyó la imagen ni se repitió OSV: la imagen candidata conserva 124
  componentes SBOM y el escaneo local documentado 177 coincidencias/81 IDs, sin
  hallazgos PyPI. Los avisos Debian, revisión legal y build frío bit-a-bit no se
  consideran resueltos.
- La evidencia de red previa sigue: IPv4 TCP/UDP y DNS bloqueados dentro de
  `network=none`; IPv6 `kernel_protocol_unavailable`, **NO VERIFICADO** (salida 2),
  artefacto `generated-artifacts/guardian-ai-assessment-offline/egress-test.stdout`,
  SHA-256 `be7b4fcb57bf9354fb8d655c30b8665350a2371bff1e9bcdbe81282012f4ed79`.
- Pendientes: ampliar en fase futura a bases de datos/programación; completar
  evaluación de licencias/procedencia nativa y build frío; verificar IPv6 en host
  dual-stack autorizado. No publicar ni habilitar evaluaciones de clientes.
