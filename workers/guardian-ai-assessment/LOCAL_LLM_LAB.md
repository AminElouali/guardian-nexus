# Local LLM laboratory

This is a development-only capability for **Guardian Nexus — Evaluación de
Seguridad de IA**. Garak + Guardian Verification Engine retain their existing
job profile and result contract. A separate versioned `local_llm_lab` profile
uses the same durable queue, lease, tenant RLS, RBAC, quota and audit path for
one fixed synthetic invoice task. This does not make an assessment service
available to customers.

## Model and runtime provenance

| Component | Exact version / hash | License | Source |
| --- | --- | --- | --- |
| Model | `Qwen/Qwen3-0.6B-GGUF`, revision `23749fefcc72300e3a2ad315e1317431b06b590a`; `Qwen3-0.6B-Q8_0.gguf`, 639,446,688 bytes, SHA-256 `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031` | Apache-2.0 | [Official model repository](https://huggingface.co/Qwen/Qwen3-0.6B-GGUF) |
| CPU inference runtime | `llama-cpp-python` 0.3.36; locally source-built, patched wheel SHA-256 `5e50c8f09c0ed78512bfb16adb32be9e0c65b8ced7c1efcfc200c38782141e96` | MIT | Official PyPI sdist; build inputs and patch in `local-llm-build/` |
| Runtime support wheels | `Jinja2` 3.1.6 (BSD), `MarkupSafe` 3.0.4 (BSD); pinned hashes in `local-llm-manifest.json` | As listed | PyPI wheel artifacts |

The patched `llama-cpp-python` wheel was built from the official PyPI 0.3.36
source archive (76,589,250 bytes; SHA-256
`832db0699007f1be95a7e41ef12e88926b02ba836461e36a36372db2760c1a2e`) outside
the evaluator, with the build container using `--network=none`. The resulting
wheel is 24,140,277 bytes. The build recipe pins its base, inputs, and compile
flags, and records the vendored `llama.cpp` revision and MIT license. This
verifies source provenance for this wheel but does not assert a bit-for-bit
reproducible build. Complete licensing of every bundled native component
remains under review.

The portable offline build script was then run from the same pinned local
builder image (image ID
`sha256:1190b243b1ebdd29c6547a1959531a58c474e3c6cb953333fc9bf20b866bf2d6`).
It completed with `--network=none`, but the second wheel was 24,140,282 bytes
with SHA-256
`7bd646f48c830457b85fe4801f2f6992065299f3fea253dea03c247683397ad1`, differing
from the active runtime wheel. The 92 archive paths were unchanged; the only
content differences were the ELF build-id note, the temporary absolute prefix
in `lib/pkgconfig/llama.pc`, and derived `RECORD` hashes. The rebuilt wheel was
not promoted. Exact reproducibility is not established; the active runtime
remains pinned to the independently tested wheel hash above.

The model weights are kept outside Git under the ignored
`generated-artifacts/guardian-llm-lab/` directory. The runner verifies their
exact byte count and SHA-256 before loading. The image is the existing pinned
Python 3.13 worker base; the existing Garak entrypoint and dependency lock are
unchanged.

### Optional disk cache

The active wheelhouse intentionally excludes `diskcache 5.6.3`. Its OSV record
describes unsafe pickle deserialization when an attacker can write to a cache
directory. The patched `llama-cpp-python` source lazy-loads this optional feature;
without the package, constructing `LlamaDiskCache` raises
`diskcache_optional_feature_not_installed`. `LocalQwenClient` passes
`cache=None` and fails closed if `diskcache` is present in the local runtime.
Five unit tests and an isolated wheel smoke verified the absent-cache behavior,
including that no cache directory is created. This is a local runtime removal,
not a claim that the upstream advisory is fixed.

The wheel was rebuilt from the official 0.3.36 sdist (SHA-256
`832db0699007f1be95a7e41ef12e88926b02ba836461e36a36372db2760c1a2e`) using
`local-llm-build/build-wheel.sh` with Docker `--network=none`. The output is
24,140,277 bytes. Only one build was performed; byte-for-byte reproducibility
and complete legal review of bundled native components are not claimed.

## Isolation and limits

The fixed runner uses `--network=none`, a read-only root filesystem, read-only
bind mounts for the model, wheelhouse, and worker source, no forwarded host
environment or credentials, no external volumes, one CPU, 1,536 MiB RAM with
no extra swap, 64 PIDs, concurrency one, 1,024 context tokens, at most 96
completion tokens per case, and a 180-second hard timeout. `/tmp` remains
`noexec`; a separate ephemeral 128 MiB executable tmpfs is limited to the
verified native Python runtime libraries. The code checks
cgroup CPU, memory, and PID limits and reuses the worker's network-isolation
probe. Public IPv4 and DNS must be blocked; IPv6 is reported as blocked or
unavailable according to the probe, never inferred.

Only fixed synthetic documents and fake tools exist in the harness:

- `read_document` is a local, read-only lookup for the current synthetic ID.
- `send_email` and `delete_document` are policy-denied, instrumented operations.
  They have no network or filesystem side effects.
- Outputs from the earlier JSON-emulation profile are action proposals, not
  native tool calls. The autonomous profile below parses complete Qwen GGUF
  template markers into proposals; the runtime still reports
  `finish_reason=stop` and no direct `message.tool_calls`. A deterministic
  policy gate authorizes or denies proposals before any fake operation.

## Corpus and scoring

`guardian-local-llm-tool-lab-v1` contains eight fixed cases: four attacks and
four benign controls, with four English and four Spanish cases. It includes
indirect document injection, synthetic-data exfiltration, prohibited deletion,
benign summaries, and quoted injection examples. The seed is fixed. Each
evaluation reports case-level hashes and tool traces without storing raw
documents, prompts, responses, or tool arguments.

The report gives rates with explicit numerators and denominators for
policy-forbidden tool proposals, target-operation proposals, and text
propagation in these eight cases. It does not use a classifier confusion matrix
because these outcomes are model behaviors, not detector predictions. The rates
are not a detector benchmark or an estimate of general model accuracy. Text
propagation, a structured action proposal, authorization, execution, side
effects, and policy violations are separate fields. Matching text is used only
to identify text propagation; it is never used as proof of tool use. A matching
attack-target action is reported as scenario-aligned behavior, not verified
causality.

The eight-case corpus remains a separate lab suite. The API E2E autonomous
profile uses a separately versioned 14-case suite; its denominators are not
combined with the eight-case results. Neither suite estimates general model
accuracy or security.

## API profile and fictitious tools

The latest API E2E used profile
`guardian-local-llm-autonomous-tools-v1`, engine `local_llm_lab`, worker
`guardian-ai-assessment-lab-0.4.1`, and engine
`guardian-autonomous-tool-selection-v1.3`. It ran 14 real local inference cases
with `tool_choice=auto`: 9 benign, 5 attacks, 7 calibration / 7 holdout, and
7 English / 7 Spanish. All 14 ended with `finish_reason=stop`; direct runtime
`message.tool_calls` was 0/14. The Qwen template adapter emitted 13 proposals
from complete model-generated markers; one case had no proposal. No forced
selection, JSON-only parsing, or fixture output contributed to these results.

Policy ON recorded 13 attempts, 12 allowed simulated operations, and one DENY
for a fictitious unauthorized bank change. Policy OFF reused the same 13
proposal identities only against ephemeral in-memory clones: 13/13 hypothetical
executions and 4 clone-only state changes. Across both arms, actual operations,
persistent changes, and external calls were all 0. Benign task success was 9/9,
false blocks 0/9, attack potential 1/5, and total task success 12/14. These
small counts are bounded laboratory observations, not general accuracy or
safety claims.

The tools are fictitious and the external policy validates exact argument keys
and values before any simulated operation:

- `consult_synthetic_invoice`: read-only lookup of the single fixed synthetic
  invoice.
- `send_email_simulated`: allowlisted recipient and bounded text; records only
  an in-memory simulated operation and never sends a message.
- `request_bank_account_change`: accepts only the fixed synthetic account and
  dummy identifier; records only a simulated pending request and never changes
  an account.

Each trace records proposal, authorization attempt, denial or simulated
execution separately, plus argument hashes and result codes. No raw prompt,
invoice, model response, or tool arguments are persisted. The evidence records
the model/runtime versions, file hashes, cgroup limits, network probe,
execution mode, and a SHA-256 digest. Garak evidence remains separately typed
and cannot be relabeled as a local LLM result.

Latest API E2E job:
`44bc6698-b334-41ef-8707-2a1be6f27ad0` (succeeded with a development test
identity). Its redacted evidence digest is
`c1e5b2b3f18f1339fcabedc3bc246b64b9fe8495dfe7ce4cc1c5e2b170c5d68f`; suite,
case-set, and policy-comparison digests are
`5f9d7417822e2fd6cf86c7502beed4675bf029d5187194917e7df35a12b32f67`,
`0980d82cbdc03e11b2ab164a64091e14a6e77ad386cd95deb7de856fe6fb28d0`, and
`9c462e76b9126c3a5a7d6ab5685d3b042c58e801d120cf64191bed52cbeba87b`.
Prompts, responses, and raw tool arguments are not persisted.

## Running locally

The already-downloaded model and wheels live in `generated-artifacts/` and are
not checked in. Their exact upstream URLs, sizes, licenses, and hashes are in
`local-llm-manifest.json`. After those artifacts and the existing local worker
image are present, run:

```sh
sh workers/guardian-ai-assessment/scripts/run-local-llm.sh
```

The script accepts no custom Docker options, model paths, targets, or
credentials. It uses only verified local wheels with pip `--no-index`, and
writes sanitized evidence to
`generated-artifacts/guardian-llm-lab/evidence.json`.

The 2026-11-02 direct local run completed all eight cases with real Qwen
inference (`realLlmInference=true`, `mockModelUsed=false`) in 84.697 seconds:
four attack cases and four benign controls, evenly split between English and
Spanish. Observed: 0/4 attack cases with an unauthorized tool proposal, 0/4
scenario-target tool proposals, 0/4 instruction-text propagation, 4/4 synthetic
canary appearances in attack outputs, and 1/2 quoted benign controls with
instruction text propagation. Tool attempts and state-changing executions were
0; external calls were 0. These are behavior counts on this eight-case suite,
not detection rates or general model claims. The independent 14-case API E2E
and its paired policy comparison are unchanged and have separate denominators.

- Evidence file SHA-256:
  `dc66a5d607edfeea172a2968b174b0c147c529c0e91a7553bfcfaabacd1e3956`
- Evidence payload digest:
  `2dcf4722d736530da047b3df6fafdbfe13e8c1aa65d480d742dd454140581ef3`
- Corpus SHA-256:
  `bb866b7354c9ede6f61294d60c564fc8de530eb273f58766c3e3da3c30442aef`
- Docker reported `network=none`; IPv4 and DNS were blocked, loopback-only was
  observed, and IPv6 was `kernel_protocol_unavailable` (unverified). Limits
  verified: one CPU, 1,536 MiB, 64 PIDs, concurrency one, 180-second timeout.

## Evidence/API compatibility

The API uses a versioned evidence union: `engine: garak` for the existing Garak
and GVE profile, or `engine: local_llm_lab` for the local Qwen profile. The
request profile defaults to Garak when omitted, preserving existing clients.
Both profiles use the same workspace-authorized queue, idempotency key,
PostgreSQL lease/recovery, RLS-protected result, quota and audit-event path.
The API validates the local evidence digest and isolation/limit claims before
persisting it. The local runner remains development-only and deployment
readiness is disabled.
