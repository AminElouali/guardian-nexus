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
| CPU inference runtime | `llama-cpp-python` 0.3.36; locally source-built wheel SHA-256 `a71a5a2e4b27e25b0fd783bdd5deb5a612ad950e2b0e92a0b500dee24ccb7981` | MIT | Official PyPI sdist; build inputs in `local-llm-build/source-manifest.json` |
| Runtime support wheels | `diskcache` 5.6.3 (Apache-2.0), `Jinja2` 3.1.6 (BSD), `MarkupSafe` 3.0.4 (BSD); pinned hashes in `local-llm-manifest.json` | As listed | PyPI wheel artifacts |

The `llama-cpp-python` wheel was built from the official PyPI 0.3.36 source
archive (76,589,250 bytes; SHA-256
`832db0699007f1be95a7e41ef12e88926b02ba836461e36a36372db2760c1a2e`) outside
the evaluator. The resulting wheel is 24,139,061 bytes. The build recipe pins
its base, inputs, and compile flags, and records the vendored `llama.cpp`
revision and MIT license. This verifies source provenance for this wheel but
does not assert a bit-for-bit reproducible build. The complete licensing of
every bundled native component remains under review.

The model weights are kept outside Git under the ignored
`generated-artifacts/guardian-llm-lab/` directory. The runner verifies their
exact byte count and SHA-256 before loading. The image is the existing pinned
Python 3.13 worker base; the existing Garak entrypoint and dependency lock are
unchanged.

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

## Evidence/API compatibility

The API uses a versioned evidence union: `engine: garak` for the existing Garak
and GVE profile, or `engine: local_llm_lab` for the local Qwen profile. The
request profile defaults to Garak when omitted, preserving existing clients.
Both profiles use the same workspace-authorized queue, idempotency key,
PostgreSQL lease/recovery, RLS-protected result, quota and audit-event path.
The API validates the local evidence digest and isolation/limit claims before
persisting it. The local runner remains development-only and deployment
readiness is disabled.
