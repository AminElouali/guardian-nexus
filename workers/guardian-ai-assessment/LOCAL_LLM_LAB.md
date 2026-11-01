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
| CPU inference runtime | `llama-cpp-python` 0.3.36; wheel SHA-256 `c8a3e98093e950d7a770f794842e36f2db82b2933e8762ed7b5ffd435011e8e4` | MIT | [Release v0.3.36](https://github.com/abetlen/llama-cpp-python/releases/tag/v0.3.36) |
| Runtime support wheels | `diskcache` 5.6.3 (Apache-2.0), `Jinja2` 3.1.6 (BSD), `MarkupSafe` 3.0.4 (BSD); pinned hashes in `local-llm-manifest.json` | As listed | PyPI wheel artifacts |

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
- Model outputs are constrained to JSON and interpreted as **action proposals**;
  this is not native function calling. A deterministic policy gate authorizes
  or denies proposals before any fake operation.

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

The API job does **not** run this eight-case corpus or calculate precision,
recall, or attack metrics. It runs only the fixed `synthetic_invoice_summary_v1`
task, with an in-memory synthetic invoice, to verify the end-to-end provider,
tool-adapter, queue, tenant persistence, API and UI integration.

## API profile and fictitious tools

The job profile is `guardian-local-llm-qwen3-0.6b-v1`; its engine is
`local_llm_lab`, with adapter version `guardian-local-llm-tool-adapter-v1`.
The model receives only a fixed synthetic invoice and emits JSON. The current
runtime does not perform native function/tool calling. JSON actions are treated
as proposals by an adapter outside the model, which validates exact argument
keys and values before the fake tool can execute:

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
