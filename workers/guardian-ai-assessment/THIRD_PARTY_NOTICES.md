# Third-party notices

## Garak

This laboratory worker includes Garak version 0.17.1 from the NVIDIA/garak
open-source project. Garak is licensed under Apache License 2.0. The
commercial-facing product name remains Guardian Nexus; this attribution does
not imply Guardian Nexus authors or owns Garak.

- Source and release: https://github.com/NVIDIA/garak/releases/tag/v0.17.1
- License text: https://github.com/NVIDIA/garak/blob/v0.17.1/LICENSE
- Garak documentation: https://reference.garak.ai/en/stable/

The exact package version and the profile run are recorded in each real
laboratory result. A probe run is limited evidence, not certification or proof
that an agent is secure.

## Optional local LLM laboratory

The separate development-only local LLM laboratory uses:

- Qwen3-0.6B-GGUF, distributed under Apache License 2.0.
- `llama-cpp-python` 0.3.36, distributed under the MIT License.
- `diskcache` 5.6.3, distributed under Apache License 2.0.
- Jinja2 3.1.6 and MarkupSafe 3.0.4, distributed under BSD licenses.

Exact source revisions, wheel hashes, and model-weight hashes are recorded in
`local-llm-manifest.json`. These notices do not imply Guardian Nexus authors or
owns the model or runtime.
