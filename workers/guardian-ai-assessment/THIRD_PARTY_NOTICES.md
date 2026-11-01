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

## Python runtime dependency licensing

Runtime package versions and the selected PyPI artifact SHA-256 values are
locked in `requirements-runtime.txt`. The clean image build verifies these
hashes before installation. Build-only `setuptools` and `wheel` are pinned
separately and removed before the image is used.

`langdetect` 1.0.9 has conflicting upstream license signals: its PyPI metadata
and `setup.py` state MIT, while the source archive's `LICENSE`, `NOTICE`, and
PyPI classifier identify Apache-2.0. The package is therefore treated as
license-ambiguous pending legal review; this notice does not resolve the
conflict or assert that either license is definitive.

The generated SBOM preserves unnormalized package license strings and
`NOASSERTION` where evidence is insufficient. Debian copyright files are
inventoried but their expressions are not normalized. This inventory is not
legal clearance; see `DEPENDENCY_AUDIT.md` in the project workspace.
