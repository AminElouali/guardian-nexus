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
- `llama-cpp-python` 0.3.36, built from the official PyPI source archive with
  the local `optional-diskcache.patch`; its upstream MIT license is unchanged.
- Vendored `llama.cpp` source at commit
  `0c1e57098bba43ac29e6e3b677cdceebdd22334f`, distributed under the MIT License.
- Jinja2 3.1.6 and MarkupSafe 3.0.4, distributed under BSD licenses.

Exact source revisions, wheel hashes, and model-weight hashes are recorded in
`local-llm-manifest.json`. These notices do not imply Guardian Nexus authors or
owns the model or runtime.

The active development wheelhouse excludes `diskcache`. The source patch makes
the optional disk-cache class load that dependency lazily and raise
`diskcache_optional_feature_not_installed` when called without it. The
unpatched `diskcache` wheel is retained only in ignored audit artifacts; it is
not installed in the worker image or active local-LLM wheelhouse.

The verified llama-cpp-python source archive contains these additional license
files (SHA-256 of each file in that source archive): `gguf-py/LICENSE`
MIT `ef78c7e6659e34c798194f0d344e807c722de70cbca1359ef54772661e11ca38`;
`licenses/LICENSE-jsonhpp` MIT
`c0d068392ea65358b798b8c165103560f06e9e3b38c4ab4e2d8810a7b931af86`;
`vendor/cpp-httplib/LICENSE` MIT
`4b45cbe16d7b71b89ae6127e26e0d90a029198ca5e958ad8e3d0b8bbed364d8b`;
`vendor/hash/rotate-bits/LICENSE.md` MIT
`ca0b44aec101afb6b46f4c39b23369fa06a64fb9c0add37c2689d702156fee55`;
`vendor/hash/xxhash/LICENSE` BSD-2-Clause
`6ffedbc0f7878612d2b23589f1ff2ab15633e1df7963a5d9fc750ec5500c7e7a`;
`vendor/hash/sha256/LICENSE` public domain
`b81d0022ca6367918c67b57e9647d3513ee58809fd4b0ef0b3492f1356bced25`;
`tools/ui/src/lib/vendors/big-integer/LICENSE` public domain
`e9b0e94f628e00b5ed98046cfa041696ff89eebbbdd54108ee350625bc6d0363`;
and `tools/ui/src/lib/vendors/nerdamer-prime/LICENSE` MIT
`c9f52548869a0a2e63a7100055c54cebf36b9327c8fc2da7cf9ca8dddc2f1cca`.
The built wheel carries the upstream top-level MIT notice, but this inventory
does not establish which source components are linked or provide legal
clearance; that requires a separate license review.

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
