---
name: Qwen native tool-call template
description: Preserve the GGUF tool-call schema when using Qwen3 GGUF with llama-cpp-python.
---

For Qwen3 GGUF with llama-cpp-python, use the template embedded in GGUF metadata; a generic `qwen` formatter can omit its native tool schema. In llama-cpp-python 0.3.36, autonomous Qwen output may contain a complete `<tool_call>{...}</tool_call>` block in assistant content while `message.tool_calls` is empty and `finish_reason` is `stop`. A strict adapter may normalize only complete, standalone tagged JSON with the exact `{name, arguments}` shape; never promote untagged/free JSON. Preserve provenance distinguishing model-emitted Qwen markup from calls returned directly by the runtime and from forced calls.

**Why:** The runtime's generic Jinja handler returns autonomous Qwen markup as content, so checking only `message.tool_calls` falsely reported zero selections even when the model emitted structured Qwen tool syntax.

**How to apply:** Keep the embedded tool definitions and syntax intact; hash any template change, test `tool_choice=auto` separately from forced selection, and record whether the runtime returned structured calls or a strict Qwen-markup adapter normalized them.

For each added Qwen lab vertical, keep the profile registry synchronized across API readiness, request validation, evidence validation, OpenAPI/generated types, database constraints, and UI. Tool JSON schemas must match the adapter's exact argument keys and fixed synthetic IDs/permissions. Bump the engine/corpus version when adding or changing cases.

**Why:** A profile omitted from an explicit availability list could not be launched, and a multiagent schema that omitted adapter-required child identity and permission fields failed closed at evidence validation.

**How to apply:** Validate each vertical end to end with `tool_choice=auto`; include the real adapter contract and generated API types in the change, and do not relax evidence validation to make a mismatched tool payload pass.
