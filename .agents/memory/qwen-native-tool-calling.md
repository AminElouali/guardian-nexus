---
name: Qwen native tool-call template
description: Preserve the GGUF tool-call schema when using Qwen3 GGUF with llama-cpp-python.
---

For Qwen3 GGUF with llama-cpp-python, use the template embedded in GGUF metadata; a generic `qwen` formatter can omit its native tool schema. In llama-cpp-python 0.3.36, autonomous Qwen output may contain a complete `<tool_call>{...}</tool_call>` block in assistant content while `message.tool_calls` is empty and `finish_reason` is `stop`. A strict adapter may normalize only complete, standalone tagged JSON with the exact `{name, arguments}` shape; never promote untagged/free JSON. Preserve provenance distinguishing model-emitted Qwen markup from calls returned directly by the runtime and from forced calls.

**Why:** The runtime's generic Jinja handler returns autonomous Qwen markup as content, so checking only `message.tool_calls` falsely reported zero selections even when the model emitted structured Qwen tool syntax.

**How to apply:** Keep the embedded tool definitions and syntax intact; hash any template change, test `tool_choice=auto` separately from forced selection, and record whether the runtime returned structured calls or a strict Qwen-markup adapter normalized them.
