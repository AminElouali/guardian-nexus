---
name: Qwen native tool-call template
description: Preserve the GGUF tool-call schema when using Qwen3 GGUF with llama-cpp-python.
---

For Qwen3 GGUF with llama-cpp-python, let the runtime use the template embedded in GGUF metadata. Overriding it with the generic `qwen` formatter can bypass the model's embedded tool schema. If reasoning must be disabled, derive a hash-tracked template that changes only the thinking flag, then verify a real `message.tool_calls` result and `finish_reason=tool_calls` before calling the path native.

**Why:** In the local validation, the generic formatter did not yield native tool calls, while the GGUF-embedded template did.

**How to apply:** Keep the embedded tool definitions and syntax intact; distinguish native structured calls from JSON found in ordinary response text, and retain template hashes in evidence.
