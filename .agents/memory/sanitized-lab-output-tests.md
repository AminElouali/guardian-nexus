---
name: Sanitized lab output tests
description: Keep disposable-lab failure reports useful without weakening credential redaction.
---

When testing the laboratory report's size limit, use repeated ordinary words separated by spaces. The sanitizer removes long token-like strings before applying its output-size cap, so a single long repeated character can be redacted and never exercise truncation. Test redaction and truncation with separate fixtures.

**Why:** A lab run exposed that a repeated-character truncation fixture was classified as a possible credential and reduced before the size assertion.

**How to apply:** For tests of captured TAP/stdout/stderr, keep the size fixture non-sensitive and assert that truncation preserves both the beginning and the final failure lines.
