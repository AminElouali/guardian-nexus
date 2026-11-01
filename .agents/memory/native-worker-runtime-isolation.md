---
name: Native worker runtime isolation
description: Safely loading verified native Python wheels inside network-isolated workers.
---

Keep the general temporary filesystem mounted `noexec`. When a pinned native Python wheel must load shared libraries in an isolated worker, install only verified local wheels into a separate, size-bounded, ephemeral executable tmpfs.

**Why:** The dynamic loader cannot map executable segments from a `noexec` mount; weakening the whole temporary filesystem is unnecessary.

**How to apply:** Keep model and wheel inputs read-only, verify hashes before use, disable network access, and scope executable tmpfs only to the temporary native runtime.
