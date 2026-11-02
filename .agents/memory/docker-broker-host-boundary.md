---
name: Docker broker host boundary
description: Host-level requirements before separating the assessment broker from the API.
---

**Rule:** Do not describe a broker as an authority boundary when the API and broker share a Unix identity that can access the Docker socket. Require distinct process identities, Docker-socket access only for the broker, and broker-only database credentials.

**Why:** In the current development host, the API runs as `runner`, the Docker socket is `root:runner` mode `0660`, and switching to an unprivileged UID fails with `Operation not permitted`. A sibling process or workflow under `runner` would keep Docker-daemon authority. Official docs lookup did not establish per-workflow secret isolation.

**How to apply:** Before activating a broker, verify the host can run a separate UID/GID, prove the API process cannot connect to the socket or assume the queue role, and verify secrets are scoped so the API cannot read the broker credential. Otherwise fail closed and keep the existing local-only behavior clearly labeled.
