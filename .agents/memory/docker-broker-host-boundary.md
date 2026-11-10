---
name: Docker broker host boundary
description: Host-level requirements before separating the assessment broker from the API.
---

**Rule:** Do not describe a broker as an authority boundary when the API and broker share a Unix identity that can access the Docker socket. Require distinct process identities, Docker-socket access only for the broker, and broker-only database credentials. Before any Qwen/worker execution, also require a fresh, independently signed host attestation bound to the exact gate/runner source hashes; install only its public trust key out-of-band. The running inference process must match the signed worker UID, GID, and supplementary groups.

**Why:** In the current development host, the API runs as `runner`, the Docker socket is `root:runner` mode `0660`, and switching to an unprivileged UID fails with `Operation not permitted`. A sibling process or workflow under `runner` would keep Docker-daemon authority. Process-local metadata cannot independently prove API/broker/worker identity or DB-session separation. A valid signed inventory is also insufficient if the process about to load the model actually runs under a different UID/GID or inherited groups.

**How to apply:** Before activating a broker or Qwen, verify the host can run separate UID/GID and DB roles, prove API/worker cannot connect to the socket or assume privileged queue roles, then require a fresh signed report matching current source hashes and the current worker process identity. Keep private signing material outside the workspace. Otherwise fail closed and keep the existing local-only behavior clearly labeled.
