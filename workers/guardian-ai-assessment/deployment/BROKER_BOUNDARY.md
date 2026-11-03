# Docker broker boundary: host requirements and current limitation

`broker-host-requirements.example.yaml` is a **target contract only**. It is not
an active deployment manifest, does not start a broker, and does not prove
separation on Replit. The API still has access to the development Docker socket
when the local development worker is enabled. Deployed/non-development API
processes are already prevented from starting that local worker; this is not a
Unix privilege boundary.

The API package contains a signed-grant protocol helper with strict
job/workspace/actor/profile/image/request binding, a maximum 60-second lifetime,
and a required atomic one-use claim callback. Its unit tests use an in-memory
claim set. **The helper is not wired to the queue or a broker process**; it does
not reduce the current API process's Docker authority. A production integration
must implement the callback with an atomic PostgreSQL unique-token insert and
pass the profile image ID only from the verified image lock.

## Host acceptance requirements

Before enabling a remote/local broker on any host:

1. API and broker must run under distinct effective Unix UIDs and separate
   PostgreSQL roles. A shared UID, shared Docker socket permission, or
   `setpriv` failure is an automatic rejection.
2. Use a dedicated rootless Docker daemon owned by the broker identity. Do not
   add the web API to a rootful `docker` group or mount `docker.sock` into the
   API or evaluation containers.
3. The API may submit a bounded authenticated job but may not claim worker
   leases or write worker results. The broker may claim only the dedicated
   worker queue role with tenant RLS and cannot select arbitrary tenants.
4. The broker validates the lease, tenant/workspace, actor, allowlisted profile,
   request digest, one-use grant, immutable image ID and OCI profile label
   immediately before `docker create`. Command, image reference, mounts and
   resource limits remain server-owned constants.
5. Evaluation containers retain `--network=none`, rootless/non-root execution,
   read-only root filesystem, read-only model mounts, dropped capabilities,
   `no-new-privileges`, seccomp, CPU/memory/PID/output/time limits, and verified
   cleanup.
6. Negative acceptance tests must show the API UID cannot open the broker-owned
   Docker socket, the broker UID can run only a locked profile, and forged,
   expired, replayed, tenant-mismatched or retagged-image grants never create a
   container.

## Replit development host result

The verified preflight found API UID/GID `runner:1000`, a Docker socket
accessible to that same identity, and `setpriv` unable to change UID because
the host denies `setresuid`. No host permissions or daemon settings were
changed. Therefore the required API/broker identity separation is **blocked
here**; do not claim the broker boundary is active or use the protocol helper
as a substitute for OS isolation.
