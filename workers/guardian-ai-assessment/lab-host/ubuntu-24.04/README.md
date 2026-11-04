# Guardian Nexus isolated lab host — Ubuntu 24.04

Status: **prepared configuration, not provisioned or validated on a VM**.
This package is for a dedicated, disposable, authorized Ubuntu 24.04 host. It
has not been run on Replit, and it is not a production installation.

## Trust boundaries

- `guardian-api`, `guardian-worker`, and `guardian-broker` are distinct locked
  system accounts. The API and worker must not belong to `docker` or
  `guardian-docker-broker`. Only the broker receives the dedicated socket group.
- `guardian-broker-clients` is a separate, narrow IPC group for the API-to-broker
  Unix socket. It does not grant Docker access. The API must still present a
  one-use signed grant; socket membership alone is not authorization.
- Access to the Docker daemon is effectively host-root authority. A broker
  process with socket access is **not** an OS sandbox; keep this host dedicated,
  restrict the broker API to signed, expiring, single-use grants, and require
  the broker to revalidate tenant, profile, image ID, lease, and action hash.
- Workers run as non-root containers with `--network=none`, pinned local image
  IDs, a read-only root filesystem, dropped capabilities, no-new-privileges,
  seccomp, resource/PID/output/time limits, and no Docker socket mount.
- The example service units are templates. Their `ExecStart` targets do not
  exist until a separately reviewed application release is installed. They
  are not copied, enabled, or started by `provision.sh`.
- The role SQL creates only non-login role skeletons. It grants no table
  privileges and does not establish live database sessions. The example
  `pg_service.conf`, `pg_ident.conf`, `pg_hba.conf`, and peer-login SQL show a
  passwordless local-peer pattern with distinct OS/DB identities; they are
  examples only and must be reviewed by the DBA. Exact table/function grants
  and RLS predicates remain schema-specific and unconfigured.
- The host preflight report is evidence of observed configuration only. It
  does not authorize tools or replace Guardian Policy Engine.

## Safe use

1. Take a VM snapshot and confirm it is dedicated to this lab, not shared and
   not production. Do not reuse a host whose Docker daemon serves other work.
2. Review all files and record the host's existing `docker.socket` unit and
   group policy. The script refuses containers, non-Ubuntu-24.04 systems,
   running containers, unmanaged drop-ins, and missing prerequisites.
3. First run `./provision.sh --plan`. This is read-only and does not connect to
   Docker or a database.
4. Only on the separately authorized dedicated VM, after review, run:

   ```sh
   GUARDIAN_LAB_CONFIRM_DEDICATED_HOST=Ubuntu-24.04-dedicated-lab \
     sudo -E ./provision.sh --apply
   ```

   `--apply` changes system accounts/groups and the `docker.socket` systemd
   drop-in, then restarts the socket unit. The script refuses to proceed if
   containers are running. It does not install application code, create DB
   credentials, enable services, or start Qwen.
5. Review `systemd/guardian-broker.socket.example` and the service-unit examples.
   The broker socket template requires a socket-activation-compatible broker
   entrypoint; it is not started by provisioning. Configure peer authentication
   only after review, then verify the three DB identities with the read-only
   `db/verify-roles.sql`. Do not use a superuser runtime role or `BYPASSRLS`.
   The role skeleton SQL is not an authorization grant.
6. Install and review the service-unit examples only after an application
   release exists at `/opt/guardian-nexus/current`. Keep API bound to loopback
   behind a reviewed local reverse proxy. Set service-specific environment
   files outside the repository with owner/mode `root:<service-group>` and
   mode `0640`; no file should be shared across API, worker, and broker.
7. Run the portable host preflight. The default invocation only reads host
   metadata and sensitive environment-variable **names/count**, not values.
   On the authorized Ubuntu lab only, `--probe-database` uses the three local
   peer-auth service profiles in a read-only transaction, and
   `--probe-worker-child` runs a minimal identity check as `guardian-worker`;
   neither starts Qwen. A host-boundary pass is necessary but not sufficient:
   run the existing offline process guard inside the intended worker boundary
   and verify fixed model hashes before a separate, approved inference run.
   The preflight CLI exits nonzero until the combined runtime evidence is
   present. Do not use the opt-in flags in the Replit workspace.

## Rollback

On the same dedicated VM, after stopping only Guardian Nexus lab services:

```sh
GUARDIAN_LAB_CONFIRM_DEDICATED_HOST=Ubuntu-24.04-dedicated-lab \
  sudo -E ./provision.sh --rollback
```

Rollback removes only the managed `99-guardian-nexus-lab.conf` drop-in and
restarts `docker.socket` to restore the prior unit policy. The three locked
service accounts and role skeletons are intentionally retained for manual
review; do not delete them automatically if files, processes, or grants may
still refer to them. PostgreSQL role removal and secret revocation require a
separate reviewed DBA procedure.

## Known limitations

- No Ubuntu VM was created or modified in this phase.
- No Docker daemon/socket, PostgreSQL, Qwen process, or external service was
  contacted here.
- The current Replit host does not provide independent API/broker UIDs or
  database sessions and exposes the Docker socket to the runner; the existing
  Qwen gate remains closed.
- These templates do not prove the broker is isolated or the application
  actually uses separate database roles. That requires deployment and
  host-level evidence on the authorized VM.
