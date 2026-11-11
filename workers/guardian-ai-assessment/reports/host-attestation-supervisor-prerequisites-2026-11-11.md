# Host/broker attestation prerequisites — 2026-11-11

## Result

No independently verifiable host attestation is available in this Replit
workspace. The API gate remains fail-closed; no Qwen, worker, Docker, PostgreSQL,
or service was started. This is a capability/blocker report, not an isolation
certification.

## Read-only observations

- Starting state: HEAD
  `278a959dbd720ee8d454659cece6e9aab8d4547d`, branch `main`, clean.
- Metadata checks found these expected inputs absent:
  - `/run/guardian-nexus/host-boundary-attestation.json`
  - `/etc/guardian-nexus/host-boundary-attestor-ed25519.pem`
  - `/run/guardian-nexus/host-boundary-challenge.json`
- The existing Python verifier
  `guardian_ai_assessment/host_boundary_attestation.py` performs Ed25519
  verification, canonical JSON and exact-schema checks, root-owned file checks,
  freshness/expiry checks, code-hash binding, distinct API/broker/worker UID,
  GID and DB-role checks, socket-access claims, and sandbox requirement checks.
  It also compares the current process identity to the **worker** identity.
- The current verifier payload/schema has no challenge nonce or replay state.
  Its unit tests include synthetic expiry, hash, identity and socket failures.
  The signed-attestation success test uses a synthetic payload and mocks the
  signature-verification function; it is a unit test, not host evidence.
- The API gate in `assessment-worker-api-gate.ts` remains hard-coded to
  `disabled` with `assessment_broker_identity_unverified`; it does not invoke
  the Python verifier or validate an API-process identity.
- No API challenge channel, independent supervisor/attestor service, or durable
  attestation replay-consumption interface was found in the inspected code.
- No Docker socket was opened or inspected in this audit. The latest recorded
  passive host report is dated 2026-11-10 and is historical: it reports
  `hostBoundaryReady=false`, API/broker/worker identities unverified, and
  socket metadata `root:runner` mode `0660` with read/write access reported by
  `os.access`. That report is not a current measurement or an attestation.

## Why readiness cannot safely be enabled here

The signing key, signed report, and challenge input are absent. There is no
independent supervisor to produce a response to a fresh nonce, no API-side
signature verifier, and no durable one-use/replay channel. The current API gate
therefore stays closed. Test doubles, the Python verifier’s synthetic test
payload, declarative sandbox arguments, and historical host reports cannot
establish readiness.

## Tests and limits

- No tests, preflights, workers, Qwen, Docker, PostgreSQL, services, network
  connections, or deployments were run for this report.
- Existing test files were inspected only. No current claim is made that their
  suites pass in this iteration.
- The API/worker effective identities, namespace separation, capabilities,
  `no_new_privs`, seccomp, mounts, inherited descriptors, and live DB roles
  remain unverified.

## Required external capability and next step

The host owner must provide an independently administered supervisor that can
issue a fresh challenge and one-use signed response, maintain replay protection,
and attest current API/broker/worker process identities and security properties.
The verifier must be integrated into the API using the root-provisioned public
key and read-only attestation input, bind the signed response to the exact
current code hashes, compare the API’s own identity, and remain false when any
input or capability is missing. The worker verifier must separately compare
the running worker identity. After that supervisor and protocol are available,
implement and test the API verification path; only then reconsider enabling the
gate. The first model flow after independent verification remains email, then
database.
