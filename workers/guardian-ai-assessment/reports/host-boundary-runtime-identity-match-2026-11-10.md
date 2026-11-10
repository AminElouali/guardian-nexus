# Host boundary runtime identity binding — 2026-11-10

## Result

Starting from `4785978ad35a42a8aa80c6278da377c77879a317` on `main`, the
attestation verifier now compares the process that is about to run inference
with the signed `worker` identity: effective UID, effective GID, and the full
supplementary-group set. Missing identity APIs, unreadable groups, or any
mismatch fail closed before the verifier returns a successful attestation.
The signed report's API, broker, and worker identities and socket/database
separation checks remain required.

This closes a code-level identity-substitution gap; it does **not** establish
the host boundary on this Replit workspace. The gate remains closed. No host
configuration, user/group, Docker permission, socket, service, database, or
attestation was changed or accessed. The preceding host-boundary report and
`deployment/BROKER_BOUNDARY.md` document that the Replit runner shares the
Docker-socket-accessible identity and that changing UID via `setresuid` is
denied. Those are recorded environment findings, not a fresh host probe in
this increment.

The actual boundary still requires an independently administered dedicated
lab host to verify separate API/broker/worker identities and database roles,
API/worker socket denial, and worker sandbox conditions, then provision a
fresh Ed25519 attestation out of band that matches the exact source hashes.
The Replit workspace cannot produce that evidence under the requested
non-invasive constraints.

## Tests run now

Run serially:

```text
PYTHONPATH=workers/guardian-ai-assessment python -m unittest discover -s workers/guardian-ai-assessment/tests -p 'test_host_boundary_attestation.py' -v
```

Result: **14/14 passed**. The added cases reject a signed inventory that does
not match the executing process UID/GID/groups, including a worker carrying
the broker socket group; unreadable group identity also fails closed. Tests
mock the signature verification and synthetic attestation files. They verify
the gate logic only; they do not prove a real signature, host separation, or
service identities.

`git diff --check` passed after the code/test change. It will be repeated after
this report and checkpoint update.

Not run: Qwen, a live worker, API/broker services, Docker, socket access,
PostgreSQL, external connections, E2E/UI, or deployment. No host preflight was
run in this increment.

## SHA-256

- `guardian_ai_assessment/host_boundary_attestation.py`:
  `9aa3cd4acdb8e88a14816af13a2b5cbbb8507fa47764cbb76c6ab90241119ea8`
- `tests/test_host_boundary_attestation.py`:
  `2e77bc37ba66256af7c5d9a9805347ac56f7f2dd9e3802cc77d1a7083c1f3975`
