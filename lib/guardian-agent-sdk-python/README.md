# Guardian Nexus Python SDK

Version `0.1.0` is a dependency-free client for the authenticated laboratory
API. It sends only server-allowlisted synthetic scenario IDs or one of the
eight Qwen profile IDs. The server derives the actor, role, tenant membership,
scenario action, and policy. The client cannot submit arbitrary tool names,
arguments, policy decisions, or external targets.

The SDK accepts an access-token callback from the host application's existing
authentication session. It does not store or log tokens, follow redirects,
send cookies, or permit cleartext HTTP outside loopback. It retries only
idempotent job/intent requests with the same caller key; approval decisions
are single-use and are never retried. Error objects contain only a sanitized
code and HTTP status.

The runtime package has no third-party dependencies. Unit tests use an injected
in-memory transport; one regression test opens loopback only to confirm that
HTTP redirects are refused. No test contacts a public endpoint:

```sh
cd lib/guardian-agent-sdk-python
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The SDK also consumes one persistent synthetic support approval through the
development API and PostgreSQL E2E. That test uses a development-only identity
header shim, not Clerk:

```sh
pnpm --filter @workspace/api-server run test:ai-assessment-synthetic-e2e
```

Local source use, without publishing or contacting a package registry:

```sh
PYTHONPATH=/path/to/guardian-agent-sdk-python/src python3 examples/submit_synthetic_intent.py
```

The example intentionally exits before contacting an API unless both a
loopback/API URL and an application-provided access-token callback are
configured. Do not paste tokens into source files or command history.

## Status and limits

- Fixed synthetic intent scenarios currently cover email and finance. They are
  not enterprise connectors.
- Qwen profile submission supports the eight server-allowlisted profile IDs,
  but its response remains `not_yet_verified` until a worker result is read.
- When the isolated assessment worker/broker is disabled, the API may return
  `503`; the SDK does not bypass that gate.
- This SDK has not been tested with a real Clerk browser session or an external
  customer's account.
