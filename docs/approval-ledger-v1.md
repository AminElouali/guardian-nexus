# Approval ledger and receipt: wire format v1

**Status:** the v1 serialization/signature module, isolated PostgreSQL ledger
schema, approval write path, and separate receipt-consumption path are
implemented in code. The local disposable lab exercises the application flow
as `app_runtime`; it does not use the development or production database. An
approval receipt is returned once to the caller and is not stored in the
server. The ledger stores only its digest in the signed approval event.
Production key provisioning, a multi-key public-key registry, external
chain-head anchoring, and independent security review remain outstanding.

## Canonical values

The signed payload domain is limited to strings, booleans, safe integers,
arrays, and plain objects containing those values. `null`, decimals, unsafe
integers, negative zero, non-finite numbers, undefined values, non-plain
objects, symbols, accessors, and unpaired UTF-16 surrogates are rejected.
Object keys are strings ordered lexicographically by UTF-16 code units. Strings
use JSON/ECMAScript escaping and UTF-8 output. No insignificant whitespace is
emitted. This restricted profile avoids floating-point serialization; it is
not claimed to implement all of RFC 8785.

## Signed approval receipt

Version 1 fields: `version`, `keyId`, `receiptId`, `workspaceId`, `approvalId`,
`proposalBindingSha256`, `actionSha256`, `requestedBy`, `approvedBy`,
`approvedByRole`, `issuedAt`, `expiresAt`, and `nonce`. IDs and timestamps are
strings; the version is an integer. Requester and approver must differ. The
nonce is unique per receipt and is intended to be consumed once.

The digest is SHA-256 over the ASCII domain label
`guardian-nexus:approval-receipt:v1` followed by one LF byte and then
`canonical(payload)`. The Ed25519
signature covers those same bytes. `keyId` is inside the signed payload and
selects a public key supplied by a trusted registry, never by an export.

The application signing key is supplied at runtime through
`APPROVAL_LEDGER_ED25519_PRIVATE_KEY`. Its public key ID is the stable code
identifier `guardian-nexus-approval-ledger-v1`. Missing, malformed, or
non-Ed25519 material fails closed. The disposable approval E2E creates an
ephemeral test-only Ed25519 key after its database guard passes. Receipts
expire five minutes after issuance.

The receipt commits to `proposalBindingSha256` and `actionSha256`. Under the
current binding contract, the synthetic amount is covered indirectly by
`actionSha256`; the idempotency key is linked only indirectly through the bound
job ID. There is no currency field in the current action/receipt contract, so
the receipt does not commit to currency.

## Signed ledger event

Version 1 fields: `version`, `keyId`, `workspaceId`, `sequence`, `eventId`,
`eventType`, `approvalId`, `previousEventSha256`, `occurredAt`, and `payload`.
The first event in a workspace chain uses an empty previous hash; later events
refer to the preceding event hash. `approval.approved` records the receipt ID
and digest; `approval.receipt_consumed` records those references, the nonce,
and `consumedAt`.

The digest is SHA-256 over the ASCII domain label
`guardian-nexus:approval-ledger-event:v1` followed by one LF byte and then
`canonical(event)`. Ed25519 signs the same domain-separated bytes. Event and
receipt domains are distinct.
Canonical payload versioning and `keyId` allow future formats and key rotation
without silently changing v1 interpretation.

## PostgreSQL storage contract

`workspace_approval_ledger` stores one append-only event per
`(workspace_id, sequence)`. Its `payload_canonical` column contains the complete
canonical `ApprovalLedgerEventV1` envelope as text so the bytes covered by the
digest and signature are preserved. The duplicated workspace, sequence, event
type, approval, receipt, previous hash, key ID, and timestamp columns are bound
to the corresponding envelope fields by a CHECK constraint. A partial unique
index permits at most one `approval.receipt_consumed` event for each
`receipt_id`. Deleting a workspace with ledger events is blocked by a
non-cascading foreign key.

The runtime database role has only SELECT and INSERT table privileges. RLS
scopes reads to members of the configured workspace and permits inserts only
for its owner/admin members. RLS is enabled and forced by the canonical SQL.
The database checks formats and field bindings; it does **not** verify Ed25519
signatures, event hashes, sequence continuity, or canonical byte encoding.
The API verifies receipts/events on the application write and consume paths;
the standalone bundle verifier remains the independent offline verifier.

On approval, the API conditionally updates the pending request, then creates
the v1 receipt and signed `approval.approved` event and inserts that event
inside the same workspace transaction. Key, signing, or insert failures roll
back the approval update. Denials do not issue receipts. The event payload is
exactly `receiptId` and `receiptSha256`; the complete signed receipt is returned
once in the decision response and is not recoverable from server storage after
that response. If the caller loses it, a new approval request is required.

Receipt consumption is a separate owner/admin operation. The caller presents
the signed receipt; the API verifies its signature, expiry, approval binding,
actor fields, the matching signed approval event's receipt digest, and the
complete signed event chain currently stored for that workspace. It then
appends one signed `approval.receipt_consumed` event in the same transaction.
A fixed-namespace, workspace-derived transaction advisory lock serializes
approval and consumption events; the partial unique index remains the
one-consumer constraint.

The support synthetic-refund action is not simulated at proposal or approval
time. It runs only in the in-memory clone after the receipt has passed the
workspace-chain and approval checks and the consumed event has been inserted
inside the same transaction. If the simulator cannot produce its deterministic
result, the transaction fails and the consume event rolls back. The result
returns hashes and a fixed result code; no refund, payment, customer record, or
external system is touched. Non-refund approvals retain their existing
phase-2 behavior.

## Portable export and offline verification

`POST /api/workspaces/{workspaceId}/ai-security-assessments/approval-ledger/export`
requires an owner/admin and the caller-held signed receipts for every
`approval.approved` event in that workspace. The server reads the complete
signed event chain and returns a JSON `ApprovalLedgerBundleV1`; it does not
store or reconstruct receipt bodies. The export fails rather than silently
omitting history if a receipt is missing, extra, or mismatched. Exports are
bounded to 10,000 events (at most 5,000 receipts).

Run the independent verifier in a separate process:

```sh
pnpm --filter @workspace/api-server run verify:approval-ledger-bundle -- \
  --bundle ./approval-ledger-bundle.json \
  --trusted-keys ./trusted-approval-ledger-public-keys.json
```

The trusted-key file is a JSON object mapping `keyId` to an Ed25519 public-key
PEM. Obtain and authenticate it independently; the bundle does not supply its
own trust anchor. The CLI imports only the v1 cryptographic module and Node's
standard filesystem/crypto libraries. It does not load the API, connect to a
database, or make network requests. It prints only a fixed verification code
and validity boolean. The shared TEST ONLY vectors exercise it in a clean
child process with no database/API environment.

The local end-to-end demonstration uses the repository's disposable,
process-owned PostgreSQL lab:

```sh
env -i PATH="$PATH" HOME="$HOME" LANG=C LC_ALL=C pnpm run lab:local
```

It exercises the Python SDK proposal, approval by a different workspace
administrator, caller-held receipt export, independent CLI verification before
consumption, and the synthetic refund clone after valid consumption. Negative
cases cover missing, altered, expired, wrong-workspace, wrong-action, replayed,
and chain-corrupted authorizations. The verifier child process receives only
its bundle, public-key registry, and a minimal environment; it has no database
URL, API session, secret key, or network client.

Since the server stores only receipt digests, callers must retain the signed
receipts returned by approvals. If any receipt is lost, a complete portable
bundle cannot be produced and a new approval is required; the exporter
deliberately does not claim to recover it.

## Verification and trust boundaries

The existing Python verification function remains an independent
TEST/consumer-side verifier. The Node CLI validates canonical values, event
sequence/previous hashes, digests, Ed25519 signatures, receipt references,
different actors, expiry, and duplicate/replayed receipt nonces. A
production verifier must receive trusted public keys out of band. The Node
canonicalizer takes already-parsed values; callers must not assume it can
recover lexical distinctions such as `1` versus `1.0` after a normal
`JSON.parse`.

The application writes signed events through its approval transaction, but
does not persist the receipt body or maintain a multi-key public registry.
Signatures can expose edits, insertion, reordering, and interior deletion, but
detecting tail truncation or rollback requires a separately retained trusted
head/checkpoint. A signing key available to the API host also does not protect
against compromise of that host. Live consumption verifies every stored event
signature and link plus the presented receipt; it cannot verify old receipt
bodies that are not stored. The complete offline bundle verifier checks every
receipt supplied in the archive.
