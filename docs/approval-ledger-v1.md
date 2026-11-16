# Approval ledger and receipt: wire format v1

**Status:** the v1 serialization/signature module and the isolated PostgreSQL
ledger schema are implemented. The schema is declared in Drizzle and the RLS
SQL, and the local disposable lab exercises it as `app_runtime`. No development
or production database was changed. The ledger is not connected to the
approval API or dispatch path; durable application writes, key management, and
external chain-head anchoring remain projected.

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
Those checks remain the responsibility of the standalone verifier until a
separately reviewed application integration exists.

## Verification and trust boundaries

The standalone Python verification function accepts a bundle, a trusted key
map, and a verification time. It checks canonical values, event
sequence/previous hashes, digests, Ed25519 signatures, receipt references,
different actors, expiry, and duplicate/replayed receipt nonces. The CLI in
this phase only validates the shared TEST ONLY vector; it is not yet a
production JSONL exporter/verifier. Vector mode uses public test keys and the
system OpenSSL executable. A production verifier must receive trusted public
keys out of band. The Node canonicalizer takes already-parsed values; callers
must not assume it can recover lexical distinctions such as `1` versus `1.0`
after a normal `JSON.parse`.

The storage schema can persist synthetic ledger events in the isolated lab,
but the application does not yet persist receipts/events through its approval
flow, issue keys, create a key registry, or establish an external chain-head
anchor. Signatures can expose edits,
insertion, reordering, and interior deletion, but detecting tail truncation or
rollback requires a separately retained trusted head/checkpoint. A signing key
available to the API host also does not protect against compromise of that
host.
