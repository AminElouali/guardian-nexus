# Approval ledger and receipt: wire format v1 (design only)

**Status:** projected. This document and the crypto module are isolated test
material; they are not connected to approvals, PostgreSQL, RLS, API responses,
or an execution path.

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

This phase does not persist receipts/events, issue keys, create a key registry,
or establish an external chain-head anchor. Signatures can expose edits,
insertion, reordering, and interior deletion, but detecting tail truncation or
rollback requires a separately retained trusted head/checkpoint. A signing key
available to the API host also does not protect against compromise of that
host.
