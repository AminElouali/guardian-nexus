import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  assembleApprovalLedgerBundleV1,
} from "./approval-ledger-export";
import type { ApprovalLedgerBundleV1 } from "./approval-ledger-crypto";

const vectors = JSON.parse(
  readFileSync(new URL("./approval-ledger-v1.vectors.json", import.meta.url), "utf8"),
) as { bundle: ApprovalLedgerBundleV1 };

test("bundle exporter attaches the exact receipt archive to the signed history", () => {
  const result = assembleApprovalLedgerBundleV1(
    vectors.bundle.events,
    vectors.bundle.receipts,
  );
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.deepEqual(result.bundle, vectors.bundle);
});

test("bundle exporter rejects missing and unexpected receipts", () => {
  assert.deepEqual(
    assembleApprovalLedgerBundleV1(vectors.bundle.events, []),
    { ok: false, code: "receipt_missing" },
  );
  assert.deepEqual(
    assembleApprovalLedgerBundleV1(
      [],
      vectors.bundle.receipts,
    ),
    { ok: false, code: "receipt_unexpected" },
  );
});

test("bundle exporter rejects duplicate receipts and mismatched references", () => {
  assert.deepEqual(
    assembleApprovalLedgerBundleV1(vectors.bundle.events, [
      ...vectors.bundle.receipts,
      vectors.bundle.receipts[0],
    ]),
    { ok: false, code: "receipt_duplicate" },
  );

  const altered = [...structuredClone(vectors.bundle.receipts)];
  altered[0] = {
    ...altered[0],
    payloadSha256: "f".repeat(64),
  };
  assert.deepEqual(
    assembleApprovalLedgerBundleV1(vectors.bundle.events, altered),
    { ok: false, code: "event_reference_mismatch" },
  );
});

test("bundle exporter rejects a consumed event without its matching approval reference", () => {
  const events = [...structuredClone(vectors.bundle.events)];
  events.reverse();
  assert.deepEqual(
    assembleApprovalLedgerBundleV1(events, vectors.bundle.receipts),
    { ok: false, code: "event_reference_mismatch" },
  );
});
