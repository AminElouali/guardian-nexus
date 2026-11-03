import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import {
  createAssessmentBrokerGrant,
  verifyAndConsumeAssessmentBrokerGrant,
  type AssessmentBrokerGrantBinding,
} from "./assessment-broker-grant";

const secret = "local-unit-test-only-secret-never-for-deployment";
const now = 1_800_000_000_000;

function binding(): AssessmentBrokerGrantBinding {
  return {
    jobId: randomUUID(),
    workspaceId: `workspace-${randomUUID()}`,
    actorId: `actor-${randomUUID()}`,
    leaseId: randomUUID(),
    leaseAttempt: 1,
    profileId: "guardian-agent-qwen-lab-email-v1",
    immutableImageId: `sha256:${"a".repeat(64)}`,
    requestSha256: "b".repeat(64),
  };
}

test("broker grant is signed, context-bound, and consumable only once", async () => {
  const expected = binding();
  const created = createAssessmentBrokerGrant(expected, secret, now);
  assert.equal(created.ok, true);
  if (!created.ok || !created.token) return assert.fail("grant_not_created");

  const consumed = new Set<string>();
  let claimCalls = 0;
  const claimOnce = async (tokenId: string) => {
    claimCalls += 1;
    if (consumed.has(tokenId)) return false;
    consumed.add(tokenId);
    return true;
  };
  const verified = await verifyAndConsumeAssessmentBrokerGrant(
    created.token,
    secret,
    expected,
    claimOnce,
    now + 1,
  );
  assert.equal(verified.ok, true);
  assert.equal(claimCalls, 1);

  const replay = await verifyAndConsumeAssessmentBrokerGrant(
    created.token,
    secret,
    expected,
    claimOnce,
    now + 2,
  );
  assert.deepEqual(replay, { ok: false, error: "grant_replay" });
  assert.equal(claimCalls, 2);
});

test("broker grant rejects signature changes, payload changes, and expired tokens", async () => {
  const expected = binding();
  const created = createAssessmentBrokerGrant(expected, secret, now);
  assert.equal(created.ok, true);
  if (!created.ok || !created.token) return assert.fail("grant_not_created");
  const [payload, signature] = created.token.split(".");
  assert.ok(payload);
  assert.ok(signature);
  const claimOnce = async () => true;

  assert.deepEqual(
    await verifyAndConsumeAssessmentBrokerGrant(
      `${payload}.${"0".repeat(signature.length)}`,
      secret,
      expected,
      claimOnce,
      now + 1,
    ),
    { ok: false, error: "grant_signature_invalid" },
  );
  assert.deepEqual(
    await verifyAndConsumeAssessmentBrokerGrant(
      `${Buffer.from(
        `${Buffer.from(payload, "base64url").toString("utf8")} `,
      ).toString("base64url")}.${signature}`,
      secret,
      expected,
      claimOnce,
      now + 1,
    ),
    { ok: false, error: "grant_signature_invalid" },
  );
  assert.deepEqual(
    await verifyAndConsumeAssessmentBrokerGrant(
      created.token,
      secret,
      expected,
      claimOnce,
      now + 30_000,
    ),
    { ok: false, error: "grant_expired" },
  );
});

test("broker grant mismatch and malformed configuration fail before consume", async () => {
  const expected = binding();
  const created = createAssessmentBrokerGrant(expected, secret, now);
  assert.equal(created.ok, true);
  if (!created.ok || !created.token) return assert.fail("grant_not_created");
  let claimCalls = 0;
  const claimOnce = async () => {
    claimCalls += 1;
    return true;
  };
  assert.deepEqual(
    await verifyAndConsumeAssessmentBrokerGrant(
      created.token,
      secret,
      { ...expected, workspaceId: "another-workspace" },
      claimOnce,
      now + 1,
    ),
    { ok: false, error: "grant_binding_mismatch" },
  );
  assert.equal(claimCalls, 0);
  assert.deepEqual(
    createAssessmentBrokerGrant(expected, "too-short", now),
    { ok: false, error: "grant_secret_unavailable" },
  );
  assert.deepEqual(
    createAssessmentBrokerGrant(expected, secret, now, 60_001),
    { ok: false, error: "grant_binding_invalid" },
  );
});

test("broker grant creation rejects an unrecognized profile", () => {
  const invalidProfile = {
    ...binding(),
    profileId: "caller-selected-shell" as AssessmentBrokerGrantBinding["profileId"],
  };
  assert.deepEqual(
    createAssessmentBrokerGrant(invalidProfile, secret, now),
    { ok: false, error: "grant_binding_invalid" },
  );
});

test("broker grant refuses mutable image references", () => {
  const mutableImage = {
    ...binding(),
    immutableImageId: "guardian-assessment:latest",
  };
  assert.deepEqual(
    createAssessmentBrokerGrant(
      mutableImage as AssessmentBrokerGrantBinding,
      secret,
      now,
    ),
    { ok: false, error: "grant_binding_invalid" },
  );
});

test("broker grant fails closed when durable one-use claim storage is unavailable", async () => {
  const expected = binding();
  const created = createAssessmentBrokerGrant(expected, secret, now);
  assert.equal(created.ok, true);
  if (!created.ok || !created.token) return assert.fail("grant_not_created");
  assert.deepEqual(
    await verifyAndConsumeAssessmentBrokerGrant(
      created.token,
      secret,
      expected,
      async () => {
        throw new Error("database unavailable");
      },
      now + 1,
    ),
    { ok: false, error: "grant_claim_unavailable" },
  );
});
