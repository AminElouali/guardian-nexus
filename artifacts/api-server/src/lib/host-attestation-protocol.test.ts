import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { test } from "node:test";
import {
  HOST_ATTESTATION_SUPERVISOR_ID,
  canonicalHostAttestationBytes,
  createHostAttestationChallenge,
  type HostAttestationChallenge,
  type HostAttestationNonceRepository,
  type HostAttestationPayload,
  type HostRuntimeIdentity,
} from "./host-attestation-protocol";
import {
  decideAssessmentWorkerAdmission,
  enqueueLocalAssessmentJob,
  getLocalWorkerAvailability,
} from "./assessment-worker-api-gate";

// TEST ONLY: generated in memory for contract tests; never provisioned or trusted
// by the production route or used as host-isolation evidence.
const testOnlyKeyPair = generateKeyPairSync("ed25519");
const runtimeIdentity: HostRuntimeIdentity = {
  runtimeCommit: "a".repeat(40),
  runtimeDigestSha256: "b".repeat(64),
};
const expectedApiIdentity = { uid: 1101, gid: 1101, groups: [1101] };
const workspaceId = "00000000-0000-4000-8000-000000000001";
const issuedByUserId = "user_test_only";
const fixedNow = new Date("2026-11-11T12:00:00.000Z");

class MemoryChallengeRepository implements HostAttestationNonceRepository {
  readonly rows = new Map<
    string,
    HostAttestationChallenge & {
      status: "issued" | "verified" | "rejected" | "expired";
      consumedAt: Date | null;
    }
  >();

  async insert(challenge: HostAttestationChallenge): Promise<void> {
    for (const row of this.rows.values()) {
      assert.notEqual(row.nonceSha256, challenge.nonceSha256);
    }
    this.rows.set(challenge.id, {
      ...challenge,
      status: "issued",
      consumedAt: null,
    });
  }

  async consume(input: {
    challengeId: string;
    workspaceId: string;
    now: Date;
  }) {
    const row = this.rows.get(input.challengeId);
    if (!row || row.workspaceId !== input.workspaceId) {
      return { kind: "missing" as const };
    }
    if (row.status !== "issued" || row.consumedAt) {
      return { kind: "replay" as const };
    }
    if (row.expiresAt <= input.now) {
      row.status = "expired";
      row.consumedAt = input.now;
      return { kind: "expired" as const };
    }
    return {
      kind: "consumed" as const,
      challenge: {
        id: row.id,
        workspaceId: row.workspaceId,
        nonceSha256: row.nonceSha256,
        runtimeCommit: row.runtimeCommit,
        runtimeDigestSha256: row.runtimeDigestSha256,
        issuedByUserId: row.issuedByUserId,
        issuedAt: row.issuedAt,
        expiresAt: row.expiresAt,
      },
    };
  }

  async finish(input: {
    challengeId: string;
    workspaceId: string;
    status: "verified" | "rejected";
    responseSha256: string;
    supervisorId: string | null;
    finishedAt: Date;
  }): Promise<void> {
    const row = this.rows.get(input.challengeId);
    if (
      !row ||
      row.workspaceId !== input.workspaceId ||
      row.status !== "issued" ||
      row.consumedAt
    ) {
      throw new Error("TEST_ONLY replay");
    }
    row.status = input.status;
    row.consumedAt = input.finishedAt;
  }
}

function makeHarness(options: {
  repository?: MemoryChallengeRepository;
  now?: () => Date;
  anchorAvailable?: () => boolean;
  currentRuntime?: () => HostRuntimeIdentity;
  currentApi?: () => typeof expectedApiIdentity;
} = {}) {
  const repository = options.repository ?? new MemoryChallengeRepository();
  const now = options.now ?? (() => new Date(fixedNow));
  const anchorAvailable = options.anchorAvailable ?? (() => true);
  const protocol = createHostAttestationChallenge({
    repository,
    loadTrustAnchor: () => {
      if (!anchorAvailable()) throw new Error("TEST_ONLY trust anchor absent");
      return {
        supervisorId: HOST_ATTESTATION_SUPERVISOR_ID,
        publicKey: testOnlyKeyPair.publicKey,
      };
    },
    getRuntimeIdentity: options.currentRuntime ?? (() => runtimeIdentity),
    getApiIdentity: options.currentApi ?? (() => expectedApiIdentity),
    now,
    createId: () => "00000000-0000-4000-8000-000000000002",
    createNonce: () => Buffer.alloc(32, 7).toString("base64url"),
  });
  return { protocol, repository };
}

function payloadFor(
  challenge: Awaited<ReturnType<ReturnType<typeof createHostAttestationChallenge>["issue"]>>,
): HostAttestationPayload {
  const apiIdentity = {
    uid: expectedApiIdentity.uid,
    gid: expectedApiIdentity.gid,
    groups: [...expectedApiIdentity.groups],
    databaseRole: "app_runtime",
  };
  const brokerIdentity = {
    uid: 2202,
    gid: 2202,
    groups: [2202, 3300],
    databaseRole: "app_ai_assessment_broker",
  };
  const workerIdentity = {
    uid: 3303,
    gid: 3303,
    groups: [3303],
    databaseRole: "app_ai_assessment_worker",
  };
  const serviceIdentities = {
    api: apiIdentity,
    broker: brokerIdentity,
    worker: workerIdentity,
  };
  const namespace = (prefix: string) => ({
    user: `${prefix}-user`,
    pid: `${prefix}-pid`,
    mount: `${prefix}-mount`,
    network: `${prefix}-network`,
  });
  const hardening = {
    noNewPrivileges: true as const,
    seccompEnforced: true as const,
    seccompProfileSha256: "c".repeat(64),
    capabilities: [] as never[],
    readOnlyRoot: true as const,
  };
  const session = (identity: (typeof serviceIdentities)["api"]) => ({
    databaseName: "guardian_lab_attestation_test",
    role: identity.databaseRole,
    superuser: false as const,
    bypassRls: false as const,
  });
  return {
    schemaVersion: 1,
    attestationType: "guardian_host_challenge_response",
    supervisorId: HOST_ATTESTATION_SUPERVISOR_ID,
    workspaceId,
    challengeId: challenge.id,
    nonce: challenge.nonce,
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt,
    runtimeCommit: challenge.runtimeCommit,
    runtimeDigestSha256: challenge.runtimeDigestSha256,
    serviceIdentities,
    claims: {
      namespaces: {
        api: namespace("api"),
        broker: namespace("broker"),
        worker: namespace("worker"),
      },
      processHardening: {
        api: hardening,
        broker: hardening,
        worker: hardening,
      },
      dockerSocket: {
        groupGid: 3300,
        apiAccess: "denied",
        brokerAccess: "allowed",
        workerAccess: "denied",
        mountedIntoApi: false,
        mountedIntoWorker: false,
      },
      inheritedFileDescriptors: {
        api: [],
        broker: [],
        worker: [],
      },
      databaseSessions: {
        api: session(apiIdentity),
        broker: session(brokerIdentity),
        worker: session(workerIdentity),
      },
      workerNetworkEgressDenied: true,
    },
  };
}

function signedEnvelope(payload: HostAttestationPayload) {
  return {
    payload,
    signatureBase64: sign(
      null,
      canonicalHostAttestationBytes(payload),
      testOnlyKeyPair.privateKey,
    ).toString("base64"),
  };
}

test("TEST ONLY valid signed challenge is recorded but never enables runtime gates", async () => {
  const { protocol } = makeHarness();
  const challenge = await protocol.issue({ workspaceId, issuedByUserId });
  const result = await protocol.respond({
    workspaceId,
    challengeId: challenge.id,
    envelope: signedEnvelope(payloadFor(challenge)),
  });

  assert.equal(result.attestationStatus, "verified");
  assert.equal(result.hostBoundaryReady, false);
  assert.equal(result.integratedAssessmentReady, false);
  assert.equal(result.workerAdmission, "disabled");
  assert.equal(getLocalWorkerAvailability().status, "disabled");
  assert.deepEqual(
    decideAssessmentWorkerAdmission("guardian-local-llm-qwen3-0.6b-v1"),
    {
      admitted: false,
      reasonCode: "assessment_broker_identity_unverified",
    },
  );
  assert.equal(
    enqueueLocalAssessmentJob({
      jobId: "test-only",
      workspaceId,
      actorUserId: issuedByUserId,
    }),
    false,
  );
});

test("TEST ONLY worker-supplied public key is rejected and cannot change readiness", async () => {
  const { protocol, repository } = makeHarness();
  const challenge = await protocol.issue({ workspaceId, issuedByUserId });
  const envelope = {
    ...signedEnvelope(payloadFor(challenge)),
    publicKey: "TEST ONLY worker-controlled key",
  };
  const result = await protocol.respond({
    workspaceId,
    challengeId: challenge.id,
    envelope,
  });

  assert.equal(result.attestationStatus, "rejected");
  assert.equal(result.reasonCode, "assessment_host_response_invalid");
  assert.equal(result.hostBoundaryReady, false);
  assert.equal(result.integratedAssessmentReady, false);
  assert.equal(result.workerAdmission, "disabled");
  assert.equal(repository.rows.get(challenge.id)?.status, "issued");
  assert.equal(getLocalWorkerAvailability().status, "disabled");
});

test("TEST ONLY altered signature is rejected and consumes its one-use challenge", async () => {
  const { protocol, repository } = makeHarness();
  const challenge = await protocol.issue({ workspaceId, issuedByUserId });
  const envelope = signedEnvelope(payloadFor(challenge));
  envelope.signatureBase64 = Buffer.alloc(64, 2).toString("base64");
  const result = await protocol.respond({
    workspaceId,
    challengeId: challenge.id,
    envelope,
  });
  assert.equal(result.attestationStatus, "rejected");
  assert.equal(result.reasonCode, "assessment_host_signature_invalid");
  assert.equal(repository.rows.get(challenge.id)?.status, "rejected");
  assert.equal(result.hostBoundaryReady, false);
});

test("TEST ONLY challenge replay is rejected after the first response", async () => {
  const { protocol } = makeHarness();
  const challenge = await protocol.issue({ workspaceId, issuedByUserId });
  const envelope = signedEnvelope(payloadFor(challenge));
  const first = await protocol.respond({
    workspaceId,
    challengeId: challenge.id,
    envelope,
  });
  const replay = await protocol.respond({
    workspaceId,
    challengeId: challenge.id,
    envelope,
  });
  assert.equal(first.attestationStatus, "verified");
  assert.equal(replay.attestationStatus, "replay_rejected");
  assert.equal(replay.hostBoundaryReady, false);
});

test("TEST ONLY expired durable challenge is rejected before signature acceptance", async () => {
  let clock = new Date(fixedNow);
  const { protocol, repository } = makeHarness({ now: () => new Date(clock) });
  const challenge = await protocol.issue({ workspaceId, issuedByUserId });
  clock = new Date(Date.parse(challenge.expiresAt) + 1);
  const result = await protocol.respond({
    workspaceId,
    challengeId: challenge.id,
    envelope: signedEnvelope(payloadFor(challenge)),
  });
  assert.equal(result.attestationStatus, "expired");
  assert.equal(repository.rows.get(challenge.id)?.status, "expired");
  assert.equal(result.integratedAssessmentReady, false);
});

test("TEST ONLY stale commit and runtime digest are rejected even when re-signed", async (t) => {
  for (const [field, staleValue] of [
    ["runtimeCommit", "d".repeat(40)],
    ["runtimeDigestSha256", "e".repeat(64)],
  ] as const) {
    await t.test(`${field} mismatch`, async () => {
      const { protocol } = makeHarness();
      const challenge = await protocol.issue({ workspaceId, issuedByUserId });
      const payload = payloadFor(challenge);
      payload[field] = staleValue;
      const result = await protocol.respond({
        workspaceId,
        challengeId: challenge.id,
        envelope: signedEnvelope(payload),
      });
      assert.equal(result.attestationStatus, "rejected");
      assert.equal(
        result.reasonCode,
        "assessment_host_runtime_binding_mismatch",
      );
      assert.equal(result.hostBoundaryReady, false);
    });
  }
});

test("TEST ONLY shared and mismatched service identities fail closed", async (t) => {
  await t.test("shared uid/gid/role", async () => {
    const { protocol } = makeHarness();
    const challenge = await protocol.issue({ workspaceId, issuedByUserId });
    const payload = payloadFor(challenge);
    payload.serviceIdentities.broker.uid = payload.serviceIdentities.api.uid;
    payload.serviceIdentities.broker.gid = payload.serviceIdentities.api.gid;
    payload.serviceIdentities.broker.databaseRole =
      payload.serviceIdentities.api.databaseRole;
    payload.claims.databaseSessions.broker.role =
      payload.serviceIdentities.broker.databaseRole;
    const result = await protocol.respond({
      workspaceId,
      challengeId: challenge.id,
      envelope: signedEnvelope(payload),
    });
    assert.equal(result.reasonCode, "assessment_host_identities_not_separate");
  });

  await t.test("API uid does not match the current process", async () => {
    const { protocol } = makeHarness();
    const challenge = await protocol.issue({ workspaceId, issuedByUserId });
    const payload = payloadFor(challenge);
    payload.serviceIdentities.api.uid = 9999;
    const result = await protocol.respond({
      workspaceId,
      challengeId: challenge.id,
      envelope: signedEnvelope(payload),
    });
    assert.equal(result.reasonCode, "assessment_host_api_identity_mismatch");
    assert.equal(result.hostBoundaryReady, false);
  });
});

test("TEST ONLY absent external trust anchor blocks issue and verification", async () => {
  const repository = new MemoryChallengeRepository();
  let anchorAvailable = false;
  const { protocol } = makeHarness({
    repository,
    anchorAvailable: () => anchorAvailable,
  });
  await assert.rejects(
    protocol.issue({ workspaceId, issuedByUserId }),
    /assessment_host_attestation_prerequisite_unavailable/,
  );
  assert.equal(repository.rows.size, 0);

  anchorAvailable = true;
  const challenge = await protocol.issue({ workspaceId, issuedByUserId });
  anchorAvailable = false;
  const result = await protocol.respond({
    workspaceId,
    challengeId: challenge.id,
    envelope: signedEnvelope(payloadFor(challenge)),
  });
  assert.equal(result.attestationStatus, "prerequisite_unavailable");
  assert.equal(result.hostBoundaryReady, false);
  assert.equal(repository.rows.get(challenge.id)?.status, "issued");
  assert.equal(getLocalWorkerAvailability().status, "disabled");
});

test("TEST ONLY incomplete claims are rejected without recording a readiness change", async () => {
  const { protocol, repository } = makeHarness();
  const challenge = await protocol.issue({ workspaceId, issuedByUserId });
  const payload = payloadFor(challenge) as unknown as Record<string, unknown>;
  delete (payload.claims as Record<string, unknown>).workerNetworkEgressDenied;
  const result = await protocol.respond({
    workspaceId,
    challengeId: challenge.id,
    envelope: signedEnvelope(payload as unknown as HostAttestationPayload),
  });
  assert.equal(result.attestationStatus, "rejected");
  assert.equal(result.reasonCode, "assessment_host_response_invalid");
  assert.equal(repository.rows.get(challenge.id)?.status, "issued");
  assert.equal(result.hostBoundaryReady, false);
  assert.equal(result.integratedAssessmentReady, false);
});

test("TEST ONLY unsupported socket and privilege claims fail closed", async (t) => {
  for (const mutate of [
    (payload: HostAttestationPayload) => {
      (payload.claims.dockerSocket as unknown as Record<string, unknown>).apiAccess =
        "allowed";
    },
    (payload: HostAttestationPayload) => {
      (
        payload.claims.processHardening.api as unknown as Record<
          string,
          unknown
        >
      ).noNewPrivileges = false;
    },
  ]) {
    await t.test("unsupported isolation claim is rejected", async () => {
      const { protocol, repository } = makeHarness();
      const challenge = await protocol.issue({ workspaceId, issuedByUserId });
      const payload = payloadFor(challenge);
      mutate(payload);
      const result = await protocol.respond({
        workspaceId,
        challengeId: challenge.id,
        envelope: signedEnvelope(payload),
      });
      assert.equal(result.attestationStatus, "rejected");
      assert.equal(result.reasonCode, "assessment_host_response_invalid");
      assert.equal(result.hostBoundaryReady, false);
      assert.equal(repository.rows.get(challenge.id)?.status, "issued");
    });
  }
});

test("TEST ONLY challenge issue uses a one-use 256-bit URL-safe nonce and short expiry", async () => {
  const { protocol, repository } = makeHarness();
  const challenge = await protocol.issue({ workspaceId, issuedByUserId });
  assert.match(challenge.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(
    Date.parse(challenge.expiresAt) - Date.parse(challenge.issuedAt),
    2 * 60 * 1000,
  );
  assert.equal(repository.rows.get(challenge.id)?.nonceSha256.length, 64);
});

test("TEST ONLY production nonce default uses fresh cryptographic values", async () => {
  const protocol = createHostAttestationChallenge({
    repository: new MemoryChallengeRepository(),
    loadTrustAnchor: () => ({
      supervisorId: HOST_ATTESTATION_SUPERVISOR_ID,
      publicKey: testOnlyKeyPair.publicKey,
    }),
    getRuntimeIdentity: () => runtimeIdentity,
    getApiIdentity: () => expectedApiIdentity,
    now: () => new Date(fixedNow),
  });
  const first = await protocol.issue({ workspaceId, issuedByUserId });
  const second = await protocol.issue({ workspaceId, issuedByUserId });
  assert.match(first.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.match(second.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first.nonce, second.nonce);
});
