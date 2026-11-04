import assert from "node:assert/strict";
import { test } from "node:test";
import { isLocalDockerWorkerAllowed } from "./ai-assessment-worker";
import { QWEN_POLICY_LAB_PROFILE_IDS } from "./ai-assessment-sandbox";
import {
  enqueueLocalAssessmentJob,
  getLocalWorkerAvailability,
} from "./assessment-worker-api-gate";
import { evaluateAssessmentBrokerBoundary } from "./assessment-broker-boundary";

test("API cannot enable the local Docker worker by selecting development mode", () => {
  assert.equal(
    isLocalDockerWorkerAllowed({
      NODE_ENV: "production",
      REPLIT_DEPLOYMENT: undefined,
    }),
    false,
  );
  assert.equal(
    isLocalDockerWorkerAllowed({
      NODE_ENV: "development",
      REPLIT_DEPLOYMENT: "1",
    }),
    false,
  );
  assert.equal(
    isLocalDockerWorkerAllowed({
      NODE_ENV: "test",
      REPLIT_DEPLOYMENT: undefined,
    }),
    false,
  );
  assert.equal(
    isLocalDockerWorkerAllowed({
      NODE_ENV: "development",
      REPLIT_DEPLOYMENT: undefined,
    }),
    false,
  );
});

test("API gate remains unavailable and cannot enqueue without a verified broker", () => {
  const availability = getLocalWorkerAvailability();
  assert.equal(availability.status, "disabled");
  assert.equal(availability.reasonCode, "assessment_broker_identity_unverified");
  assert.ok(availability.profiles.length >= 8);
  assert.ok(availability.profiles.every((profile) => profile.status === "disabled"));
  for (const profileId of QWEN_POLICY_LAB_PROFILE_IDS) {
    const profile = availability.profiles.find(
      (candidate) => candidate.profileId === profileId,
    );
    assert.ok(profile, `Qwen profile remains registered: ${profileId}`);
    assert.equal(profile.engine, "guardian_qwen_policy_lab");
    assert.equal(profile.status, "disabled");
    assert.equal(
      profile.reasonCode,
      "assessment_broker_identity_unverified",
      "Qwen remains fail-closed until the isolated broker is verified",
    );
  }
  assert.equal(
    enqueueLocalAssessmentJob({
      jobId: "00000000-0000-4000-8000-000000000001",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      actorUserId: "00000000-0000-4000-8000-000000000003",
    }),
    false,
  );
});

const isolatedBrokerInput = {
  processRole: "assessment-broker",
  processUid: 2001,
  processGroups: [2001, 3001],
  apiUid: 1000,
  apiGroups: [1000],
  brokerUid: 2001,
  socket: { isSocket: true, uid: 0, gid: 3001, mode: 0o660 },
  brokerDatabaseIdentityVerified: true,
};

test("broker boundary accepts only distinct identities with isolated Docker and DB access", () => {
  assert.deepEqual(
    evaluateAssessmentBrokerBoundary(isolatedBrokerInput),
    { allowed: true, reasonCode: null },
  );
});

test("broker boundary rejects shared UID, API socket access, missing socket, and unverified DB identity", () => {
  assert.equal(
    evaluateAssessmentBrokerBoundary({
      ...isolatedBrokerInput,
      processUid: 1000,
      brokerUid: 1000,
    }).reasonCode,
    "assessment_broker_shared_uid",
  );
  assert.equal(
    evaluateAssessmentBrokerBoundary({
      ...isolatedBrokerInput,
      apiGroups: [1000, 3001],
    }).reasonCode,
    "assessment_api_can_access_docker",
  );
  assert.equal(
    evaluateAssessmentBrokerBoundary({
      ...isolatedBrokerInput,
      socket: null,
    }).reasonCode,
    "assessment_docker_socket_unverified",
  );
  assert.equal(
    evaluateAssessmentBrokerBoundary({
      ...isolatedBrokerInput,
      brokerDatabaseIdentityVerified: false,
    }).reasonCode,
    "assessment_broker_database_identity_unverified",
  );
});
