import {
  createIdempotencyKey,
  GuardianNexusClient,
} from "@workspace/guardian-agent-sdk";

// The embedding application supplies its existing session-token callback.
declare const getHostSessionAccessToken: () => Promise<string | null>;

const client = new GuardianNexusClient({
  baseUrl: "http://127.0.0.1:3000",
  workspaceId: "123e4567-e89b-42d3-a456-426614174000",
  getAccessToken: getHostSessionAccessToken,
});

const submitted = await client.submitQwenEvaluation({
  profileId: "guardian-agent-qwen-lab-email-v1",
  idempotencyKey: createIdempotencyKey(),
});
const result = await client.waitForQwenEvaluation(
  submitted.job.id,
  submitted.job.profileId,
  {
    intervalMs: 2_000,
    maxAttempts: 120,
  },
);
console.log({
  status: result.job.status,
  profile: result.report.verticalId,
  decisions: result.report.counts,
  evidenceSha256: result.report.evidenceSha256,
});
