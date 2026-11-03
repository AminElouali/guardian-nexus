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

const submitted = await client.submitIntent({
  scenarioId: "finance.trusted_bank_change_approval",
  idempotencyKey: createIdempotencyKey(),
});
const result = await client.waitForJob(submitted.job.id, {
  intervalMs: 500,
  maxAttempts: 60,
});
console.log({ status: result.status, jobId: result.id });
