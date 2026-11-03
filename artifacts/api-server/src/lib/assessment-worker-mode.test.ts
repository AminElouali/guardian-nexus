import assert from "node:assert/strict";
import { test } from "node:test";
import { isLocalDockerWorkerAllowed } from "./ai-assessment-worker";

test("local Docker worker is disabled outside un-deployed development", () => {
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
    true,
  );
});
