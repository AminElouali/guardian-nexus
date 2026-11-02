import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import {
  ASSESSMENT_EXECUTION_LIMITS,
  parseAssessmentImageLock,
  validateAssessmentImageInspection,
  verifyAssessmentImageLockSources,
} from "./ai-assessment-sandbox";
import {
  stopAndVerifyAssessmentContainer,
  type DockerControlSpawner,
} from "./assessment-container-control";
import {
  classifyAssessmentExecutionFailure,
  createAssessmentOutputCapture,
  createAssessmentTimeout,
} from "./assessment-output-limit";

const workerRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../workers/guardian-ai-assessment",
);
const repoRoot = resolve(workerRoot, "../..");
const evidencePath = resolve(
  repoRoot,
  "generated-artifacts/guardian-ai-assessment/container-hardening-integration.json",
);
const lock = parseAssessmentImageLock(
  JSON.parse(
    readFileSync(resolve(workerRoot, "profile-image-lock.json"), "utf8"),
  ) as unknown,
);
const dockerConfig = mkdtempSync(join(tmpdir(), "guardian-test-docker-config-"));
chmodSync(dockerConfig, 0o700);
const dockerEnv: NodeJS.ProcessEnv = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  HOME: "/tmp",
  DOCKER_CONFIG: dockerConfig,
};
const dockerSpawner: DockerControlSpawner = (args) =>
  spawn("docker", args, {
    stdio: ["ignore", "pipe", "ignore"],
    env: dockerEnv,
  });
const MAX_STDOUT_BYTES = ASSESSMENT_EXECUTION_LIMITS.maxStdoutBytes;

after(() => {
  rmSync(dockerConfig, { recursive: true, force: true });
});

function runDockerSync(args: string[]) {
  return spawnSync("docker", args, {
    encoding: "utf8",
    timeout: 3_000,
    maxBuffer: 16 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
    env: dockerEnv,
  });
}

function assertNoResidualContainer(containerName: string): void {
  const inspect = runDockerSync(["container", "inspect", containerName]);
  const listed = runDockerSync([
    "ps",
    "-a",
    "--filter",
    `name=^/${containerName}$`,
    "--format",
    "{{.Names}}",
  ]);
  assert.equal(listed.status, 0, "docker ps verification must succeed");
  assert.equal(listed.stdout.trim(), "", "no container may remain");
  assert.notEqual(inspect.status, 0, "docker inspect must report removed container");
}

type ProbeResult = {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  outputExceeded: boolean;
  outputBytesAtLeast: number;
  retainedOutputBytes: number;
  stopRequested: boolean;
  stopVerified: boolean;
  elapsedMs: number;
};

async function runPinnedProbe(
  containerName: string,
  script: string,
  timeoutMs: number,
): Promise<ProbeResult> {
  const imageId = lock.images.qwen.imageId;
  const child = spawn(
    "docker",
    [
      "run",
      "--rm",
      "--init",
      "--pull=never",
      `--name=${containerName}`,
      "--network=none",
      "--read-only",
      "--pids-limit=64",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "--user=65532:65532",
      "--log-driver=none",
      "--cpus=1",
      "--memory=256m",
      "--memory-swap=256m",
      "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
      "--entrypoint=python",
      imageId,
      "-B",
      "-c",
      script,
    ],
    {
      stdio: ["ignore", "pipe", "ignore"],
      env: dockerEnv,
    },
  );
  const startedAt = Date.now();
  let stopRequested = false;
  let stopPromise: Promise<Awaited<ReturnType<typeof stopAndVerifyAssessmentContainer>>> | undefined;
  const requestStop = () => {
    if (!stopPromise) {
      stopRequested = true;
      stopPromise = stopAndVerifyAssessmentContainer(
        containerName,
        dockerSpawner,
      );
    }
    child.kill("SIGKILL");
  };
  const output = createAssessmentOutputCapture(MAX_STDOUT_BYTES, requestStop);
  const timeout = createAssessmentTimeout(timeoutMs, requestStop);

  return new Promise((resolve, reject) => {
    child.stdout.on("data", (chunk: Buffer) => output.recordChunk(chunk));
    child.once("error", () => {
      timeout.cancel();
      reject(new Error("test_docker_run_spawn_failed"));
    });
    child.once("close", async (exitCode, signal) => {
      timeout.cancel();
      const stopResult = stopPromise
        ? await stopPromise
        : {
            killExitCode: null,
            removeExitCode: null,
            residualContainerPresent: null,
            verifiedRemoved: false,
          };
      resolve({
        exitCode,
        signal,
        timedOut: timeout.timedOut,
        outputExceeded: output.exceeded,
        outputBytesAtLeast: output.bytesReceived,
        retainedOutputBytes: Buffer.byteLength(output.output),
        stopRequested,
        stopVerified: stopResult.verifiedRemoved,
        elapsedMs: Date.now() - startedAt,
      });
    });
  });
}

test(
  "pinned local container fails closed on real stdout overflow and timeout, then is absent",
  { timeout: 30_000 },
  async () => {
    assert.equal(process.env.NODE_ENV, "development");
    assert.notEqual(process.env.REPLIT_DEPLOYMENT, "1");
    assert.equal(
      verifyAssessmentImageLockSources(lock, workerRoot),
      true,
      "profile image lock must match its local Dockerfile sources",
    );

    const inspected = runDockerSync([
      "image",
      "inspect",
      "--format",
      "{{json .}}",
      lock.images.qwen.imageId,
    ]);
    assert.equal(inspected.status, 0, "locked image must exist locally");
    const imageInspection = JSON.parse(inspected.stdout) as Parameters<
      typeof validateAssessmentImageInspection
    >[1];
    assert.ok(imageInspection, "image inspect must return an object");
    assert.equal(imageInspection.Id, lock.images.qwen.imageId);
    assert.equal(
      validateAssessmentImageInspection(
        "guardian-local-llm-qwen3-0.6b-v1",
        imageInspection,
        lock,
      ).ok,
      true,
      "test image identity and profile labels must verify",
    );

    const overflowName = `guardian-ai-lab-${randomUUID()}`;
    let overflow: ProbeResult | undefined;
    try {
      overflow = await runPinnedProbe(
        overflowName,
        'import sys,time; sys.stdout.buffer.write(b"Z"*65537); sys.stdout.flush(); time.sleep(30)',
        8_000,
      );
      assert.equal(overflow.outputExceeded, true);
      assert.equal(overflow.timedOut, false);
      assert.equal(overflow.stopRequested, true);
      assert.equal(overflow.stopVerified, true);
      assert.notEqual(overflow.exitCode, 0);
      assert.ok(overflow.elapsedMs < 8_000);
      assert.ok(overflow.retainedOutputBytes <= MAX_STDOUT_BYTES);
      assert.equal(
        classifyAssessmentExecutionFailure({
          timedOut: overflow.timedOut,
          outputExceeded: overflow.outputExceeded,
          exitCode: overflow.exitCode,
        }),
        "worker_output_limit_exceeded",
      );
      assertNoResidualContainer(overflowName);
    } finally {
      await stopAndVerifyAssessmentContainer(overflowName, dockerSpawner);
    }

    const timeoutName = `guardian-ai-lab-${randomUUID()}`;
    let timeoutResult: ProbeResult | undefined;
    try {
      timeoutResult = await runPinnedProbe(
        timeoutName,
        "import time; time.sleep(30)",
        750,
      );
      assert.equal(timeoutResult.outputExceeded, false);
      assert.equal(timeoutResult.timedOut, true);
      assert.equal(timeoutResult.stopRequested, true);
      assert.equal(timeoutResult.stopVerified, true);
      assert.notEqual(timeoutResult.exitCode, 0);
      assert.ok(timeoutResult.elapsedMs < 8_000);
      assert.equal(timeoutResult.retainedOutputBytes, 0);
      assert.equal(
        classifyAssessmentExecutionFailure({
          timedOut: timeoutResult.timedOut,
          outputExceeded: timeoutResult.outputExceeded,
          exitCode: timeoutResult.exitCode,
        }),
        "worker_timeout",
      );
      assertNoResidualContainer(timeoutName);
    } finally {
      await stopAndVerifyAssessmentContainer(timeoutName, dockerSpawner);
    }

    const evidence = {
      schemaVersion: 1,
      imageId: lock.images.qwen.imageId,
      network: "none",
      user: "65532:65532",
      resourceLimits: {
        cpu: "1",
        memory: "256m",
        pids: 64,
        stdoutBytes: MAX_STDOUT_BYTES,
      },
      overflow,
      timeout: timeoutResult,
      rawOutputPersisted: false,
      createdAt: new Date().toISOString(),
    };
    mkdirSync(dirname(evidencePath), { recursive: true });
    writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, {
      mode: 0o600,
    });
    const evidenceHash = createHash("sha256")
      .update(readFileSync(evidencePath))
      .digest("hex");
    assert.match(evidenceHash, /^[a-f0-9]{64}$/);
  },
);
