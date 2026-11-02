import type { ChildProcess } from "node:child_process";
import { createAssessmentTimeout } from "./assessment-output-limit";

export type DockerControlResult = {
  exitCode: number | null;
  spawnError: boolean;
  timedOut: boolean;
  outputExceeded: boolean;
  stdout: string;
};

export type DockerControlSpawner = (args: string[]) => ChildProcess;

export type AssessmentContainerStopResult = {
  killExitCode: number | null;
  removeExitCode: number | null;
  residualContainerPresent: boolean | null;
  verifiedRemoved: boolean;
};

const MAX_CONTROL_STDOUT_BYTES = 4 * 1024;
export const DOCKER_CONTROL_TIMEOUT_MS = 3_000;
const SAFE_CONTAINER_NAME = /^guardian-ai-lab-[a-f0-9-]{36}$/;

export function runDockerControlCommand(
  args: string[],
  spawnDocker: DockerControlSpawner,
  timeoutMs = DOCKER_CONTROL_TIMEOUT_MS,
): Promise<DockerControlResult> {
  return new Promise((resolve) => {
    let stdout = "";
    let stdoutBytes = 0;
    let outputExceeded = false;
    let settled = false;
    let child: ChildProcess;

    const finish = (result: DockerControlResult) => {
      if (settled) return;
      settled = true;
      timeout.cancel();
      resolve(result);
    };

    try {
      child = spawnDocker(args);
    } catch {
      resolve({
        exitCode: null,
        spawnError: true,
        timedOut: false,
        outputExceeded: false,
        stdout: "",
      });
      return;
    }

    const timeout = createAssessmentTimeout(timeoutMs, () => {
      child.kill("SIGKILL");
    });

    child.stdout?.on("data", (chunk: Buffer) => {
      if (settled || outputExceeded) return;
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes > MAX_CONTROL_STDOUT_BYTES) {
        outputExceeded = true;
        stdout = "";
        child.kill("SIGKILL");
        return;
      }
      stdout += chunk.toString("utf8");
    });
    child.once("error", () => {
      finish({
        exitCode: null,
        spawnError: true,
        timedOut: timeout.timedOut,
        outputExceeded,
        stdout: "",
      });
    });
    child.once("close", (exitCode) => {
      finish({
        exitCode,
        spawnError: false,
        timedOut: timeout.timedOut,
        outputExceeded,
        stdout: outputExceeded ? "" : stdout,
      });
    });
  });
}

export async function stopAndVerifyAssessmentContainer(
  containerName: string,
  spawnDocker: DockerControlSpawner,
): Promise<AssessmentContainerStopResult> {
  if (!SAFE_CONTAINER_NAME.test(containerName)) {
    return {
      killExitCode: null,
      removeExitCode: null,
      residualContainerPresent: null,
      verifiedRemoved: false,
    };
  }

  const killResult = await runDockerControlCommand(
    ["kill", "--signal=KILL", containerName],
    spawnDocker,
  );
  const removeResult = await runDockerControlCommand(
    ["rm", "--force", containerName],
    spawnDocker,
  );
  const listResult = await runDockerControlCommand(
    [
      "ps",
      "-a",
      "--filter",
      `name=^/${containerName}$`,
      "--format",
      "{{.Names}}",
    ],
    spawnDocker,
  );
  const residualContainerPresent =
    listResult.exitCode === 0
      ? listResult.stdout.trim().split("\n").includes(containerName)
      : null;

  return {
    killExitCode: killResult.exitCode,
    removeExitCode: removeResult.exitCode,
    residualContainerPresent,
    verifiedRemoved: residualContainerPresent === false,
  };
}
