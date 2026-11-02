import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import {
  runDockerControlCommand,
  stopAndVerifyAssessmentContainer,
  type DockerControlSpawner,
} from "./assessment-container-control";

const containerName =
  "guardian-ai-lab-12345678-1234-1234-1234-123456789abc";

type FakeChild = ChildProcess & {
  stdout: PassThrough;
  kill: (signal?: NodeJS.Signals) => boolean;
};

function fakeChild(options: {
  output?: Buffer;
  exitCode?: number | null;
  emitError?: boolean;
  neverClose?: boolean;
} = {}): FakeChild {
  const child = new EventEmitter() as FakeChild;
  child.stdout = new PassThrough();
  child.kill = () => {
    if (!options.neverClose) {
      queueMicrotask(() => child.emit("close", null, "SIGKILL"));
    }
    return true;
  };
  queueMicrotask(() => {
    if (options.emitError) {
      child.emit("error", new Error("test spawn failure"));
      return;
    }
    if (options.neverClose) return;
    if (options.output) child.stdout.write(options.output);
    child.stdout.end();
    child.emit("close", options.exitCode ?? 0, null);
  });
  return child;
}

function sequenceSpawner(
  responses: Array<{
    args: string[];
    child: FakeChild;
  }>,
  captured: string[][] = [],
): DockerControlSpawner {
  let index = 0;
  return (args) => {
    captured.push(args);
    const response = responses[index++];
    assert.ok(response, `unexpected Docker control call: ${args.join(" ")}`);
    assert.deepEqual(args, response.args);
    return response.child;
  };
}

test("container cleanup kills, removes, and confirms absence by exact name", async () => {
  const calls: string[][] = [];
  const result = await stopAndVerifyAssessmentContainer(
    containerName,
    sequenceSpawner(
      [
        {
          args: ["kill", "--signal=KILL", containerName],
          child: fakeChild({ exitCode: 0 }),
        },
        {
          args: ["rm", "--force", containerName],
          child: fakeChild({ exitCode: 0 }),
        },
        {
          args: [
            "ps",
            "-a",
            "--filter",
            `name=^/${containerName}$`,
            "--format",
            "{{.Names}}",
          ],
          child: fakeChild({ output: Buffer.from("") }),
        },
      ],
      calls,
    ),
  );

  assert.equal(result.killExitCode, 0);
  assert.equal(result.removeExitCode, 0);
  assert.equal(result.residualContainerPresent, false);
  assert.equal(result.verifiedRemoved, true);
  assert.equal(calls.length, 3);
});

test("cleanup fails closed when a residual container remains or Docker control fails", async () => {
  const residual = await stopAndVerifyAssessmentContainer(
    containerName,
    sequenceSpawner([
      {
        args: ["kill", "--signal=KILL", containerName],
        child: fakeChild({ exitCode: 1 }),
      },
      {
        args: ["rm", "--force", containerName],
        child: fakeChild({ exitCode: 1 }),
      },
      {
        args: [
          "ps",
          "-a",
          "--filter",
          `name=^/${containerName}$`,
          "--format",
          "{{.Names}}",
        ],
        child: fakeChild({ output: Buffer.from(`${containerName}\n`) }),
      },
    ]),
  );
  assert.equal(residual.residualContainerPresent, true);
  assert.equal(residual.verifiedRemoved, false);

  const failed = await stopAndVerifyAssessmentContainer(
    containerName,
    sequenceSpawner([
      {
        args: ["kill", "--signal=KILL", containerName],
        child: fakeChild({ emitError: true }),
      },
      {
        args: ["rm", "--force", containerName],
        child: fakeChild({ exitCode: 1 }),
      },
      {
        args: [
          "ps",
          "-a",
          "--filter",
          `name=^/${containerName}$`,
          "--format",
          "{{.Names}}",
        ],
        child: fakeChild({ exitCode: 1 }),
      },
    ]),
  );
  assert.equal(failed.residualContainerPresent, null);
  assert.equal(failed.verifiedRemoved, false);
});

test("container cleanup rejects unsafe names without invoking Docker", async () => {
  let calls = 0;
  const result = await stopAndVerifyAssessmentContainer(
    "guardian-ai-lab-$(id)",
    () => {
      calls += 1;
      return fakeChild();
    },
  );
  assert.equal(result.verifiedRemoved, false);
  assert.equal(calls, 0);
});

test("Docker control command has a hard deadline even if the child never closes", async () => {
  const child = fakeChild({ neverClose: true });
  const result = await runDockerControlCommand(["ps"], () => child, 10);
  assert.equal(result.timedOut, true);
  assert.equal(result.exitCode, null);
  assert.equal(result.stdout, "");
});

test("Docker control output is bounded and discarded after overflow", async () => {
  const child = fakeChild({ output: Buffer.alloc(4 * 1024 + 1, "X") });
  const result = await runDockerControlCommand(["ps"], () => child, 100);
  assert.equal(result.outputExceeded, true);
  assert.equal(result.stdout, "");
});
