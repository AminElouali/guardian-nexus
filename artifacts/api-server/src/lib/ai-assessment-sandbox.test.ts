import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  ASSESSMENT_EXECUTION_LIMITS,
  getAssessmentImageReference,
  launchWithPinnedAssessmentImage,
  parseAssessmentImageLock,
  validateAssessmentImageInspection,
  verifyAssessmentImageLockSources,
  type AssessmentImageLock,
  type DockerImageInspection,
} from "./ai-assessment-sandbox";

const workerRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../workers/guardian-ai-assessment",
);
const lock = parseAssessmentImageLock(
  JSON.parse(
    readFileSync(resolve(workerRoot, "profile-image-lock.json"), "utf8"),
  ) as unknown,
);

function inspection(key: "garak" | "qwen"): DockerImageInspection {
  return {
    Id: lock.images[key].imageId,
    Config: { Labels: { ...lock.images[key].labels } },
  };
}

const mounts = {
  modelPath: "/workspace/Qwen3-0.6B-Q8_0.gguf",
  wheelhousePath: "/workspace/wheelhouse",
  manifestPath: "/workspace/local-llm-manifest.json",
  sourcePath: "/workspace/guardian_ai_assessment",
};

test("profile lock is local-only, source-hash checked, and binds exact image IDs and OCI labels", () => {
  assert.equal(lock.provenance.signedAttestation, false);
  assert.equal(verifyAssessmentImageLockSources(lock, workerRoot), true);
  assert.equal(
    getAssessmentImageReference("guardian-local-agent-v1", lock),
    "guardian-ai-assessment:garak-gve-profile-candidate",
  );
  assert.equal(
    getAssessmentImageReference("guardian-local-llm-qwen3-0.6b-v1", lock),
    "guardian-ai-assessment:qwen-gve-profile-candidate",
  );
  assert.equal(
    validateAssessmentImageInspection(
      "guardian-local-agent-v1",
      inspection("garak"),
      lock,
    ).ok,
    true,
  );
  assert.equal(
    validateAssessmentImageInspection(
      "guardian-local-llm-qwen3-0.6b-v1",
      inspection("qwen"),
      lock,
    ).ok,
    true,
  );
});

test("wrong, retagged, and missing image identity or labels fail before Docker run", () => {
  let runCalls = 0;
  const run = (args: string[]) => {
    runCalls += 1;
    return args;
  };

  const requestInspection = inspection("qwen");
  assert.equal(
    validateAssessmentImageInspection(
      "guardian-local-llm-qwen3-0.6b-v1",
      requestInspection,
      lock,
    ).ok,
    true,
  );
  const retaggedAtRequest = {
    ...inspection("qwen"),
    Id: lock.images.garak.imageId,
  };
  assert.deepEqual(
    validateAssessmentImageInspection(
      "guardian-local-llm-qwen3-0.6b-v1",
      retaggedAtRequest,
      lock,
    ),
    { ok: false, reasonCode: "worker_image_identity_mismatch" },
  );
  assert.deepEqual(
    validateAssessmentImageInspection(
      "guardian-local-llm-qwen3-0.6b-v1",
      undefined,
      lock,
    ),
    { ok: false, reasonCode: "worker_image_identity_mismatch" },
  );

  const retaggedBetweenRequestAndExecution = {
    ...inspection("qwen"),
    Id: lock.images.garak.imageId,
  };
  assert.throws(
    () =>
      launchWithPinnedAssessmentImage(
        "guardian-local-llm-qwen3-0.6b-v1",
        "guardian-ai-lab-00000000-0000-4000-8000-000000000001",
        retaggedBetweenRequestAndExecution,
        lock,
        mounts,
        run,
      ),
    /worker_image_identity_mismatch/,
  );
  assert.equal(runCalls, 0, "no docker run callback occurs on digest mismatch");

  const wrongLabel = inspection("qwen");
  wrongLabel.Config!.Labels!["org.guardian.profile"] = "garak-gve-v1";
  assert.throws(
    () =>
      launchWithPinnedAssessmentImage(
        "guardian-local-llm-qwen3-0.6b-v1",
        "guardian-ai-lab-00000000-0000-4000-8000-000000000001",
        wrongLabel,
        lock,
        mounts,
        run,
      ),
    /worker_image_profile_mismatch/,
  );
  assert.equal(runCalls, 0);

  const missingLabel = inspection("garak");
  delete missingLabel.Config!.Labels!["org.guardian.engine"];
  assert.throws(
    () =>
      launchWithPinnedAssessmentImage(
        "guardian-local-agent-v1",
        "guardian-ai-lab-00000000-0000-4000-8000-000000000002",
        missingLabel,
        lock,
        mounts,
        run,
      ),
    /worker_image_profile_mismatch/,
  );
  assert.equal(runCalls, 0);
});

test("a tag change after inspection cannot change the immutable image passed to Docker", () => {
  let localTagNow = lock.images.garak.reference;
  let capturedArgs: string[] | undefined;
  const result = launchWithPinnedAssessmentImage(
    "guardian-local-agent-v1",
    "guardian-ai-lab-00000000-0000-4000-8000-000000000003",
    inspection("garak"),
    lock,
    mounts,
    (args) => {
      localTagNow = lock.images.qwen.reference;
      capturedArgs = args;
      return "started";
    },
  );

  assert.equal(result, "started");
  assert.notEqual(localTagNow, lock.images.garak.reference);
  assert.equal(capturedArgs?.at(-1), lock.images.garak.imageId);
  assert.notEqual(capturedArgs?.at(-1), localTagNow);
});

test("Garak and Qwen Docker argument contracts retain isolation and profile-specific limits", () => {
  const garakArgs = launchWithPinnedAssessmentImage(
    "guardian-local-agent-v1",
    "guardian-ai-lab-00000000-0000-4000-8000-000000000004",
    inspection("garak"),
    lock,
    mounts,
    (args) => args,
  );
  const qwenArgs = launchWithPinnedAssessmentImage(
    "guardian-local-llm-native-tools-v1",
    "guardian-ai-lab-00000000-0000-4000-8000-000000000005",
    inspection("qwen"),
    lock,
    mounts,
    (args) => args,
  );

  for (const args of [garakArgs, qwenArgs]) {
    assert.ok(args.includes("--network=none"));
    assert.ok(args.includes("--read-only"));
    assert.ok(args.includes("--pids-limit=64"));
    assert.ok(args.includes("--cap-drop=ALL"));
    assert.ok(args.includes("--security-opt=no-new-privileges"));
    assert.ok(args.includes("--user=65532:65532"));
    assert.ok(args.includes("--pull=never"));
    assert.equal(args.includes("--security-opt=seccomp=unconfined"), false);
    assert.equal(args.some((arg) => arg.includes("/var/run/docker.sock")), false);
  }

  assert.ok(garakArgs.includes("--cpus=0.5"));
  assert.ok(garakArgs.includes("--memory=768m"));
  assert.ok(garakArgs.includes("--memory-swap=768m"));
  assert.ok(garakArgs.includes(ASSESSMENT_EXECUTION_LIMITS.garak.tmpfs));
  assert.equal(garakArgs.at(-1), lock.images.garak.imageId);
  assert.equal(garakArgs.some((arg) => arg.startsWith("--mount=")), false);

  assert.ok(qwenArgs.includes("--cpus=1"));
  assert.ok(qwenArgs.includes("--memory=1536m"));
  assert.ok(qwenArgs.includes("--memory-swap=1536m"));
  assert.ok(qwenArgs.includes(ASSESSMENT_EXECUTION_LIMITS.qwen.tmpfs));
  assert.ok(
    qwenArgs.includes(ASSESSMENT_EXECUTION_LIMITS.qwen.executableRuntimeTmpfs),
  );
  assert.ok(
    qwenArgs.some(
      (arg) =>
        arg ===
        "--mount=type=bind,src=/workspace/Qwen3-0.6B-Q8_0.gguf,dst=/models/Qwen3-0.6B-Q8_0.gguf,readonly",
    ),
  );
  assert.ok(qwenArgs.some((arg) => arg.includes("src=/workspace/wheelhouse") && arg.endsWith(",readonly")));
  assert.ok(qwenArgs.some((arg) => arg.includes("src=/workspace/local-llm-manifest.json") && arg.endsWith(",readonly")));
  assert.ok(qwenArgs.some((arg) => arg.includes("src=/workspace/guardian_ai_assessment") && arg.endsWith(",readonly")));
  assert.equal(qwenArgs[qwenArgs.indexOf("-ceu") - 1], lock.images.qwen.imageId);
  assert.ok(qwenArgs.at(-1)?.includes("--native-tool-suite-job"));
  const autonomousArgs = launchWithPinnedAssessmentImage(
    "guardian-local-llm-autonomous-tools-v1",
    "guardian-ai-lab-00000000-0000-4000-8000-000000000006",
    inspection("qwen"),
    lock,
    mounts,
    (args) => args,
  );
  assert.ok(autonomousArgs.at(-1)?.includes("--autonomous-tool-selection-job"));
  assert.equal(ASSESSMENT_EXECUTION_LIMITS.maxStdoutBytes, 64 * 1024);
  assert.equal(ASSESSMENT_EXECUTION_LIMITS.garak.timeoutMs, 135_000);
  assert.equal(ASSESSMENT_EXECUTION_LIMITS.qwen.timeoutMs, 180_000);
});

test("profile image lock cannot be redirected to an arbitrary image or command", () => {
  const altered = structuredClone(lock) as AssessmentImageLock;
  altered.images.garak.reference = "attacker/other:latest";
  assert.throws(
    () => parseAssessmentImageLock(altered),
    /worker_image_lock_invalid/,
  );

  const alteredQwen = structuredClone(lock) as AssessmentImageLock;
  alteredQwen.images.qwen.imageId = "not-an-image-id";
  assert.throws(
    () => parseAssessmentImageLock(alteredQwen),
    /worker_image_lock_invalid/,
  );
});
