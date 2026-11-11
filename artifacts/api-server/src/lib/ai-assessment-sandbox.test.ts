import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  ASSESSMENT_EXECUTION_LIMITS,
  POLICY_LAB_PROFILE_IDS,
  QWEN_POLICY_LAB_PROFILE_IDS,
  QWEN_HOST_BOUNDARY_ATTESTATION_PATH,
  QWEN_HOST_BOUNDARY_PUBLIC_KEY_PATH,
  buildAssessmentDockerRunArgs,
  getAssessmentImageReference,
  launchWithPinnedAssessmentImage,
  parseAssessmentImageLock,
  validateAssessmentImageInspection,
  verifyAssessmentImageLockSources,
  type AssessmentMountPaths,
  type AssessmentImageLock,
  type DockerImageInspection,
  type AssessmentProfileId,
} from "./ai-assessment-sandbox";
import { classifyDockerImageInspectResult } from "./assessment-docker-inspection";
import {
  enqueueLocalAssessmentJob,
  getLocalWorkerAvailability,
  isAssessmentProfileAvailable,
} from "./assessment-worker-api-gate";

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

test("all eight Qwen profile argument builds retain read-only mounts and fail-closed container settings", () => {
  const expectedProfiles = [
    "guardian-agent-qwen-lab-email-v1",
    "guardian-agent-qwen-lab-database-v1",
    "guardian-agent-qwen-lab-finance-v1",
    "guardian-agent-qwen-lab-programming-v1",
    "guardian-agent-qwen-lab-customer-service-v1",
    "guardian-agent-qwen-lab-browser-v1",
    "guardian-agent-qwen-lab-infrastructure-v1",
    "guardian-agent-qwen-lab-multiagent-v1",
  ] as const;
  assert.deepEqual(
    [...QWEN_POLICY_LAB_PROFILE_IDS].sort(),
    [...expectedProfiles].sort(),
  );
  const gateBefore = getLocalWorkerAvailability();
  assert.equal(gateBefore.status, "disabled");
  assert.equal(gateBefore.reasonCode, "assessment_broker_identity_unverified");

  for (const profileId of expectedProfiles) {
    const args = buildAssessmentDockerRunArgs(
      `guardian-ai-lab-${profileId}`,
      profileId,
      lock.images.qwen.imageId,
      mounts,
    );
    const attestationMount =
      `--mount=type=bind,src=${QWEN_HOST_BOUNDARY_ATTESTATION_PATH},dst=${QWEN_HOST_BOUNDARY_ATTESTATION_PATH},readonly`;
    const publicKeyMount =
      `--mount=type=bind,src=${QWEN_HOST_BOUNDARY_PUBLIC_KEY_PATH},dst=${QWEN_HOST_BOUNDARY_PUBLIC_KEY_PATH},readonly`;

    assert.ok(args.includes(attestationMount), `${profileId} attestation mount`);
    assert.ok(args.includes(publicKeyMount), `${profileId} public key mount`);
    assert.ok(args.includes("--network=none"));
    assert.ok(args.includes("--user=65532:65532"));
    assert.ok(args.includes("--read-only"));
    assert.ok(args.includes("--cap-drop=ALL"));
    assert.ok(args.includes("--security-opt=no-new-privileges"));
    assert.ok(
      args.some((argument) =>
        argument.includes(
          `python -m guardian_ai_assessment.qwen_policy_lab --profile-id '${profileId}'`,
        ),
      ),
      `${profileId} must retain the existing Qwen policy-lab runner`,
    );
    assert.equal(
      args.some((argument) => /docker\.sock/i.test(argument)),
      false,
      `${profileId} must not receive or expose the Docker socket`,
    );
    assert.equal(args.includes("--privileged"), false);
  }

  assert.deepEqual(
    getLocalWorkerAvailability(),
    gateBefore,
    "argument construction must not alter worker readiness",
  );
  assert.ok(
    getLocalWorkerAvailability().profiles.every(
      (profile) =>
        profile.status === "disabled" &&
        profile.reasonCode === "assessment_broker_identity_unverified",
    ),
  );
  assert.equal(
    isAssessmentProfileAvailable(expectedProfiles[0]),
    false,
    "argument tests must not mark an assessment profile available",
  );
  assert.equal(
    enqueueLocalAssessmentJob({
      jobId: "offline-args-test-only",
      workspaceId: "offline-workspace",
      actorUserId: "offline-test-actor",
    }),
    false,
    "the API gate must keep the queue closed",
  );
});

test("unknown Qwen profiles and incomplete Qwen mount configuration fail closed", () => {
  assert.throws(
    () =>
      buildAssessmentDockerRunArgs(
        "guardian-ai-lab-unknown",
        "guardian-agent-qwen-lab-unknown-v1" as AssessmentProfileId,
        lock.images.qwen.imageId,
        mounts,
      ),
    /invalid_assessment_profile/,
  );

  const incompleteMounts = {
    ...mounts,
    wheelhousePath: "",
  };
  assert.throws(
    () =>
      buildAssessmentDockerRunArgs(
        "guardian-ai-lab-incomplete",
        QWEN_POLICY_LAB_PROFILE_IDS[0],
        lock.images.qwen.imageId,
        incompleteMounts,
      ),
    /worker_mount_configuration_invalid/,
  );

  const missingMounts = { modelPath: mounts.modelPath } as AssessmentMountPaths;
  assert.throws(
    () =>
      buildAssessmentDockerRunArgs(
        "guardian-ai-lab-missing-mounts",
        QWEN_POLICY_LAB_PROFILE_IDS[0],
        lock.images.qwen.imageId,
        missingMounts,
      ),
    /worker_mount_configuration_invalid/,
  );

  const gate = getLocalWorkerAvailability();
  assert.equal(gate.status, "disabled");
  assert.equal(gate.reasonCode, "assessment_broker_identity_unverified");
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

test("eight policy lab profiles use the pinned offline image with minimal read-only inputs", () => {
  assert.equal(POLICY_LAB_PROFILE_IDS.length, 8);
  for (const [index, profileId] of POLICY_LAB_PROFILE_IDS.entries()) {
    const args = launchWithPinnedAssessmentImage(
      profileId,
      `guardian-ai-lab-00000000-0000-4000-8000-${String(index + 20).padStart(12, "0")}`,
      inspection("qwen"),
      lock,
      mounts,
      (value) => value,
    );
    assert.ok(args.includes("--network=none"));
    assert.ok(args.includes("--pull=never"));
    assert.ok(args.includes("--read-only"));
    assert.ok(args.includes("--cap-drop=ALL"));
    assert.ok(args.includes("--security-opt=no-new-privileges"));
    assert.ok(args.includes("--user=65532:65532"));
    assert.ok(args.includes("--cpus=0.25"));
    assert.ok(args.includes("--memory=256m"));
    assert.ok(args.includes("--memory-swap=256m"));
    assert.ok(args.includes("--pids-limit=64"));
    assert.ok(args.includes(ASSESSMENT_EXECUTION_LIMITS.policyLab.tmpfs));
    assert.ok(args.some((arg) => arg.endsWith("/guardian_ai_assessment,readonly")));
    assert.equal(args.some((arg) => arg.includes("/models/")), false);
    assert.equal(args.some((arg) => arg.includes("/wheelhouse")), false);
    assert.equal(args.some((arg) => arg.includes("docker.sock")), false);
    assert.equal(args.at(-1), profileId);
    assert.ok(args.includes("exec python -B -m guardian_ai_assessment.policy_lab --profile-id \"$1\""));
  }
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

test("Docker inspection failures and malformed responses fail closed before launch", () => {
  const profile = "guardian-local-llm-qwen3-0.6b-v1";
  const validJson = JSON.stringify(inspection("qwen"));

  assert.equal(
    classifyDockerImageInspectResult(
      profile,
      { error: Object.assign(new Error("spawn docker ENOENT"), {}), status: null, stdout: "" },
      lock,
    ).reasonCode,
    "docker_not_available",
  );
  assert.equal(
    classifyDockerImageInspectResult(
      profile,
      { error: new Error("spawn docker ETIMEDOUT"), status: null, stdout: "" },
      lock,
    ).reasonCode,
    "docker_readiness_check_failed",
  );
  assert.equal(
    classifyDockerImageInspectResult(
      profile,
      { status: 1, stdout: "", error: null },
      lock,
    ).reasonCode,
    "worker_image_not_built",
  );
  assert.equal(
    classifyDockerImageInspectResult(
      profile,
      { status: 0, stdout: "{", error: null },
      lock,
    ).reasonCode,
    "worker_image_profile_mismatch",
  );
  assert.deepEqual(
    classifyDockerImageInspectResult(
      profile,
      { status: 0, stdout: validJson, error: null },
      lock,
    ),
    { inspection: inspection("qwen"), reasonCode: null },
  );
});
