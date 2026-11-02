import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export type AssessmentProfileId =
  | "guardian-local-agent-v1"
  | "guardian-local-llm-qwen3-0.6b-v1"
  | "guardian-local-llm-native-tools-v1"
  | "guardian-local-llm-autonomous-tools-v1"
  | PolicyLabProfileId;

export const POLICY_LAB_PROFILE_IDS = [
  "guardian-agent-lab-email-v1",
  "guardian-agent-lab-database-v1",
  "guardian-agent-lab-finance-v1",
  "guardian-agent-lab-programming-v1",
  "guardian-agent-lab-customer-service-v1",
  "guardian-agent-lab-browser-v1",
  "guardian-agent-lab-infrastructure-v1",
  "guardian-agent-lab-multiagent-v1",
] as const;

export type PolicyLabProfileId = (typeof POLICY_LAB_PROFILE_IDS)[number];

export type AssessmentImageKey = "garak" | "qwen";

export type AssessmentImageLockEntry = {
  reference: string;
  imageId: string;
  labels: Record<string, string>;
  sourceDockerfile: string;
  sourceDockerfileSha256: string;
};

export type AssessmentImageLock = {
  schemaVersion: 1;
  provenance: {
    scope: "development";
    method: "local_docker_inspect";
    signedAttestation: false;
  };
  images: Record<AssessmentImageKey, AssessmentImageLockEntry>;
};

export type DockerImageInspection = {
  Id?: unknown;
  Config?: {
    Labels?: Record<string, string> | null;
  } | null;
};

export type AssessmentMountPaths = {
  modelPath: string;
  wheelhousePath: string;
  manifestPath: string;
  sourcePath: string;
};

export const ASSESSMENT_EXECUTION_LIMITS = {
  maxPids: 64,
  maxStdoutBytes: 64 * 1024,
  garak: {
    cpus: "0.5",
    memory: "768m",
    memorySwap: "768m",
    timeoutMs: 135_000,
    tmpfs: "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
  },
  qwen: {
    cpus: "1",
    memory: "1536m",
    memorySwap: "1536m",
    timeoutMs: 180_000,
    tmpfs: "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777",
    executableRuntimeTmpfs:
      "--tmpfs=/opt/llm-runtime:rw,exec,nosuid,nodev,size=128m,mode=1777",
  },
  policyLab: {
    cpus: "0.25",
    memory: "256m",
    memorySwap: "256m",
    timeoutMs: 30_000,
    tmpfs: "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
  },
} as const;

const PROFILE_IMAGE_REFERENCE: Record<AssessmentImageKey, string> = {
  garak: "guardian-ai-assessment:garak-gve-profile-candidate",
  qwen: "guardian-ai-assessment:qwen-gve-profile-candidate",
};

const PROFILE_IDS: Record<AssessmentImageKey, readonly AssessmentProfileId[]> = {
  garak: ["guardian-local-agent-v1"],
  qwen: [
    "guardian-local-llm-qwen3-0.6b-v1",
    "guardian-local-llm-native-tools-v1",
    "guardian-local-llm-autonomous-tools-v1",
    ...POLICY_LAB_PROFILE_IDS,
  ],
};

const SOURCE_DOCKFILES: Record<AssessmentImageKey, string> = {
  garak: "Dockerfile.offline",
  qwen: "Dockerfile.qwen.offline",
};

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const HEX_SHA256_PATTERN = /^[a-f0-9]{64}$/;
const PROFILE_LABEL_KEY = "org.guardian.profile";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function imageKeyForProfile(profileId: AssessmentProfileId): AssessmentImageKey {
  if (PROFILE_IDS.garak.includes(profileId)) return "garak";
  if (PROFILE_IDS.qwen.includes(profileId)) return "qwen";
  throw new Error("invalid_assessment_profile");
}

export function isPolicyLabProfile(
  profileId: AssessmentProfileId,
): profileId is PolicyLabProfileId {
  return (POLICY_LAB_PROFILE_IDS as readonly string[]).includes(profileId);
}

export function parseAssessmentImageLock(value: unknown): AssessmentImageLock {
  if (!isRecord(value) || value.schemaVersion !== 1 || !isRecord(value.images)) {
    throw new Error("worker_image_lock_invalid");
  }
  const provenance = value.provenance;
  if (
    !isRecord(provenance) ||
    provenance.scope !== "development" ||
    provenance.method !== "local_docker_inspect" ||
    provenance.signedAttestation !== false
  ) {
    throw new Error("worker_image_lock_invalid");
  }

  const parsedImages = {} as Record<AssessmentImageKey, AssessmentImageLockEntry>;
  for (const key of ["garak", "qwen"] as const) {
    const rawEntry = value.images[key];
    if (!isRecord(rawEntry) || !isRecord(rawEntry.labels)) {
      throw new Error("worker_image_lock_invalid");
    }
    const expectedProfileLabel = key === "garak" ? "garak-gve-v1" : "qwen-gve-v1";
    const expectedEngineLabel =
      key === "garak"
        ? "garak-0.17.1+guardian-verification"
        : "local-llm-lab+guardian-verification";
    if (
      rawEntry.reference !== PROFILE_IMAGE_REFERENCE[key] ||
      typeof rawEntry.imageId !== "string" ||
      !SHA256_PATTERN.test(rawEntry.imageId) ||
      rawEntry.labels[PROFILE_LABEL_KEY] !== expectedProfileLabel ||
      rawEntry.labels["org.guardian.engine"] !== expectedEngineLabel ||
      typeof rawEntry.sourceDockerfile !== "string" ||
      rawEntry.sourceDockerfile !== SOURCE_DOCKFILES[key] ||
      typeof rawEntry.sourceDockerfileSha256 !== "string" ||
      !HEX_SHA256_PATTERN.test(rawEntry.sourceDockerfileSha256)
    ) {
      throw new Error("worker_image_lock_invalid");
    }
    const labels: Record<string, string> = {};
    for (const [label, labelValue] of Object.entries(rawEntry.labels)) {
      if (typeof labelValue !== "string" || labelValue.length > 256) {
        throw new Error("worker_image_lock_invalid");
      }
      labels[label] = labelValue;
    }
    parsedImages[key] = {
      reference: rawEntry.reference,
      imageId: rawEntry.imageId,
      labels,
      sourceDockerfile: rawEntry.sourceDockerfile,
      sourceDockerfileSha256: rawEntry.sourceDockerfileSha256,
    };
  }

  return {
    schemaVersion: 1,
    provenance: {
      scope: "development",
      method: "local_docker_inspect",
      signedAttestation: false,
    },
    images: parsedImages,
  };
}

export function readAssessmentImageLock(path: string): AssessmentImageLock {
  try {
    return parseAssessmentImageLock(
      JSON.parse(readFileSync(path, "utf8")) as unknown,
    );
  } catch (error) {
    if (error instanceof Error && error.message === "worker_image_lock_invalid") {
      throw error;
    }
    throw new Error("worker_image_lock_unavailable");
  }
}

export function verifyAssessmentImageLockSources(
  lock: AssessmentImageLock,
  workerRoot: string,
): boolean {
  try {
    return (["garak", "qwen"] as const).every((key) => {
      const entry = lock.images[key];
      const bytes = readFileSync(resolve(workerRoot, entry.sourceDockerfile));
      return (
        createHash("sha256").update(bytes).digest("hex") ===
        entry.sourceDockerfileSha256
      );
    });
  } catch {
    return false;
  }
}

export function getAssessmentImageReference(
  profileId: AssessmentProfileId,
  lock: AssessmentImageLock,
): string {
  return lock.images[imageKeyForProfile(profileId)].reference;
}

export function hasExpectedAssessmentImageLabel(
  profileId: AssessmentProfileId,
  labels: Record<string, string> | null | undefined,
  lock: AssessmentImageLock,
): boolean {
  const entry = lock.images[imageKeyForProfile(profileId)];
  return Object.entries(entry.labels).every(
    ([key, expectedValue]) => labels?.[key] === expectedValue,
  );
}

export function validateAssessmentImageInspection(
  profileId: AssessmentProfileId,
  inspection: DockerImageInspection | null | undefined,
  lock: AssessmentImageLock,
): { ok: true; imageId: string } | { ok: false; reasonCode: string } {
  const entry = lock.images[imageKeyForProfile(profileId)];
  if (inspection?.Id !== entry.imageId) {
    return { ok: false, reasonCode: "worker_image_identity_mismatch" };
  }
  if (!hasExpectedAssessmentImageLabel(profileId, inspection.Config?.Labels, lock)) {
    return { ok: false, reasonCode: "worker_image_profile_mismatch" };
  }
  return { ok: true, imageId: entry.imageId };
}

export function buildAssessmentDockerRunArgs(
  containerName: string,
  profileId: AssessmentProfileId,
  imageId: string,
  mounts: AssessmentMountPaths,
): string[] {
  if (!SHA256_PATTERN.test(imageId)) {
    throw new Error("worker_image_identity_mismatch");
  }
  const common = [
    "run",
    "--rm",
    "--init",
    "--pull=never",
    `--name=${containerName}`,
    "--network=none",
    "--read-only",
    `--pids-limit=${ASSESSMENT_EXECUTION_LIMITS.maxPids}`,
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--user=65532:65532",
    "--log-driver=none",
  ];
  if (imageKeyForProfile(profileId) === "garak") {
    return [
      ...common,
      `--cpus=${ASSESSMENT_EXECUTION_LIMITS.garak.cpus}`,
      `--memory=${ASSESSMENT_EXECUTION_LIMITS.garak.memory}`,
      `--memory-swap=${ASSESSMENT_EXECUTION_LIMITS.garak.memorySwap}`,
      ASSESSMENT_EXECUTION_LIMITS.garak.tmpfs,
      imageId,
    ];
  }
  if (isPolicyLabProfile(profileId)) {
    return [
      ...common,
      `--cpus=${ASSESSMENT_EXECUTION_LIMITS.policyLab.cpus}`,
      `--memory=${ASSESSMENT_EXECUTION_LIMITS.policyLab.memory}`,
      `--memory-swap=${ASSESSMENT_EXECUTION_LIMITS.policyLab.memorySwap}`,
      ASSESSMENT_EXECUTION_LIMITS.policyLab.tmpfs,
      `--mount=type=bind,src=${mounts.sourcePath},dst=/opt/guardian-assessment/guardian_ai_assessment,readonly`,
      "--workdir=/opt/guardian-assessment",
      "--entrypoint=/bin/sh",
      imageId,
      "-ceu",
      'exec python -B -m guardian_ai_assessment.policy_lab --profile-id "$1"',
      "--",
      profileId,
    ];
  }
  return [
    ...common,
    `--cpus=${ASSESSMENT_EXECUTION_LIMITS.qwen.cpus}`,
    `--memory=${ASSESSMENT_EXECUTION_LIMITS.qwen.memory}`,
    `--memory-swap=${ASSESSMENT_EXECUTION_LIMITS.qwen.memorySwap}`,
    ASSESSMENT_EXECUTION_LIMITS.qwen.tmpfs,
    ASSESSMENT_EXECUTION_LIMITS.qwen.executableRuntimeTmpfs,
    `--mount=type=bind,src=${mounts.modelPath},dst=/models/Qwen3-0.6B-Q8_0.gguf,readonly`,
    `--mount=type=bind,src=${mounts.wheelhousePath},dst=/wheelhouse,readonly`,
    `--mount=type=bind,src=${mounts.manifestPath},dst=/opt/guardian-assessment/local-llm-manifest.json,readonly`,
    `--mount=type=bind,src=${mounts.sourcePath},dst=/opt/guardian-assessment/guardian_ai_assessment,readonly`,
    "--workdir=/opt/guardian-assessment",
    "--entrypoint=/bin/sh",
    imageId,
    "-ceu",
    `python -m pip install --no-index --no-deps --disable-pip-version-check --no-cache-dir --target=/opt/llm-runtime /wheelhouse/llama_cpp_python-0.3.36-py3-none-linux_x86_64.whl /wheelhouse/jinja2-3.1.6-py3-none-any.whl /wheelhouse/markupsafe-3.0.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl >&2; export PYTHONPATH=/opt/llm-runtime:/opt/guardian-assessment; exec python -m guardian_ai_assessment.llm_lab ${
      profileId === "guardian-local-llm-native-tools-v1"
        ? "--native-tool-suite-job"
        : profileId === "guardian-local-llm-autonomous-tools-v1"
          ? "--autonomous-tool-selection-job"
          : "--integration-job"
    }`,
  ];
}

export function launchWithPinnedAssessmentImage<T>(
  profileId: AssessmentProfileId,
  containerName: string,
  inspection: DockerImageInspection | null | undefined,
  lock: AssessmentImageLock,
  mounts: AssessmentMountPaths,
  launch: (args: string[]) => T,
): T {
  const validation = validateAssessmentImageInspection(profileId, inspection, lock);
  if (!validation.ok) throw new Error(validation.reasonCode);
  return launch(
    buildAssessmentDockerRunArgs(
      containerName,
      profileId,
      validation.imageId,
      mounts,
    ),
  );
}
