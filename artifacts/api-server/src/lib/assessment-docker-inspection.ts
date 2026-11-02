import {
  validateAssessmentImageInspection,
  type AssessmentImageLock,
  type AssessmentProfileId,
  type DockerImageInspection,
} from "./ai-assessment-sandbox";

export type DockerImageInspectResult = {
  error?: Error | null;
  status: number | null;
  stdout: string;
};

export type DockerImageInspectDecision = {
  inspection: DockerImageInspection | null;
  reasonCode: string | null;
};

export function classifyDockerImageInspectResult(
  profileId: AssessmentProfileId,
  result: DockerImageInspectResult,
  lock: AssessmentImageLock,
): DockerImageInspectDecision {
  if (result.error?.message.includes("ENOENT")) {
    return { inspection: null, reasonCode: "docker_not_available" };
  }
  if (result.error) {
    return { inspection: null, reasonCode: "docker_readiness_check_failed" };
  }
  if (result.status !== 0) {
    return { inspection: null, reasonCode: "worker_image_not_built" };
  }

  try {
    const inspection = JSON.parse(result.stdout.trim()) as DockerImageInspection;
    const validation = validateAssessmentImageInspection(
      profileId,
      inspection,
      lock,
    );
    return validation.ok
      ? { inspection, reasonCode: null }
      : { inspection: null, reasonCode: validation.reasonCode };
  } catch {
    return { inspection: null, reasonCode: "worker_image_profile_mismatch" };
  }
}
