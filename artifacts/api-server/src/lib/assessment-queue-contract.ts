export const AI_ASSESSMENT_WORKER_VERSION = "guardian-ai-assessment-lab-0.5.2";
export const GARAK_PROFILE_ID = "guardian-local-agent-v1";
export const AI_ASSESSMENT_JOB_MAX_ATTEMPTS = 2;

export function isAiAssessmentJobRetryable(
  status: string,
  attempts: number,
): boolean {
  return status === "failed" && attempts < AI_ASSESSMENT_JOB_MAX_ATTEMPTS;
}

export type LocalWorkerAvailability = {
  status: "ready" | "unavailable" | "disabled";
  workerVersion: string;
  reasonCode: string | null;
  profiles: Array<{
    profileId: import("./ai-assessment-sandbox").AssessmentProfileId;
    engine:
      | "garak"
      | "local_llm_lab"
      | "guardian_policy_lab"
      | "guardian_qwen_policy_lab";
    status: "ready" | "unavailable" | "disabled";
    reasonCode: string | null;
  }>;
};
