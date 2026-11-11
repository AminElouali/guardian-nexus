import {
  POLICY_LAB_PROFILE_IDS,
  QWEN_POLICY_LAB_PROFILE_IDS,
  type AssessmentProfileId,
} from "./ai-assessment-sandbox";
import {
  AI_ASSESSMENT_WORKER_VERSION,
  GARAK_PROFILE_ID,
  type LocalWorkerAvailability,
} from "./assessment-queue-contract";

const profileEngines: Array<{
  profileId: AssessmentProfileId;
  engine: LocalWorkerAvailability["profiles"][number]["engine"];
}> = [
  { profileId: GARAK_PROFILE_ID, engine: "garak" },
  { profileId: "guardian-local-llm-qwen3-0.6b-v1", engine: "local_llm_lab" },
  { profileId: "guardian-local-llm-native-tools-v1", engine: "local_llm_lab" },
  {
    profileId: "guardian-local-llm-autonomous-tools-v1",
    engine: "local_llm_lab",
  },
  ...POLICY_LAB_PROFILE_IDS.map((profileId) => ({
    profileId,
    engine: "guardian_policy_lab" as const,
  })),
  ...QWEN_POLICY_LAB_PROFILE_IDS.map((profileId) => ({
    profileId,
    engine: "guardian_qwen_policy_lab" as const,
  })),
];

const BROKER_UNAVAILABLE_REASON = "assessment_broker_identity_unverified";

export type AssessmentWorkerAdmission =
  | { admitted: true }
  | { admitted: false; reasonCode: string };

export function getLocalWorkerAvailability(): LocalWorkerAvailability {
  return {
    status: "disabled",
    workerVersion: AI_ASSESSMENT_WORKER_VERSION,
    reasonCode: BROKER_UNAVAILABLE_REASON,
    profiles: profileEngines.map(({ profileId, engine }) => ({
      profileId,
      engine,
      status: "disabled",
      reasonCode: BROKER_UNAVAILABLE_REASON,
    })),
  };
}

export function decideAssessmentWorkerAdmission(
  profileId: AssessmentProfileId,
): AssessmentWorkerAdmission {
  const availability = getLocalWorkerAvailability();
  const profile = availability.profiles.find(
    (candidate) => candidate.profileId === profileId,
  );
  if (availability.status === "ready" && profile?.status === "ready") {
    return { admitted: true };
  }
  return {
    admitted: false,
    reasonCode:
      profile?.reasonCode ??
      availability.reasonCode ??
      "assessment_profile_unavailable",
  };
}

export function isAssessmentProfileAvailable(
  profileId: AssessmentProfileId,
): boolean {
  return decideAssessmentWorkerAdmission(profileId).admitted;
}

export function enqueueLocalAssessmentJob(_item: {
  jobId: string;
  workspaceId: string;
  actorUserId: string;
}): boolean {
  return false;
}
