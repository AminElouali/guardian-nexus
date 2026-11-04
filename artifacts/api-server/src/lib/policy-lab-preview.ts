import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { POLICY_LAB_PROFILE_IDS, type PolicyLabProfileId } from "./ai-assessment-sandbox";
import { PreviewWorkspaceAiAssessmentPolicyLabResponse } from "@workspace/api-zod";

const POLICY_LAB_WORKER_ROOT = resolve(
  process.cwd(),
  "../../workers/guardian-ai-assessment",
);
const POLICY_LAB_RUN_TIMEOUT_MS = 5_000;
const POLICY_LAB_MAX_OUTPUT_BYTES = 64 * 1024;
let previewRunning = false;

export type PolicyLabPreviewErrorCode =
  | "unsupported_policy_lab_profile"
  | "policy_preview_busy"
  | "policy_preview_runner_failed"
  | "policy_preview_timed_out"
  | "policy_preview_evidence_invalid";

export class PolicyLabPreviewError extends Error {
  constructor(public readonly code: PolicyLabPreviewErrorCode) {
    super(code);
    this.name = "PolicyLabPreviewError";
  }
}

type RunnerCommand = {
  executable: "python3";
  args: string[];
  cwd: string;
  env: Record<string, string>;
  timeout: number;
  maxBuffer: number;
};

export function buildPolicyLabPreviewCommand(profileId: string): RunnerCommand {
  if (!POLICY_LAB_PROFILE_IDS.includes(profileId as PolicyLabProfileId)) {
    throw new PolicyLabPreviewError("unsupported_policy_lab_profile");
  }

  return {
    executable: "python3",
    args: [
      "-S",
      "-B",
      "-m",
      "guardian_ai_assessment.policy_lab",
      "--profile-id",
      profileId,
      "--execution-context",
      "api_policy_preview",
    ],
    cwd: POLICY_LAB_WORKER_ROOT,
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      PYTHONPATH: POLICY_LAB_WORKER_ROOT,
      PYTHONNOUSERSITE: "1",
      PYTHONDONTWRITEBYTECODE: "1",
      PYTHONHASHSEED: "0",
    },
    timeout: POLICY_LAB_RUN_TIMEOUT_MS,
    maxBuffer: POLICY_LAB_MAX_OUTPUT_BYTES,
  };
}

function runBoundedCommand(command: RunnerCommand): Promise<string> {
  return new Promise((resolveOutput, reject) => {
    execFile(
      command.executable,
      command.args,
      {
        cwd: command.cwd,
        env: command.env,
        timeout: command.timeout,
        killSignal: "SIGKILL",
        maxBuffer: command.maxBuffer,
        encoding: "utf8",
        windowsHide: true,
      },
      (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }
        resolveOutput(stdout);
      },
    );
  });
}

function validatePreviewEvidence(
  value: unknown,
  expectedProfileId: PolicyLabProfileId,
) {
  const parsed =
    PreviewWorkspaceAiAssessmentPolicyLabResponse.shape.evidence.safeParse(
      value,
    );
  if (!parsed.success) {
    throw new PolicyLabPreviewError("policy_preview_evidence_invalid");
  }

  const evidence = parsed.data;
  const casesRespectDispatchOrder = evidence.cases.every((item) => {
    const dispatch = item.toolTrace.policyOn;
    if (dispatch.dispatchStatus === "simulated_execution") {
      return (
        item.policyOn.decision === "allow" &&
        dispatch.invoked &&
        item.policyOn.executed &&
        dispatch.events.some((event) => event.phase === "executed" && event.executed) &&
        dispatch.externalSideEffect === false &&
        dispatch.persistentStateMutation === false
      );
    }
    if (dispatch.dispatchStatus === "adapter_validation_denied") {
      return (
        item.policyOn.decision === "deny" &&
        dispatch.invoked &&
        dispatch.events.every((event) => event.phase !== "executed" && !event.executed) &&
        !item.policyOn.executed
      );
    }
    if (dispatch.dispatchStatus === "approval_required_before_dispatch") {
      return (
        item.policyOn.decision === "require_approval" &&
        !dispatch.invoked &&
        dispatch.events.length === 0 &&
        !item.policyOn.executed
      );
    }
    return (
      dispatch.dispatchStatus === "blocked_by_policy_before_dispatch" &&
      item.policyOn.decision === "deny" &&
      !dispatch.invoked &&
      dispatch.events.length === 0 &&
      !item.policyOn.executed
    );
  });
  const policyOffIsCounterfactual = evidence.cases.every(
    (item) =>
      item.policyOff.executed === false &&
      item.toolTrace.policyOff.invoked === false &&
      item.toolTrace.policyOff.events.length === 0,
  );

  if (
    evidence.profileId !== expectedProfileId ||
    evidence.engineVersion !== "guardian-agent-policy-lab-v3" ||
    evidence.executionContext !== "api_policy_preview" ||
    evidence.executionMode !== "deterministic_fixture" ||
    evidence.proposalOrigin !== "controlled_fixture_not_llm" ||
    evidence.modelInference !== false ||
    evidence.limits.network !== "host_network_unisolated" ||
    evidence.limits.processIsolation !== "shared_api_identity" ||
    evidence.limits.dockerSocketAccess !== "not_assessed" ||
    evidence.limits.externalCalls !== 0 ||
    evidence.limits.actualOperations !== 0 ||
    evidence.selfCheckStatus !== "passed" ||
    evidence.summary.actualOperations !== 0 ||
    evidence.summary.persistentStateChanges !== 0 ||
    evidence.summary.externalCalls !== 0 ||
    evidence.summary.unauthorizedExecutions !== 0 ||
    !casesRespectDispatchOrder ||
    !policyOffIsCounterfactual
  ) {
    throw new PolicyLabPreviewError("policy_preview_evidence_invalid");
  }

  return evidence;
}

export async function runPolicyLabPreview(profileId: string) {
  const command = buildPolicyLabPreviewCommand(profileId);
  if (previewRunning) {
    throw new PolicyLabPreviewError("policy_preview_busy");
  }

  previewRunning = true;
  try {
    const stdout = await runBoundedCommand(command);
    let result: unknown;
    try {
      result = JSON.parse(stdout);
    } catch {
      throw new PolicyLabPreviewError("policy_preview_evidence_invalid");
    }
    return validatePreviewEvidence(result, profileId as PolicyLabProfileId);
  } catch (error) {
    if (error instanceof PolicyLabPreviewError) {
      throw error;
    }
    const systemError = error as NodeJS.ErrnoException & { killed?: boolean };
    throw new PolicyLabPreviewError(
      systemError.code === "ETIMEDOUT" || systemError.killed
        ? "policy_preview_timed_out"
        : "policy_preview_runner_failed",
    );
  } finally {
    previewRunning = false;
  }
}
