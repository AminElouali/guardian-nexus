import { isGitHubActionsApprovalLabTarget } from "../lib/approval-e2e-db-guard";

if (!isGitHubActionsApprovalLabTarget(process.env)) {
  throw new Error(
    "Refusing PostgreSQL lab command outside the exact disposable CI target.",
  );
}

if (process.argv.includes("--emit-verification-marker")) {
  if (process.env.GUARDIAN_APPROVAL_E2E_CI_STAGE !== "approval-e2e") {
    throw new Error("A CI target marker is only available for the E2E stage.");
  }
  console.log(
    `guardian-approval-lab:${process.env.GITHUB_RUN_ID}:${process.env.GITHUB_RUN_ATTEMPT}:${process.env.GITHUB_SHA}`,
  );
} else {
  console.log("Disposable PostgreSQL CI target contract accepted.");
}
