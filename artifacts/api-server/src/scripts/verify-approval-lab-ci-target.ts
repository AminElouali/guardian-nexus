import { diagnoseGitHubActionsApprovalLabTarget } from "../lib/approval-e2e-db-guard";

const decision = await diagnoseGitHubActionsApprovalLabTarget(process.env);
if (!decision.accepted) {
  console.error(
    JSON.stringify({
      category: decision.category,
      stage: decision.stage,
    }),
  );
  process.exitCode = 1;
} else if (process.argv.length > 2) {
  throw new Error("Unexpected arguments to the PostgreSQL lab guard.");
} else {
  console.log("Disposable PostgreSQL CI target contract accepted.");
}
