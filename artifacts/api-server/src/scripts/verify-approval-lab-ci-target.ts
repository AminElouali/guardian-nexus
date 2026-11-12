import { isGitHubActionsApprovalLabTarget } from "../lib/approval-e2e-db-guard";

if (!(await isGitHubActionsApprovalLabTarget(process.env))) {
  throw new Error(
    "Refusing PostgreSQL lab command outside the exact disposable CI target.",
  );
}

if (process.argv.length > 2) {
  throw new Error("Unexpected arguments to the PostgreSQL lab guard.");
}

console.log("Disposable PostgreSQL CI target contract accepted.");
