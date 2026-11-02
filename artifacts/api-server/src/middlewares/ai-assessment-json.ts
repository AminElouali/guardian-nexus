import express, { type ErrorRequestHandler } from "express";

export const AI_ASSESSMENT_LAB_JOB_ROUTE =
  "/api/workspaces/:workspaceId/ai-security-assessments/lab/jobs";
export const AI_ASSESSMENT_LAB_JSON_LIMIT_BYTES = 8 * 1024;

export const aiAssessmentLabJsonParser = express.json({
  limit: AI_ASSESSMENT_LAB_JSON_LIMIT_BYTES,
});

const AI_ASSESSMENT_LAB_JOB_PATH_PATTERN =
  /^\/api\/workspaces\/[^/]+\/ai-security-assessments\/lab\/jobs\/?$/;

export const aiAssessmentLabBodySizeErrorHandler: ErrorRequestHandler = (
  error,
  req,
  res,
  next,
) => {
  const errorType =
    error && typeof error === "object" && "type" in error
      ? (error as { type?: unknown }).type
      : undefined;
  if (
    errorType === "entity.too.large" &&
    req.method === "POST" &&
    AI_ASSESSMENT_LAB_JOB_PATH_PATTERN.test(req.path)
  ) {
    res.status(413).json({ error: "AI assessment request body too large" });
    return;
  }
  next(error);
};
