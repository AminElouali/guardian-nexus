import React from "react";
import { RefreshCw } from "lucide-react";
import { getWorkspaceLoadErrorCopy } from "@/lib/workspace-load-errors";

type WorkspaceQueryErrorProps = {
  error: unknown;
  onRetry: () => void;
  isRetrying?: boolean;
  testId?: string;
  buttonTestId?: string;
  compact?: boolean;
};

export function WorkspaceQueryError({
  error,
  onRetry,
  isRetrying = false,
  testId = "status-query-error",
  buttonTestId = "button-retry",
  compact = false,
}: WorkspaceQueryErrorProps) {
  const copy = getWorkspaceLoadErrorCopy(error);

  return (
    <div
      className={`notice notice-error workspace-query-error${compact ? " workspace-query-error-compact" : ""}`}
      role="alert"
      data-testid={testId}
      data-error-kind={copy.kind}
    >
      <div className="notice-icon">
        <RefreshCw size={17} aria-hidden="true" />
      </div>
      <div>
        <strong>{copy.title}</strong>
        <p>{copy.detail}</p>
      </div>
      <button
        type="button"
        className="button button-secondary"
        onClick={onRetry}
        disabled={isRetrying}
        data-testid={buttonTestId}
      >
        {isRetrying ? "Reintentando…" : "Reintentar"}
      </button>
    </div>
  );
}
