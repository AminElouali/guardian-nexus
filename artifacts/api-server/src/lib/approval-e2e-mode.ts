export type ApprovalE2eMode = {
  focused: boolean;
  forbidden: boolean;
  omittedSubtestCount: number;
};

export function inspectApprovalE2eMode(
  env: Readonly<Record<string, string | undefined>>,
  omittedSubtestCount: number,
): ApprovalE2eMode {
  const focused = env.GUARDIAN_LAB_CONNECTOR_CREDENTIAL_E2E_ONLY === "1";
  const forbidden =
    focused &&
    (env.CI === "true" ||
      env.GUARDIAN_APPROVAL_E2E_REQUIRED === "1" ||
      env.GUARDIAN_APPROVAL_E2E_CI_SERVICE !== undefined);
  return {
    focused,
    forbidden,
    omittedSubtestCount: focused ? omittedSubtestCount : 0,
  };
}

export const FOCUSED_APPROVAL_E2E_FORBIDDEN_MESSAGE =
  "focused_approval_e2e_mode_forbidden";

export function formatFocusedApprovalE2eAnnouncement(
  omittedSubtestCount: number,
): string {
  return `MODO FOCALIZADO: se omiten ${omittedSubtestCount} subpruebas`;
}
