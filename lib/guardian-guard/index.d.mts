export type SignedApprovalReceiptV1 = {
  payload: Record<string, unknown>;
  payloadSha256: string;
  signature: string;
};

export class GuardianGuardError extends Error {
  code: string;
}

export function canonicalizeV1(value: unknown): string;
export function hashActionArguments(
  actionType: string,
  args: Record<string, string | number | boolean>,
): { argumentsSha256: string; actionSha256: string };
export function verifyApprovalReceiptOffline(
  receipt: unknown,
  trustedKeys: Record<string, unknown> | Map<string, unknown>,
  expected: Record<string, string>,
  verificationTime?: Date,
): { valid: true; code: "ok" } | { valid: false; code: string };
export function executeGuardedSandboxAction(input: {
  apiBaseUrl: string;
  requestHeaders?: Record<string, string>;
  receipt: SignedApprovalReceiptV1;
  trustedKeys: Record<string, unknown> | Map<string, unknown>;
  expected: Record<string, string>;
  action: {
    actionType: string;
    args: Record<string, string | number | boolean>;
  };
  sandboxSmtp: { port: number; credential: string };
  fetchImpl?: typeof fetch;
  verificationTime?: Date;
}): Promise<{
  executed: true;
  mode: "local_smtp_capture_only";
  receiptId: string;
  consumedEventSha256: string;
  actionSha256: string;
  externalEffect: false;
}>;
