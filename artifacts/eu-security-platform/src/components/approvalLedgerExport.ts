import {
  ApiError,
  FetchTransportError,
  ResponseParseError,
} from "@workspace/api-client-react";

export type ApprovalLedgerExportFailure =
  | { kind: "network" }
  | { kind: "client" }
  | { kind: "download" }
  | { kind: "http"; status: number };

export type ApprovalLedgerExportResult =
  | { ok: true }
  | { ok: false; failure: ApprovalLedgerExportFailure };

export function classifyApprovalLedgerExportFailure(
  error: unknown,
): ApprovalLedgerExportFailure {
  if (error instanceof FetchTransportError) return { kind: "network" };
  if (error instanceof ResponseParseError) return { kind: "client" };
  if (error instanceof ApiError) return { kind: "http", status: error.status };
  return { kind: "client" };
}

export function approvalLedgerExportFailureMessage(
  failure: ApprovalLedgerExportFailure,
): string {
  switch (failure.kind) {
    case "network":
      return "No se pudo conectar con el servidor. No se recibió una respuesta HTTP.";
    case "client":
      return "El navegador no pudo preparar la solicitud o interpretar la respuesta.";
    case "download":
      return "El servidor respondió, pero el navegador no pudo iniciar la descarga.";
    case "http":
      return `La API respondió con HTTP ${failure.status}.`;
  }
}

export async function requestAndDownloadApprovalLedgerBundle<T>(
  request: () => Promise<T>,
  download: (bundle: T) => void,
): Promise<ApprovalLedgerExportResult> {
  let bundle: T;
  try {
    bundle = await request();
  } catch (error) {
    return { ok: false, failure: classifyApprovalLedgerExportFailure(error) };
  }

  try {
    download(bundle);
    return { ok: true };
  } catch {
    return { ok: false, failure: { kind: "download" } };
  }
}
