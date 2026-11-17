import React, { useMemo, useRef, useState, type ChangeEvent } from "react";
import type {
  AiAssessmentApprovalReceiptConsumeResponse,
  SignedApprovalLedgerEventV1,
  SignedApprovalReceiptV1,
} from "@workspace/api-client-react";
import { Button } from "@/components/ui/button";
import { WorkspaceQueryError } from "@/components/WorkspaceQueryError";
import {
  approvalLedgerExportFailureMessage,
  type ApprovalLedgerExportFailure,
} from "./approvalLedgerExport";
import {
  importSavedApprovalReceipt,
  MAX_APPROVAL_RECEIPT_JSON_BYTES,
  savedReceiptImportFailureMessage,
} from "./approvalReceiptImport";

export type ReceiptConsumeDisplay = {
  httpStatus: number | null;
  response?: AiAssessmentApprovalReceiptConsumeResponse;
};

type ApprovalLedgerDemoProps = {
  receipts: Array<{ approvalId: string; receipt: SignedApprovalReceiptV1 }>;
  consumeResults: Record<string, ReceiptConsumeDisplay>;
  events: SignedApprovalLedgerEventV1[];
  recentlyApprovedReceiptId?: string | null;
  eventsLoading: boolean;
  eventsError: boolean;
  eventsErrorDetail?: unknown;
  eventsRetrying?: boolean;
  exporting: boolean;
  exportFailure?: ApprovalLedgerExportFailure;
  onRetryEvents: () => void;
  onConsume: (approvalId: string, receipt: SignedApprovalReceiptV1) => void;
  onAddReceipt: (approvalId: string, receipt: SignedApprovalReceiptV1) => void;
  onExport: (receipts: SignedApprovalReceiptV1[]) => void;
};

function stringifyReceipt(receipt: SignedApprovalReceiptV1): string {
  return `${JSON.stringify(receipt, null, 2)}\n`;
}

function downloadJson(filename: string, content: string): void {
  const blob = new Blob([content], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function ApprovalLedgerDemo({
  receipts,
  consumeResults,
  events,
  recentlyApprovedReceiptId,
  eventsLoading,
  eventsError,
  eventsErrorDetail,
  eventsRetrying = false,
  exporting,
  exportFailure,
  onRetryEvents,
  onConsume,
  onAddReceipt,
  onExport,
}: ApprovalLedgerDemoProps) {
  const [copyMessage, setCopyMessage] = useState("");
  const [receiptJson, setReceiptJson] = useState("");
  const [receiptImportMessage, setReceiptImportMessage] = useState("");
  const [receiptImportError, setReceiptImportError] = useState("");
  const [readingReceiptFile, setReadingReceiptFile] = useState(false);
  const receiptFileInput = useRef<HTMLInputElement>(null);
  const receiptIndex = useMemo(
    () => new Map(receipts.map(({ receipt }) => [
      receipt.payload.receiptId,
      receipt,
    ])),
    [receipts],
  );
  const missingApprovalIds = useMemo(
    () =>
      events.filter((signedEvent) => {
        if (signedEvent.event.eventType !== "approval.approved") return false;
        const receipt = receiptIndex.get(
          signedEvent.event.payload.receiptId,
        );
        return !receipt ||
          receipt.payloadSha256 !== signedEvent.event.payload.receiptSha256;
      }).map((signedEvent) => signedEvent.event.approvalId),
    [events, receiptIndex],
  );
  const missingReceiptCount = missingApprovalIds.length;
  const receiptValues = receipts.map(({ receipt }) => receipt);

  function acceptSavedReceipt(json: string) {
    setReceiptImportMessage("");
    setReceiptImportError("");
    if (eventsLoading || eventsError) {
      setReceiptImportError(
        "Carga los eventos del registro antes de añadir un recibo.",
      );
      return;
    }
    const result = importSavedApprovalReceipt(json, events, receipts);
    if (!result.ok) {
      setReceiptImportError(savedReceiptImportFailureMessage(result.failure));
      return;
    }
    onAddReceipt(result.approvalId, result.receipt);
    setReceiptJson("");
    setReceiptImportMessage(
      "Recibo añadido solo a esta sesión. El servidor comprobará su firma y vínculo al exportar.",
    );
  }

  async function handleReceiptFileChange(
    event: ChangeEvent<HTMLInputElement>,
  ) {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file) return;

    setReceiptImportMessage("");
    setReceiptImportError("");
    if (!file.name.toLowerCase().endsWith(".json")) {
      setReceiptImportError("Selecciona un archivo .json.");
      input.value = "";
      return;
    }
    if (file.size > MAX_APPROVAL_RECEIPT_JSON_BYTES) {
      setReceiptImportError(savedReceiptImportFailureMessage("too_large"));
      input.value = "";
      return;
    }

    setReadingReceiptFile(true);
    try {
      acceptSavedReceipt(await file.text());
    } catch {
      setReceiptImportError("No se pudo leer el archivo JSON.");
    } finally {
      setReadingReceiptFile(false);
      input.value = "";
    }
  }

  return (
    <section
      className="panel ai-evaluation-history"
      data-testid="approval-ledger-demo"
      aria-labelledby="approval-ledger-demo-title"
    >
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">REEMBOLSO SINTÉTICO · SOLO LABORATORIO</span>
          <h2 id="approval-ledger-demo-title">Recibos y registro de aprobaciones</h2>
        </div>
        <span className="ai-evaluation-state ai-state-pending">
          <i /> Sin pagos ni efectos externos
        </span>
      </div>
      <p>
        La operación es una simulación en memoria con una fixture fija. No usa
        pagos reales, datos de clientes ni servicios externos. Las firmas y
        hashes ayudan a detectar manipulación al verificarlos con claves
        confiables; la truncación de eventos posteriores solo se detecta al
        comparar con un punto de control externo confiable.
      </p>

      <div className="ai-history-list" data-testid="approval-receipt-list">
        {receipts.length === 0 ? (
          <div className="ai-history-empty" data-testid="approval-receipt-empty">
            Aún no hay un recibo de reembolso sintético en esta sesión. El
            servidor no conserva el recibo; si se pierde, hay que volver a
            proponer y aprobar.
          </div>
        ) : receipts.map(({ approvalId, receipt }) => {
          const json = stringifyReceipt(receipt);
          const consume = consumeResults[approvalId];
          const operation = consume?.response?.syntheticRefundOperation;
          return (
            <article
              className="panel ai-evaluation-card"
              key={approvalId}
              data-testid={`approval-receipt-${approvalId}`}
            >
              <h3>Recibo firmado de reembolso sintético</h3>
              <p>
                El servidor devuelve este recibo una vez y no lo conserva. Si
                se pierde, hay que volver a proponer y aprobar la acción.
              </p>
              {recentlyApprovedReceiptId === approvalId && (
                <p
                  className="notice notice-warning"
                  role="alert"
                  data-testid={`status-save-receipt-${approvalId}`}
                >
                  Guarde el recibo ahora: el servidor no lo conserva y al
                  recargar se pierde.
                </p>
              )}
              <div className="ai-evaluation-actions">
                <Button
                  variant="outline"
                  data-testid={`button-copy-receipt-${approvalId}`}
                  onClick={() => {
                    if (!navigator.clipboard?.writeText) {
                      setCopyMessage("Este navegador no permite copiarlo automáticamente.");
                    } else {
                      void navigator.clipboard.writeText(json).then(
                        () => setCopyMessage("Recibo copiado."),
                        () => setCopyMessage("No se pudo copiar el recibo."),
                      );
                    }
                  }}
                >
                  Copiar recibo JSON
                </Button>
                <Button
                  variant={recentlyApprovedReceiptId === approvalId ? "default" : "outline"}
                  data-testid={`button-download-receipt-${approvalId}`}
                  onClick={() =>
                    downloadJson(
                      `guardian-receipt-${receipt.payload.receiptId}.json`,
                      json,
                    )
                  }
                >
                  Descargar recibo JSON
                </Button>
                <Button
                  data-testid={`button-consume-receipt-${approvalId}`}
                  disabled={Boolean(consume?.response) || consume?.httpStatus === 409}
                  onClick={() => onConsume(approvalId, receipt)}
                >
                  Consumir recibo sintético
                </Button>
              </div>
              {copyMessage && (
                <small role="status" data-testid="receipt-copy-status">
                  {copyMessage}
                </small>
              )}
              <details className="approval-technical-details">
                <summary>Ver el recibo firmado</summary>
                <pre data-testid={`receipt-json-${approvalId}`}>{json}</pre>
              </details>
              {consume && (
                <div
                  className={consume.response
                    ? "notice notice-success"
                    : "notice notice-error"}
                  role={consume.response ? "status" : "alert"}
                  data-testid={`receipt-consume-result-${approvalId}`}
                >
                  <p>
                    Resultado HTTP: {consume.httpStatus ?? "sin respuesta"}
                  </p>
                  {consume.response ? (
                    <>
                      <p>
                        Consumo registrado en la simulación sintética. No se
                        envió dinero ni se llamó a un sistema externo.
                      </p>
                      <dl className="approval-summary">
                        <div>
                          <dt>Hash del evento de consumo</dt>
                          <dd><code>{consume.response.consumedEventSha256}</code></dd>
                        </div>
                        {operation && (
                          <>
                            <div><dt>Código de resultado</dt><dd>{operation.resultCode}</dd></div>
                            <div><dt>SHA-256 del resultado</dt><dd><code>{operation.resultSha256}</code></dd></div>
                            <div><dt>SHA-256 antes</dt><dd><code>{operation.beforeStateSha256}</code></dd></div>
                            <div><dt>SHA-256 después</dt><dd><code>{operation.afterStateSha256}</code></dd></div>
                          </>
                        )}
                      </dl>
                    </>
                  ) : (
                    <p>
                      El recibo fue rechazado. No se confirmó una simulación
                      por esta respuesta.
                    </p>
                  )}
                </div>
              )}
            </article>
          );
        })}
      </div>

      <section className="panel ai-evaluation-card" data-testid="approval-ledger-events">
        <div className="panel-heading">
          <div>
            <span className="panel-kicker">LECTURA · SOLO OWNER/ADMIN</span>
            <h3>Eventos firmados del workspace</h3>
          </div>
          <span className="ai-evaluation-state ai-state-pending">
            {events.length} eventos
          </span>
        </div>
        {eventsLoading && (
          <div role="status" className="ai-history-empty">
            Cargando el registro de eventos…
          </div>
        )}
        {eventsError && (
          <WorkspaceQueryError
            error={eventsErrorDetail}
            onRetry={onRetryEvents}
            isRetrying={eventsRetrying}
            compact
            testId="status-approval-ledger-events-error"
            buttonTestId="button-retry-approval-ledger-events"
          />
        )}
        {!eventsLoading && !eventsError && events.length === 0 && (
          <div className="ai-history-empty">Todavía no hay eventos registrados.</div>
        )}
        {events.length > 0 && (
          <ol className="ai-history-list">
            {events.map((signedEvent) => (
              <li
                key={signedEvent.event.eventId}
                data-testid={`approval-ledger-event-${signedEvent.event.sequence}`}
              >
                <strong>
                  #{signedEvent.event.sequence} · {signedEvent.event.eventType}
                </strong>
                <span> Aprobación sintética {signedEvent.event.approvalId}</span>
                <code> SHA-256 {signedEvent.eventSha256}</code>
              </li>
            ))}
          </ol>
        )}
        {missingReceiptCount > 0 && (
          <div className="notice notice-error" data-testid="approval-ledger-missing-receipts">
            <p>
              No se puede exportar un bundle completo desde esta sesión: faltan
              {` ${missingReceiptCount} `}recibos que el servidor no conserva.
              Cargue los recibos guardados para continuar.
            </p>
            <ul data-testid="approval-ledger-missing-approval-ids">
              {missingApprovalIds.map((approvalId) => (
                <li key={approvalId}>
                  Falta el recibo para approvalId <code>{approvalId}</code>
                </li>
              ))}
            </ul>
          </div>
        )}
        <section
          className="panel ai-evaluation-card"
          aria-labelledby="approval-receipt-import-title"
          data-testid="approval-receipt-import"
        >
          <h3 id="approval-receipt-import-title">Cargar recibo guardado</h3>
          <p>
            Seleccione un archivo .json o pegue el JSON del recibo firmado v1.
            Se conserva solo en memoria durante esta sesión (máximo 16 KiB).
            El servidor verificará firma y correspondencia al exportar.
          </p>
          <label htmlFor="approval-receipt-file">Archivo JSON del recibo</label>
          <input
            ref={receiptFileInput}
            id="approval-receipt-file"
            type="file"
            accept=".json,application/json"
            data-testid="input-approval-receipt-file"
            disabled={readingReceiptFile || eventsLoading || eventsError}
            onChange={(event) => void handleReceiptFileChange(event)}
          />
          <label htmlFor="approval-receipt-json">O pegue el JSON</label>
          <textarea
            id="approval-receipt-json"
            className="text-input"
            rows={6}
            maxLength={MAX_APPROVAL_RECEIPT_JSON_BYTES + 1}
            value={receiptJson}
            onChange={(event) => setReceiptJson(event.target.value)}
            data-testid="input-approval-receipt-json"
            disabled={readingReceiptFile || eventsLoading || eventsError}
          />
          <Button
            variant="outline"
            type="button"
            data-testid="button-load-approval-receipt"
            disabled={
              readingReceiptFile ||
              eventsLoading ||
              eventsError ||
              receiptJson.trim().length === 0
            }
            onClick={() => acceptSavedReceipt(receiptJson)}
          >
            {readingReceiptFile ? "Leyendo recibo…" : "Cargar recibo guardado"}
          </Button>
          {receiptImportError && (
            <p role="alert" data-testid="status-approval-receipt-import-error">
              {receiptImportError}
            </p>
          )}
          {receiptImportMessage && (
            <p role="status" data-testid="status-approval-receipt-import">
              {receiptImportMessage}
            </p>
          )}
        </section>
        {exportFailure && (
          <p
            className="notice notice-error"
            role="alert"
            data-testid="approval-ledger-export-error"
          >
            {approvalLedgerExportFailureMessage(exportFailure)}
          </p>
        )}
        <div className="ai-evaluation-actions">
          <Button
            variant="outline"
            data-testid="button-export-approval-ledger"
            disabled={
              exporting ||
              eventsLoading ||
              eventsError ||
              missingReceiptCount > 0
            }
            onClick={() => onExport(receiptValues)}
          >
            {exporting ? "Preparando exportación…" : "Descargar bundle JSON"}
          </Button>
        </div>
      </section>
    </section>
  );
}
