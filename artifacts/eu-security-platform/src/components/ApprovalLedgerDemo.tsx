import React, { useMemo, useState } from "react";
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

export type ReceiptConsumeDisplay = {
  httpStatus: number | null;
  response?: AiAssessmentApprovalReceiptConsumeResponse;
};

type ApprovalLedgerDemoProps = {
  receipts: Array<{ approvalId: string; receipt: SignedApprovalReceiptV1 }>;
  consumeResults: Record<string, ReceiptConsumeDisplay>;
  events: SignedApprovalLedgerEventV1[];
  eventsLoading: boolean;
  eventsError: boolean;
  eventsErrorDetail?: unknown;
  eventsRetrying?: boolean;
  exporting: boolean;
  exportFailure?: ApprovalLedgerExportFailure;
  onRetryEvents: () => void;
  onConsume: (approvalId: string, receipt: SignedApprovalReceiptV1) => void;
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
  eventsLoading,
  eventsError,
  eventsErrorDetail,
  eventsRetrying = false,
  exporting,
  exportFailure,
  onRetryEvents,
  onConsume,
  onExport,
}: ApprovalLedgerDemoProps) {
  const [copyMessage, setCopyMessage] = useState("");
  const receiptIndex = useMemo(
    () => new Map(receipts.map(({ receipt }) => [
      receipt.payload.receiptId,
      receipt,
    ])),
    [receipts],
  );
  const missingReceiptCount = useMemo(
    () =>
      events.filter((signedEvent) => {
        if (signedEvent.event.eventType !== "approval.approved") return false;
        const receipt = receiptIndex.get(
          signedEvent.event.payload.receiptId,
        );
        return !receipt ||
          receipt.payloadSha256 !== signedEvent.event.payload.receiptSha256;
      }).length,
    [events, receiptIndex],
  );
  const receiptValues = receipts.map(({ receipt }) => receipt);

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
                  variant="outline"
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
          <p className="notice notice-error" data-testid="approval-ledger-missing-receipts">
            No se puede exportar un bundle completo desde esta sesión: faltan
            {` ${missingReceiptCount} `}recibos que el servidor no conserva.
            Guarde los recibos al aprobar para poder incluirlos.
          </p>
        )}
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
