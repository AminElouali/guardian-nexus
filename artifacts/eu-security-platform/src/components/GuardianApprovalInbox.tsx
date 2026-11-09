import React from "react";
import type { AiAssessmentApproval } from "@workspace/api-client-react";
import { Button } from "@/components/ui/button";

type ApprovalDecision = "approve" | "deny";

type GuardianApprovalInboxProps = {
  approvals: AiAssessmentApproval[];
  canDecide: boolean;
  loading: boolean;
  error: boolean;
  mutationPending: boolean;
  message: string;
  errorMessage: string;
  onRetry: () => void;
  onDecision: (
    approvalId: string,
    proposalBindingSha256: string,
    decision: ApprovalDecision,
  ) => void;
};

export function GuardianApprovalInbox({
  approvals,
  canDecide,
  loading,
  error,
  mutationPending,
  message,
  errorMessage,
  onRetry,
  onDecision,
}: GuardianApprovalInboxProps) {
  function describeAction(approval: AiAssessmentApproval) {
    if (approval.syntheticActionRef === "guardian.synthetic.finance.bank-change.v1") {
      return {
        action: "Revisar un cambio de cuenta bancaria ficticio",
        scope: "Datos financieros sintéticos; no se modifica ninguna cuenta real.",
        risk: "Riesgo considerado: cambio de datos de pago sin autorización.",
      };
    }
    if (approval.syntheticActionRef === "guardian.synthetic.support.refund.v1") {
      return {
        action: "Revisar una solicitud de reembolso ficticia",
        scope: "Cuenta y solicitud de soporte sintéticas; no se emite ningún reembolso.",
        risk: "Riesgo considerado: aprobar un reembolso sin la revisión correspondiente.",
      };
    }
    return {
      action: "Acción sintética; el detalle no está disponible en este registro.",
      scope: "El alcance concreto no consta en los datos de la solicitud.",
      risk: "No hay información suficiente para describir un riesgo específico.",
    };
  }

  function confirmDecision(
    approval: AiAssessmentApproval,
    decision: ApprovalDecision,
  ) {
    if (decision === "approve") {
      const { action, scope } = describeAction(approval);
      const confirmed = window.confirm(
        `Confirmación de impacto sintético\n\n${action}.\n${scope}\n\nLa aprobación puede registrar una simulación en memoria, pero no ejecuta herramientas ni afecta sistemas externos. ¿Quieres continuar?`,
      );
      if (!confirmed) return;
    }
    onDecision(
      approval.id,
      approval.proposalBindingSha256,
      decision,
    );
  }

  return (
    <section id="guardian-approval-inbox" className="panel ai-evaluation-history" data-testid="approval-inbox">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">REVISIÓN HUMANA · SOLO LABORATORIO</span>
          <h2>Bandeja de aprobaciones</h2>
        </div>
        <span className="ai-evaluation-state ai-state-pending">
          <i /> Sin acciones externas
        </span>
      </div>
      <p>
        Apruebe o deniegue propuestas sintéticas vinculadas a evidencia
        verificable. Solo dos acciones allow-listed pueden simularse una vez en
        una copia efímera en memoria; nunca se llama a herramientas ni sistemas
        externos.
      </p>
      {message && (
        <div className="notice notice-success" role="status" data-testid="approval-success">
          {message}
        </div>
      )}
      {errorMessage && (
        <div className="notice notice-error" role="alert" data-testid="approval-error">
          {errorMessage}
        </div>
      )}
      {loading && (
        <div className="ai-history-empty" role="status">
          Cargando aprobaciones de este espacio…
        </div>
      )}
      {error && (
        <div className="notice notice-error" role="alert">
          No se pudo cargar la bandeja.{" "}
          <Button variant="outline" onClick={onRetry} data-testid="button-retry-approvals">
            Reintentar
          </Button>
        </div>
      )}
      {!loading && !error && approvals.length === 0 && (
        <div className="ai-history-empty" data-testid="approval-empty">
          No hay propuestas pendientes; no se generan aprobaciones ficticias.
        </div>
      )}
      {approvals.length > 0 && (
        <div className="ai-history-list">
          {approvals.map((approval) => {
            const provenanceLabel =
              approval.modelInference === true &&
              approval.executionMode === "real_local_qwen_inference" &&
              approval.toolCallOrigin === "guardian_qwen_native_markup_adapter"
                ? "Inferencia Qwen local · marcador adaptado; no es tool call nativa"
                : approval.modelInference === true &&
                    approval.executionMode === "real_local_qwen_inference" &&
                    approval.toolCallOrigin === "runtime_message_tool_calls"
                  ? "Inferencia Qwen local · message.tool_calls nativa"
                  : approval.modelInference === false &&
                      approval.executionMode === "deterministic_fixture" &&
                      approval.toolCallOrigin === "controlled_fixture_not_llm"
                    ? "Fixture determinista · no es inferencia de modelo"
                    : "Procedencia no verificada en este registro";
            const publicProvenanceLabel =
              approval.modelInference === false &&
              approval.executionMode === "deterministic_fixture" &&
              approval.toolCallOrigin === "controlled_fixture_not_llm"
                ? "Prueba sintética controlada"
                : approval.modelInference === true &&
                    approval.executionMode === "real_local_qwen_inference" &&
                    approval.toolCallOrigin === "guardian_qwen_native_markup_adapter"
                  ? "Propuesta adaptada en laboratorio"
                  : approval.modelInference === true &&
                      approval.executionMode === "real_local_qwen_inference" &&
                      approval.toolCallOrigin === "runtime_message_tool_calls"
                    ? "Propuesta estructurada recibida en laboratorio"
                    : "Procedencia no verificada";
            const actionInfo = describeAction(approval);
            const statusLabel = {
              pending: "Pendiente",
              approved:
                approval.execution === "synthetic_action_simulated_once"
                  ? "Aprobada · simulación sintética realizada una vez"
                  : "Aprobada · solo decisión",
              denied: "Denegada",
              expired: "Caducada",
            }[approval.status];
            return (
              <article
                className="panel ai-evaluation-card"
                key={approval.id}
                data-testid={`approval-card-${approval.id}`}
              >
                <div className="panel-heading">
                  <div>
                    <span className="panel-kicker">
                      PROPUESTA SINTÉTICA
                    </span>
                    <h3>Propuesta requiere revisión</h3>
                  </div>
                  <span
                    className={`ai-evaluation-state ${approval.status === "pending" ? "ai-state-pending" : "ai-state-complete"}`}
                    data-testid={`approval-status-${approval.id}`}
                  >
                    <i /> {statusLabel}
                  </span>
                </div>
                <dl className="approval-summary" data-testid={`approval-summary-${approval.id}`}>
                  <div><dt>Solicitud</dt><dd>{actionInfo.action}</dd></div>
                  <div><dt>Origen</dt><dd data-testid={`approval-provenance-${approval.id}`}>{canDecide ? provenanceLabel : publicProvenanceLabel}</dd></div>
                  <div><dt>Riesgo considerado</dt><dd>{actionInfo.risk}</dd></div>
                  <div><dt>Alcance</dt><dd>{actionInfo.scope}</dd></div>
                  <div><dt>Motivo</dt><dd>No hay un motivo de texto en el registro de la API.</dd></div>
                  <div><dt>Caducidad</dt><dd>{new Date(approval.expiresAt).toLocaleString("es-ES")}</dd></div>
                </dl>
                {canDecide && <details className="approval-technical-details">
                  <summary>Procedencia técnica y vínculo de evidencia</summary>
                  <p>Job: {approval.jobId}</p>
                  <p>SHA-256 de propuesta: {approval.proposalSha256}</p>
                  <p>SHA-256 de vínculo: {approval.proposalBindingSha256}</p>
                </details>}
                {approval.status === "pending" &&
                  canDecide &&
                  !approval.canCurrentUserDecide && (
                    <small>
                      La solicitud debe revisarla otro owner/admin. El solicitante
                      no puede aprobarla.
                    </small>
                  )}
                {approval.canCurrentUserDecide &&
                  approval.status === "pending" && (
                    <div className="ai-evaluation-actions">
                      <Button
                        onClick={() =>
                          confirmDecision(approval, "approve")
                        }
                        disabled={mutationPending}
                        data-testid={`button-approve-${approval.id}`}
                      >
                      Aprobar · solo laboratorio
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() =>
                          confirmDecision(approval, "deny")
                        }
                        disabled={mutationPending}
                        data-testid={`button-deny-${approval.id}`}
                      >
                        Denegar
                      </Button>
                    </div>
                  )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}
