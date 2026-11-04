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
  return (
    <section className="panel ai-evaluation-history" data-testid="approval-inbox">
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
                      CASO SINTÉTICO · {approval.caseId}
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
                <p>
                  Solicitud de un miembro del espacio; caduca{" "}
                  {new Date(approval.expiresAt).toLocaleString("es-ES")}.
                </p>
                <details>
                  <summary>Vínculo de evidencia y trazabilidad</summary>
                  <p>Job: {approval.jobId}</p>
                  <p data-testid={`approval-provenance-${approval.id}`}>
                    Origen: {provenanceLabel}
                  </p>
                  <p>SHA-256 de propuesta: {approval.proposalSha256}</p>
                  <p>SHA-256 de vínculo: {approval.proposalBindingSha256}</p>
                </details>
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
                          onDecision(
                            approval.id,
                            approval.proposalBindingSha256,
                            "approve",
                          )
                        }
                        disabled={mutationPending}
                        data-testid={`button-approve-${approval.id}`}
                      >
                      Aprobar · solo laboratorio
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() =>
                          onDecision(
                            approval.id,
                            approval.proposalBindingSha256,
                            "deny",
                          )
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
