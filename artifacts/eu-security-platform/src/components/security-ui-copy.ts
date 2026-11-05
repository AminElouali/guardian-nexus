/**
 * Versioned, allow-listed copy for customer-facing security outcomes.
 * Raw engine codes are intentionally never used as a fallback.
 */
export const SECURITY_UI_COPY_VERSION = "guardian-security-ui-copy/1.0.0";

export type PublicSecurityDecision =
  | "allow"
  | "deny"
  | "require_approval"
  | "bypassed_counterfactual"
  | "no_proposal";

type DecisionCopy = {
  label: string;
  tone: "allow" | "deny" | "approval" | "neutral";
  title: string;
  summary: string;
  operationStatus: string;
  executionStatus: string;
  actionNeeded: string;
};

type ReasonCopy = {
  title: string;
  whatHappened: string;
  why: string;
};

const DECISION_COPY: Record<PublicSecurityDecision, DecisionCopy> = {
  allow: {
    label: "Permitido en la simulación",
    tone: "allow",
    title: "La solicitud se autorizó en esta prueba",
    summary: "La propuesta coincidió con los permisos definidos para este escenario sintético.",
    operationStatus: "Permitida en la prueba",
    executionStatus: "Resultado de simulación",
    actionNeeded: "No se requiere ninguna acción real.",
  },
  deny: {
    label: "Bloqueado",
    tone: "deny",
    title: "Se ha bloqueado una solicitud del agente",
    summary: "La solicitud no podía continuar con los permisos disponibles.",
    operationStatus: "Bloqueada",
    executionStatus: "No realizada",
    actionNeeded: "No se requiere ninguna acción real; esta prueba es simulada.",
  },
  require_approval: {
    label: "Requiere aprobación",
    tone: "approval",
    title: "La operación necesita revisión humana",
    summary: "La prueba indica que hace falta autorización antes de continuar.",
    operationStatus: "Pendiente de revisión",
    executionStatus: "No realizada",
    actionNeeded: "Esta previsualización no crea una solicitud persistente de aprobación.",
  },
  bypassed_counterfactual: {
    label: "Solo contrafactual",
    tone: "neutral",
    title: "Resultado hipotético",
    summary: "Este resultado se calculó sobre una copia de prueba y no representa una autorización.",
    operationStatus: "No autorizada",
    executionStatus: "Nunca ejecutada",
    actionNeeded: "No se requiere ninguna acción; el resultado es hipotético.",
  },
  no_proposal: {
    label: "Sin propuesta",
    tone: "neutral",
    title: "No se recibió una propuesta de acción",
    summary: "El agente no propuso una operación en este caso. Esto no es una denegación.",
    operationStatus: "No propuesta",
    executionStatus: "No realizada",
    actionNeeded: "No se requiere ninguna acción.",
  },
};

const REASON_COPY: Record<string, ReasonCopy> = {
  synthetic_policy_allowlist: {
    title: "Acción dentro del alcance de la prueba",
    whatHappened: "La solicitud se mantuvo dentro de los permisos definidos para este escenario.",
    why: "Los permisos de la prueba permitían esta operación limitada.",
  },
  permission_not_granted: {
    title: "Permiso no concedido",
    whatHappened: "Un agente intentó realizar una operación para la que no tenía autorización.",
    why: "La operación no estaba incluida en los permisos concedidos.",
  },
  resource_outside_workspace: {
    title: "Se ha impedido un acceso no autorizado",
    whatHappened: "Un agente intentó consultar información fuera de su espacio de trabajo autorizado.",
    why: "El agente no tenía permiso para acceder a esos datos.",
  },
  delegated_permissions_exceed_parent: {
    title: "La delegación superaba los permisos originales",
    whatHappened: "Un agente delegado intentó utilizar más permisos que el agente que inició la solicitud.",
    why: "La delegación debe conservar el alcance y los permisos originales.",
  },
  external_destination_not_allowed: {
    title: "Destino no autorizado",
    whatHappened: "Un agente intentó enviar información a un destino no permitido en esta prueba.",
    why: "El destino no estaba incluido en el alcance autorizado.",
  },
  human_approval_required: {
    title: "Hace falta aprobación humana",
    whatHappened: "La operación propuesta requiere una revisión antes de poder continuar.",
    why: "La prueba no permite continuar sin una autorización humana.",
  },
  operation_outside_policy: {
    title: "Operación fuera del alcance permitido",
    whatHappened: "Un agente propuso una operación que no estaba permitida en este escenario.",
    why: "La solicitud no coincidía con las operaciones autorizadas.",
  },
  untrusted_content_cannot_authorize_action: {
    title: "Contenido externo sin autoridad",
    whatHappened: "Una instrucción incluida en contenido no confiable intentó cambiar la acción del agente.",
    why: "El contenido recibido no puede conceder permisos ni autorizar operaciones.",
  },
  synthetic_tool_adapter_validation_failed: {
    title: "Solicitud no válida para la prueba",
    whatHappened: "La solicitud no cumplió los requisitos para continuar en el escenario.",
    why: "La operación se detuvo antes de iniciar cualquier acción.",
  },
};

const CASE_LABELS: Record<string, string> = {
  email_benign_read_and_draft: "Preparar un borrador de correo",
  email_adversarial_external_exfiltration: "Intento de envío de información a un destino no autorizado",
  database_benign_scoped_read: "Consultar un registro dentro del espacio autorizado",
  database_adversarial_bulk_export: "Intento de exportar registros fuera del alcance",
  finance_benign_invoice_read: "Consultar una factura de ejemplo",
  finance_adversarial_transfer_request: "Solicitud de transferencia que requiere revisión",
  programming_benign_diff_proposal: "Proponer un cambio de ejemplo",
  programming_adversarial_host_command: "Intento de ejecutar un comando no autorizado",
  support_benign_ticket_reply_draft: "Preparar una respuesta de ejemplo",
  support_adversarial_refund_request: "Solicitud de reembolso que requiere revisión",
  browser_benign_local_page_read: "Consultar una página de ejemplo",
  browser_adversarial_external_form_submit: "Intento de enviar un formulario fuera del alcance",
  infrastructure_benign_config_read: "Consultar una configuración de ejemplo",
  infrastructure_adversarial_admin_grant: "Intento de cambiar permisos de administración",
  multiagent_benign_read_only_delegation: "Delegar una consulta limitada",
  multiagent_adversarial_permission_escalation: "Intento de ampliar permisos mediante delegación",
};

const VERTICAL_LABELS: Record<string, string> = {
  Correo: "Correo",
  "Bases de datos": "Bases de datos",
  Finanzas: "Finanzas",
  Programación: "Programación",
  "Atención al cliente": "Atención al cliente",
  Navegador: "Navegador",
  Infraestructura: "Infraestructura",
  Multiagente: "Multiagente",
};

const INSTRUCTION_SOURCE_LABELS: Record<string, string> = {
  trusted_user_request: "Solicitud del usuario de prueba",
  user_request: "Solicitud del usuario de prueba",
  untrusted_fixture_content: "Contenido no confiable del escenario sintético",
};

const DISPATCH_STATUS_LABELS: Record<string, string> = {
  simulated_execution: "Solo simulada en el estado temporal de la prueba.",
  adapter_validation_denied: "Se detuvo durante la validación; no se realizó.",
  approval_required_before_dispatch: "Se detuvo antes de la revisión humana.",
  blocked_by_policy_before_dispatch: "Se detuvo antes de realizar la operación.",
  counterfactual_clone_only: "Solo cálculo hipotético; no se realizó.",
};

const SAFE_UNKNOWN_REASON: ReasonCopy = {
  title: "Resultado no verificado",
  whatHappened: "La solicitud no pudo verificarse con la información disponible.",
  why: "No se muestra un motivo que no haya sido reconocido y comprobado.",
};

function hasOwnKey<T extends Record<string, unknown>>(record: T, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

export function getPublicDecision(decision: unknown): PublicSecurityDecision | null {
  if (
    typeof decision === "string" &&
    hasOwnKey(DECISION_COPY, decision)
  ) {
    return decision as PublicSecurityDecision;
  }
  return null;
}

export function getPublicDecisionLabel(decision: unknown): string {
  const safeDecision = getPublicDecision(decision);
  return safeDecision ? DECISION_COPY[safeDecision].label : "Resultado no verificado";
}

export function getPublicReasonCopy(reasonCode: unknown): ReasonCopy {
  if (
    typeof reasonCode === "string" &&
    hasOwnKey(REASON_COPY, reasonCode)
  ) {
    return REASON_COPY[reasonCode];
  }
  return SAFE_UNKNOWN_REASON;
}

export function getPublicReasonLabel(reasonCode: unknown): string {
  return getPublicReasonCopy(reasonCode).why;
}

export function getPublicCaseLabel(caseId: unknown): string {
  return typeof caseId === "string" && hasOwnKey(CASE_LABELS, caseId)
    ? CASE_LABELS[caseId]
    : "Solicitud de prueba";
}

export function getPublicVerticalLabel(verticalLabel: unknown): string {
  return typeof verticalLabel === "string" && hasOwnKey(VERTICAL_LABELS, verticalLabel)
    ? VERTICAL_LABELS[verticalLabel]
    : "Agente";
}

export function getPublicInstructionSourceLabel(source: unknown): string {
  return typeof source === "string" && hasOwnKey(INSTRUCTION_SOURCE_LABELS, source)
    ? INSTRUCTION_SOURCE_LABELS[source]
    : "Origen no identificado en esta prueba";
}

export function getPublicDispatchStatusLabel(status: unknown): string {
  return typeof status === "string" && hasOwnKey(DISPATCH_STATUS_LABELS, status)
    ? DISPATCH_STATUS_LABELS[status]
    : "Estado de ejecución no verificado.";
}

export function getPolicyOutcomePresentation(
  decisionValue: unknown,
  reasonCode: unknown,
  executed: boolean,
) {
  const decision = getPublicDecision(decisionValue);
  const outcome = decision ? DECISION_COPY[decision] : {
    ...DECISION_COPY.bypassed_counterfactual,
    label: "Resultado no verificado",
    title: "No se puede verificar el resultado",
    summary: "La información disponible no permite confirmar una decisión.",
    operationStatus: "No verificada",
    executionStatus: executed ? "Ejecución registrada en la prueba" : "No verificada",
    actionNeeded: "Revisa la evidencia de la prueba antes de sacar conclusiones.",
  };
  const reason = getPublicReasonCopy(reasonCode);
  const explanation = decision === "no_proposal"
    ? {
        whatHappened: "El agente no presentó una acción para este caso.",
        why: "Sin una propuesta, no hay una operación que autorizar o bloquear.",
      }
    : decision === "bypassed_counterfactual"
      ? {
          whatHappened: "Se calculó un resultado hipotético sobre una copia de prueba.",
          why: "Este cálculo no concede permiso ni inicia una operación.",
        }
      : reason;
  const execution = executed
    ? decision === "allow"
      ? "La evidencia indica que la acción se realizó dentro de la simulación; no hubo un efecto externo."
      : "La evidencia indica una ejecución, aunque este resultado no la esperaba. Se requiere revisión."
    : decision === "deny"
      ? "No. La solicitud se detuvo antes de realizar la operación."
      : decision === "require_approval"
        ? "No. La prueba no realizó la operación ni creó una solicitud persistente de aprobación."
        : decision === "bypassed_counterfactual"
          ? "No. El resultado hipotético nunca realiza la operación."
          : decision === "no_proposal"
            ? "No. No hubo una propuesta de acción."
            : "No hay constancia de que la operación se realizara.";

  return {
    ...outcome,
    title: decision === "deny" ? reason.title : outcome.title,
    operationStatus: executed && decision !== "allow"
      ? "Resultado que requiere revisión"
      : outcome.operationStatus,
    executionStatus: executed && decision !== "allow"
      ? "Ejecución en revisión"
      : decision === "allow"
        ? executed ? "Realizada en simulación" : "Autorizada, no realizada"
        : outcome.executionStatus,
    whatHappened: explanation.whatHappened,
    why: explanation.why,
    execution: decision === "deny" && executed
      ? "La evidencia indica una ejecución dentro de la simulación; el estado requiere revisión."
      : execution,
    simulationNotice:
      "Este resultado corresponde a una prueba controlada. No representa un intento real ni acredita por sí solo la seguridad de un entorno de producción.",
  };
}
