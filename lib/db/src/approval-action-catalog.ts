export type ApprovalActionDecision = "allow" | "deny" | "require_approval";
export type ApprovalActionValue = string | number | boolean;
export type ApprovalActionService =
  | "email"
  | "support"
  | "finance"
  | "data"
  | "code"
  | "web"
  | "cloud"
  | "multiagent";
export type ApprovalActionProfileId =
  | "guardian-agent-lab-email-v1"
  | "guardian-agent-lab-database-v1"
  | "guardian-agent-lab-finance-v1"
  | "guardian-agent-lab-programming-v1"
  | "guardian-agent-lab-customer-service-v1"
  | "guardian-agent-lab-browser-v1"
  | "guardian-agent-lab-infrastructure-v1"
  | "guardian-agent-lab-multiagent-v1";

export type GenericActionGatewayEvidence = {
  engine: "guardian_action_gateway";
  engineVersion: "guardian-action-catalog-v1" | "guardian-workspace-rules-v2";
  profileId: ApprovalActionProfileId;
  executionMode: "deterministic_fixture";
  modelInference: false;
  toolCallOrigin: "controlled_fixture_not_llm";
  evidenceVersion: 1 | 2;
  actionType: string;
  arguments: Record<string, ApprovalActionValue>;
  actionSha256: string;
  argumentsSha256: string;
  proposalSha256: string;
  ruleId: string;
  decision: "require_approval";
  agentId: string;
  synthetic: true;
  summary: string;
  messagePreview: string;
  requestedByUserId: string;
  workspaceId: string;
  ruleVersionId?: string | null;
  ruleDocumentSha256?: string | null;
  ruleDocument?: {
    version: 1;
    rules: Array<{
      id: string;
      decision: ApprovalActionDecision;
      when: {
        all?: Array<{
          field: string;
          op: "eq" | "gt" | "lte";
          value: string | number | boolean;
        }>;
        any?: Array<{
          field: string;
          op: "eq" | "gt" | "lte";
          value: string | number | boolean;
        }>;
      };
    }>;
  } | null;
  decisionEscalation?: "rule_allow_escalated_to_approval";
  evidenceSha256: string;
};

export const APPROVAL_ACTION_RISK_TYPES = [
  "read",
  "internal_write",
  "external_send",
  "money_movement",
  "permission_change",
  "delete_or_export",
  "execute_or_deploy",
  "corporate_commitment",
] as const;
export type ApprovalActionRiskType =
  (typeof APPROVAL_ACTION_RISK_TYPES)[number];

type PropertyRule = {
  type: "string" | "integer" | "boolean";
  required?: boolean;
  min?: number;
  max?: number;
  maxLength?: number;
  pattern?: RegExp;
  enum?: readonly (string | number | boolean)[];
};

type ActionRule = {
  id: string;
  conditionText: string;
  decision: ApprovalActionDecision;
  when: {
    all?: readonly {
      field: string;
      op: "eq" | "gt" | "lte";
      value: string | number | boolean;
    }[];
    any?: readonly {
      field: string;
      op: "eq" | "gt" | "lte";
      value: string | number | boolean;
    }[];
  };
};

export type ApprovalActionDefinition = {
  actionType: string;
  service: ApprovalActionService;
  profileId: ApprovalActionProfileId;
  label: string;
  description: string;
  readOnly: boolean;
  riskClass: "low" | "medium" | "high";
  riskCategories: readonly (
    | "money"
    | "internal_email"
    | "external_email"
    | "customer_data"
    | "infrastructure"
    | "data"
    | "code"
    | "web"
    | "multiagent"
  )[];
  riskTypes: readonly ApprovalActionRiskType[];
  defaultDecision: "deny";
  allowedApproverRoles: readonly ("owner" | "admin")[];
  receiptExpirySeconds: number;
  requiresIndependentApprover: boolean;
  syntheticTemplateText?: string;
  argumentSchema: {
    type: "object";
    additionalProperties: false;
    properties: Readonly<Record<string, PropertyRule>>;
  };
  rules: readonly ActionRule[];
};

const sandboxRecipient = /^[A-Za-z0-9._+-]+@(?:example\.test|guardian\.invalid)$/;
const internalSandboxRecipient = /^[A-Za-z0-9._+-]+@guardian\.invalid$/;
const syntheticTicket = /^TICKET-SYNTH-[A-Z0-9-]{1,40}$/;
const syntheticAccount = /^LAB-ACCOUNT-[A-Z0-9-]{1,32}$/;
const syntheticId = /^[A-Z][A-Z0-9-]{2,63}$/;
const syntheticRepository = /^REPO-SYNTH-[A-Z0-9-]{1,40}$/;

type CatalogActionInput = Omit<
  ApprovalActionDefinition,
  "defaultDecision" | "allowedApproverRoles" | "receiptExpirySeconds"
>;

function syntheticAction(input: CatalogActionInput): ApprovalActionDefinition {
  return {
    ...input,
    defaultDecision: "deny",
    allowedApproverRoles: ["owner", "admin"],
    receiptExpirySeconds: 300,
  };
}

const additionalApprovalActions: readonly ApprovalActionDefinition[] = [
  syntheticAction({
    actionType: "guardian.email.reply.internal.v1",
    service: "email",
    profileId: "guardian-agent-lab-email-v1",
    label: "Responder correo interno",
    description: "Responde con una plantilla sintética a una conversación interna.",
    readOnly: false,
    riskClass: "low",
    riskCategories: ["internal_email"],
    riskTypes: ["internal_write"],
    requiresIndependentApprover: false,
    syntheticTemplateText: "[SYNTHETIC] Respuesta interna simulada; no se envía a ningún servicio.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        thread_id: { type: "string", required: true, pattern: /^THREAD-SYNTH-[A-Z0-9-]{1,40}$/ },
        to: { type: "string", required: true, maxLength: 254, pattern: internalSandboxRecipient },
        template_id: { type: "string", required: true, enum: ["guardian-internal-reply-v1"] },
      },
    },
    rules: [
      { id: "email.internal-reply.allow.v1", conditionText: "Respuesta a un buzón interno sintético", decision: "allow", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.email.send.external_sensitive.v1",
    service: "email",
    profileId: "guardian-agent-lab-email-v1",
    label: "Enviar correo externo sensible",
    description: "Propone un correo externo con adjuntos o datos de clientes.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["external_email", "customer_data"],
    riskTypes: ["external_send", "delete_or_export"],
    requiresIndependentApprover: false,
    syntheticTemplateText: "[SYNTHETIC] Correo sensible capturado solo en el entorno de pruebas.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        to: { type: "string", required: true, maxLength: 254, pattern: sandboxRecipient },
        template_id: { type: "string", required: true, enum: ["guardian-sensitive-email-v1"] },
        has_attachments: { type: "boolean", required: true },
        contains_customer_data: { type: "boolean", required: true },
      },
    },
    rules: [
      { id: "email.sensitive-external.approval.v1", conditionText: "Correo externo con adjuntos o datos de clientes", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.email.forwarding_rule.create.v1",
    service: "email",
    profileId: "guardian-agent-lab-email-v1",
    label: "Crear regla de reenvío",
    description: "Reenviar buzones o automatizar reenvíos está bloqueado.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["external_email", "customer_data"],
    riskTypes: ["delete_or_export", "external_send"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] La regla de reenvío se bloquea; no se modifica ningún buzón.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        mailbox_id: { type: "string", required: true, pattern: /^MAILBOX-SYNTH-[A-Z0-9-]{1,40}$/ },
        forward_to: { type: "string", required: true, maxLength: 254, pattern: sandboxRecipient },
      },
    },
    rules: [
      { id: "email.forwarding.deny.v1", conditionText: "Los reenvíos automáticos están bloqueados", decision: "deny", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.support.customer_account.close.v1",
    service: "support",
    profileId: "guardian-agent-lab-customer-service-v1",
    label: "Cerrar o borrar cuenta de cliente",
    description: "Acción sintética de cierre o borrado de una cuenta de cliente.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["customer_data"],
    riskTypes: ["delete_or_export"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] La operación de cuenta solo se registra como propuesta de prueba.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        account_id: { type: "string", required: true, pattern: syntheticAccount },
        operation: { type: "string", required: true, enum: ["close", "delete"] },
        case_id: { type: "string", required: true, pattern: syntheticTicket },
      },
    },
    rules: [
      { id: "support.account-close.approval.v1", conditionText: "Cerrar o borrar una cuenta requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.finance.balance_invoice.read.v1",
    service: "finance",
    profileId: "guardian-agent-lab-finance-v1",
    label: "Consultar saldo o factura sintética",
    description: "Lectura de datos financieros ficticios y aislados.",
    readOnly: true,
    riskClass: "low",
    riskCategories: ["money"],
    riskTypes: ["read"],
    requiresIndependentApprover: false,
    syntheticTemplateText: "[SYNTHETIC] Consulta financiera de demostración; no se conecta a bancos.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        resource_type: { type: "string", required: true, enum: ["balance", "invoice"] },
        resource_id: { type: "string", required: true, pattern: /^FIN-SYNTH-[A-Z0-9-]{1,40}$/ },
      },
    },
    rules: [
      { id: "finance.read.allow.v1", conditionText: "Lectura de un recurso financiero sintético", decision: "allow", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.finance.vendor_payment.known.v1",
    service: "finance",
    profileId: "guardian-agent-lab-finance-v1",
    label: "Pagar a proveedor conocido",
    description: "Pago sintético a un proveedor previamente conocido; requiere aprobación.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["money"],
    riskTypes: ["money_movement"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El pago se mantiene como propuesta; no se mueve dinero.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        vendor_id: { type: "string", required: true, pattern: /^VENDOR-SYNTH-[A-Z0-9-]{1,40}$/ },
        amount_cents: { type: "integer", required: true, min: 1, max: 10_000_000 },
        invoice_id: { type: "string", required: true, pattern: /^INVOICE-SYNTH-[A-Z0-9-]{1,40}$/ },
      },
    },
    rules: [
      { id: "finance.known-vendor-payment.approval.v1", conditionText: "El pago a proveedor conocido requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.finance.vendor_payment.new.v1",
    service: "finance",
    profileId: "guardian-agent-lab-finance-v1",
    label: "Pagar a proveedor nuevo",
    description: "Pago sintético a un proveedor nuevo; se bloquea por defecto.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["money"],
    riskTypes: ["money_movement"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El proveedor nuevo queda bloqueado hasta una política explícita.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        vendor_id: { type: "string", required: true, pattern: /^VENDOR-SYNTH-[A-Z0-9-]{1,40}$/ },
        amount_cents: { type: "integer", required: true, min: 1, max: 10_000_000 },
        invoice_id: { type: "string", required: true, pattern: /^INVOICE-SYNTH-[A-Z0-9-]{1,40}$/ },
      },
    },
    rules: [
      { id: "finance.new-vendor-payment.deny.v1", conditionText: "Los pagos a proveedores nuevos quedan bloqueados por defecto", decision: "deny", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.data.query.read.v1",
    service: "data",
    profileId: "guardian-agent-lab-database-v1",
    label: "Consultar datos sintéticos",
    description: "Consulta un conjunto ficticio mediante una consulta predefinida.",
    readOnly: true,
    riskClass: "low",
    riskCategories: ["data"],
    riskTypes: ["read"],
    requiresIndependentApprover: false,
    syntheticTemplateText: "[SYNTHETIC] Consulta de datos ficticios; no ejecuta SQL arbitrario.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        query_id: { type: "string", required: true, enum: ["demo.open-items.v1", "demo.aggregate-counts.v1"] },
        scope_id: { type: "string", required: true, pattern: /^DATA-SYNTH-[A-Z0-9-]{1,40}$/ },
      },
    },
    rules: [
      { id: "data.query.read.allow.v1", conditionText: "Lectura de una consulta sintética predefinida", decision: "allow", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.data.customer.export.v1",
    service: "data",
    profileId: "guardian-agent-lab-database-v1",
    label: "Exportar datos de clientes",
    description: "Exportación sintética de datos de clientes; requiere aprobación.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["data", "customer_data"],
    riskTypes: ["delete_or_export"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] La exportación se registra como propuesta y no contiene datos reales.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        dataset_id: { type: "string", required: true, pattern: /^DATASET-SYNTH-[A-Z0-9-]{1,40}$/ },
        record_limit: { type: "integer", required: true, min: 1, max: 10_000 },
      },
    },
    rules: [
      { id: "data.customer-export.approval.v1", conditionText: "Exportar datos de clientes requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.data.bulk.modify.v1",
    service: "data",
    profileId: "guardian-agent-lab-database-v1",
    label: "Modificar datos en lote",
    description: "Modificación sintética de registros; requiere aprobación.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["data"],
    riskTypes: ["internal_write"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] La modificación en lote no se ejecuta; solo se evalúa.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        dataset_id: { type: "string", required: true, pattern: /^DATASET-SYNTH-[A-Z0-9-]{1,40}$/ },
        operation: { type: "string", required: true, enum: ["set_status", "add_tag"] },
        record_limit: { type: "integer", required: true, min: 1, max: 10_000 },
      },
    },
    rules: [
      { id: "data.bulk-modify.approval.v1", conditionText: "La modificación masiva requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.data.bulk.delete.v1",
    service: "data",
    profileId: "guardian-agent-lab-database-v1",
    label: "Borrar datos en lote",
    description: "El borrado masivo o de tablas está bloqueado.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["data", "customer_data"],
    riskTypes: ["delete_or_export"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El borrado masivo queda bloqueado; no se elimina ningún dato.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        dataset_id: { type: "string", required: true, pattern: /^DATASET-SYNTH-[A-Z0-9-]{1,40}$/ },
        record_limit: { type: "integer", required: true, min: 1, max: 10_000 },
      },
    },
    rules: [
      { id: "data.bulk-delete.deny.v1", conditionText: "El borrado masivo está bloqueado", decision: "deny", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.code.pull_request.open.v1",
    service: "code",
    profileId: "guardian-agent-lab-programming-v1",
    label: "Abrir pull request sintético",
    description: "Prepara una solicitud de cambio ficticia; no accede a repositorios reales.",
    readOnly: false,
    riskClass: "low",
    riskCategories: ["code"],
    riskTypes: ["internal_write"],
    requiresIndependentApprover: false,
    syntheticTemplateText: "[SYNTHETIC] Pull request de demostración; no se contacta GitHub.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        repository_id: { type: "string", required: true, pattern: syntheticRepository },
        title: { type: "string", required: true, maxLength: 120, pattern: /^[A-Za-z0-9][A-Za-z0-9 .:_-]{0,119}$/ },
        source_branch: { type: "string", required: true, maxLength: 80, pattern: /^[a-z0-9][a-z0-9/_-]{0,79}$/ },
      },
    },
    rules: [
      { id: "code.pull-request.open.allow.v1", conditionText: "Abrir un pull request sintético", decision: "allow", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.code.pull_request.merge_main.v1",
    service: "code",
    profileId: "guardian-agent-lab-programming-v1",
    label: "Fusionar en rama principal",
    description: "Fusionar cambios en la rama principal requiere aprobación.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["code"],
    riskTypes: ["execute_or_deploy"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] La fusión queda como propuesta; no modifica repositorios.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        repository_id: { type: "string", required: true, pattern: syntheticRepository },
        pull_request_id: { type: "string", required: true, pattern: /^PR-SYNTH-[A-Z0-9-]{1,40}$/ },
        target_branch: { type: "string", required: true, enum: ["main"] },
      },
    },
    rules: [
      { id: "code.merge-main.approval.v1", conditionText: "Fusionar en main requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.code.deploy.production.v1",
    service: "code",
    profileId: "guardian-agent-lab-programming-v1",
    label: "Desplegar a producción",
    description: "Un despliegue de producción sintético requiere aprobación.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["code", "infrastructure"],
    riskTypes: ["execute_or_deploy"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El despliegue no se ejecuta ni llega a producción.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        release_id: { type: "string", required: true, pattern: /^RELEASE-SYNTH-[A-Z0-9-]{1,40}$/ },
        target_environment: { type: "string", required: true, enum: ["production"] },
        repository_id: { type: "string", required: true, pattern: syntheticRepository },
      },
    },
    rules: [
      { id: "code.deploy-production.approval.v1", conditionText: "Desplegar a producción requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.code.secret.access.v1",
    service: "code",
    profileId: "guardian-agent-lab-programming-v1",
    label: "Leer o cambiar secretos",
    description: "El acceso a secretos está bloqueado en esta demo.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["code"],
    riskTypes: ["read", "permission_change"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El acceso a secretos está bloqueado.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        repository_id: { type: "string", required: true, pattern: syntheticRepository },
        operation: { type: "string", required: true, enum: ["read", "change"] },
        secret_ref: { type: "string", required: true, pattern: /^SECRET-REF-SYNTH-[A-Z0-9-]{1,40}$/ },
      },
    },
    rules: [
      { id: "code.secrets.deny.v1", conditionText: "Leer o cambiar secretos está bloqueado", decision: "deny", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.web.navigate.read.v1",
    service: "web",
    profileId: "guardian-agent-lab-browser-v1",
    label: "Navegar y leer página sintética",
    description: "Consulta un contenido local de demostración, sin navegar por internet.",
    readOnly: true,
    riskClass: "low",
    riskCategories: ["web"],
    riskTypes: ["read"],
    requiresIndependentApprover: false,
    syntheticTemplateText: "[SYNTHETIC] Página de prueba local; no se realiza ninguna conexión web.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        page_id: { type: "string", required: true, pattern: /^PAGE-SYNTH-[A-Z0-9-]{1,40}$/ },
        host: { type: "string", required: true, enum: ["example.test", "docs.example.test"] },
      },
    },
    rules: [
      { id: "web.navigate.read.allow.v1", conditionText: "Lectura de una página sintética permitida", decision: "allow", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.web.personal_data.submit.v1",
    service: "web",
    profileId: "guardian-agent-lab-browser-v1",
    label: "Enviar formulario con datos personales",
    description: "El envío de datos personales simulados requiere aprobación.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["web", "customer_data"],
    riskTypes: ["external_send"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El formulario no se envía a un sitio externo.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        form_id: { type: "string", required: true, pattern: /^FORM-SYNTH-[A-Z0-9-]{1,40}$/ },
        host: { type: "string", required: true, enum: ["example.test", "docs.example.test"] },
        data_class: { type: "string", required: true, enum: ["personal"] },
      },
    },
    rules: [
      { id: "web.personal-form.approval.v1", conditionText: "Enviar datos personales requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.web.purchase.v1",
    service: "web",
    profileId: "guardian-agent-lab-browser-v1",
    label: "Comprar o pagar",
    description: "La compra sintética requiere aprobación y no mueve dinero.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["web", "money"],
    riskTypes: ["money_movement", "corporate_commitment"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] La compra se registra solo como una propuesta.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        item_id: { type: "string", required: true, pattern: /^ITEM-SYNTH-[A-Z0-9-]{1,40}$/ },
        amount_cents: { type: "integer", required: true, min: 1, max: 10_000_000 },
        host: { type: "string", required: true, enum: ["example.test"] },
      },
    },
    rules: [
      { id: "web.purchase.approval.v1", conditionText: "Comprar o pagar requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.web.unapproved_credentials.submit.v1",
    service: "web",
    profileId: "guardian-agent-lab-browser-v1",
    label: "Introducir credenciales en sitio no aprobado",
    description: "Introducir credenciales en sitios no aprobados está bloqueado.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["web"],
    riskTypes: ["permission_change", "external_send"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] La entrada de credenciales está bloqueada.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        host: { type: "string", required: true, maxLength: 253, pattern: /^[a-z0-9.-]+$/ },
        credential_ref: { type: "string", required: true, pattern: /^CREDENTIAL-REF-SYNTH-[A-Z0-9-]{1,40}$/ },
      },
    },
    rules: [
      { id: "web.unapproved-credentials.deny.v1", conditionText: "No se introducen credenciales en sitios no aprobados", decision: "deny", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.cloud.resource.read.v1",
    service: "cloud",
    profileId: "guardian-agent-lab-infrastructure-v1",
    label: "Consultar recursos o costes cloud",
    description: "Lectura de infraestructura ficticia sin acceso a una cuenta cloud.",
    readOnly: true,
    riskClass: "low",
    riskCategories: ["infrastructure"],
    riskTypes: ["read"],
    requiresIndependentApprover: false,
    syntheticTemplateText: "[SYNTHETIC] Vista de recursos y costes de laboratorio; sin conexión cloud.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        resource_id: { type: "string", required: true, pattern: /^CLOUD-SYNTH-[A-Z0-9-]{1,40}$/ },
        view: { type: "string", required: true, enum: ["resource", "cost"] },
      },
    },
    rules: [
      { id: "cloud.resource-read.allow.v1", conditionText: "Lectura de recursos y costes sintéticos", decision: "allow", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.cloud.resource.create.v1",
    service: "cloud",
    profileId: "guardian-agent-lab-infrastructure-v1",
    label: "Crear recurso cloud con coste",
    description: "Crear recursos potencialmente facturables requiere aprobación.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["infrastructure", "money"],
    riskTypes: ["money_movement", "internal_write"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El recurso queda como propuesta; no se crea en cloud.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        resource_type: { type: "string", required: true, enum: ["compute", "storage", "database"] },
        resource_id: { type: "string", required: true, pattern: /^CLOUD-SYNTH-[A-Z0-9-]{1,40}$/ },
        estimated_cost_cents: { type: "integer", required: true, min: 0, max: 10_000_000 },
      },
    },
    rules: [
      { id: "cloud.resource-create.approval.v1", conditionText: "Crear recursos con coste requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.cloud.iam.permission.change.v1",
    service: "cloud",
    profileId: "guardian-agent-lab-infrastructure-v1",
    label: "Cambiar permisos IAM",
    description: "Los cambios de permisos cloud requieren aprobación.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["infrastructure"],
    riskTypes: ["permission_change"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El cambio IAM queda como propuesta; no cambia permisos reales.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        principal_id: { type: "string", required: true, pattern: /^PRINCIPAL-SYNTH-[A-Z0-9-]{1,40}$/ },
        role_id: { type: "string", required: true, pattern: /^ROLE-SYNTH-[A-Z0-9-]{1,40}$/ },
      },
    },
    rules: [
      { id: "cloud.iam-change.approval.v1", conditionText: "Cambiar permisos IAM requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.cloud.production_destructive.v1",
    service: "cloud",
    profileId: "guardian-agent-lab-infrastructure-v1",
    label: "Borrar recurso de producción o hacer público almacenamiento",
    description: "Las acciones cloud destructivas o de exposición pública están bloqueadas.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["infrastructure", "data"],
    riskTypes: ["delete_or_export", "permission_change"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] La acción destructiva cloud queda bloqueada.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        operation: { type: "string", required: true, enum: ["delete_production_resource", "make_storage_public"] },
        resource_id: { type: "string", required: true, pattern: /^CLOUD-SYNTH-[A-Z0-9-]{1,40}$/ },
      },
    },
    rules: [
      { id: "cloud.production-destructive.deny.v1", conditionText: "Borrar producción o hacer público un bucket está bloqueado", decision: "deny", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.multiagent.delegate_equal_or_lower.v1",
    service: "multiagent",
    profileId: "guardian-agent-lab-multiagent-v1",
    label: "Delegar con permisos iguales o menores",
    description: "Delegación sintética a un agente con alcance igual o menor.",
    readOnly: false,
    riskClass: "medium",
    riskCategories: ["multiagent"],
    riskTypes: ["permission_change"],
    requiresIndependentApprover: false,
    syntheticTemplateText: "[SYNTHETIC] La delegación solo se evalúa; no se transmite ninguna credencial.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        target_agent_id: { type: "string", required: true, pattern: /^AGENT-SYNTH-[A-Z0-9-]{1,40}$/ },
        permission_scope: { type: "string", required: true, enum: ["read", "propose", "execute-synthetic"] },
      },
    },
    rules: [
      { id: "multiagent.delegate-same-or-lower.allow.v1", conditionText: "Delegación con alcance igual o menor", decision: "allow", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.multiagent.delegate_higher_scope.v1",
    service: "multiagent",
    profileId: "guardian-agent-lab-multiagent-v1",
    label: "Delegar con permisos superiores",
    description: "Delegar a un agente con más permisos requiere aprobación.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["multiagent"],
    riskTypes: ["permission_change"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] La delegación de permisos superiores no cambia credenciales.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        target_agent_id: { type: "string", required: true, pattern: /^AGENT-SYNTH-[A-Z0-9-]{1,40}$/ },
        requested_scope: { type: "string", required: true, enum: ["admin", "owner"] },
      },
    },
    rules: [
      { id: "multiagent.delegate-higher.approval.v1", conditionText: "Delegar permisos superiores requiere aprobación", decision: "require_approval", when: {} },
    ],
  }),
  syntheticAction({
    actionType: "guardian.multiagent.privilege_escalation.v1",
    service: "multiagent",
    profileId: "guardian-agent-lab-multiagent-v1",
    label: "Autoasignar permisos o eludir aprobación",
    description: "La autoasignación de permisos y la elusión por otro agente están bloqueadas.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["multiagent"],
    riskTypes: ["permission_change"],
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El intento de escalada de privilegios queda bloqueado.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        operation: { type: "string", required: true, enum: ["self_assign", "bypass_approval"] },
        target_agent_id: { type: "string", required: true, pattern: /^AGENT-SYNTH-[A-Z0-9-]{1,40}$/ },
      },
    },
    rules: [
      { id: "multiagent.privilege-escalation.deny.v1", conditionText: "Autoasignar permisos o eludir aprobación está bloqueado", decision: "deny", when: {} },
    ],
  }),
];

// This is the shared source of action identifiers and policy templates. The
// database CHECK is generated from APPROVAL_ACTION_REFS below; SQL deployments
// mirror that exact list in lib/db/sql/rls-policies.sql.
export const APPROVAL_ACTION_CATALOG: readonly ApprovalActionDefinition[] = [
  {
    actionType: "guardian.synthetic.support.refund.v1",
    service: "support",
    profileId: "guardian-agent-lab-customer-service-v1",
    label: "Reembolso sintético",
    description: "Fixture existente; solo simula cambios en memoria.",
    readOnly: false,
    riskClass: "medium",
    riskCategories: ["money", "customer_data"],
    riskTypes: ["money_movement"],
    defaultDecision: "deny",
    allowedApproverRoles: ["owner", "admin"],
    receiptExpirySeconds: 300,
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El reembolso solo se evalúa en un clon de memoria.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        ticket_id: { type: "string", required: true, pattern: syntheticTicket },
        amount_cents: { type: "integer", required: true, min: 1, max: 1000000 },
      },
    },
    rules: [
      { id: "refund.fixture.requires-independent-approval.v1", conditionText: "Importe de la fixture dentro del límite sintético", decision: "require_approval", when: {} },
    ],
  },
  {
    actionType: "guardian.synthetic.finance.bank-change.v1",
    service: "finance",
    profileId: "guardian-agent-lab-finance-v1",
    label: "Cambio bancario sintético",
    description: "Fixture existente; solo simula cambios en memoria.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["money", "infrastructure"],
    riskTypes: ["internal_write", "money_movement"],
    defaultDecision: "deny",
    allowedApproverRoles: ["owner", "admin"],
    receiptExpirySeconds: 300,
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El cambio bancario solo se evalúa en un clon de memoria.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        account_id: { type: "string", required: true, pattern: syntheticAccount },
        new_iban: { type: "string", required: true, pattern: /^DE00LAB[0-9A-Z]{16}$/ },
      },
    },
    rules: [
      { id: "bank-change.fixture.requires-independent-approval.v1", conditionText: "Cambio bancario de laboratorio", decision: "require_approval", when: {} },
    ],
  },
  {
    actionType: "guardian.support.reply.send.v1",
    service: "support",
    profileId: "guardian-agent-lab-customer-service-v1",
    label: "Responder a soporte",
    description: "Solo ejemplos sintéticos dirigidos a dominios de prueba.",
    readOnly: false,
    riskClass: "medium",
    riskCategories: ["customer_data", "internal_email", "external_email"],
    riskTypes: ["internal_write", "external_send"],
    defaultDecision: "deny",
    allowedApproverRoles: ["owner", "admin"],
    receiptExpirySeconds: 300,
    requiresIndependentApprover: false,
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        ticket_id: { type: "string", required: true, pattern: syntheticTicket },
        recipient_email: { type: "string", required: true, maxLength: 254, pattern: sandboxRecipient },
        recipient_type: { type: "string", required: true, enum: ["internal", "external"] },
        compensation_cents: { type: "integer", required: true, min: 0, max: 1000000 },
        template_id: { type: "string", required: true, enum: ["synthetic-support-reply-v1"] },
      },
    },
    syntheticTemplateText:
      "[SYNTHETIC] Gracias por contactar con soporte. Este mensaje solo se captura en el buzón local de pruebas.",
    rules: [
      { id: "support.compensation.over-50-eur.approval.v1", conditionText: "Compensación superior a 50 EUR", decision: "require_approval", when: { any: [{ field: "compensation_cents", op: "gt", value: 5000 }] } },
      { id: "support.internal.no-compensation.allow.v1", conditionText: "Destinatario interno y sin compensación", decision: "allow", when: { all: [{ field: "recipient_type", op: "eq", value: "internal" }, { field: "compensation_cents", op: "eq", value: 0 }] } },
      { id: "support.external-or-compensation.approval.v1", conditionText: "Destinatario externo o compensación de hasta 50 EUR", decision: "require_approval", when: {} },
    ],
  },
  {
    actionType: "guardian.email.send.external.v1",
    service: "email",
    profileId: "guardian-agent-lab-email-v1",
    label: "Enviar correo externo de prueba",
    description: "Entrega solo a un buzón sandbox local; no usa proveedores externos.",
    readOnly: false,
    riskClass: "high",
    riskCategories: ["external_email"],
    riskTypes: ["external_send"],
    defaultDecision: "deny",
    allowedApproverRoles: ["owner", "admin"],
    receiptExpirySeconds: 300,
    requiresIndependentApprover: true,
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        to: { type: "string", required: true, maxLength: 254, pattern: sandboxRecipient },
        template_id: { type: "string", required: true, enum: ["guardian-demo-email-v1"] },
      },
    },
    syntheticTemplateText:
      "[SYNTHETIC] Mensaje de prueba de Guardian Nexus. Capturado localmente; no se entrega a un proveedor externo.",
    rules: [
      { id: "external-email.sandbox.requires-independent-approval.v1", conditionText: "Correo de prueba enviado únicamente al buzón sandbox", decision: "require_approval", when: {} },
    ],
  },
  ...additionalApprovalActions,
] as const;

export const APPROVAL_ACTION_REFS = APPROVAL_ACTION_CATALOG.map(
  (action) => action.actionType,
) as readonly string[];

export type CatalogActionRef = (typeof APPROVAL_ACTION_CATALOG)[number]["actionType"];

export function isCatalogActionRef(value: string): value is CatalogActionRef {
  return APPROVAL_ACTION_REFS.includes(value);
}

export function getApprovalActionDefinition(
  actionType: string,
): ApprovalActionDefinition | undefined {
  return APPROVAL_ACTION_CATALOG.find((action) => action.actionType === actionType);
}

export function validateApprovalActionArguments(
  definition: ApprovalActionDefinition,
  value: unknown,
): { ok: true; args: Record<string, ApprovalActionValue> } | { ok: false; issues: string[] } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, issues: ["arguments_not_object"] };
  }
  const input = value as Record<string, unknown>;
  const allowedKeys = new Set(Object.keys(definition.argumentSchema.properties));
  const issues: string[] = [];
  for (const key of Object.keys(input)) {
    if (!allowedKeys.has(key)) issues.push(`unknown_argument:${key}`);
  }
  const args: Record<string, ApprovalActionValue> = {};
  for (const [key, rule] of Object.entries(definition.argumentSchema.properties)) {
    const item = input[key];
    if (item === undefined) {
      if (rule.required) issues.push(`missing_argument:${key}`);
      continue;
    }
    if (
      rule.type === "string" &&
      (typeof item !== "string" ||
        (rule.maxLength !== undefined && item.length > rule.maxLength) ||
        (rule.pattern !== undefined && !rule.pattern.test(item)) ||
        (rule.enum !== undefined && !rule.enum.includes(item)))
    ) {
      issues.push(`invalid_argument:${key}`);
      continue;
    }
    if (
      rule.type === "integer" &&
      (typeof item !== "number" ||
        !Number.isSafeInteger(item) ||
        (rule.min !== undefined && item < rule.min) ||
        (rule.max !== undefined && item > rule.max))
    ) {
      issues.push(`invalid_argument:${key}`);
      continue;
    }
    if (rule.type === "boolean" && typeof item !== "boolean") {
      issues.push(`invalid_argument:${key}`);
      continue;
    }
    args[key] = item as ApprovalActionValue;
  }
  return issues.length ? { ok: false, issues } : { ok: true, args };
}

function matchesRuleAtom(
  args: Readonly<Record<string, ApprovalActionValue>>,
  condition: NonNullable<ActionRule["when"]["all"]>[number],
): boolean {
  const actual = args[condition.field];
  if (condition.op === "eq") return actual === condition.value;
  if (typeof actual !== "number" || typeof condition.value !== "number") return false;
  return condition.op === "gt" ? actual > condition.value : actual <= condition.value;
}

export function evaluateApprovalAction(
  actionType: string,
  value: unknown,
): {
  ok: true;
  decision: ApprovalActionDecision;
  reasonCode: string;
  ruleId: string | null;
  definition: ApprovalActionDefinition;
  args: Record<string, ApprovalActionValue>;
} | {
  ok: false;
  decision: "deny";
  reasonCode: "unknown_action" | "arguments_invalid";
  issues: string[];
} {
  const definition = getApprovalActionDefinition(actionType);
  if (!definition) {
    return { ok: false, decision: "deny", reasonCode: "unknown_action", issues: [] };
  }
  const validated = validateApprovalActionArguments(definition, value);
  if (!validated.ok) {
    return {
      ok: false,
      decision: "deny",
      reasonCode: "arguments_invalid",
      issues: validated.issues,
    };
  }
  for (const rule of definition.rules) {
    const allMatch = rule.when.all?.every((condition) =>
      matchesRuleAtom(validated.args, condition),
    ) ?? true;
    const anyMatch = rule.when.any?.some((condition) =>
      matchesRuleAtom(validated.args, condition),
    ) ?? true;
    if (allMatch && anyMatch) {
      return {
        ok: true,
        decision: rule.decision,
        reasonCode: rule.decision === "deny"
          ? "blocked_by_template"
          : rule.decision === "allow"
            ? "allowed_by_template"
            : "human_approval_required",
        ruleId: rule.id,
        definition,
        args: validated.args,
      };
    }
  }
  return {
    ok: true,
    decision: definition.defaultDecision,
    reasonCode: "default_block",
    ruleId: null,
    definition,
    args: validated.args,
  };
}
