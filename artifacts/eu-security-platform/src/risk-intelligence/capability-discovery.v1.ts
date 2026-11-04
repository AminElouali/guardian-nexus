import {
  RISK_INTELLIGENCE_CATALOG,
  type AgentRiskProfile,
  type RiskProfileId,
} from "./catalog.v1";

export type DataSensitivity = "public" | "internal" | "confidential" | "secret";

/**
 * Advisory-only declarations. This schema intentionally has no tenant, actor,
 * identity, approval, authorization, policy-decision, or execution fields.
 */
export interface DeclaredAgentCapabilities {
  profileId: RiskProfileId;
  toolNames: string[];
  permissionNames: string[];
  dataSensitivity: DataSensitivity;
  untrustedInputs: boolean;
  externalRecipients: boolean;
  persistentEffects: boolean;
  destructiveOperations: boolean;
  privilegeChanges: boolean;
  delegation: boolean;
  approvalRequired: boolean;
  dependencies: string[];
}

export interface CapabilityRiskFinding {
  findingId: string;
  title: string;
  rationale: string;
  classification: "known_source_concept" | "inferred_from_declared_capability";
  validationState: "pending_validation" | "confirmed_by_test";
  sourceRefs: string[];
  riskItemRefs: string[];
  recommendation: string;
}

export interface CapabilityAnalysis {
  schemaVersion: "guardian-capability-discovery/1.0.0";
  profileId: RiskProfileId;
  mode: "local_advisory_only";
  declaredCounts: {
    tools: number;
    permissions: number;
    dependencies: number;
  };
  findings: CapabilityRiskFinding[];
  decisionAuthority: "guardian_policy_engine_only";
  policyDecision: null;
  actionDispatched: false;
  evidenceNote: string;
}

const PROFILE_IDS = new Set<string>(
  RISK_INTELLIGENCE_CATALOG.profiles.map((profile) => profile.id),
);
const DECLARATION_KEYS = [
  "profileId",
  "toolNames",
  "permissionNames",
  "dataSensitivity",
  "untrustedInputs",
  "externalRecipients",
  "persistentEffects",
  "destructiveOperations",
  "privilegeChanges",
  "delegation",
  "approvalRequired",
  "dependencies",
].sort();
const ALLOWED_SENSITIVITY = new Set<DataSensitivity>([
  "public",
  "internal",
  "confidential",
  "secret",
]);

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  try {
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function assertStringList(value: unknown, key: string): asserts value is string[] {
  if (
    !Array.isArray(value) ||
    value.length > 12 ||
    value.some(
      (entry) =>
        typeof entry !== "string" ||
        entry.trim().length === 0 ||
        entry.length > 80 ||
        /[\u0000-\u001f]/u.test(entry),
    )
  ) {
    throw new Error(`risk_capability_${key}_invalid`);
  }
}

function validateDeclaration(
  input: unknown,
): asserts input is DeclaredAgentCapabilities {
  if (!isPlainRecord(input)) {
    throw new Error("risk_capability_declaration_invalid");
  }
  const keys = Object.keys(input).sort();
  if (
    keys.length !== DECLARATION_KEYS.length ||
    keys.some((key, index) => key !== DECLARATION_KEYS[index])
  ) {
    throw new Error("risk_capability_declaration_schema_mismatch");
  }
  if (typeof input.profileId !== "string" || !PROFILE_IDS.has(input.profileId)) {
    throw new Error("risk_capability_profile_invalid");
  }
  assertStringList(input.toolNames, "tools");
  assertStringList(input.permissionNames, "permissions");
  assertStringList(input.dependencies, "dependencies");
  if (
    typeof input.dataSensitivity !== "string" ||
    !ALLOWED_SENSITIVITY.has(input.dataSensitivity as DataSensitivity)
  ) {
    throw new Error("risk_capability_sensitivity_invalid");
  }
  for (const key of [
    "untrustedInputs",
    "externalRecipients",
    "persistentEffects",
    "destructiveOperations",
    "privilegeChanges",
    "delegation",
    "approvalRequired",
  ] as const) {
    if (typeof input[key] !== "boolean") {
      throw new Error("risk_capability_signal_invalid");
    }
  }
}

function profileFor(id: RiskProfileId): AgentRiskProfile {
  const profile = RISK_INTELLIGENCE_CATALOG.profiles.find(
    (candidate) => candidate.id === id,
  );
  if (!profile) {
    throw new Error("risk_capability_profile_invalid");
  }
  return profile;
}

type Signal =
  | "tool_surface"
  | "dependency_boundary"
  | "untrusted_input"
  | "sensitive_data"
  | "external_recipient"
  | "persistent_effect"
  | "destructive_operation"
  | "privilege_change"
  | "delegation"
  | "approval_boundary";

function selectedRiskItems(profile: AgentRiskProfile, signal: Signal): string[] {
  const preferred = {
    tool_surface: [profile.hazards[0], profile.unsafeControlActions[0]],
    dependency_boundary: [profile.causalScenarios[0], profile.constraints[0]],
    untrusted_input: [profile.hazards[0], profile.unsafeControlActions[0]],
    sensitive_data: [profile.losses[0], profile.constraints[profile.constraints.length - 1]],
    external_recipient: [profile.unsafeControlActions[0], profile.hazards[0]],
    persistent_effect: [profile.unsafeControlActions[1], profile.constraints[1]],
    destructive_operation: [profile.hazards[1], profile.unsafeControlActions[1]],
    privilege_change: [profile.hazards[1], profile.unsafeControlActions[0]],
    delegation: [profile.hazards[1], profile.unsafeControlActions[1]],
    approval_boundary: [
      profile.causalScenarios[profile.causalScenarios.length - 1],
      profile.constraints[profile.constraints.length - 1],
    ],
  }[signal];
  return [
    ...new Set(
      preferred
        .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry))
        .map((entry) => entry.id),
    ),
  ];
}

const SIGNALS: ReadonlyArray<{
  key: Signal;
  enabled: (declaration: DeclaredAgentCapabilities) => boolean;
  title: string;
  rationale: string;
  recommendation: string;
}> = [
  {
    key: "tool_surface",
    enabled: (declaration) =>
      declaration.toolNames.length > 0 || declaration.permissionNames.length > 0,
    title: "Herramientas y permisos declarados",
    rationale:
      "Se declararon superficies de herramienta o permisos; no se verificó que existan ni que el agente pueda usarlos.",
    recommendation:
      "Verificar cada herramienta y permiso en el límite de confianza del servidor; no aceptar declaraciones del modelo como autoridad.",
  },
  {
    key: "dependency_boundary",
    enabled: (declaration) => declaration.dependencies.length > 0,
    title: "Dependencias declaradas",
    rationale:
      "Se declararon dependencias que podrían influir en contexto o delegación; su identidad y alcance no se validaron.",
    recommendation:
      "Inventariar dependencias y propagar procedencia; no heredar permisos por dependencia.",
  },
  {
    key: "untrusted_input",
    enabled: (declaration) => declaration.untrustedInputs,
    title: "Contenido no confiable",
    rationale:
      "La declaración incluye mensajes, filas, páginas, código o salidas de herramientas no confiables.",
    recommendation:
      "Etiquetar la procedencia en la entrada y separar el contenido de usuario de la intención autenticada.",
  },
  {
    key: "sensitive_data",
    enabled: (declaration) => declaration.dataSensitivity !== "public",
    title: "Datos internos o sensibles",
    rationale:
      "La sensibilidad declarada no es pública; esta entrada no verifica clasificación real ni exposición.",
    recommendation:
      "Aplicar mínimo privilegio, minimización y redacción antes de incluir o exportar datos.",
  },
  {
    key: "external_recipient",
    enabled: (declaration) => declaration.externalRecipients,
    title: "Destinatarios o destinos externos",
    rationale:
      "Se declaró la posibilidad de enviar datos o acciones a un destino externo.",
    recommendation:
      "Comprobar destino, tenant, intención y permiso exactos antes del despacho; la página no realiza envíos.",
  },
  {
    key: "persistent_effect",
    enabled: (declaration) => declaration.persistentEffects,
    title: "Efecto persistente",
    rationale:
      "Se declaró que una acción puede cambiar estado; no se ejecutó ni se confirmó el efecto.",
    recommendation:
      "Exigir una decisión determinista vigente y vincularla al payload exacto antes de cualquier adaptador.",
  },
  {
    key: "destructive_operation",
    enabled: (declaration) => declaration.destructiveOperations,
    title: "Operación destructiva",
    rationale:
      "Se declaró una operación de borrado o de impacto irreversible.",
    recommendation:
      "Mantener deny por defecto, validar alcance y exigir revisión separada donde aplique.",
  },
  {
    key: "privilege_change",
    enabled: (declaration) => declaration.privilegeChanges,
    title: "Cambio de identidad o privilegios",
    rationale:
      "Se declaró capacidad de cambiar roles, permisos o configuración de acceso.",
    recommendation:
      "No permitir que el agente se conceda permisos; revalidar identidad y rol desde fuentes autenticadas.",
  },
  {
    key: "delegation",
    enabled: (declaration) => declaration.delegation,
    title: "Delegación entre agentes",
    rationale:
      "Se declaró delegación; la identidad y el alcance de cada salto no se verificaron.",
    recommendation:
      "Propagar actor raíz y tenant y restringir cada capacidad delegada a la intersección del scope autorizado.",
  },
  {
    key: "approval_boundary",
    enabled: (declaration) => declaration.approvalRequired,
    title: "Frontera de aprobación",
    rationale:
      "Se declaró que ciertas acciones requieren aprobación; este análisis no acredita una aprobación persistente.",
    recommendation:
      "Vincular una aprobación vigente al hash exacto, actor y tenant; bloquear replay, expiración o revocación.",
  },
];

export function analyzeDeclaredCapabilities(
  input: unknown,
): CapabilityAnalysis {
  validateDeclaration(input);
  const declaration = input;
  const profile = profileFor(declaration.profileId);
  const findings = SIGNALS.filter((signal) => signal.enabled(declaration)).map(
    (signal) => ({
      findingId: `GNRI-DISC-${profile.id}-${signal.key}`,
      title: signal.title,
      rationale: signal.rationale,
      classification:
        signal.key === "untrusted_input"
          ? ("known_source_concept" as const)
          : ("inferred_from_declared_capability" as const),
      validationState: "pending_validation" as const,
      sourceRefs:
        signal.key === "untrusted_input"
          ? ["mitre-atlas", "owasp-agentic", "mit-stpa"]
          : ["owasp-agentic", "nist-ai-rmf", "mit-stpa"],
      riskItemRefs: selectedRiskItems(profile, signal.key),
      recommendation: signal.recommendation,
    }),
  );

  return {
    schemaVersion: "guardian-capability-discovery/1.0.0",
    profileId: declaration.profileId,
    mode: "local_advisory_only",
    declaredCounts: {
      tools: declaration.toolNames.length,
      permissions: declaration.permissionNames.length,
      dependencies: declaration.dependencies.length,
    },
    findings,
    decisionAuthority: "guardian_policy_engine_only",
    policyDecision: null,
    actionDispatched: false,
    evidenceNote:
      "Las declaraciones son sintéticas y no verificadas. Ningún hallazgo está confirmado por una prueba de runtime.",
  };
}
